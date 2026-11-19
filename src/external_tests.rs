use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;

use crate::collection_context::CollectionContext;
use crate::collectors::external::{self, ExternalError};
use crate::job::{Backend, InventoryKind, Job, Name, Scope, Target};
use crate::process::CommandSpec;

#[test]
fn collector_arguments_match_backend_contracts() {
    let cases = [
        (
            Scope::Host,
            Target::Host,
            Backend::Hbom,
            InventoryKind::Hbom,
            vec!["hbom", "-p"],
            vec![],
            "",
        ),
        (
            Scope::Host,
            Target::Host,
            Backend::Syft {
                exclusions: vec![],
                respect_gitignore: false,
            },
            InventoryKind::Sbom,
            vec!["syft", "scan", "dir:/", "-o", "cyclonedx-json"],
            vec![],
            "dir:/",
        ),
        (
            Scope::Application {
                name: Name::new("api".into()).unwrap(),
                version: Some("1.2.3".into()),
            },
            Target::Directory("/source tree".into()),
            Backend::Syft {
                exclusions: vec!["./dist/**".into(), "./cache space/**".into()],
                respect_gitignore: false,
            },
            InventoryKind::Sbom,
            vec![
                "syft",
                "scan",
                "dir:/source tree",
                "-o",
                "cyclonedx-json",
                "--source-name",
                "api",
                "--source-version",
                "1.2.3",
                "--exclude",
                "./dist/**",
                "--exclude",
                "./cache space/**",
            ],
            vec!["./dist/**", "./cache space/**"],
            "/source tree",
        ),
        (
            Scope::Application {
                name: Name::new("image".into()).unwrap(),
                version: None,
            },
            Target::RegistryImage("example/app:v1".into()),
            Backend::Syft {
                exclusions: vec!["./cache/**".into(), "./cache/**".into()],
                respect_gitignore: false,
            },
            InventoryKind::Sbom,
            vec![
                "syft",
                "scan",
                "registry:example/app:v1",
                "-o",
                "cyclonedx-json",
                "--source-name",
                "image",
                "--exclude",
                "./cache/**",
            ],
            vec!["./cache/**"],
            "registry:example/app:v1",
        ),
    ];

    for (scope, target, backend, kind, expected, expected_exclusions, expected_target) in cases {
        let job = Job::new(scope, None, kind, target, backend).unwrap();
        let context =
            CollectionContext::new(Duration::from_secs(5), Arc::new(AtomicBool::new(false)));

        let (executable, arguments, exclusions, target) =
            external::prepare(&job, &context).unwrap();

        assert_eq!(exclusions, expected_exclusions);
        assert_eq!(target, expected_target);
        let actual: Vec<OsString> = std::iter::once(executable).chain(arguments).collect();
        assert_eq!(
            actual,
            expected.into_iter().map(OsString::from).collect::<Vec<_>>()
        );
    }
}

#[test]
fn command_substitutes_only_argument_tokens_without_shell_expansion() {
    let spec = CommandSpec::new(
        "scanner-{target}".into(),
        [
            "--path={target}",
            "{target}/{target}",
            "$HOME; $(touch bad) *",
            "",
        ]
        .map(OsString::from)
        .to_vec(),
    )
    .unwrap();
    let job = Job::new(
        Scope::Application {
            name: Name::new("api".into()).unwrap(),
            version: None,
        },
        None,
        InventoryKind::Sbom,
        Target::Directory("/source tree; $(touch bad)".into()),
        Backend::Command(spec),
    )
    .unwrap();

    for _ in 0..2 {
        let context =
            CollectionContext::new(Duration::from_secs(5), Arc::new(AtomicBool::new(false)));

        let (executable, arguments, exclusions, target) =
            external::prepare(&job, &context).unwrap();

        assert!(exclusions.is_empty());
        assert_eq!(target, "/source tree; $(touch bad)");
        assert_eq!(executable, "scanner-{target}");
        assert_eq!(
            arguments,
            [
                "--path=/source tree; $(touch bad)",
                "/source tree; $(touch bad)//source tree; $(touch bad)",
                "$HOME; $(touch bad) *",
                ""
            ]
            .map(OsString::from)
        );
    }
}

#[test]
fn host_command_target_depends_on_inventory_kind() {
    for (kind, expected, expected_target) in [
        (
            InventoryKind::Sbom,
            vec!["--target=dir:/", "dir:/", "literal"],
            "dir:/",
        ),
        (InventoryKind::Hbom, vec!["--target=", "", "literal"], ""),
        (InventoryKind::Cbom, vec!["--target=", "", "literal"], ""),
    ] {
        let spec = CommandSpec::new(
            "scanner-{target}".into(),
            ["--target={target}", "{target}", "literal"]
                .map(OsString::from)
                .to_vec(),
        )
        .unwrap();
        let job = Job::new(
            Scope::Host,
            None,
            kind,
            Target::Host,
            Backend::Command(spec),
        )
        .unwrap();
        let context =
            CollectionContext::new(Duration::from_secs(5), Arc::new(AtomicBool::new(false)));

        let (executable, arguments, exclusions, target) =
            external::prepare(&job, &context).unwrap();

        assert!(exclusions.is_empty());
        assert_eq!(target, expected_target);
        assert_eq!(executable, "scanner-{target}");
        assert_eq!(
            arguments,
            expected.into_iter().map(OsString::from).collect::<Vec<_>>()
        );
    }
}

#[test]
fn doctor_checks_files_without_executing_collector() {
    let directory = tempfile::tempdir().unwrap();
    let script = directory.path().join("collector");
    let marker = directory.path().join("executed");
    std::fs::write(
        &script,
        b"#!/bin/sh\nprintf executed > \"$1\"\nprintf bom\nprintf log >&2\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let job = Job::new(
        Scope::Application {
            name: Name::new("api".into()).unwrap(),
            version: None,
        },
        None,
        InventoryKind::Sbom,
        Target::Directory(directory.path().into()),
        Backend::Command(
            CommandSpec::new(script.into_os_string(), vec![marker.as_os_str().to_owned()]).unwrap(),
        ),
    )
    .unwrap();

    external::check(&job).unwrap();

    assert!(!marker.exists());

    let context = CollectionContext::new(Duration::from_secs(5), Arc::new(AtomicBool::new(false)));
    let (mut output, mut stderr) = (Vec::new(), Vec::new());

    let result = external::collect(&job, &context, &mut output, &mut stderr).unwrap();

    assert_eq!(output, b"bom");
    assert_eq!(stderr, b"log");
    assert_eq!(std::fs::read(marker).unwrap(), b"executed");
    assert!(matches!(
        result.coverage(),
        crate::collection_outcome::Coverage::Unknown
    ));
}

#[test]
fn doctor_rejects_a_file_as_directory_target() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let job = Job::new(
        Scope::Application {
            name: Name::new("api".into()).unwrap(),
            version: None,
        },
        None,
        InventoryKind::Sbom,
        Target::Directory(file.path().into()),
        Backend::Command(CommandSpec::new("/bin/sh".into(), vec![]).unwrap()),
    )
    .unwrap();

    assert!(matches!(
        external::check(&job),
        Err(ExternalError::NotDirectory { .. })
    ));
}

#[test]
fn git_ignores_preserve_negations_tracked_files_and_escape_globs() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    assert!(
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["init", "--quiet"])
            .status()
            .unwrap()
            .success()
    );
    for (path, content) in [
        (".gitignore", "cache/\n*.log\n!keep.log\nweird*/\n"),
        ("cache/module/go.mod", "ignored"),
        ("drop.log", "ignored"),
        ("keep.log", "included"),
        ("tracked.log", "included"),
        ("nested/.gitignore", "secret.txt\n!keep.log\n"),
        ("nested/secret.txt", "ignored"),
        ("nested/keep.log", "included"),
        ("weird[1]/module", "ignored"),
        ("source.go", "included"),
    ] {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    assert!(
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["add", "--force", "tracked.log"])
            .status()
            .unwrap()
            .success()
    );

    for (target, expected) in [
        (
            root.to_path_buf(),
            vec![
                "./manual/**",
                "./.git",
                "./.git/**",
                "./cache/**",
                "./drop.log",
                "./nested/secret.txt",
                "./weird\\[1\\]/**",
            ],
        ),
        (
            root.join("nested"),
            vec!["./manual/**", "./.git", "./.git/**", "./secret.txt"],
        ),
    ] {
        let expected_target = target.to_str().unwrap().to_owned();
        let job = Job::new(
            Scope::Application {
                name: Name::new("api".into()).unwrap(),
                version: None,
            },
            None,
            InventoryKind::Sbom,
            Target::Directory(target),
            Backend::Syft {
                exclusions: vec!["./manual/**".into(), "./manual/**".into()],
                respect_gitignore: true,
            },
        )
        .unwrap();
        let context =
            CollectionContext::new(Duration::from_secs(5), Arc::new(AtomicBool::new(false)));

        let (_, arguments, exclusions, target) = external::prepare(&job, &context).unwrap();

        assert_eq!(exclusions, expected);
        assert_eq!(target, expected_target);
        let actual: Vec<_> = arguments
            .windows(2)
            .filter(|pair| pair[0] == "--exclude")
            .map(|pair| pair[1].clone())
            .collect();
        assert_eq!(
            actual,
            expected.into_iter().map(OsString::from).collect::<Vec<_>>()
        );

        let Backend::Syft { exclusions, .. } = job.backend() else {
            unreachable!()
        };
        assert_eq!(exclusions, &["./manual/**", "./manual/**"]);
    }
}
