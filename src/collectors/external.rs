use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use thiserror::Error;

use crate::collection::context::CollectionContext;
use crate::collection::outcome::{CollectionOutcome, ExecutionScope};
use crate::job::{Backend, InventoryKind, Job, Scope, Target};
use crate::process::{Process, ProcessError};

#[derive(Debug, Error)]
pub(crate) enum ExternalError {
    #[error("external collector process failed")]
    Process(#[from] ProcessError),
    #[error("external collector process failed")]
    Execution {
        #[source]
        source: ProcessError,
        exclusions: Vec<String>,
        target: String,
    },
    #[error("backend or target is unsupported by external collectors")]
    UnsupportedTarget,
    #[error("Syft cannot inventory a NixOS host closure")]
    NixosHost,
    #[error("cannot inspect target {path:?}")]
    TargetIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("target is not a directory: {path:?}")]
    NotDirectory { path: PathBuf },
}

struct PreparedCommand {
    executable: OsString,
    arguments: Vec<OsString>,
    exclusions: Vec<String>,
    target: String,
}

pub(crate) fn check(job: &Job) -> Result<(), ExternalError> {
    let executable = match &job.backend {
        Backend::Hbom => OsStr::new("hbom"),
        Backend::Syft {
            respect_gitignore, ..
        } => {
            if job.scope.is_host() && std::path::Path::new("/run/current-system").exists() {
                return Err(ExternalError::NixosHost);
            }
            if *respect_gitignore {
                Process::find_executable(OsStr::new("git"))?;
            }
            OsStr::new("syft")
        }
        Backend::Command(command) => command.executable(),
        _ => return Err(ExternalError::UnsupportedTarget),
    };
    Process::find_executable(executable)?;

    if !job.scope.is_host()
        && let Target::Directory(path) = &job.target
    {
        let metadata = std::fs::metadata(path).map_err(|source| ExternalError::TargetIo {
            path: path.clone(),
            source,
        })?;
        if !metadata.is_dir() {
            return Err(ExternalError::NotDirectory { path: path.clone() });
        }
    }

    Ok(())
}

pub(crate) fn collect(
    job: &Job,
    context: &CollectionContext,
    output: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<CollectionOutcome, ExternalError> {
    check(job)?;
    let prepared = prepare_command(job, context)?;

    Process::stream(
        &prepared.executable,
        &prepared.arguments,
        context.deadline,
        &context.cancelled,
        output,
        stderr,
    )
    .map_err(|source| ExternalError::Execution {
        source,
        exclusions: prepared.exclusions.clone(),
        target: prepared.target.clone(),
    })?;

    Ok(CollectionOutcome {
        scope: ExecutionScope {
            target: Some(prepared.target),
            exclusions: Some(prepared.exclusions),
        },
        ..CollectionOutcome::external()
    })
}

#[cfg(test)]
pub(crate) fn prepare(
    job: &Job,
    context: &CollectionContext,
) -> Result<(OsString, Vec<OsString>, Vec<String>, String), ExternalError> {
    let prepared = prepare_command(job, context)?;
    Ok((
        prepared.executable,
        prepared.arguments,
        prepared.exclusions,
        prepared.target,
    ))
}

fn prepare_command(
    job: &Job,
    context: &CollectionContext,
) -> Result<PreparedCommand, ExternalError> {
    let target = match &job.target {
        Target::Host if matches!(job.kind, InventoryKind::Sbom) => OsString::from("dir:/"),
        Target::Directory(path) | Target::NixClosure(path) => path.as_os_str().to_owned(),
        target => OsString::from(target.display()),
    };
    let (executable, mut arguments) = command(job, &target)?;

    let mut patterns: Vec<OsString> = match &job.backend {
        Backend::Syft { exclusions, .. } => exclusions.iter().map(OsString::from).collect(),
        _ => Vec::new(),
    };
    if let Backend::Syft {
        respect_gitignore: true,
        ..
    } = &job.backend
    {
        let Target::Directory(path) = &job.target else {
            return Err(ExternalError::UnsupportedTarget);
        };
        let git_arguments = [
            OsString::from("-C"),
            path.as_os_str().to_owned(),
            OsString::from("ls-files"),
            OsString::from("--others"),
            OsString::from("--ignored"),
            OsString::from("--exclude-standard"),
            OsString::from("--directory"),
            OsString::from("-z"),
        ];
        let ignored_paths_output = Process::capture(
            OsStr::new("git"),
            &git_arguments,
            context.deadline,
            &context.cancelled,
            64 << 20,
            1 << 20,
        )?;

        patterns.extend([OsString::from("./.git"), OsString::from("./.git/**")]);
        for path in ignored_paths_output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
        {
            let is_directory = path.ends_with(b"/");
            let path = if is_directory {
                &path[..path.len() - 1]
            } else {
                path
            };
            let mut pattern = b"./".to_vec();
            for byte in path {
                if b"\\*?[]{}".contains(byte) {
                    pattern.push(b'\\');
                }
                pattern.push(*byte);
            }
            if is_directory {
                pattern.extend_from_slice(b"/**");
            }
            patterns.push(OsString::from_vec(pattern));
        }
    }

    let mut exclusions = Vec::new();
    let mut unique_patterns = std::collections::HashSet::new();
    for pattern in patterns {
        if unique_patterns.insert(pattern.clone()) {
            exclusions.push(crate::path_encoding::path_text(std::path::Path::new(
                &pattern,
            )));
            arguments.extend([OsString::from("--exclude"), pattern]);
        }
    }

    Ok(PreparedCommand {
        executable,
        arguments,
        exclusions,
        target: crate::path_encoding::path_text(std::path::Path::new(&target)),
    })
}

fn command(
    job: &Job,
    effective_target: &OsStr,
) -> Result<(OsString, Vec<OsString>), ExternalError> {
    match &job.backend {
        Backend::Hbom => Ok(("hbom".into(), vec!["-p".into()])),
        Backend::Syft { .. } => {
            let target = match &job.target {
                Target::Host => OsString::from("dir:/"),
                Target::Directory(path) => {
                    let mut directory_target = OsString::from("dir:");
                    directory_target.push(path);
                    directory_target
                }
                Target::RegistryImage(image) => OsString::from(format!("registry:{image}")),
                _ => return Err(ExternalError::UnsupportedTarget),
            };
            let mut arguments = vec!["scan".into(), target, "-o".into(), "cyclonedx-json".into()];
            if let Scope::Application { name, version } = &job.scope {
                arguments.extend(["--source-name".into(), name.as_str().into()]);
                if let Some(version) = version {
                    arguments.extend(["--source-version".into(), version.into()]);
                }
            }

            Ok(("syft".into(), arguments))
        }
        Backend::Command(command) => {
            let arguments = command
                .arguments
                .iter()
                .map(|argument| {
                    let mut substituted_argument = Vec::new();
                    let mut remaining_bytes = argument.as_bytes();
                    while let Some(token_start) = remaining_bytes
                        .windows(8)
                        .position(|window| window == b"{target}")
                    {
                        substituted_argument.extend_from_slice(&remaining_bytes[..token_start]);
                        substituted_argument.extend_from_slice(effective_target.as_bytes());
                        remaining_bytes = &remaining_bytes[token_start + 8..];
                    }
                    substituted_argument.extend_from_slice(remaining_bytes);
                    OsString::from_vec(substituted_argument)
                })
                .collect();

            Ok((command.executable().to_owned(), arguments))
        }
        _ => Err(ExternalError::UnsupportedTarget),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, atomic::AtomicBool};
    use std::time::Duration;

    use crate::collection::context::CollectionContext;
    use crate::collectors::external::{self, ExternalError};
    use crate::job::{Backend, InventoryKind, Job, Name, Scope, Target};
    use crate::process::CommandSpecification;

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

        for (scope, target, backend, kind, expected, expected_exclusions, expected_target) in cases
        {
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
        let command = CommandSpecification::new(
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
            Backend::Command(command),
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
            let command = CommandSpecification::new(
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
                Backend::Command(command),
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
                CommandSpecification::new(
                    script.into_os_string(),
                    vec![marker.as_os_str().to_owned()],
                )
                .unwrap(),
            ),
        )
        .unwrap();

        external::check(&job).unwrap();

        assert!(!marker.exists());

        let context =
            CollectionContext::new(Duration::from_secs(5), Arc::new(AtomicBool::new(false)));
        let (mut output, mut stderr) = (Vec::new(), Vec::new());

        let result = external::collect(&job, &context, &mut output, &mut stderr).unwrap();

        assert_eq!(output, b"bom");
        assert_eq!(stderr, b"log");
        assert_eq!(std::fs::read(marker).unwrap(), b"executed");
        assert!(matches!(
            result.coverage,
            crate::collection::outcome::Coverage::Unknown
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
            Backend::Command(CommandSpecification::new("/bin/sh".into(), vec![]).unwrap()),
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

            let Backend::Syft { exclusions, .. } = &job.backend else {
                unreachable!()
            };
            assert_eq!(exclusions, &["./manual/**", "./manual/**"]);
        }
    }
}
