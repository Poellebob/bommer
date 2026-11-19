use std::path::Path;
use std::time::Duration;

use crate::config::{CollectorError, Config, ConfigError};
use crate::model::{Backend, InventoryKind, JobError, Name, Target};
use crate::plan::{Plan, PlanError, Selection};

const BASE: &str = "version: 1\noutput: {directory: /tmp/inventories}\n";

#[test]
fn configuration_defaults_and_explicit_duration() {
    let config = Config::parse(BASE).unwrap();

    assert_eq!(config.output_directory(), Path::new("/tmp/inventories"));
    assert_eq!(config.timeout(), Duration::from_secs(600));
    assert!(config.jobs().is_empty());

    for (input, nanos) in [
        ("1h2m3.004005006s", 3_723_004_005_006),
        ("+.5s", 500_000_000),
        ("1.s", 1_000_000_000),
        ("1us", 1_000),
        ("0.0000000009s1ns", 1),
        ("0.9999999999999999999ns", 1),
        ("2562047h47m16.854775807s", i64::MAX as u64),
    ] {
        let config = Config::parse(&format!("{BASE}timeout: '{input}'\n")).unwrap();
        assert_eq!(config.timeout(), Duration::from_nanos(nanos), "{input}");
    }

    for input in [
        "0",
        "0s",
        "-1s",
        "1d",
        "1",
        "1 s",
        ".s",
        "1..2s",
        "1e3s",
        "2562047h47m16.854775808s",
    ] {
        assert!(
            matches!(
                Config::parse(&format!("{BASE}timeout: '{input}'\n")),
                Err(ConfigError::InvalidTimeout)
            ),
            "{input}"
        );
    }
}

#[test]
fn strict_yaml_rejects_unknown_duplicate_and_extra_documents() {
    for text in [
        format!("{BASE}unexpected: true\n"),
        "version: 1\noutput: {directory: /tmp, typo: true}\n".into(),
        format!("{BASE}host: {{hbom: {{enable: true}}}}\n"),
        format!(
            "{BASE}host: {{inventories: [{{name: x, kind: cbom, collector: {{certificates: {{typo: true}}}}}}]}}\n"
        ),
        format!("{BASE}version: 1\n"),
        format!("{BASE}host: {{sbom: {{enabled: false, enabled: true}}}}\n"),
        format!("{BASE}---\nversion: 1\n"),
        format!("{BASE}---\n"),
        format!("{BASE}...\n---\n"),
        "version: [".into(),
        "version: nope\noutput: {directory: /tmp}\n".into(),
    ] {
        assert!(
            matches!(Config::parse(&text), Err(ConfigError::InvalidYaml(_))),
            "{text:?}"
        );
    }

    for text in ["", "# only a comment\n", "---\n"] {
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::EmptyDocument)
        ));
    }
}

#[test]
fn required_fields_and_io_errors_are_typed() {
    assert!(matches!(
        Config::parse("version: 2\noutput: {directory: /tmp}\n"),
        Err(ConfigError::UnsupportedVersion { version: 2 })
    ));
    assert!(matches!(
        Config::parse("version: 1\n"),
        Err(ConfigError::MissingOutputDirectory)
    ));

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    assert!(
        matches!(Config::load(&path), Err(ConfigError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound)
    );

    std::fs::write(&path, BASE).unwrap();
    assert_eq!(
        Config::load(&path).unwrap().output_directory(),
        Path::new("/tmp/inventories")
    );
}

#[test]
fn null_fields_have_go_zero_value_behavior() {
    let config = Config::parse(&format!("{BASE}timeout: null\nhost: {{hbom: null, sbom: {{enabled: null, command: null}}, inventories: null}}\napplications: null\n")).unwrap();

    assert_eq!(config.timeout(), Duration::from_secs(600));
    assert!(config.jobs().is_empty());
}

#[test]
fn names_and_targets_are_validated_even_without_enabled_collectors() {
    for name in ["", "../api", "a.b", "a/b", "a b", "-api"] {
        let text = format!(
            "{BASE}applications: [{{name: '{name}', target: {{type: directory, path: /app}}}}]\n"
        );

        assert!(matches!(
            Config::parse(&text),
            Err(ConfigError::InvalidName { .. })
        ));
    }

    for names in ["host", "api, api"] {
        let apps = names
            .split(", ")
            .map(|name| format!("{{name: {name}, target: {{type: directory, path: /app}}}}"))
            .collect::<Vec<_>>()
            .join(", ");

        assert!(matches!(
            Config::parse(&format!("{BASE}applications: [{apps}]\n")),
            Err(ConfigError::DuplicateName { .. })
        ));
    }

    for target in [
        "{}",
        "{type: directory}",
        "{type: directory, path: /app, image: x}",
        "{type: container}",
        "{type: container, image: x, path: /app}",
        "{type: nix-closure}",
        "{type: file, path: /app}",
    ] {
        assert!(matches!(
            Config::parse(&format!(
                "{BASE}applications: [{{name: api, target: {target}}}]\n"
            )),
            Err(ConfigError::InvalidTarget { .. })
        ));
    }

    assert!(matches!(
        Config::parse(&format!(
            "{BASE}host: {{inventories: [{{name: certs, kind: unknown}}]}}\n"
        )),
        Err(ConfigError::InvalidKind { .. })
    ));
    assert!(matches!(
        Config::parse(&format!(
            "{BASE}host: {{inventories: [{{name: certs, kind: cbom}}, {{name: certs, kind: sbom}}]}}\n"
        )),
        Err(ConfigError::DuplicateName { .. })
    ));
}

#[test]
fn disabled_collectors_preserve_go_validation_behavior() {
    let config = Config::parse(&format!("{BASE}host:\n  inventories:\n    - name: off\n      kind: cbom\n      collector:\n        backend: unknown\n        certificates: {{paths: [''], max_file_bytes: -1}}\n        nix: {{roots: [relative]}}\n        import: {{path: ''}}\n")).unwrap();

    assert!(config.jobs().is_empty());
}

#[test]
fn enabled_collectors_reject_mismatched_and_unused_options() {
    for options in [
        "backend: syft, certificates: {}",
        "backend: syft, nix: {}",
        "backend: syft, import: {}",
        "backend: syft, command: [scanner]",
        "backend: command, command: [scanner], exclude: [secret]",
        "backend: command, command: [scanner], respect_gitignore: true",
        "backend: command, command: []",
        "backend: command, command: ['', arg]",
        "backend: unknown",
        "backend: syft, exclude: ['']",
        "backend: syft, respect_gitignore: true",
        "backend: certificates, certificates: {paths: [/etc/ssl]}",
    ] {
        assert!(
            matches!(
                Config::parse(&format!(
                    "{BASE}host: {{sbom: {{enabled: true, {options}}}}}\n"
                )),
                Err(ConfigError::InvalidCollector { .. })
            ),
            "{options}"
        );
    }

    assert!(matches!(
        Config::parse(&format!(
            "{BASE}host: {{sbom: {{enabled: true, backend: syft, nix: {{}}}}}}\n"
        )),
        Err(ConfigError::InvalidCollector {
            source: CollectorError::OptionsMismatch,
            ..
        })
    ));
}

#[test]
fn native_backend_options_and_scope_contracts() {
    for (kind, target, options, valid) in [
        (
            "cbom",
            "directory",
            "backend: certificates, certificates: {paths: [certs]}",
            true,
        ),
        (
            "cbom",
            "nix-closure",
            "backend: certificates, certificates: {paths: [certs]}",
            true,
        ),
        (
            "cbom",
            "container",
            "backend: certificates, certificates: {paths: [/etc/ssl]}",
            false,
        ),
        ("cbom", "directory", "backend: certificates", false),
        (
            "cbom",
            "directory",
            "backend: certificates, certificates: {paths: []}",
            false,
        ),
        (
            "cbom",
            "directory",
            "backend: certificates, certificates: {paths: ['']}",
            false,
        ),
        (
            "cbom",
            "directory",
            "backend: import, import: {path: /tmp/cbom.json}",
            true,
        ),
        (
            "cbom",
            "container",
            "backend: import, import: {path: /tmp/cbom.json}",
            true,
        ),
        (
            "cbom",
            "nix-closure",
            "backend: import, import: {path: /tmp/cbom.json}",
            true,
        ),
        ("cbom", "directory", "backend: import, import: {}", false),
        ("sbom", "nix-closure", "backend: nix", true),
        (
            "sbom",
            "nix-closure",
            "backend: nix, nix: {roots: [relative]}",
            false,
        ),
        (
            "sbom",
            "directory",
            "backend: nix, nix: {roots: [/nix/store/root]}",
            false,
        ),
        ("sbom", "nix-closure", "backend: syft", false),
        (
            "cbom",
            "nix-closure",
            "backend: command, command: [scanner]",
            false,
        ),
        ("hbom", "directory", "backend: hbom", false),
        (
            "hbom",
            "directory",
            "backend: command, command: [scanner]",
            true,
        ),
        (
            "sbom",
            "directory",
            "backend: syft, respect_gitignore: true",
            true,
        ),
    ] {
        let location = if target == "container" {
            "image: example/api:1"
        } else {
            "path: /app"
        };
        let text = format!(
            "{BASE}applications: [{{name: api, target: {{type: {target}, {location}}}, inventories: [{{name: test, kind: {kind}, collector: {{enabled: true, {options}}}}}]}}]\n"
        );

        let result = Config::parse(&text);

        assert_eq!(result.is_ok(), valid, "{text}: {result:?}");
        if !valid {
            assert!(matches!(result, Err(ConfigError::InvalidCollector { .. })));
        }
    }

    for (options, valid) in [
        ("backend: nix", false),
        ("backend: nix, nix: {roots: [/nix/store/root]}", true),
        ("backend: nix, nix: {roots: [relative]}", false),
    ] {
        assert_eq!(
            Config::parse(&format!(
                "{BASE}host: {{sbom: {{enabled: true, {options}}}}}\n"
            ))
            .is_ok(),
            valid
        );
    }

    let result = Config::parse(&format!(
        "{BASE}host: {{inventories: [{{name: certs, kind: cbom, collector: {{enabled: true, backend: certificates, certificates: {{paths: [relative]}}}}}}]}}\n"
    ));

    assert!(matches!(
        result,
        Err(ConfigError::InvalidCollector {
            source: CollectorError::Contract(JobError::Options),
            ..
        })
    ));
}

#[test]
fn certificates_normalize_default_and_enforce_limits() {
    for (limit, expected) in [
        (-1, None),
        (0, Some(4 << 20)),
        (1, Some(1)),
        (64 << 20, Some(64 << 20)),
        ((64 << 20) + 1, None),
    ] {
        let text = format!(
            "{BASE}host: {{inventories: [{{name: certs, kind: cbom, collector: {{enabled: true, backend: certificates, certificates: {{paths: [/etc/ssl], max_file_bytes: {limit}}}}}}}]}}\n"
        );

        let result = Config::parse(&text);

        match expected {
            Some(expected) => {
                let config = result.unwrap();
                let Backend::Certificates {
                    max_file_bytes,
                    include_identity,
                    ..
                } = config.jobs()[0].backend()
                else {
                    panic!("expected certificates");
                };

                assert_eq!(*max_file_bytes, expected);
                assert!(!include_identity);
            }
            None => assert!(matches!(result, Err(ConfigError::InvalidCollector { .. }))),
        }
    }
}

#[test]
fn planning_preserves_order_metadata_and_selection() {
    let config = Config::parse(&format!("{BASE}host:\n  hbom: {{enabled: true, backend: hbom}}\n  sbom: {{enabled: true, backend: syft}}\n  inventories:\n    - name: certs\n      kind: cbom\n      collector: {{enabled: true, backend: certificates, certificates: {{paths: [/etc/ssl]}}}}\napplications:\n  - name: api\n    version: '2.3'\n    target: {{type: container, image: example/api:2}}\n    sbom: {{enabled: true, backend: syft}}\n    cbom: {{enabled: true, backend: command, command: [scanner, '{{target}}']}}\n    inventories:\n      - name: producer\n        kind: cbom\n        collector: {{enabled: true, backend: import, import: {{path: producer.json}}}}\n")).unwrap();
    for (kind, app, expected) in [
        (
            None,
            None,
            vec![
                "host.hbom",
                "host.sbom",
                "host.certs.cbom",
                "api.sbom",
                "api.cbom",
                "api.producer.cbom",
            ],
        ),
        (
            Some(InventoryKind::Cbom),
            None,
            vec!["host.certs.cbom", "api.cbom", "api.producer.cbom"],
        ),
        (
            None,
            Some("api"),
            vec!["api.sbom", "api.cbom", "api.producer.cbom"],
        ),
        (
            Some(InventoryKind::Cbom),
            Some("api"),
            vec!["api.cbom", "api.producer.cbom"],
        ),
    ] {
        let selection = Selection::new(kind, app.map(|name| Name::new(name.into()).unwrap()));
        let plan = Plan::build(&config, &selection).unwrap();

        assert_eq!(
            plan.jobs().iter().map(|job| job.stem()).collect::<Vec<_>>(),
            expected
        );
    }

    let job = &config.jobs()[3];
    assert_eq!(job.scope().version(), Some("2.3"));
    assert!(matches!(job.target(), Target::RegistryImage(image) if image == "example/api:2"));
    assert!(matches!(config.jobs()[1].target(), Target::Host));

    let Backend::Command(spec) = config.jobs()[4].backend() else {
        panic!("expected command");
    };

    assert_eq!(spec.executable(), "scanner");
    assert_eq!(spec.arguments(), &[std::ffi::OsString::from("{target}")]);
}

#[test]
fn disabled_application_is_known_but_has_empty_selection() {
    let config = Config::parse(&format!(
        "{BASE}applications: [{{name: off, target: {{type: directory, path: /app}}}}]\n"
    ))
    .unwrap();

    assert_eq!(
        config
            .applications()
            .iter()
            .map(Name::as_str)
            .collect::<Vec<_>>(),
        ["off"]
    );

    for application in [None, Some("off")] {
        let selection = Selection::new(
            None,
            application.map(|name| Name::new(name.into()).unwrap()),
        );

        assert!(matches!(
            Plan::build(&config, &selection),
            Err(PlanError::EmptySelection)
        ));
    }

    let selection = Selection::new(None, Some(Name::new("missing".into()).unwrap()));
    assert!(
        matches!(Plan::build(&config, &selection), Err(PlanError::UnknownApplication { name }) if name.as_str() == "missing")
    );
}
