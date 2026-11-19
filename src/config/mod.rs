//! Decode configuration into validated collector jobs and run settings.

pub(crate) mod document;
pub(crate) mod duration;

use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

use crate::config::document::{Collector, Document, Inventory};
use crate::config::duration::parse_duration;
use crate::job::{Backend, InventoryKind, Job, JobError, Name, NameError, Scope, Target};
use crate::process::CommandSpecification;

#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) output_directory: PathBuf,
    pub(crate) timeout: Duration,
    pub(crate) jobs: Vec<Job>,
    pub(crate) applications: Vec<Name>,
}

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("cannot read configuration {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid YAML configuration: {0}")]
    InvalidYaml(#[source] Box<serde_saphyr::Error>),
    #[error("configuration must contain a nonempty YAML document")]
    EmptyDocument,
    #[error("version must be 1, got {version}")]
    UnsupportedVersion { version: i64 },

    #[error("output.directory is required")]
    MissingOutputDirectory,
    #[error("timeout must be a positive Go duration")]
    InvalidTimeout,

    #[error("invalid name {name:?} in {scope}: {source}")]
    InvalidName {
        scope: String,
        name: String,
        #[source]
        source: NameError,
    },
    #[error("duplicate or reserved name {name:?} in {scope}")]
    DuplicateName { scope: String, name: String },

    #[error("invalid target for application {name}")]
    InvalidTarget { name: String },
    #[error("invalid inventory kind {kind:?} in {scope}")]
    InvalidKind { scope: String, kind: String },
    #[error("invalid collector in {scope}: {source}")]
    InvalidCollector {
        scope: String,
        #[source]
        source: CollectorError,
    },
}

#[derive(Debug, Error)]
pub(crate) enum CollectorError {
    #[error("backend-specific options do not match the backend")]
    OptionsMismatch,
    #[error("unused command or Syft options")]
    UnusedOptions,
    #[error("unsupported backend {backend:?}")]
    UnsupportedBackend { backend: String },
    #[error("required collector options are missing or invalid")]
    InvalidOptions,

    #[error("invalid backend contract")]
    Contract(#[source] JobError),
}

impl Config {
    pub(crate) fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;

        Self::parse(&text)
    }

    pub(crate) fn parse(text: &str) -> Result<Self, ConfigError> {
        let options = serde_saphyr::options! {
            duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
            with_snippet: false,
            legacy_octal_numbers: true,
        };
        let document = serde_saphyr::from_str_with_options::<Option<Document>>(text, options)
            .map_err(|source| ConfigError::InvalidYaml(Box::new(source)))?
            .ok_or(ConfigError::EmptyDocument)?;

        if document.version != 1 {
            return Err(ConfigError::UnsupportedVersion {
                version: document.version,
            });
        }
        if document.output.directory.is_empty() {
            return Err(ConfigError::MissingOutputDirectory);
        }

        let timeout = if document.timeout.is_empty() {
            Duration::from_secs(600)
        } else {
            parse_duration(&document.timeout).ok_or(ConfigError::InvalidTimeout)?
        };
        let mut configuration = Self {
            output_directory: document.output.directory.into(),
            timeout,
            jobs: Vec::new(),
            applications: Vec::new(),
        };

        configuration.add_collector(
            &Scope::Host,
            &Target::Host,
            None,
            InventoryKind::Hbom,
            document.host.hbom,
        )?;
        configuration.add_collector(
            &Scope::Host,
            &Target::Host,
            None,
            InventoryKind::Sbom,
            document.host.sbom,
        )?;
        configuration.add_inventories(&Scope::Host, &Target::Host, document.host.inventories)?;

        let mut seen = HashSet::from([String::from("host")]);
        for application in document.applications {
            let name = checked_name(&application.name, "applications")?;
            if !seen.insert(application.name.clone()) {
                return Err(ConfigError::DuplicateName {
                    scope: "applications".into(),
                    name: application.name,
                });
            }

            let target = match application.target.kind.as_str() {
                "directory"
                    if !application.target.path.is_empty()
                        && application.target.image.is_empty() =>
                {
                    Target::Directory(application.target.path.into())
                }
                "nix-closure"
                    if !application.target.path.is_empty()
                        && application.target.image.is_empty() =>
                {
                    Target::NixClosure(application.target.path.into())
                }
                "container"
                    if !application.target.image.is_empty()
                        && application.target.path.is_empty() =>
                {
                    Target::RegistryImage(application.target.image)
                }
                _ => {
                    return Err(ConfigError::InvalidTarget {
                        name: application.name,
                    });
                }
            };

            configuration.applications.push(name.clone());
            let scope = Scope::Application {
                name,
                version: (!application.version.is_empty()).then_some(application.version),
            };
            configuration.add_collector(
                &scope,
                &target,
                None,
                InventoryKind::Sbom,
                application.sbom,
            )?;
            configuration.add_collector(
                &scope,
                &target,
                None,
                InventoryKind::Cbom,
                application.cbom,
            )?;
            configuration.add_inventories(&scope, &target, application.inventories)?;
        }

        Ok(configuration)
    }

    fn add_inventories(
        &mut self,
        scope: &Scope,
        target: &Target,
        inventories: Vec<Inventory>,
    ) -> Result<(), ConfigError> {
        let mut seen = HashSet::new();
        for inventory in inventories {
            let name = checked_name(&inventory.name, scope.name())?;
            if !seen.insert(inventory.name.clone()) {
                return Err(ConfigError::DuplicateName {
                    scope: scope.name().into(),
                    name: inventory.name,
                });
            }

            let kind = match inventory.kind.as_str() {
                "hbom" => InventoryKind::Hbom,
                "sbom" => InventoryKind::Sbom,
                "cbom" => InventoryKind::Cbom,
                _ => {
                    return Err(ConfigError::InvalidKind {
                        scope: scope.name().into(),
                        kind: inventory.kind,
                    });
                }
            };
            self.add_collector(scope, target, Some(name), kind, inventory.collector)?;
        }

        Ok(())
    }

    fn add_collector(
        &mut self,
        scope: &Scope,
        target: &Target,
        inventory: Option<Name>,
        kind: InventoryKind,
        collector: Collector,
    ) -> Result<(), ConfigError> {
        if !collector.enabled {
            return Ok(());
        }

        let context = format!(
            "{}.{}",
            scope.name(),
            inventory.as_ref().map_or(kind.as_str(), Name::as_str)
        );
        let invalid = |source| ConfigError::InvalidCollector {
            scope: context.clone(),
            source,
        };

        if (collector.nix.is_some() && collector.backend != "nix")
            || (collector.certificates.is_some() && collector.backend != "certificates")
            || (collector.import.is_some() && collector.backend != "import")
        {
            return Err(invalid(CollectorError::OptionsMismatch));
        }
        if (!collector.command.is_empty() && collector.backend != "command")
            || ((!collector.exclude.is_empty() || collector.respect_gitignore)
                && (kind != InventoryKind::Sbom || collector.backend != "syft"))
        {
            return Err(invalid(CollectorError::UnusedOptions));
        }

        let backend = match collector.backend.as_str() {
            "hbom" => Backend::Hbom,
            "syft" => Backend::Syft {
                exclusions: collector.exclude,
                respect_gitignore: collector.respect_gitignore,
            },
            "command" => {
                let mut arguments = collector.command.into_iter().map(OsString::from);
                let executable = arguments
                    .next()
                    .ok_or_else(|| invalid(CollectorError::InvalidOptions))?;
                let specification = CommandSpecification::new(executable, arguments.collect())
                    .map_err(|_| invalid(CollectorError::InvalidOptions))?;

                Backend::Command(specification)
            }
            "nix" => Backend::Nix {
                roots: collector.nix.unwrap_or_default().roots,
            },
            "certificates" => {
                let options = collector
                    .certificates
                    .ok_or_else(|| invalid(CollectorError::InvalidOptions))?;
                if !(0..=64 << 20).contains(&options.max_file_bytes) {
                    return Err(invalid(CollectorError::InvalidOptions));
                }

                Backend::Certificates {
                    paths: options.paths,
                    max_file_bytes: if options.max_file_bytes == 0 {
                        4 << 20
                    } else {
                        options.max_file_bytes as u64
                    },
                    include_identity: options.include_identity,
                }
            }
            "import" => Backend::Import {
                path: collector
                    .import
                    .ok_or_else(|| invalid(CollectorError::InvalidOptions))?
                    .path,
            },
            _ => {
                return Err(invalid(CollectorError::UnsupportedBackend {
                    backend: collector.backend,
                }));
            }
        };

        let job = Job::new(scope.clone(), inventory, kind, target.clone(), backend)
            .map_err(|source| invalid(CollectorError::Contract(source)))?;
        self.jobs.push(job);

        Ok(())
    }
}

fn checked_name(value: &str, scope: &str) -> Result<Name, ConfigError> {
    Name::new(value.to_owned()).map_err(|source| ConfigError::InvalidName {
        scope: scope.into(),
        name: value.into(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use crate::config::{CollectorError, Config, ConfigError};
    use crate::job::{Backend, JobError};

    const BASE: &str = "version: 1\noutput: {directory: /tmp/inventories}\n";

    #[test]
    fn configuration_defaults_and_explicit_duration() {
        let configuration = Config::parse(BASE).unwrap();

        assert_eq!(
            configuration.output_directory,
            Path::new("/tmp/inventories")
        );
        assert_eq!(configuration.timeout, Duration::from_secs(600));
        assert!(configuration.jobs.is_empty());

        for (input, nanoseconds) in [
            ("1h2m3.004005006s", 3_723_004_005_006),
            ("+.5s", 500_000_000),
            ("1.s", 1_000_000_000),
            ("1us", 1_000),
            ("0.0000000009s1ns", 1),
            ("0.9999999999999999999ns", 1),
            ("2562047h47m16.854775807s", i64::MAX as u64),
        ] {
            let configuration = Config::parse(&format!("{BASE}timeout: '{input}'\n")).unwrap();

            assert_eq!(
                configuration.timeout,
                Duration::from_nanos(nanoseconds),
                "{input}"
            );
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
            Config::load(&path).unwrap().output_directory,
            Path::new("/tmp/inventories")
        );
    }

    #[test]
    fn validation_reports_the_first_error_in_configuration_order() {
        assert!(matches!(
            Config::parse("version: 2\ntimeout: invalid\n"),
            Err(ConfigError::UnsupportedVersion { version: 2 })
        ));
        assert!(matches!(
            Config::parse("version: 1\ntimeout: invalid\n"),
            Err(ConfigError::MissingOutputDirectory)
        ));
        assert!(matches!(
            Config::parse(&format!(
                "{BASE}timeout: invalid\nhost: {{hbom: {{enabled: true, backend: unknown}}}}\n"
            )),
            Err(ConfigError::InvalidTimeout)
        ));
        assert!(matches!(
            Config::parse(&format!(
                "{BASE}host: {{hbom: {{enabled: true, backend: unknown}}}}\napplications: [{{name: '../invalid'}}]\n"
            )),
            Err(ConfigError::InvalidCollector { scope, .. }) if scope == "host.hbom"
        ));
        assert!(matches!(
            Config::parse(&format!("{BASE}applications: [{{name: host}}]\n")),
            Err(ConfigError::DuplicateName { .. })
        ));
        assert!(matches!(
            Config::parse(&format!(
                "{BASE}host: {{sbom: {{enabled: true, backend: syft, nix: {{}}, command: [scanner]}}}}\n"
            )),
            Err(ConfigError::InvalidCollector {
                source: CollectorError::OptionsMismatch,
                ..
            })
        ));
    }

    #[test]
    fn null_fields_have_go_zero_value_behavior() {
        let configuration = Config::parse(&format!("{BASE}timeout: null\nhost: {{hbom: null, sbom: {{enabled: null, command: null}}, inventories: null}}\napplications: null\n")).unwrap();

        assert_eq!(configuration.timeout, Duration::from_secs(600));
        assert!(configuration.jobs.is_empty());
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
            let applications = names
                .split(", ")
                .map(|name| format!("{{name: {name}, target: {{type: directory, path: /app}}}}"))
                .collect::<Vec<_>>()
                .join(", ");

            assert!(matches!(
                Config::parse(&format!("{BASE}applications: [{applications}]\n")),
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
        let configuration = Config::parse(&format!("{BASE}host:\n  inventories:\n    - name: off\n      kind: cbom\n      collector:\n        backend: unknown\n        certificates: {{paths: [''], max_file_bytes: -1}}\n        nix: {{roots: [relative]}}\n        import: {{path: ''}}\n")).unwrap();

        assert!(configuration.jobs.is_empty());
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
                    let configuration = result.unwrap();
                    let Backend::Certificates {
                        max_file_bytes,
                        include_identity,
                        ..
                    } = &configuration.jobs[0].backend
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
}
