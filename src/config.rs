//! Decode configuration into validated collector jobs and run settings.

use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Deserializer};
use thiserror::Error;

use crate::model::{
    Backend, CommandSpec, InventoryKind, Job, JobError, Name, NameError, Scope, Target,
};

#[derive(Debug)]
pub(crate) struct Config {
    output_directory: PathBuf,
    timeout: Duration,
    jobs: Vec<Job>,
    applications: Vec<Name>,
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

// YAML null has the same zero-value behavior as an omitted Go configuration field.
fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Document {
    #[serde(deserialize_with = "null_default")]
    version: i64,
    #[serde(deserialize_with = "null_default")]
    output: Output,
    #[serde(deserialize_with = "null_default")]
    timeout: String,
    #[serde(deserialize_with = "null_default")]
    host: Host,
    #[serde(deserialize_with = "null_default")]
    applications: Vec<Application>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Output {
    #[serde(deserialize_with = "null_default")]
    directory: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Host {
    #[serde(deserialize_with = "null_default")]
    hbom: Collector,
    #[serde(deserialize_with = "null_default")]
    sbom: Collector,
    #[serde(deserialize_with = "null_default")]
    inventories: Vec<Inventory>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Application {
    #[serde(deserialize_with = "null_default")]
    name: String,
    #[serde(deserialize_with = "null_default")]
    version: String,
    #[serde(deserialize_with = "null_default")]
    target: RawTarget,
    #[serde(deserialize_with = "null_default")]
    sbom: Collector,
    #[serde(deserialize_with = "null_default")]
    cbom: Collector,
    #[serde(deserialize_with = "null_default")]
    inventories: Vec<Inventory>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawTarget {
    #[serde(rename = "type", deserialize_with = "null_default")]
    kind: String,
    #[serde(deserialize_with = "null_default")]
    path: String,
    #[serde(deserialize_with = "null_default")]
    image: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Inventory {
    #[serde(deserialize_with = "null_default")]
    name: String,
    #[serde(deserialize_with = "null_default")]
    kind: String,
    #[serde(deserialize_with = "null_default")]
    collector: Collector,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Collector {
    #[serde(deserialize_with = "null_default")]
    enabled: bool,
    #[serde(deserialize_with = "null_default")]
    backend: String,
    #[serde(deserialize_with = "null_default")]
    command: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    exclude: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    respect_gitignore: bool,
    nix: Option<NixOptions>,
    certificates: Option<CertificateOptions>,
    import: Option<ImportOptions>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NixOptions {
    #[serde(deserialize_with = "null_default")]
    roots: Vec<PathBuf>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CertificateOptions {
    #[serde(deserialize_with = "null_default")]
    paths: Vec<PathBuf>,
    #[serde(deserialize_with = "null_default")]
    max_file_bytes: i64,
    #[serde(deserialize_with = "null_default")]
    include_identity: bool,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ImportOptions {
    #[serde(deserialize_with = "null_default")]
    path: PathBuf,
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
        let mut config = Self {
            output_directory: document.output.directory.into(),
            timeout,
            jobs: Vec::new(),
            applications: Vec::new(),
        };

        config.add_collector(
            &Scope::Host,
            &Target::Host,
            None,
            InventoryKind::Hbom,
            document.host.hbom,
        )?;
        config.add_collector(
            &Scope::Host,
            &Target::Host,
            None,
            InventoryKind::Sbom,
            document.host.sbom,
        )?;
        config.add_inventories(&Scope::Host, &Target::Host, document.host.inventories)?;

        let mut seen = HashSet::from([String::from("host")]);
        for app in document.applications {
            let name = checked_name(&app.name, "applications")?;
            if !seen.insert(app.name.clone()) {
                return Err(ConfigError::DuplicateName {
                    scope: "applications".into(),
                    name: app.name,
                });
            }

            let target = match app.target.kind.as_str() {
                "directory" if !app.target.path.is_empty() && app.target.image.is_empty() => {
                    Target::Directory(app.target.path.into())
                }
                "nix-closure" if !app.target.path.is_empty() && app.target.image.is_empty() => {
                    Target::NixClosure(app.target.path.into())
                }
                "container" if !app.target.image.is_empty() && app.target.path.is_empty() => {
                    Target::RegistryImage(app.target.image)
                }
                _ => return Err(ConfigError::InvalidTarget { name: app.name }),
            };

            config.applications.push(name.clone());
            let scope = Scope::Application {
                name,
                version: (!app.version.is_empty()).then_some(app.version),
            };
            config.add_collector(&scope, &target, None, InventoryKind::Sbom, app.sbom)?;
            config.add_collector(&scope, &target, None, InventoryKind::Cbom, app.cbom)?;
            config.add_inventories(&scope, &target, app.inventories)?;
        }

        Ok(config)
    }

    pub(crate) fn output_directory(&self) -> &Path {
        &self.output_directory
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(crate) fn jobs(&self) -> &[Job] {
        &self.jobs
    }

    pub(crate) fn applications(&self) -> &[Name] {
        &self.applications
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
                let mut args = collector.command.into_iter().map(OsString::from);
                let executable = args
                    .next()
                    .ok_or_else(|| invalid(CollectorError::InvalidOptions))?;
                let spec = CommandSpec::new(executable, args.collect())
                    .map_err(|_| invalid(CollectorError::InvalidOptions))?;

                Backend::Command(spec)
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

fn parse_duration(text: &str) -> Option<Duration> {
    let mut rest = text.strip_prefix('+').unwrap_or(text);
    let mut total = 0_u64;

    while !rest.is_empty() {
        let end = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_digit() || *byte == b'.')
            .count();
        let number = &rest[..end];
        if !number.bytes().any(|byte| byte.is_ascii_digit()) {
            return None;
        }

        let mut parts = number.split('.');
        let whole = parts.next()?;
        let fraction = parts.next().unwrap_or("");
        if parts.next().is_some() {
            return None;
        }

        rest = &rest[end..];
        let (unit, scale) = [
            ("ns", 1_u64),
            ("us", 1_000),
            ("\u{00b5}s", 1_000),
            ("\u{03bc}s", 1_000),
            ("ms", 1_000_000),
            ("s", 1_000_000_000),
            ("m", 60_000_000_000),
            ("h", 3_600_000_000_000),
        ]
        .into_iter()
        .find(|(unit, _)| rest.starts_with(unit))?;
        rest = &rest[unit.len()..];

        let integral = if whole.is_empty() {
            0
        } else {
            whole.parse::<u64>().ok()?
        };
        let mut nanos = integral.checked_mul(scale)?;

        // Match time.ParseDuration's bounded significand and floating-point scaling.
        let mut numerator = 0_u64;
        let mut divisor = 1_f64;
        for digit in fraction.bytes() {
            if numerator > i64::MAX as u64 / 10 {
                break;
            }
            let next = numerator * 10 + u64::from(digit - b'0');
            if next > 1_u64 << 63 {
                break;
            }
            numerator = next;
            divisor *= 10.0;
        }
        if numerator > 0 {
            nanos = nanos.checked_add((numerator as f64 * (scale as f64 / divisor)) as u64)?;
        }

        total = total.checked_add(nanos)?;
        if total > i64::MAX as u64 {
            return None;
        }
    }

    (total > 0).then(|| Duration::from_nanos(total))
}
