use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

use crate::path_encoding::path_text;
use crate::process::CommandSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum InventoryKind {
    Hbom,
    Sbom,
    Cbom,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub(crate) struct Name(String);

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum NameError {
    #[error("name must not be empty")]
    Empty,
    #[error(
        "name must start with an ASCII letter or digit and contain only letters, digits, '_' or '-'"
    )]
    InvalidCharacters,
}

#[derive(Debug, Clone)]
pub(crate) enum Scope {
    Host,
    Application { name: Name, version: Option<String> },
}

#[derive(Debug, Clone)]
pub(crate) enum Target {
    Host,
    Directory(PathBuf),
    RegistryImage(String),
    NixClosure(PathBuf),
}

#[derive(Debug, Clone)]
pub(crate) enum Backend {
    Hbom,
    Syft {
        exclusions: Vec<String>,
        respect_gitignore: bool,
    },
    Command(CommandSpec),
    Nix {
        roots: Vec<PathBuf>,
    },
    Certificates {
        paths: Vec<PathBuf>,
        max_file_bytes: u64,
        include_identity: bool,
    },
    Import {
        path: PathBuf,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct Job {
    scope: Scope,
    inventory: Option<Name>,
    kind: InventoryKind,
    target: Target,
    backend: Backend,
}

#[derive(Debug, Error)]
pub(crate) enum JobError {
    #[error("backend does not support this inventory kind")]
    BackendKind,
    #[error("backend does not support this target or scope")]
    BackendTarget,

    #[error("collector options are missing or invalid")]
    Options,

    #[error("application name 'host' is reserved")]
    ReservedName,
}

impl InventoryKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Hbom => "hbom",
            Self::Sbom => "sbom",
            Self::Cbom => "cbom",
        }
    }
}

impl Name {
    pub(crate) fn new(value: String) -> Result<Self, NameError> {
        let Some(first) = value.bytes().next() else {
            return Err(NameError::Empty);
        };
        if !first.is_ascii_alphanumeric()
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(NameError::InvalidCharacters);
        }

        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Scope {
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Host => "host",
            Self::Application { name, .. } => name.as_str(),
        }
    }

    pub(crate) fn version(&self) -> Option<&str> {
        match self {
            Self::Host => None,
            Self::Application { version, .. } => version.as_deref(),
        }
    }

    pub(crate) fn is_host(&self) -> bool {
        matches!(self, Self::Host)
    }
}

impl Target {
    pub(crate) fn path(&self) -> Option<&Path> {
        match self {
            Self::Directory(path) | Self::NixClosure(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn display(&self) -> String {
        match self {
            Self::Host => String::new(),
            Self::Directory(p) | Self::NixClosure(p) => path_text(p),
            Self::RegistryImage(image) => format!("registry:{image}"),
        }
    }
}

impl Backend {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Hbom => "hbom",
            Self::Syft { .. } => "syft",
            Self::Command(_) => "command",
            Self::Nix { .. } => "nix",
            Self::Certificates { .. } => "certificates",
            Self::Import { .. } => "import",
        }
    }

    pub(crate) fn is_native(&self) -> bool {
        matches!(
            self,
            Self::Nix { .. } | Self::Certificates { .. } | Self::Import { .. }
        )
    }
}

impl Job {
    pub(crate) fn new(
        scope: Scope,
        inventory: Option<Name>,
        kind: InventoryKind,
        target: Target,
        backend: Backend,
    ) -> Result<Self, JobError> {
        let host = scope.is_host();
        if !host && scope.name() == "host" {
            return Err(JobError::ReservedName);
        }

        let kind_ok = match &backend {
            Backend::Command(_) => true,
            Backend::Hbom => kind == InventoryKind::Hbom,
            Backend::Syft { .. } | Backend::Nix { .. } => kind == InventoryKind::Sbom,
            Backend::Certificates { .. } | Backend::Import { .. } => kind == InventoryKind::Cbom,
        };
        if !kind_ok {
            return Err(JobError::BackendKind);
        }

        if !host && matches!(target, Target::Host) {
            return Err(JobError::BackendTarget);
        }
        if matches!(target, Target::NixClosure(_))
            && !matches!(
                backend,
                Backend::Nix { .. } | Backend::Certificates { .. } | Backend::Import { .. }
            )
        {
            return Err(JobError::BackendTarget);
        }

        match &backend {
            Backend::Hbom if !host => return Err(JobError::BackendTarget),
            Backend::Syft {
                exclusions,
                respect_gitignore,
            } => {
                if exclusions.iter().any(String::is_empty) {
                    return Err(JobError::Options);
                }
                if *respect_gitignore && (host || !matches!(target, Target::Directory(_))) {
                    return Err(JobError::BackendTarget);
                }
            }
            Backend::Nix { roots } => {
                if (!host && !matches!(target, Target::NixClosure(_))) || (host && roots.is_empty())
                {
                    return Err(JobError::BackendTarget);
                }
                if roots.iter().any(|p| !p.is_absolute()) {
                    return Err(JobError::Options);
                }
            }
            Backend::Certificates {
                paths,
                max_file_bytes,
                ..
            } => {
                if matches!(target, Target::RegistryImage(_)) {
                    return Err(JobError::BackendTarget);
                }
                if paths.is_empty()
                    || paths
                        .iter()
                        .any(|p| p.as_os_str().is_empty() || (host && !p.is_absolute()))
                    || *max_file_bytes == 0
                    || *max_file_bytes > 64 << 20
                {
                    return Err(JobError::Options);
                }
            }
            Backend::Import { path } if path.as_os_str().is_empty() => {
                return Err(JobError::Options);
            }
            _ => {}
        }

        Ok(Self {
            scope,
            inventory,
            kind,
            target,
            backend,
        })
    }

    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }

    pub(crate) fn inventory(&self) -> Option<&Name> {
        self.inventory.as_ref()
    }

    pub(crate) fn kind(&self) -> InventoryKind {
        self.kind
    }

    pub(crate) fn target(&self) -> &Target {
        &self.target
    }

    pub(crate) fn backend(&self) -> &Backend {
        &self.backend
    }

    pub(crate) fn stem(&self) -> String {
        match &self.inventory {
            Some(name) => format!(
                "{}.{}.{}",
                self.scope.name(),
                name.as_str(),
                self.kind.as_str()
            ),
            None => format!("{}.{}", self.scope.name(), self.kind.as_str()),
        }
    }
}
