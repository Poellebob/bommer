use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InventoryKind {
    Hbom,
    Sbom,
    Cbom,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Name(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NameError {
    Empty,
    InvalidCharacters,
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
pub(crate) struct CommandSpec {
    executable: OsString,
    arguments: Vec<OsString>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommandError {
    EmptyExecutable,
}

impl CommandSpec {
    pub(crate) fn new(
        executable: OsString,
        arguments: Vec<OsString>,
    ) -> Result<Self, CommandError> {
        if executable.is_empty() {
            return Err(CommandError::EmptyExecutable);
        }
        Ok(Self {
            executable,
            arguments,
        })
    }

    pub(crate) fn executable(&self) -> &std::ffi::OsStr {
        &self.executable
    }

    pub(crate) fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
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

// Job construction stays private until planning can enforce backend/target invariants.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Collected,
    Partial,
    NoFindings,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Coverage {
    Unknown,
    DeclaredScope,
    ProducerDeclaredUnverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiagnosticCode {
    MissingPath,
    UnreadablePath,
    SymlinkRefused,
    UnsupportedFile,
    MalformedCertificate,
    LimitExceeded,
}

#[derive(Debug, Clone)]
pub(crate) struct Diagnostic {
    code: DiagnosticCode,
    path: Option<PathBuf>,
}

#[derive(Debug)]
pub(crate) struct CollectionOutcome {
    status: Status,
    findings: usize,
    coverage: Coverage,
    diagnostics: Vec<Diagnostic>,
    collector_version: Option<String>,
}
