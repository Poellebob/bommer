use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum InventoryKind {
    Hbom,
    Sbom,
    Cbom,
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

#[derive(Debug, Clone)]
pub(crate) enum Target {
    Host,
    Directory(PathBuf),
    RegistryImage(String),
    NixClosure(PathBuf),
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

#[derive(Debug, Clone)]
pub(crate) struct CommandSpec {
    executable: OsString,
    arguments: Vec<OsString>,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub(crate) enum CommandError {
    #[error("command requires an executable")]
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
    pub(crate) fn executable(&self) -> &OsStr {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Status {
    Collected,
    Partial,
    NoFindings,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Coverage {
    Unknown,
    DeclaredScope,
    ProducerDeclaredUnverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DiagnosticCode {
    MissingPath,
    UnreadablePath,
    SymlinkRefused,
    UnsupportedFile,
    MalformedCertificate,
    LimitExceeded,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Diagnostic {
    code: DiagnosticCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}
impl Diagnostic {
    pub(crate) fn new(code: DiagnosticCode, path: Option<PathBuf>) -> Self {
        Self {
            code,
            path: path.as_deref().map(path_text),
        }
    }
    #[cfg(test)]
    pub(crate) fn code(&self) -> DiagnosticCode {
        self.code
    }
}

#[derive(Debug)]
pub(crate) struct CollectionOutcome {
    status: Status,
    findings: usize,
    coverage: Coverage,
    diagnostics: Vec<Diagnostic>,
    collector_version: Option<String>,
    evidence: serde_json::Value,
    exclusions: Option<Vec<String>>,
    target: Option<String>,
}

impl CollectionOutcome {
    pub(crate) fn observed(
        findings: usize,
        coverage: Coverage,
        diagnostics: Vec<Diagnostic>,
        evidence: serde_json::Value,
        collector_version: Option<String>,
    ) -> Self {
        let status = if !diagnostics.is_empty() {
            Status::Partial
        } else if findings == 0 {
            Status::NoFindings
        } else {
            Status::Collected
        };
        Self {
            status,
            findings,
            coverage,
            diagnostics,
            evidence,
            collector_version,
            exclusions: None,
            target: None,
        }
    }
    pub(crate) fn external() -> Self {
        Self {
            status: Status::Collected,
            findings: 0,
            coverage: Coverage::Unknown,
            diagnostics: vec![],
            collector_version: None,
            evidence: serde_json::Value::Null,
            exclusions: None,
            target: None,
        }
    }
    pub(crate) fn status(&self) -> Status {
        self.status
    }
    pub(crate) fn findings(&self) -> usize {
        self.findings
    }
    pub(crate) fn coverage(&self) -> Coverage {
        self.coverage
    }
    pub(crate) fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
    pub(crate) fn collector_version(&self) -> Option<&str> {
        self.collector_version.as_deref()
    }
    pub(crate) fn evidence(&self) -> &serde_json::Value {
        &self.evidence
    }
    pub(crate) fn with_exclusions(mut self, exclusions: Vec<String>) -> Self {
        self.exclusions = Some(exclusions);
        self
    }
    pub(crate) fn with_target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }
    pub(crate) fn exclusions(&self) -> Option<&[String]> {
        self.exclusions.as_deref()
    }
    pub(crate) fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }
}

// JSON strings cannot represent arbitrary Unix path bytes. Reserved prefixes keep
// the tagged hex form distinguishable from literal UTF-8 paths with the same text.
pub(crate) fn path_text(path: &Path) -> String {
    match path.to_str() {
        Some(text)
            if text.starts_with("bommer:unix-bytes:") || text.starts_with("bommer:utf8:") =>
        {
            format!("bommer:utf8:{text}")
        }
        Some(text) => text.into(),
        None => format!(
            "bommer:unix-bytes:{}",
            hex::encode(path.as_os_str().as_encoded_bytes())
        ),
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FailureKind {
    Cancelled,
    Timeout,
    ProcessExit,
    OutputLimit,
    Spawn,
    Io,
    Validation,
    Collection,
}

#[derive(Debug, Serialize)]
pub(crate) struct Failure {
    kind: FailureKind,
    #[serde(rename = "exitCode", skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
}

impl Failure {
    pub(crate) fn new(kind: FailureKind) -> Self {
        Self {
            kind,
            exit_code: None,
            stream: None,
            limit: None,
        }
    }
    pub(crate) fn exited(code: Option<i32>) -> Self {
        Self {
            exit_code: code,
            ..Self::new(FailureKind::ProcessExit)
        }
    }
    pub(crate) fn limited(stream: &'static str, limit: usize) -> Self {
        Self {
            stream: Some(stream),
            limit: Some(limit),
            ..Self::new(FailureKind::OutputLimit)
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CollectionContext {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum Interrupted {
    #[error("collection cancelled")]
    Cancelled,
    #[error("collection timed out")]
    Timeout,
}

impl CollectionContext {
    pub(crate) fn new(timeout: Duration, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            cancelled,
        }
    }
    pub(crate) fn check(&self) -> Result<(), Interrupted> {
        if self.cancelled.load(Ordering::Relaxed) {
            Err(Interrupted::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(Interrupted::Timeout)
        } else {
            Ok(())
        }
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn cancelled(&self) -> &AtomicBool {
        &self.cancelled
    }
}
