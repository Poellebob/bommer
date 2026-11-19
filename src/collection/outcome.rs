use std::path::PathBuf;

use serde::Serialize;

use crate::path_encoding::path_text;

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
    pub(crate) code: DiagnosticCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct ExecutionScope {
    pub(crate) target: Option<String>,
    pub(crate) exclusions: Option<Vec<String>>,
}

#[derive(Debug)]
pub(crate) struct CollectionOutcome {
    pub(crate) status: Status,
    pub(crate) findings: usize,
    pub(crate) coverage: Coverage,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) collector_version: Option<String>,
    pub(crate) evidence: serde_json::Value,
    pub(crate) scope: ExecutionScope,
}

impl Diagnostic {
    pub(crate) fn new(code: DiagnosticCode, path: Option<PathBuf>) -> Self {
        Self {
            code,
            path: path.as_deref().map(path_text),
        }
    }
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
            scope: ExecutionScope::default(),
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
            scope: ExecutionScope::default(),
        }
    }
}
