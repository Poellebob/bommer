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
    code: DiagnosticCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
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
