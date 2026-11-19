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

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::collection::outcome::{
        CollectionOutcome, Coverage, Diagnostic, DiagnosticCode, Status,
    };

    #[test]
    fn observed_status_prioritizes_diagnostics_over_findings() {
        for (findings, diagnostic, status) in [
            (0, false, Status::NoFindings),
            (1, false, Status::Collected),
            (0, true, Status::Partial),
            (1, true, Status::Partial),
        ] {
            let diagnostics = if diagnostic {
                vec![Diagnostic::new(DiagnosticCode::MissingPath, None)]
            } else {
                vec![]
            };
            let outcome = CollectionOutcome::observed(
                findings,
                Coverage::DeclaredScope,
                diagnostics,
                json!({"source": "fixture"}),
                Some("1.2.3".into()),
            );

            assert_eq!(outcome.status, status);
            assert_eq!(outcome.findings, findings);
            assert_eq!(outcome.coverage, Coverage::DeclaredScope);
            assert_eq!(outcome.diagnostics.len(), usize::from(diagnostic));
            assert_eq!(outcome.evidence, json!({"source": "fixture"}));
            assert_eq!(outcome.collector_version.as_deref(), Some("1.2.3"));
            assert_eq!(outcome.scope.exclusions, None);
            assert_eq!(outcome.scope.target, None);
        }
    }

    #[test]
    fn external_outcome_is_collected_without_observed_findings() {
        let outcome = CollectionOutcome::external();

        assert_eq!(outcome.status, Status::Collected);
        assert_eq!(outcome.findings, 0);
        assert_eq!(outcome.coverage, Coverage::Unknown);
        assert!(outcome.diagnostics.is_empty());
        assert_eq!(outcome.collector_version, None);
        assert_eq!(outcome.evidence, Value::Null);
        assert_eq!(outcome.scope.exclusions, None);
        assert_eq!(outcome.scope.target, None);
    }

    #[test]
    fn diagnostics_encode_paths_and_omit_absent_paths() {
        let diagnostic = Diagnostic::new(
            DiagnosticCode::MissingPath,
            Some("bommer:unix-bytes:ff".into()),
        );
        assert_eq!(
            serde_json::to_value(diagnostic).unwrap(),
            json!({"code": "missing-path", "path": "bommer:utf8:bommer:unix-bytes:ff"})
        );
        assert_eq!(
            serde_json::to_value(Diagnostic::new(DiagnosticCode::MissingPath, None)).unwrap(),
            json!({"code": "missing-path"})
        );
    }
}
