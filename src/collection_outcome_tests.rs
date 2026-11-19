use serde_json::{Value, json};

use crate::collection_outcome::{CollectionOutcome, Coverage, Diagnostic, DiagnosticCode, Status};

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

        assert_eq!(outcome.status(), status);
        assert_eq!(outcome.findings(), findings);
        assert_eq!(outcome.coverage(), Coverage::DeclaredScope);
        assert_eq!(outcome.diagnostics().len(), usize::from(diagnostic));
        assert_eq!(outcome.evidence(), &json!({"source": "fixture"}));
        assert_eq!(outcome.collector_version(), Some("1.2.3"));
        assert_eq!(outcome.exclusions(), None);
        assert_eq!(outcome.target(), None);
    }
}

#[test]
fn external_outcome_is_collected_without_observed_findings() {
    let outcome = CollectionOutcome::external();

    assert_eq!(outcome.status(), Status::Collected);
    assert_eq!(outcome.findings(), 0);
    assert_eq!(outcome.coverage(), Coverage::Unknown);
    assert!(outcome.diagnostics().is_empty());
    assert_eq!(outcome.collector_version(), None);
    assert_eq!(outcome.evidence(), &Value::Null);
    assert_eq!(outcome.exclusions(), None);
    assert_eq!(outcome.target(), None);
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
