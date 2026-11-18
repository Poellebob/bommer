use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;

use crate::bom::{ValidationError, Validator};
use crate::collectors::import::{self, ImportError};
use crate::json::DecodeError;
use crate::model::{
    Backend, CollectionContext, Coverage, InventoryKind, Job, Scope, Status, Target,
};

fn import_job(path: &Path) -> Job {
    Job::new(
        Scope::Host,
        None,
        InventoryKind::Cbom,
        Target::Host,
        Backend::Import { path: path.into() },
    )
    .unwrap()
}

fn context() -> CollectionContext {
    CollectionContext::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false)))
}

#[test]
fn deeply_nested_schema_valid_cbom_is_imported_without_changing_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("deep.json");
    let validator = Validator::new().unwrap();
    for spec in ["1.6", "1.7"] {
        // Seventy component ancestors put this valid CBOM beyond 128 JSON levels.
        let input = format!(
            " \n{{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"{spec}\",\"version\":1,\"components\":[{}{}{}]}}\t\n",
            r#"{"type":"cryptographic-asset","name":"ancestor","components":["#.repeat(70),
            r#"{"type":"cryptographic-asset","name":"leaf"}"#,
            "]}".repeat(70),
        );
        fs::write(&path, input.as_bytes()).unwrap();
        let mut output = Vec::new();
        let outcome = import::collect(&import_job(&path), &context(), &mut output).unwrap();
        assert_eq!(outcome.status(), Status::Collected);
        assert_eq!(outcome.findings(), 71);
        assert_eq!(outcome.coverage(), Coverage::ProducerDeclaredUnverified);
        assert_eq!(output, input.as_bytes());
        assert_eq!(fs::read(&path).unwrap(), input.as_bytes());
        let summary = validator.validate(&output, true).unwrap();
        assert_eq!(summary.spec_version(), spec);
        assert_eq!(summary.component_count(), 71);
    }
}

#[test]
fn import_and_validator_share_typed_depth_limit_without_writing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("too-deep.json");
    let input = format!(
        "{{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[{}{}{}]}}",
        r#"{"type":"cryptographic-asset","name":"ancestor","components":["#.repeat(260),
        r#"{"type":"cryptographic-asset","name":"leaf"}"#,
        "]}".repeat(260),
    );
    fs::write(&path, input.as_bytes()).unwrap();
    let mut output = Vec::new();
    assert!(matches!(
        import::collect(&import_job(&path), &context(), &mut output),
        Err(ImportError::Decode(DecodeError::DepthExceeded {
            limit: 512
        }))
    ));
    assert!(output.is_empty());
    assert!(matches!(
        Validator::new().unwrap().validate(input.as_bytes(), false),
        Err(ValidationError::Decode(DecodeError::DepthExceeded {
            limit: 512
        }))
    ));
}

#[test]
fn import_duplicate_errors_preserve_decoded_key_and_do_not_write() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("duplicate.json");
    for input in [
        r#"{"note":"PRIVATE KEY-----","note":"safe"}"#,
        r#"{"nested":[{"note":null,"\u006eote":"safe"}]}"#,
    ] {
        fs::write(&path, input).unwrap();
        let mut output = Vec::new();
        assert!(matches!(
            import::collect(&import_job(&path), &context(), &mut output),
            Err(ImportError::Decode(DecodeError::DuplicateKey { key })) if key == "note"
        ));
        assert!(output.is_empty());
    }
}

#[test]
fn import_distinguishes_invalid_json_trailing_documents_and_nonobjects() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("invalid.json");
    for input in ["{", "{} {}", "null", "[]"] {
        fs::write(&path, input).unwrap();
        let mut output = Vec::new();
        let result = import::collect(&import_job(&path), &context(), &mut output);
        match input {
            "{" => assert!(matches!(
                result,
                Err(ImportError::Decode(DecodeError::InvalidJson { .. }))
            )),
            "{} {}" => assert!(matches!(
                result,
                Err(ImportError::Decode(DecodeError::MultipleDocuments))
            )),
            _ => assert!(matches!(result, Err(ImportError::InvalidJson))),
        }
        assert!(output.is_empty());
    }
}

#[test]
fn non_utf8_import_path_is_safe_evidence_and_preserves_source_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join(OsString::from_vec(b"producer-\xff.json".to_vec()));
    let input = b" \n{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[{\"type\":\"cryptographic-asset\",\"name\":\"AES\"}]}\t\n";
    fs::write(&path, input).unwrap();
    let mut output = Vec::new();
    let outcome = import::collect(&import_job(&path), &context(), &mut output).unwrap();
    assert_eq!(output, input);
    assert_eq!(outcome.findings(), 1);
    assert_eq!(outcome.coverage(), Coverage::ProducerDeclaredUnverified);
    assert!(outcome.evidence()["sourcePath"].is_string());
    assert_eq!(outcome.evidence()["origin"], "imported");
    assert!(serde_json::to_vec(outcome.evidence()).is_ok());
}
