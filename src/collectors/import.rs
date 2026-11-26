use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::collection::context::{CollectionContext, Interrupted};
use crate::collection::outcome::{CollectionOutcome, Coverage};
use crate::job::{Backend, Job};
use crate::json;

#[derive(Debug, Error)]
pub(crate) enum ImportError {
    #[error("invalid import options")]
    Options,
    #[error("import I/O failed")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Interrupted(#[from] Interrupted),
    #[error("import must be a regular file")]
    NotRegular,
    #[error("import exceeds 64 MiB")]
    LimitExceeded,
    #[error("cannot decode import: {0}")]
    Decode(#[from] json::DecodeError),
    #[error("import must be a JSON object")]
    InvalidJson,
    #[error("import contains private cryptographic material")]
    PrivateMaterial,
    #[error("nonempty CBOM has no cryptographic assets")]
    NoCryptographicAssets,
}

const LIMIT: u64 = 64 << 20;

fn open(job: &Job) -> Result<File, ImportError> {
    let Backend::Import { path } = &job.backend else {
        return Err(ImportError::Options);
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(ImportError::NotRegular);
    }
    if metadata.len() > LIMIT {
        return Err(ImportError::LimitExceeded);
    }

    Ok(file)
}

pub(crate) fn check(job: &Job) -> Result<(), ImportError> {
    open(job).map(|_| ())
}

fn inspect_document(document: &Value, context: &CollectionContext) -> Result<usize, ImportError> {
    let mut pending_values = vec![document];
    let mut findings = 0;
    while let Some(value) = pending_values.pop() {
        context.check()?;
        match value {
            Value::String(value) if value.contains("PRIVATE KEY-----") => {
                return Err(ImportError::PrivateMaterial);
            }
            Value::Object(object) => {
                if object.get("type").and_then(Value::as_str) == Some("cryptographic-asset") {
                    findings += 1;
                }
                if object
                    .get("relatedCryptoMaterialProperties")
                    .and_then(Value::as_object)
                    .is_some_and(|material| material.contains_key("value"))
                {
                    return Err(ImportError::PrivateMaterial);
                }
                pending_values.extend(object.values());
            }
            Value::Array(values) => pending_values.extend(values),
            _ => {}
        }
    }

    if findings == 0
        && document
            .get("components")
            .and_then(Value::as_array)
            .is_some_and(|components| !components.is_empty())
    {
        return Err(ImportError::NoCryptographicAssets);
    }

    Ok(findings)
}

pub(crate) fn collect(
    job: &Job,
    context: &CollectionContext,
    output: &mut dyn Write,
) -> Result<CollectionOutcome, ImportError> {
    context.check()?;
    let mut file = open(job)?.take(LIMIT + 1);
    let mut data = Vec::new();
    let mut buffer = [0; 64 << 10];
    loop {
        context.check()?;
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        data.extend_from_slice(&buffer[..bytes_read]);
        if data.len() as u64 > LIMIT {
            return Err(ImportError::LimitExceeded);
        }
    }

    // Do not use the BOM validator here: imports are leaves and preserve producer graphs.
    let document = json::decode(&data)?;
    if !document.is_object() {
        return Err(ImportError::InvalidJson);
    }
    let findings = inspect_document(&document, context)?;

    let Backend::Import { path } = &job.backend else {
        return Err(ImportError::Options);
    };
    let evidence = json!({"origin":"imported", "sourcePath":crate::path_encoding::path_text(path), "sourceSHA256":hex::encode(Sha256::digest(&data)), "discovery":"not-observed-locally", "applicationAssociation":"configuration-declared-not-verified"});

    context.check()?;
    output.write_all(&data)?;

    Ok(CollectionOutcome::observed(
        findings,
        Coverage::ProducerDeclaredUnverified,
        vec![],
        evidence,
        Some("import/1".into()),
    ))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::path::Path;
    use std::sync::{Arc, atomic::AtomicBool};
    use std::time::Duration;

    use serde_json::{Value, json};

    use crate::bom::validation::{ValidationError, Validator};
    use crate::collection::context::CollectionContext;
    use crate::collection::outcome::{Coverage, Status};
    use crate::collectors::import::{self, ImportError};
    use crate::job::{Backend, InventoryKind, Job, Scope, Target};
    use crate::json::DecodeError;

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

        for specification_version in ["1.6", "1.7"] {
            // Seventy component ancestors put this valid CBOM beyond 128 JSON levels.
            let input = format!(
                " \n{{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"{specification_version}\",\"version\":1,\"components\":[{}{}{}]}}\t\n",
                r#"{"type":"cryptographic-asset","name":"ancestor","components":["#.repeat(70),
                r#"{"type":"cryptographic-asset","name":"leaf"}"#,
                "]}".repeat(70),
            );
            fs::write(&path, input.as_bytes()).unwrap();
            let mut output = Vec::new();

            let outcome = import::collect(&import_job(&path), &context(), &mut output).unwrap();

            assert_eq!(outcome.status, Status::Collected);
            assert_eq!(outcome.findings, 71);
            assert_eq!(outcome.coverage, Coverage::ProducerDeclaredUnverified);
            assert_eq!(output, input.as_bytes());
            assert_eq!(fs::read(&path).unwrap(), input.as_bytes());

            let summary = validator.validate(&output, true).unwrap();
            assert_eq!(summary.version, specification_version);
            assert_eq!(summary.component_count, 71);
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
        assert_eq!(outcome.findings, 1);
        assert_eq!(outcome.coverage, Coverage::ProducerDeclaredUnverified);
        assert!(outcome.evidence["sourcePath"].is_string());
        assert_eq!(outcome.evidence["origin"], "imported");
        assert!(serde_json::to_vec(&outcome.evidence).is_ok());
    }

    const IMPORT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/native-import.json"
    ));

    #[test]
    fn import_preserves_bytes_graph_and_unverified_provenance() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("producer.json");
        fs::write(&path, IMPORT).unwrap();
        let job = import_job(&path);
        import::check(&job).unwrap();
        let mut output = Vec::new();

        let outcome = import::collect(&job, &context(), &mut output).unwrap();

        assert_eq!(output, IMPORT);
        assert_eq!(fs::read(&path).unwrap(), IMPORT);
        assert_eq!(outcome.status, Status::Collected);
        assert_eq!(outcome.findings, 1);
        assert_eq!(outcome.coverage, Coverage::ProducerDeclaredUnverified);
        assert_eq!(outcome.evidence["sourcePath"], json!(path));
        assert_eq!(
            outcome.evidence["sourceSHA256"],
            "f0c6554e7164cb9b11d221eb10553719657137a1a66890ef2beac9a648a9b7f3"
        );
        assert_eq!(outcome.evidence["origin"], "imported");
        assert_eq!(outcome.evidence["discovery"], "not-observed-locally");
        assert_eq!(
            outcome.evidence["applicationAssociation"],
            "configuration-declared-not-verified"
        );

        Validator::new().unwrap().validate(&output, false).unwrap();
        let document: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            document["dependencies"],
            json!([{"ref":"aes","dependsOn":["aes"]}])
        );
    }

    #[test]
    fn import_rejects_private_material_before_writing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.json");

        for data in [
            r#"{"components":[],"note":"-----BEGIN PRIVATE KEY-----"}"#,
            r#"{"components":[],"nested":[{"note":"-----BEGIN RSA PRIVATE\u0020KEY-----"}]}"#,
            r#"{"nested":{"relatedCryptoMaterialProperties":{"value":null}}}"#,
            r#"{"nested":{"relatedCryptoMaterialProperties":{"\u0076alue":"c2VjcmV0"}}}"#,
        ] {
            fs::write(&path, data).unwrap();
            let mut output = Vec::new();

            assert!(matches!(
                import::collect(&import_job(&path), &context(), &mut output),
                Err(import::ImportError::PrivateMaterial)
            ));
            assert!(output.is_empty());
        }
    }

    #[test]
    fn import_rejects_ambiguous_json_and_non_cbom_components() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.json");

        for data in [
            r#"{"note":"PRIVATE KEY-----","note":"safe"}"#,
            r#"{"note":"safe","\u006eote":"safe"}"#,
            r#"{"components":[{"name":"a","name":"b"}]}"#,
            "{} {}",
            "{",
        ] {
            fs::write(&path, data).unwrap();
            let mut output = Vec::new();

            assert!(matches!(
                import::collect(&import_job(&path), &context(), &mut output),
                Err(import::ImportError::Decode(_))
            ));
            assert!(output.is_empty());
        }

        for data in ["[]", "null"] {
            fs::write(&path, data).unwrap();

            assert!(matches!(
                import::collect(&import_job(&path), &context(), &mut Vec::new()),
                Err(import::ImportError::InvalidJson)
            ));
        }

        fs::write(
            &path,
            br#"{"components":[{"type":"library","name":"not crypto"}]}"#,
        )
        .unwrap();

        assert!(matches!(
            import::collect(&import_job(&path), &context(), &mut Vec::new()),
            Err(import::ImportError::NoCryptographicAssets)
        ));

        fs::write(&path, br#"{"components":[]}"#).unwrap();

        let outcome = import::collect(&import_job(&path), &context(), &mut Vec::new()).unwrap();

        assert_eq!(outcome.status, Status::NoFindings);
        assert_eq!(outcome.findings, 0);
    }

    #[test]
    fn import_limits_and_nonregular_files_are_checked_without_blocking() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large.json");
        fs::File::create(&path)
            .unwrap()
            .set_len((64 << 20) + 1)
            .unwrap();

        assert!(matches!(
            import::check(&import_job(&path)),
            Err(import::ImportError::LimitExceeded)
        ));
        assert!(matches!(
            import::check(&import_job(directory.path())),
            Err(import::ImportError::NotRegular)
        ));

        let fifo = directory.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();

        assert!(matches!(
            import::check(&import_job(&fifo)),
            Err(import::ImportError::NotRegular)
        ));
    }
}
