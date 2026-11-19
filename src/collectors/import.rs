use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::json;
use crate::model::{Backend, CollectionContext, CollectionOutcome, Coverage, Interrupted, Job};

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
    let Backend::Import { path } = job.backend() else {
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
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..count]);
        if data.len() as u64 > LIMIT {
            return Err(ImportError::LimitExceeded);
        }
    }

    // Do not use the BOM validator here: imports are leaves and preserve producer graphs.
    let document = json::decode(&data)?;
    if !document.is_object() {
        return Err(ImportError::InvalidJson);
    }

    let mut pending = vec![&document];
    let mut findings = 0;
    while let Some(value) = pending.pop() {
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
                pending.extend(object.values());
            }
            Value::Array(values) => pending.extend(values),
            _ => {}
        }
    }
    if findings == 0
        && document
            .get("components")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
    {
        return Err(ImportError::NoCryptographicAssets);
    }

    let Backend::Import { path } = job.backend() else {
        return Err(ImportError::Options);
    };
    let evidence = json!({"origin":"imported", "sourcePath":crate::model::path_text(path), "sourceSHA256":hex::encode(Sha256::digest(&data)), "discovery":"not-observed-locally", "applicationAssociation":"configuration-declared-not-verified"});

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
