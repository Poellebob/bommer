use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use thiserror::Error;

use crate::bom::document::Document;
use crate::model::{Backend, CollectionContext, CollectionOutcome, Coverage, Interrupted, Job};
use crate::process::{Process, ProcessError};

#[derive(Debug, Error)]
pub(crate) enum NixError {
    #[error("invalid Nix options")]
    Options,
    #[error("root is not an existing top-level Nix store output")]
    InvalidRoot { path: PathBuf },
    #[error("Nix I/O failed")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Interrupted(#[from] Interrupted),
    #[error("local Nix query failed")]
    Process(#[from] ProcessError),
    #[error("unsupported Nix version")]
    InvalidVersion,
    #[error("invalid Nix metadata")]
    InvalidMetadata,
    #[error("incomplete Nix closure")]
    IncompleteClosure { missing: PathBuf },
}

fn store_path(path: &str) -> bool {
    let Some(name) = path.strip_prefix("/nix/store/") else {
        return false;
    };
    name.len() > 33
        && name.as_bytes()[32] == b'-'
        && name.as_bytes()[..32]
            .iter()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(byte))
        && name.as_bytes()[33..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+._?=-".contains(byte))
}

fn is_output(path: &str) -> bool {
    store_path(path) && !path.ends_with(".drv")
}

fn roots(job: &Job) -> Result<(Vec<PathBuf>, Vec<String>), NixError> {
    let Backend::Nix { roots } = job.backend() else {
        return Err(NixError::Options);
    };
    let configured = if roots.is_empty() {
        vec![job.target().path().ok_or(NixError::Options)?.to_path_buf()]
    } else {
        roots.clone()
    };

    let mut resolved = BTreeSet::new();
    for path in &configured {
        let canonical = path
            .canonicalize()
            .map_err(|_| NixError::InvalidRoot { path: path.clone() })?;
        let metadata = canonical.metadata()?;
        let text = canonical
            .to_str()
            .ok_or_else(|| NixError::InvalidRoot { path: path.clone() })?;
        if !is_output(text) || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(NixError::InvalidRoot { path: path.clone() });
        }
        resolved.insert(text.to_owned());
    }

    Ok((configured, resolved.into_iter().collect()))
}

pub(crate) fn check(job: &Job) -> Result<(), NixError> {
    roots(job)?;
    Process::find_executable(OsStr::new("nix"))?;
    Ok(())
}

#[derive(Deserialize)]
struct PathInfo {
    #[serde(default, deserialize_with = "optional_string")]
    path: String,
    #[serde(rename = "narHash")]
    nar_hash: String,
    #[serde(rename = "narSize")]
    nar_size: u64,
    references: Vec<String>,
    #[serde(default, deserialize_with = "optional_string")]
    deriver: String,
    version: Option<u64>,
}

fn optional_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

fn valid_hash(hash: &str) -> bool {
    for (algorithm, length) in [
        ("md5", 16usize),
        ("sha1", 20),
        ("sha256", 32),
        ("sha512", 64),
    ] {
        if let Some(value) = hash.strip_prefix(&format!("{algorithm}-")) {
            return STANDARD
                .decode(value)
                .is_ok_and(|bytes| bytes.len() == length);
        }
        if let Some(value) = hash.strip_prefix(&format!("{algorithm}:")) {
            let alphabet: &[u8] = if value.len() == length * 2 {
                b"0123456789abcdef"
            } else if value.len() == (length * 8).div_ceil(5) {
                b"0123456789abcdfghijklmnpqrsvwxyz"
            } else {
                return false;
            };
            return value.bytes().all(|byte| alphabet.contains(&byte));
        }
    }

    false
}

fn decode(data: &[u8]) -> Result<BTreeMap<String, PathInfo>, NixError> {
    let value: Value = serde_json::from_slice(data).map_err(|_| NixError::InvalidMetadata)?;
    let mut entries = BTreeMap::new();
    match value {
        Value::Object(values) => {
            for (path, value) in values {
                entries.insert(
                    path,
                    serde_json::from_value::<PathInfo>(value)
                        .map_err(|_| NixError::InvalidMetadata)?,
                );
            }
        }
        Value::Array(values) => {
            for value in values {
                let info: PathInfo =
                    serde_json::from_value(value).map_err(|_| NixError::InvalidMetadata)?;
                if entries.insert(info.path.clone(), info).is_some() {
                    return Err(NixError::InvalidMetadata);
                }
            }
        }
        _ => return Err(NixError::InvalidMetadata),
    }

    if entries.is_empty() {
        return Err(NixError::InvalidMetadata);
    }
    for (path, info) in &entries {
        if !is_output(path)
            || (!info.path.is_empty() && info.path != *path)
            || info.version.is_some_and(|version| version != 1)
            || !valid_hash(&info.nar_hash)
            || (!info.deriver.is_empty()
                && info.deriver != "unknown-deriver"
                && !(store_path(&info.deriver) && info.deriver.ends_with(".drv")))
        {
            return Err(NixError::InvalidMetadata);
        }

        for reference in &info.references {
            if !entries.contains_key(reference) {
                return Err(NixError::IncompleteClosure {
                    missing: reference.into(),
                });
            }
        }
    }

    Ok(entries)
}

pub(crate) fn collect(
    job: &Job,
    context: &CollectionContext,
    output: &mut dyn Write,
) -> Result<CollectionOutcome, NixError> {
    context.check()?;
    let (configured, roots) = roots(job)?;
    let executable = Process::find_executable(OsStr::new("nix"))?;
    let run = |args: &[OsString]| {
        Process::capture(
            executable.as_os_str(),
            args,
            context.deadline(),
            context.cancelled(),
            64 << 20,
            16 << 10,
        )
    };

    let version_output = run(&["--version".into()])?;
    let version = std::str::from_utf8(version_output.stdout())
        .map_err(|_| NixError::InvalidVersion)?
        .trim();
    let (args, store) = query_arguments(version, &roots)?;
    let captured = run(&args)?;

    context.check()?;
    let (document, findings) = closure_document(captured.stdout(), &roots, job, version)?;

    context.check()?;
    document.write(output)?;

    Ok(CollectionOutcome::observed(
        findings,
        Coverage::DeclaredScope,
        vec![],
        json!({"scope":"store-reference closure","storeDirectory":"/nix/store","configuredRoots":configured.iter().map(|path| crate::model::path_text(path)).collect::<Vec<_>>(),"resolvedRoots":roots,"nixVersion":version,"storeConnection":store}),
        Some(version.into()),
    ))
}

pub(crate) fn query_arguments(
    version: &str,
    roots: &[String],
) -> Result<(Vec<OsString>, &'static str), NixError> {
    let numbers = version
        .strip_prefix("nix (Nix) ")
        .ok_or(NixError::InvalidVersion)?;
    if numbers.contains(['\r', '\n']) {
        return Err(NixError::InvalidVersion);
    }
    let (major, rest) = numbers.split_once('.').ok_or(NixError::InvalidVersion)?;
    if major.is_empty() || !major.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NixError::InvalidVersion);
    }
    let minor: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let (major, minor) = (
        major.parse::<u64>().map_err(|_| NixError::InvalidVersion)?,
        minor.parse::<u64>().map_err(|_| NixError::InvalidVersion)?,
    );

    let store = if Path::new("/nix/var/nix/daemon-socket/socket")
        .metadata()
        .is_ok_and(|metadata| metadata.file_type().is_socket())
    {
        "unix:///nix/var/nix/daemon-socket/socket"
    } else {
        "local"
    };
    let mut args: Vec<OsString> = [
        "--extra-experimental-features",
        "nix-command",
        "path-info",
        "--store",
        store,
        "--offline",
        "--recursive",
        "--json",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    if major > 2 || (major == 2 && minor >= 34) {
        args.extend(["--json-format".into(), "1".into()]);
    }
    args.extend(roots.iter().map(Into::into));

    Ok((args, store))
}

pub(crate) fn closure_document(
    data: &[u8],
    roots: &[String],
    job: &Job,
    version: &str,
) -> Result<(Document, usize), NixError> {
    let entries = decode(data)?;
    for root in roots {
        if !entries.contains_key(root) {
            return Err(NixError::IncompleteClosure {
                missing: root.into(),
            });
        }
    }

    let mut components = Vec::new();
    let mut dependencies = Vec::new();
    for (path, info) in &entries {
        let mut properties = vec![
            json!({"name":"bommer:nix:store-path","value":path}),
            json!({"name":"bommer:nix:nar-hash","value":info.nar_hash}),
            json!({"name":"bommer:nix:nar-size","value":info.nar_size.to_string()}),
        ];
        if !info.deriver.is_empty() && info.deriver != "unknown-deriver" {
            properties.push(json!({"name":"bommer:nix:deriver","value":info.deriver}));
        }
        components.push(
            json!({"type":"file", "bom-ref":path, "name":&path[44..], "properties":properties}),
        );
        let references: BTreeSet<_> = info.references.iter().collect();
        dependencies.push(json!({"ref":path,"dependsOn":references}));
    }

    let reference = format!("bommer:inventory:{}", job.stem());
    let mut root = json!({"type":"file", "bom-ref":reference, "name":job.scope().name()});
    if let Some(version) = job.scope().version() {
        root["version"] = version.into();
    }
    dependencies.push(json!({"ref":reference,"dependsOn":roots}));

    let document = Document::new(
        components,
        dependencies,
        vec![
            json!({"name":"bommer:nix:scope","value":"store-reference closure"}),
            json!({"name":"bommer:nix:version","value":version}),
        ],
    )
    .with_metadata_component(root);

    Ok((document, entries.len()))
}
