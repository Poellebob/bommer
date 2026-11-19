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
use crate::collection::context::{CollectionContext, Interrupted};
use crate::collection::outcome::{CollectionOutcome, Coverage};
use crate::job::{Backend, Job};
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
    let Backend::Nix { roots } = &job.backend else {
        return Err(NixError::Options);
    };
    let configured = if roots.is_empty() {
        vec![job.target.path().ok_or(NixError::Options)?.to_path_buf()]
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
            context.deadline,
            &context.cancelled,
            64 << 20,
            16 << 10,
        )
    };

    let version_output = run(&["--version".into()])?;
    let version = std::str::from_utf8(&version_output.stdout)
        .map_err(|_| NixError::InvalidVersion)?
        .trim();
    let (args, store) = query_arguments(version, &roots)?;
    let captured = run(&args)?;

    context.check()?;
    let (document, findings) = closure_document(&captured.stdout, &roots, job, version)?;

    context.check()?;
    document.write(output)?;

    Ok(CollectionOutcome::observed(
        findings,
        Coverage::DeclaredScope,
        vec![],
        json!({"scope":"store-reference closure","storeDirectory":"/nix/store","configuredRoots":configured.iter().map(|path| crate::path_encoding::path_text(path)).collect::<Vec<_>>(),"resolvedRoots":roots,"nixVersion":version,"storeConnection":store}),
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
    let mut root = json!({"type":"file", "bom-ref":reference, "name":job.scope.name()});
    if let Some(version) = job.scope.version() {
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

#[cfg(test)]
mod tests {

    use crate::bom::validation::Validator;
    use crate::collection::context::CollectionContext;
    use crate::collectors::nix;
    use crate::job::{Backend, InventoryKind, Job, Name, Scope, Target};
    use serde_json::{Value, json};
    use std::path::Path;
    use std::sync::{Arc, atomic::AtomicBool};
    use std::time::Duration;
    const APP: &str = "/nix/store/00000000000000000000000000000000-app-with-dashes-1.2-bin";
    const LIB: &str = "/nix/store/11111111111111111111111111111111-library-2-dev";

    fn context() -> CollectionContext {
        CollectionContext::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false)))
    }

    fn nix_job() -> Job {
        Job::new(
            Scope::Application {
                name: Name::new("app".into()).unwrap(),
                version: Some("1.2".into()),
            },
            None,
            InventoryKind::Sbom,
            Target::NixClosure(APP.into()),
            Backend::Nix { roots: vec![] },
        )
        .unwrap()
    }

    #[test]
    fn nix_current_and_legacy_metadata_preserve_graph_and_nar_semantics() {
        let hash = "sha256-7bO3fpkymZrnfW2Z6uxcYwBALxPVrZ9msGQrTG1MNZo=";
        let current = json!({APP:{"narHash":hash,"narSize":96,"references":[LIB,APP,LIB],"version":1},LIB:{"narHash":hash,"narSize":205456,"references":[],"version":1}});
        let legacy = json!([{"path":LIB,"narHash":hash,"narSize":205456,"references":[]},{"path":APP,"narHash":hash,"narSize":96,"references":[APP,LIB]}]);
        let mut results = Vec::new();

        for metadata in [current, legacy] {
            let (document, findings) = nix::closure_document(
                &serde_json::to_vec(&metadata).unwrap(),
                &[APP.into()],
                &nix_job(),
                "nix (Nix) 2.34.8",
            )
            .unwrap();

            assert_eq!(findings, 2);
            let mut output = Vec::new();
            document.write(&mut output).unwrap();
            let summary = Validator::new().unwrap().validate(&output, false).unwrap();
            assert_eq!(summary.component_count, 2);
            let document: Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(document["components"].as_array().unwrap().len(), 2);
            assert_eq!(
                document["metadata"]["component"],
                json!({"type":"file", "name":"app", "version":"1.2", "bom-ref":"bommer:inventory:app.sbom"})
            );
            assert_eq!(
                document["dependencies"],
                json!([{"ref":APP,"dependsOn":[APP,LIB]},{"ref":LIB,"dependsOn":[]},{"ref":"bommer:inventory:app.sbom","dependsOn":[APP]}])
            );

            let component = &document["components"][0];
            assert_eq!(component["name"], "app-with-dashes-1.2-bin");
            assert!(component.get("version").is_none());
            assert!(component.get("hashes").is_none());
            assert_eq!(
                component["properties"][1],
                json!({"name":"bommer:nix:nar-hash","value":hash})
            );
            assert_eq!(
                component["properties"][2],
                json!({"name":"bommer:nix:nar-size","value":"96"})
            );
            results.push(output);
        }

        assert_eq!(results[0], results[1]);
    }

    #[test]
    fn nix_query_contract_is_explicitly_local_offline_and_versioned() {
        for (version, format_flag) in [
            ("nix (Nix) 2.18.9", false),
            ("nix (Nix) 2.34.8", true),
            ("nix (Nix) 3.0pre", true),
        ] {
            let (arguments, store) =
                nix::query_arguments(version, &[APP.into(), LIB.into()]).unwrap();

            assert!(matches!(
                store,
                "local" | "unix:///nix/var/nix/daemon-socket/socket"
            ));
            let mut expected: Vec<std::ffi::OsString> = [
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
            if format_flag {
                expected.extend(["--json-format".into(), "1".into()]);
            }
            expected.extend([APP.into(), LIB.into()]);
            assert_eq!(arguments, expected);
        }

        for version in [
            "unexpected fork",
            "nix (Nix) 2",
            "nix (Nix) +2.34",
            "nix (Nix) 2.x",
            "nix (Nix) 2.34\ninjected",
        ] {
            assert!(matches!(
                nix::query_arguments(version, &[APP.into()]),
                Err(nix::NixError::InvalidVersion)
            ));
        }
    }

    #[test]
    fn nix_rejects_missing_roots_and_incomplete_or_malformed_metadata() {
        let valid = json!({"narHash":"sha256:0000000000000000000000000000000000000000000000000000","narSize":0,"references":[]});

        for (field, replacement) in [
            ("narHash", json!("sha256-invalid")),
            ("narSize", json!(-1)),
            ("narSize", Value::Null),
            ("references", Value::Null),
            ("version", json!(2)),
            ("deriver", json!("invalid")),
        ] {
            let mut info = valid.clone();
            info[field] = replacement;
            let data = serde_json::to_vec(&json!({APP:info})).unwrap();

            assert!(matches!(
                nix::closure_document(&data, &[APP.into()], &nix_job(), "nix (Nix) 2.34.8"),
                Err(nix::NixError::InvalidMetadata)
            ));
        }

        let mut incomplete = valid.clone();
        incomplete["references"] = json!([LIB]);

        assert!(
            matches!(nix::closure_document(&serde_json::to_vec(&json!({APP:incomplete})).unwrap(), &[APP.into()], &nix_job(), "nix (Nix) 2.34.8"), Err(nix::NixError::IncompleteClosure { missing }) if missing == Path::new(LIB))
        );
        assert!(
            matches!(nix::closure_document(&serde_json::to_vec(&json!({LIB:valid})).unwrap(), &[APP.into()], &nix_job(), "nix (Nix) 2.34.8"), Err(nix::NixError::IncompleteClosure { missing }) if missing == Path::new(APP))
        );

        let directory = tempfile::tempdir().unwrap();
        let job = Job::new(
            Scope::Host,
            None,
            InventoryKind::Sbom,
            Target::Host,
            Backend::Nix {
                roots: vec![directory.path().into()],
            },
        )
        .unwrap();

        assert!(matches!(
            nix::collect(&job, &context(), &mut Vec::new()),
            Err(nix::NixError::InvalidRoot { .. })
        ));
    }
}
