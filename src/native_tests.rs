use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

use crate::bom::Validator;
use crate::collectors::{certificates, import, nix};
use crate::model::{
    Backend, CollectionContext, Coverage, DiagnosticCode, Interrupted, InventoryKind, Job, Name,
    Scope, Status, Target,
};
use crate::scan::Scan;

// Public P-384 fixture from x509-parser's MIT/Apache-2.0 no_extensions.pem.
const CERTIFICATE: &[u8] = include_bytes!("../tests/fixtures/native-ec.pem");
const IMPORT: &[u8] = include_bytes!("../tests/fixtures/native-import.json");
const APP: &str = "/nix/store/00000000000000000000000000000000-app-with-dashes-1.2-bin";
const LIB: &str = "/nix/store/11111111111111111111111111111111-library-2-dev";

fn context() -> CollectionContext {
    CollectionContext::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false)))
}

fn certificate_job(root: &Path, paths: &[&str], limit: u64, identity: bool) -> Job {
    Job::new(
        Scope::Application {
            name: Name::new("app".into()).unwrap(),
            version: None,
        },
        None,
        InventoryKind::Cbom,
        Target::Directory(root.into()),
        Backend::Certificates {
            paths: paths.iter().map(Into::into).collect(),
            max_file_bytes: limit,
            include_identity: identity,
        },
    )
    .unwrap()
}

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

fn certificate_der() -> Vec<u8> {
    STANDARD
        .decode(
            CERTIFICATE
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.starts_with(b"-----"))
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
        )
        .unwrap()
}

#[test]
fn certificate_non_utf8_sources_and_symlinks_serialize_without_losing_path_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory
        .path()
        .join(OsString::from_vec(b"scope-\xff".to_vec()));
    fs::create_dir(&root).unwrap();
    let certificate_path = root.join(OsString::from_vec(b"cert-\xfe.pem".to_vec()));
    let link_path = root.join(OsString::from_vec(b"link-\xfd.pem".to_vec()));
    fs::write(&certificate_path, CERTIFICATE).unwrap();
    symlink(&certificate_path, &link_path).unwrap();
    let mut output = Vec::new();
    let job = certificate_job(&root, &["."], 4 << 20, false);

    let outcome = certificates::collect(&job, &context(), &mut output).unwrap();

    assert_eq!(outcome.status(), Status::Partial);
    assert_eq!(outcome.findings(), 1);
    assert_eq!(outcome.diagnostics().len(), 1);
    assert_eq!(
        outcome.diagnostics()[0].code(),
        DiagnosticCode::SymlinkRefused
    );

    let source_text = format!(
        "bommer:unix-bytes:{}",
        hex::encode(certificate_path.as_os_str().as_bytes())
    );
    let link_text = format!(
        "bommer:unix-bytes:{}",
        hex::encode(link_path.as_os_str().as_bytes())
    );
    let diagnostics = serde_json::to_value(outcome.diagnostics()).unwrap();
    assert_eq!(diagnostics[0]["path"], link_text);
    assert_eq!(
        outcome.evidence()["sources"]["certificate:sha256:39f41ff9385a90df31a90fc6c0c686cf2343dea2f18cd058339a0d00a07a51cb"],
        json!([source_text])
    );
    assert_eq!(
        Validator::new()
            .unwrap()
            .validate(&output, false)
            .unwrap()
            .component_count(),
        3
    );

    let document: Value = serde_json::from_slice(&output).unwrap();
    let certificate = document["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["cryptoProperties"]["assetType"] == "certificate")
        .unwrap();
    assert!(
        certificate["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|property| property["name"] == "bommer:certificate:source"
                && property["value"] == source_text)
    );

    let output_root = tempfile::tempdir().unwrap();

    let report = Scan::new()
        .unwrap()
        .execute(
            &[job],
            output_root.path(),
            Duration::from_secs(10),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();

    assert!(report.is_unsuccessful());
    let manifest: Value =
        serde_json::from_slice(&fs::read(report.directory().join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["results"][0]["status"], "partial");
    assert_eq!(
        manifest["results"][0]["target"],
        format!(
            "bommer:unix-bytes:{}",
            hex::encode(root.as_os_str().as_bytes())
        )
    );
    assert_eq!(manifest["results"][0]["diagnostics"][0]["path"], link_text);
}

#[test]
fn certificate_depth_rejections_spend_the_shared_entry_and_diagnostic_budget() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    let branch = root.join("branch");
    fs::create_dir_all(&branch).unwrap();
    for index in 0..20 {
        fs::write(branch.join(format!("{index}.pem")), CERTIFICATE).unwrap();
    }
    let after = directory.path().join("after.pem");
    fs::write(&after, CERTIFICATE).unwrap();
    let job = certificate_job(&root, &[".", after.to_str().unwrap()], 4 << 20, false);
    let mut output = Vec::new();

    let outcome = certificates::collect_with_limits(&job, &context(), &mut output, 6, 1).unwrap();

    assert_eq!(outcome.status(), Status::Partial);
    assert_eq!(outcome.findings(), 0);
    assert!(outcome.diagnostics().len() <= 6);
    assert!(
        outcome
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code() == DiagnosticCode::LimitExceeded)
    );
    let diagnostics = serde_json::to_value(outcome.diagnostics()).unwrap();
    assert_eq!(
        diagnostics
            .as_array()
            .unwrap()
            .iter()
            .filter(|diagnostic| diagnostic["path"]
                .as_str()
                .is_some_and(|path| Path::new(path).parent() == Some(branch.as_path())))
            .count(),
        4
    );
    assert_eq!(
        Validator::new()
            .unwrap()
            .validate(&output, false)
            .unwrap()
            .component_count(),
        0
    );
}

#[test]
fn certificate_relative_application_targets_use_working_directory_without_following_links() {
    let cwd = std::env::current_dir().unwrap();
    let directory = tempfile::tempdir_in(&cwd).unwrap();
    let relative = directory.path().strip_prefix(&cwd).unwrap();
    fs::write(directory.path().join("cert.pem"), CERTIFICATE).unwrap();

    for (target, path) in [
        (relative, "cert.pem".to_string()),
        (
            Path::new("."),
            relative.join("cert.pem").to_str().unwrap().to_owned(),
        ),
    ] {
        let job = certificate_job(target, &[&path], 4 << 20, false);
        certificates::check(&job).unwrap();
        let mut output = Vec::new();

        let outcome = certificates::collect(&job, &context(), &mut output).unwrap();

        assert_eq!(outcome.status(), Status::Collected);
        assert_eq!(outcome.findings(), 1);
        let summary = Validator::new().unwrap().validate(&output, false).unwrap();
        assert_eq!(summary.component_count(), 3);
        let document: Value = serde_json::from_slice(&output).unwrap();
        let certificate = document["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["cryptoProperties"]["assetType"] == "certificate")
            .unwrap();
        assert!(
            certificate["properties"]
                .as_array()
                .unwrap()
                .iter()
                .any(|property| property["name"] == "bommer:certificate:source"
                    && property["value"] == json!(directory.path().join("cert.pem")))
        );

        let output_root = tempfile::tempdir().unwrap();

        let report = Scan::new()
            .unwrap()
            .execute(
                &[job],
                output_root.path(),
                Duration::from_secs(10),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();

        assert!(!report.is_unsuccessful());
        let manifest: Value =
            serde_json::from_slice(&fs::read(report.directory().join("manifest.json")).unwrap())
                .unwrap();
        let expected_target = if target == Path::new(".") {
            cwd.as_path()
        } else {
            directory.path()
        };
        assert_eq!(manifest["results"][0]["target"], json!(expected_target));
    }

    symlink(directory.path(), directory.path().join("target-link")).unwrap();
    let target = relative.join("target-link");

    let outcome = certificates::collect(
        &certificate_job(&target, &["cert.pem"], 4 << 20, false),
        &context(),
        &mut Vec::new(),
    )
    .unwrap();

    assert_eq!(outcome.status(), Status::Partial);
    assert_eq!(outcome.findings(), 0);
    assert_eq!(
        outcome.diagnostics()[0].code(),
        DiagnosticCode::SymlinkRefused
    );
}

#[test]
fn certificate_host_provenance_keeps_an_empty_target() {
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("cert.pem");
    fs::write(&certificate, CERTIFICATE).unwrap();
    let job = Job::new(
        Scope::Host,
        None,
        InventoryKind::Cbom,
        Target::Host,
        Backend::Certificates {
            paths: vec![certificate],
            max_file_bytes: 4 << 20,
            include_identity: false,
        },
    )
    .unwrap();
    let output_root = tempfile::tempdir().unwrap();

    let report = Scan::new()
        .unwrap()
        .execute(
            &[job],
            output_root.path(),
            Duration::from_secs(10),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();

    assert!(!report.is_unsuccessful());
    let manifest: Value =
        serde_json::from_slice(&fs::read(report.directory().join("manifest.json")).unwrap())
            .unwrap();
    assert!(manifest["results"][0].get("target").is_none());
    assert_eq!(manifest["results"][0]["findings"], 1);
}

#[test]
fn certificate_application_targets_reject_parent_traversal_even_with_absolute_paths() {
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("cert.pem");
    fs::write(&certificate, CERTIFICATE).unwrap();

    for target in [
        Path::new(".."),
        Path::new("./../app"),
        &directory.path().join("child/.."),
        &directory.path().join("missing/../target"),
    ] {
        let job = certificate_job(target, &[certificate.to_str().unwrap()], 4 << 20, false);
        let mut output = Vec::new();

        assert!(matches!(
            certificates::check(&job),
            Err(certificates::CertificateError::InvalidTarget { .. })
        ));
        assert!(matches!(
            certificates::collect(&job, &context(), &mut output),
            Err(certificates::CertificateError::InvalidTarget { .. })
        ));
        assert!(output.is_empty());
    }
}

#[test]
fn certificate_nix_profile_targets_must_resolve_to_existing_store_outputs() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("cert.pem"), CERTIFICATE).unwrap();
    symlink(directory.path(), directory.path().join("profile")).unwrap();
    let job = Job::new(
        Scope::Application {
            name: Name::new("app".into()).unwrap(),
            version: None,
        },
        None,
        InventoryKind::Cbom,
        Target::NixClosure(directory.path().join("profile")),
        Backend::Certificates {
            paths: vec!["cert.pem".into()],
            max_file_bytes: 4 << 20,
            include_identity: false,
        },
    )
    .unwrap();
    let mut output = Vec::new();

    assert!(matches!(
        certificates::check(&job),
        Err(certificates::CertificateError::InvalidTarget { .. })
    ));
    assert!(matches!(
        certificates::collect(&job, &context(), &mut output),
        Err(certificates::CertificateError::InvalidTarget { .. })
    ));
    assert!(output.is_empty());
}

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
    assert_eq!(outcome.status(), Status::Collected);
    assert_eq!(outcome.findings(), 1);
    assert_eq!(outcome.coverage(), Coverage::ProducerDeclaredUnverified);
    assert_eq!(outcome.evidence()["sourcePath"], json!(path));
    assert_eq!(
        outcome.evidence()["sourceSHA256"],
        "f0c6554e7164cb9b11d221eb10553719657137a1a66890ef2beac9a648a9b7f3"
    );
    assert_eq!(outcome.evidence()["origin"], "imported");
    assert_eq!(outcome.evidence()["discovery"], "not-observed-locally");
    assert_eq!(
        outcome.evidence()["applicationAssociation"],
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

    assert_eq!(outcome.status(), Status::NoFindings);
    assert_eq!(outcome.findings(), 0);
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

#[test]
fn certificates_deduplicate_bundle_and_der_and_keep_identity_opt_in() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let mut bundle =
        b"-----BEGIN PRIVATE KEY-----\nSECRET-MARKER\n-----END PRIVATE KEY-----\n".to_vec();
    bundle.extend_from_slice(CERTIFICATE);
    fs::write(root.join("bundle.pem"), bundle).unwrap();
    fs::write(root.join("copy.der"), certificate_der()).unwrap();
    let job = certificate_job(
        root,
        &["bundle.pem", "copy.der", "bundle.pem"],
        4 << 20,
        false,
    );
    let mut output = Vec::new();

    let outcome = certificates::collect(&job, &context(), &mut output).unwrap();

    assert_eq!(outcome.status(), Status::Collected);
    assert_eq!(outcome.findings(), 1);
    assert_eq!(outcome.coverage(), Coverage::DeclaredScope);
    assert!(outcome.diagnostics().is_empty());

    let summary = Validator::new().unwrap().validate(&output, false).unwrap();
    assert_eq!(summary.component_count(), 3);
    let document: Value = serde_json::from_slice(&output).unwrap();
    let components = document["components"].as_array().unwrap();
    assert_eq!(components.len(), 3);

    let certificate = components
        .iter()
        .find(|component| component["cryptoProperties"]["assetType"] == "certificate")
        .unwrap();
    let metadata = &certificate["cryptoProperties"]["certificateProperties"];
    assert_eq!(
        certificate["bom-ref"],
        "certificate:sha256:39f41ff9385a90df31a90fc6c0c686cf2343dea2f18cd058339a0d00a07a51cb"
    );
    assert_eq!(metadata["certificateFormat"], "X.509");
    assert_eq!(metadata["notValidBefore"], "2018-11-13T02:54:40Z");
    assert_eq!(metadata["notValidAfter"], "2019-11-13T02:54:40Z");
    assert!(metadata.get("subjectName").is_none());
    assert!(metadata.get("issuerName").is_none());
    assert!(metadata.get("subjectPublicKeyRef").is_none());
    assert!(
        components
            .iter()
            .any(|component| component["name"] == "ECDSA-P-384")
    );
    assert!(
        components
            .iter()
            .any(|component| component["name"] == "ECDSA-SHA256")
    );

    let properties = certificate["properties"].as_array().unwrap();
    assert!(
        properties
            .iter()
            .any(|property| property["name"] == "bommer:certificate:expired"
                && property["value"] == "true")
    );
    assert_eq!(
        properties
            .iter()
            .filter(|property| property["name"] == "bommer:certificate:source")
            .count(),
        2
    );

    let text = String::from_utf8(output.clone()).unwrap();
    for forbidden in [
        "benno",
        "SECRET-MARKER",
        "PRIVATE KEY",
        "encodedCertificate",
    ] {
        assert!(!text.contains(forbidden));
    }

    let mut reordered = Vec::new();

    certificates::collect(
        &certificate_job(root, &["copy.der", "bundle.pem"], 4 << 20, false),
        &context(),
        &mut reordered,
    )
    .unwrap();

    assert_eq!(output, reordered);

    let mut identity = Vec::new();

    certificates::collect(
        &certificate_job(root, &["copy.der"], 4 << 20, true),
        &context(),
        &mut identity,
    )
    .unwrap();

    Validator::new()
        .unwrap()
        .validate(&identity, false)
        .unwrap();
    let identity: Value = serde_json::from_slice(&identity).unwrap();
    let certificate = identity["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["cryptoProperties"]["assetType"] == "certificate")
        .unwrap();
    assert_eq!(
        certificate["cryptoProperties"]["certificateProperties"]["subjectName"],
        "CN=benno"
    );
}

#[test]
fn certificate_algorithm_assets_cover_rsa_ec_and_ed25519_with_resolved_roles() {
    let directory = tempfile::tempdir().unwrap();
    let mut bundle = CERTIFICATE.to_vec();
    bundle.extend_from_slice(include_bytes!("../tests/fixtures/native-rsa.pem"));
    bundle.extend_from_slice(include_bytes!("../tests/fixtures/native-ed25519.pem"));
    fs::write(directory.path().join("bundle.pem"), bundle).unwrap();
    let mut output = Vec::new();

    let outcome = certificates::collect(
        &certificate_job(directory.path(), &["bundle.pem"], 4 << 20, false),
        &context(),
        &mut output,
    )
    .unwrap();

    assert_eq!(outcome.status(), Status::Collected);
    assert_eq!(outcome.findings(), 3);
    let summary = Validator::new().unwrap().validate(&output, false).unwrap();
    assert_eq!(summary.component_count(), 9);
    let document: Value = serde_json::from_slice(&output).unwrap();
    let components = document["components"].as_array().unwrap();
    assert_eq!(components.len(), 9);
    for name in [
        "RSA-2048",
        "SHA256-RSA",
        "ECDSA-P-384",
        "ECDSA-SHA256",
        "Ed25519",
    ] {
        assert!(components.iter().any(|component| component["name"] == name));
    }

    let rsa = components
        .iter()
        .find(|component| component["name"] == "RSA-2048")
        .unwrap();
    assert_eq!(
        rsa["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"],
        "2048"
    );

    for certificate in components
        .iter()
        .filter(|component| component["cryptoProperties"]["assetType"] == "certificate")
    {
        let signature =
            &certificate["cryptoProperties"]["certificateProperties"]["signatureAlgorithmRef"];
        let asset = components
            .iter()
            .find(|component| &component["bom-ref"] == signature)
            .unwrap();
        assert_eq!(asset["properties"][0]["value"], "signature");

        let public_key = &certificate["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|property| property["name"] == "bommer:certificate:public-key-algorithm-ref")
            .unwrap()["value"];
        let asset = components
            .iter()
            .find(|component| &component["bom-ref"] == public_key)
            .unwrap();
        assert_eq!(asset["properties"][0]["value"], "public-key");
    }

    let text = String::from_utf8(output).unwrap();
    assert!(!text.contains("TEST-IDENTITY"));
}

#[test]
fn certificate_traversal_refuses_links_in_roots_ancestors_and_children() {
    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("cert.der"), certificate_der()).unwrap();
    symlink(outside.path(), directory.path().join("link")).unwrap();
    symlink(
        outside.path().join("cert.der"),
        directory.path().join("file.der"),
    )
    .unwrap();

    for path in ["link", "file.der", "link/cert.der", "link/../cert.der", "."] {
        let mut output = Vec::new();

        let outcome = certificates::collect(
            &certificate_job(directory.path(), &[path], 4 << 20, false),
            &context(),
            &mut output,
        )
        .unwrap();

        assert_eq!(outcome.status(), Status::Partial);
        assert_eq!(outcome.findings(), 0);
        assert!(
            outcome
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code() == DiagnosticCode::SymlinkRefused)
        );
    }

    let job = certificate_job(
        &directory.path().join("link"),
        &["cert.der"],
        4 << 20,
        false,
    );

    let outcome = certificates::collect(&job, &context(), &mut Vec::new()).unwrap();

    assert_eq!(outcome.status(), Status::Partial);
    assert_eq!(outcome.findings(), 0);
}

#[test]
fn certificate_coverage_reports_malformed_missing_oversize_and_fifo() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let validator = Validator::new().unwrap();
    fs::write(
        root.join("bad.pem"),
        b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    fs::write(root.join("oversize.der"), certificate_der()).unwrap();
    fs::write(root.join("ordinary.txt"), b"ordinary").unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        root.join("fifo.pem"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();

    for (path, limit, expected) in [
        ("bad.pem", 4 << 20, DiagnosticCode::MalformedCertificate),
        ("missing", 4 << 20, DiagnosticCode::MissingPath),
        ("oversize.der", 10, DiagnosticCode::LimitExceeded),
        ("fifo.pem", 4 << 20, DiagnosticCode::UnsupportedFile),
    ] {
        let mut output = Vec::new();

        let outcome = certificates::collect(
            &certificate_job(root, &[path], limit, false),
            &context(),
            &mut output,
        )
        .unwrap();

        assert_eq!(outcome.status(), Status::Partial);
        assert_eq!(outcome.findings(), 0);
        assert_eq!(outcome.diagnostics().len(), 1);
        assert_eq!(outcome.diagnostics()[0].code(), expected);
        assert_eq!(
            validator
                .validate(&output, false)
                .unwrap()
                .component_count(),
            0
        );
    }

    let mut output = Vec::new();

    let outcome = certificates::collect(
        &certificate_job(root, &["ordinary.txt"], 2, false),
        &context(),
        &mut output,
    )
    .unwrap();

    assert_eq!(outcome.status(), Status::NoFindings);
    assert_eq!(
        validator
            .validate(&output, false)
            .unwrap()
            .component_count(),
        0
    );

    let mut mixed = b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n".to_vec();
    mixed.extend_from_slice(CERTIFICATE);
    fs::write(root.join("mixed.pem"), mixed).unwrap();
    output.clear();

    let outcome = certificates::collect(
        &certificate_job(root, &["mixed.pem"], 4 << 20, false),
        &context(),
        &mut output,
    )
    .unwrap();

    assert_eq!(outcome.status(), Status::Partial);
    assert_eq!(outcome.findings(), 1);
    assert_eq!(
        validator
            .validate(&output, false)
            .unwrap()
            .component_count(),
        3
    );
}

#[test]
fn certificate_depth_is_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let mut path = directory.path().to_path_buf();
    for _ in 0..129 {
        path.push("d");
        fs::create_dir(&path).unwrap();
    }
    fs::write(path.join("cert.pem"), CERTIFICATE).unwrap();

    let outcome = certificates::collect(
        &certificate_job(directory.path(), &["."], 4 << 20, false),
        &context(),
        &mut Vec::new(),
    )
    .unwrap();

    assert_eq!(outcome.status(), Status::Partial);
    assert_eq!(outcome.findings(), 0);
    assert!(
        outcome
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == DiagnosticCode::LimitExceeded)
    );
}

#[test]
fn native_cancellation_and_writer_errors_remain_typed() {
    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.json");
    fs::write(&source, IMPORT).unwrap();
    let cancelled =
        CollectionContext::new(Duration::from_secs(10), Arc::new(AtomicBool::new(true)));
    let mut output = Vec::new();

    assert!(matches!(
        import::collect(&import_job(&source), &cancelled, &mut output),
        Err(import::ImportError::Interrupted(Interrupted::Cancelled))
    ));
    let job = certificate_job(directory.path(), &["."], 4 << 20, false);
    assert!(matches!(
        certificates::collect(&job, &cancelled, &mut output),
        Err(certificates::CertificateError::Interrupted(
            Interrupted::Cancelled
        ))
    ));
    assert!(matches!(
        nix::collect(&nix_job(), &cancelled, &mut output),
        Err(nix::NixError::Interrupted(Interrupted::Cancelled))
    ));
    assert!(output.is_empty());

    assert!(
        matches!(import::collect(&import_job(&source), &context(), &mut Broken), Err(import::ImportError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe)
    );
    assert!(
        matches!(certificates::collect(&job, &context(), &mut Broken), Err(certificates::CertificateError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe)
    );
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
        assert_eq!(summary.component_count(), 2);
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
        let (arguments, store) = nix::query_arguments(version, &[APP.into(), LIB.into()]).unwrap();

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
