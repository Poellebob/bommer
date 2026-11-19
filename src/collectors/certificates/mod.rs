mod assets;
mod discovery;
pub(crate) mod error;
mod types;

use std::io::Write;

use crate::collection::context::CollectionContext;
use crate::collection::outcome::{CollectionOutcome, Coverage, ExecutionScope};
use crate::collectors::certificates::error::CertificateError;
use crate::job::{Backend, Job};
use crate::path_encoding::path_text;

pub(crate) fn check(job: &Job) -> Result<(), CertificateError> {
    // Missing/refused paths are coverage diagnostics during collection, not fatal preflight.
    let target = discovery::resolve_target(job)?;
    discovery::configured_paths(job, target.as_deref()).map(|_| ())
}

pub(crate) fn collect(
    job: &Job,
    context: &CollectionContext,
    output: &mut dyn Write,
) -> Result<CollectionOutcome, CertificateError> {
    collect_with_limits(job, context, output, 100_000, 128)
}

pub(crate) fn collect_with_limits(
    job: &Job,
    context: &CollectionContext,
    output: &mut dyn Write,
    entry_limit: usize,
    depth_limit: usize,
) -> Result<CollectionOutcome, CertificateError> {
    let discovery = discovery::discover(job, context, entry_limit, depth_limit)?;
    let Backend::Certificates {
        include_identity, ..
    } = &job.backend
    else {
        return Err(CertificateError::Options);
    };
    let assets = assets::build(&discovery.observations, *include_identity, context)?;

    context.check()?;
    assets.document.write(output)?;

    Ok(CollectionOutcome {
        scope: ExecutionScope {
            target: Some(
                discovery
                    .target
                    .as_deref()
                    .map(path_text)
                    .unwrap_or_default(),
            ),
            exclusions: None,
        },
        ..CollectionOutcome::observed(
            discovery.observations.len(),
            Coverage::DeclaredScope,
            discovery.diagnostics,
            assets.evidence,
            Some("certificates/1".into()),
        )
    })
}

#[cfg(test)]
mod tests {

    use crate::bom::validation::Validator;
    use crate::collection::context::CollectionContext;
    use crate::collection::outcome::{Coverage, DiagnosticCode, Status};
    use crate::collectors::certificates;
    use crate::job::{Backend, InventoryKind, Job, Name, Scope, Target};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::Value;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::sync::{Arc, atomic::AtomicBool};
    use std::time::Duration;
    // Public P-384 fixture from x509-parser's MIT/Apache-2.0 no_extensions.pem.
    const CERTIFICATE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/native-ec.pem"
    ));

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

        let outcome =
            certificates::collect_with_limits(&job, &context(), &mut output, 6, 1).unwrap();

        assert_eq!(outcome.status, Status::Partial);
        assert_eq!(outcome.findings, 0);
        assert!(outcome.diagnostics.len() <= 6);
        assert!(
            outcome
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code == DiagnosticCode::LimitExceeded)
        );
        let diagnostics = serde_json::to_value(&outcome.diagnostics).unwrap();
        assert_eq!(
            diagnostics
                .as_array()
                .unwrap()
                .iter()
                .filter(
                    |diagnostic| diagnostic["path"]
                        .as_str()
                        .is_some_and(|path| Path::new(path).parent() == Some(branch.as_path()))
                )
                .count(),
            4
        );
        assert_eq!(
            Validator::new()
                .unwrap()
                .validate(&output, false)
                .unwrap()
                .component_count,
            0
        );
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
                Err(certificates::error::CertificateError::InvalidTarget { .. })
            ));
            assert!(matches!(
                certificates::collect(&job, &context(), &mut output),
                Err(certificates::error::CertificateError::InvalidTarget { .. })
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
            Err(certificates::error::CertificateError::InvalidTarget { .. })
        ));
        assert!(matches!(
            certificates::collect(&job, &context(), &mut output),
            Err(certificates::error::CertificateError::InvalidTarget { .. })
        ));
        assert!(output.is_empty());
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

        assert_eq!(outcome.status, Status::Collected);
        assert_eq!(outcome.findings, 1);
        assert_eq!(outcome.coverage, Coverage::DeclaredScope);
        assert!(outcome.diagnostics.is_empty());

        let summary = Validator::new().unwrap().validate(&output, false).unwrap();
        assert_eq!(summary.component_count, 3);
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
        bundle.extend_from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/native-rsa.pem"
        )));
        bundle.extend_from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/native-ed25519.pem"
        )));
        fs::write(directory.path().join("bundle.pem"), bundle).unwrap();
        let mut output = Vec::new();

        let outcome = certificates::collect(
            &certificate_job(directory.path(), &["bundle.pem"], 4 << 20, false),
            &context(),
            &mut output,
        )
        .unwrap();

        assert_eq!(outcome.status, Status::Collected);
        assert_eq!(outcome.findings, 3);
        let summary = Validator::new().unwrap().validate(&output, false).unwrap();
        assert_eq!(summary.component_count, 9);
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

            assert_eq!(outcome.status, Status::Partial);
            assert_eq!(outcome.findings, 0);
            assert!(
                outcome
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == DiagnosticCode::SymlinkRefused)
            );
        }

        let job = certificate_job(
            &directory.path().join("link"),
            &["cert.der"],
            4 << 20,
            false,
        );

        let outcome = certificates::collect(&job, &context(), &mut Vec::new()).unwrap();

        assert_eq!(outcome.status, Status::Partial);
        assert_eq!(outcome.findings, 0);
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

            assert_eq!(outcome.status, Status::Partial);
            assert_eq!(outcome.findings, 0);
            assert_eq!(outcome.diagnostics.len(), 1);
            assert_eq!(outcome.diagnostics[0].code, expected);
            assert_eq!(
                validator.validate(&output, false).unwrap().component_count,
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

        assert_eq!(outcome.status, Status::NoFindings);
        assert_eq!(
            validator.validate(&output, false).unwrap().component_count,
            0
        );

        let mut mixed =
            b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n".to_vec();
        mixed.extend_from_slice(CERTIFICATE);
        fs::write(root.join("mixed.pem"), mixed).unwrap();
        output.clear();

        let outcome = certificates::collect(
            &certificate_job(root, &["mixed.pem"], 4 << 20, false),
            &context(),
            &mut output,
        )
        .unwrap();

        assert_eq!(outcome.status, Status::Partial);
        assert_eq!(outcome.findings, 1);
        assert_eq!(
            validator.validate(&output, false).unwrap().component_count,
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

        assert_eq!(outcome.status, Status::Partial);
        assert_eq!(outcome.findings, 0);
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == DiagnosticCode::LimitExceeded)
        );
    }
}
