//! Execute scans and publish validated inventory artifacts.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;

use crate::bom::validation::{ValidationError, Validator};
use crate::collection::context::{CollectionContext, Interrupted};
use crate::collection::failure::{Failure, FailureKind};
use crate::collection::outcome::{ExecutionScope, Status};
use crate::collectors::{self, CollectionError};
use crate::job::Job;
use crate::manifest::{JobResult, Manifest, ManifestError};
use crate::output::{OutputError, RunOutput};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ScanError {
    #[error("cannot register cancellation signal")]
    Signal(#[source] io::Error),

    #[error(transparent)]
    Output(#[from] OutputError),

    #[error(transparent)]
    Manifest(#[from] ManifestError),

    #[error(transparent)]
    Validation(#[from] ValidationError),
}

#[derive(Debug, thiserror::Error)]
enum JobFailure {
    #[error(transparent)]
    Collection(#[from] CollectionError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Interrupted(#[from] Interrupted),

    #[error("collector reported findings without inventory components")]
    EmptyCollected,
    #[error("collector output exceeds 64 MiB")]
    TooLarge,
    #[error("cannot read candidate artifact")]
    Read(#[from] io::Error),
}

#[derive(Debug)]
pub(crate) struct ScanReport {
    pub(crate) directory: PathBuf,
    pub(crate) unsuccessful: bool,
}

pub(crate) struct Scan {
    validator: Validator,
}

impl JobFailure {
    fn details(&self) -> Failure {
        match self {
            Self::Collection(error) => error.details(),
            Self::Interrupted(Interrupted::Cancelled) => Failure::new(FailureKind::Cancelled),
            Self::Interrupted(Interrupted::Timeout) => Failure::new(FailureKind::Timeout),
            Self::Validation(_) | Self::EmptyCollected => Failure::new(FailureKind::Validation),
            Self::TooLarge => Failure::limited("stdout", 64 << 20),
            Self::Read(_) => Failure::new(FailureKind::Io),
        }
    }
}

pub(crate) fn run(jobs: &[Job], root: &Path, timeout: Duration) -> Result<ScanReport, ScanError> {
    let cancelled = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, Arc::clone(&cancelled)).map_err(ScanError::Signal)?;
    }

    Scan::new()?.execute(jobs, root, timeout, cancelled)
}

impl Scan {
    pub(crate) fn new() -> Result<Self, ScanError> {
        Ok(Self {
            validator: Validator::new()?,
        })
    }

    pub(crate) fn execute(
        &self,
        jobs: &[Job],
        root: &Path,
        timeout: Duration,
        cancelled: Arc<AtomicBool>,
    ) -> Result<ScanReport, ScanError> {
        let output = RunOutput::create(root)?;
        let mut manifest = Manifest::new();
        output.checkpoint(&manifest)?;

        for job in jobs {
            let mut result = JobResult::pending(job)?;
            let context = CollectionContext::new(timeout, Arc::clone(&cancelled));
            let mut candidate = output.candidate()?;
            let mut stderr = output.log(job)?;

            let collected = (|| -> Result<_, JobFailure> {
                let mut outcome = collectors::collect(job, &context, &mut candidate, &mut stderr)?;
                result.collected(&mut outcome);
                context.check()?;

                candidate.seek(SeekFrom::Start(0))?;
                let mut bytes = Vec::new();
                candidate
                    .by_ref()
                    .take((64 << 20) + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > 64 << 20 {
                    return Err(JobFailure::TooLarge);
                }

                let summary = self.validator.validate(&bytes, !job.backend.is_native())?;
                if summary.component_count == 0 && outcome.status == Status::Collected {
                    return Err(JobFailure::EmptyCollected);
                }

                context.check()?;
                Ok((outcome, bytes, summary))
            })();

            match collected {
                Ok((outcome, bytes, summary)) => {
                    let artifact = output.publish(job, candidate, &bytes)?;
                    result.complete(
                        outcome,
                        artifact,
                        &summary.version,
                        summary.component_count,
                        !job.backend.is_native(),
                    );
                }
                Err(error) => {
                    let scope = if let JobFailure::Collection(error) = &error
                        && let Some((target, exclusions)) = error.execution_scope()
                    {
                        ExecutionScope {
                            target: Some(target.into()),
                            exclusions: Some(exclusions.to_vec()),
                        }
                    } else {
                        ExecutionScope::default()
                    };

                    result.fail(&error, error.details(), scope);
                }
            }

            result.finish()?;
            manifest.record(result);
            output.checkpoint(&manifest)?;
        }

        Ok(ScanReport {
            directory: output.directory().into(),
            unsuccessful: manifest.is_unsuccessful(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::io::{self, Write};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::{Duration, Instant};

    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use crate::bom::validation::Validator;
    use crate::collection::context::{CollectionContext, Interrupted};
    use crate::collection::outcome::{CollectionOutcome, DiagnosticCode, ExecutionScope, Status};
    use crate::collectors::{certificates, external, import, nix};
    use crate::config::Config;
    use crate::job::{Backend, InventoryKind, Job, Name, Scope, Target};
    use crate::manifest::{JobResult, Manifest};
    use crate::output::RunOutput;
    use crate::scan::{Scan, ScanReport};

    const BOM: &str = r#"{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"scan-fixture","version":"2.3.4"}]}"#;

    fn script(directory: &Path, name: &str, body: &str) -> PathBuf {
        let path = directory.join(name);
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn command_config(commands: &[(&str, &Path)]) -> Config {
        let inventories: Vec<_> = commands
            .iter()
            .map(|(name, executable)| {
                json!({
                    "name": name,
                    "kind": "sbom",
                    "collector": {"enabled": true, "backend": "command", "command": [executable]},
                })
            })
            .collect();
        // JSON is a YAML subset; serialization safely quotes temporary paths.
        Config::parse(
            &json!({
                "version": 1,
                "output": {"directory": "unused-test-output"},
                "host": {"inventories": inventories},
            })
            .to_string(),
        )
        .unwrap()
    }

    fn execute(config: &Config, root: &Path, cancelled: bool) -> ScanReport {
        Scan::new()
            .unwrap()
            .execute(
                &config.jobs,
                root,
                Duration::from_secs(10),
                Arc::new(AtomicBool::new(cancelled)),
            )
            .unwrap()
    }

    fn manifest(directory: &Path) -> Value {
        serde_json::from_slice(&fs::read(directory.join("manifest.json")).unwrap()).unwrap()
    }

    fn entries(directory: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn assert_private(path: &Path, mode: u32) {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            mode,
            "{}",
            path.display()
        );
    }

    fn assert_failed(result: &Value) {
        assert_eq!(result["status"], "failed");
        assert_eq!(result["coverage"], "unknown");
        assert_eq!(result["findings"], 0);
        assert!(
            result["error"]
                .as_str()
                .is_some_and(|error| !error.is_empty())
        );
        for key in ["artifact", "sha256", "specVersion"] {
            assert!(result.get(key).is_none(), "failed result contains {key}");
        }
    }

    #[test]
    fn empty_scan_checkpoints_a_successful_manifest() {
        let temporary = tempfile::tempdir().unwrap();
        let report = Scan::new()
            .unwrap()
            .execute(
                &[],
                temporary.path(),
                Duration::from_secs(10),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
        assert!(!report.unsuccessful);
        assert_eq!(manifest(&report.directory)["results"], json!([]));
        assert_eq!(entries(&report.directory), ["manifest.json"]);
    }

    #[test]
    fn successful_scan_publishes_validated_artifact_hash_and_private_v2_manifest() {
        let temporary = tempfile::tempdir().unwrap();
        let executable = script(temporary.path(), "success", &format!("printf '%s' '{BOM}'"));
        let config = command_config(&[("packages", &executable)]);
        let root = temporary.path().join("output");

        let report = execute(&config, &root, false);

        assert!(!report.unsuccessful);
        assert_eq!(report.directory.parent(), Some(root.as_path()));
        assert_eq!(entries(&root).len(), 2); // Lock and retained run directory.

        let document = manifest(&report.directory);
        assert_eq!(document["version"], 2);
        assert_eq!(document["bommerVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(document["validation"], "json-schema-offline");
        assert_eq!(document["results"].as_array().unwrap().len(), 1);

        let result = &document["results"][0];
        assert_eq!(result["name"], "host");
        assert_eq!(result["inventory"], "packages");
        assert_eq!(result["scope"], "host");
        assert_eq!(result["kind"], "sbom");
        assert_eq!(result["backend"], "command");
        assert_eq!(result["status"], "collected");
        assert_eq!(result["coverage"], "unknown");
        assert_eq!(result["specVersion"], "1.6");
        assert_eq!(result["findings"], 1);
        assert_eq!(result["target"], "dir:/");
        assert!(result.get("error").is_none());
        assert!(result.get("failure").is_none());
        for key in ["started", "finished"] {
            time::OffsetDateTime::parse(
                result[key].as_str().unwrap(),
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap();
        }
        assert_eq!(result["artifact"], "host.packages.sbom.cdx.json");
        let bytes = fs::read(report.directory.join("host.packages.sbom.cdx.json")).unwrap();
        assert_eq!(bytes, BOM.as_bytes());
        assert_eq!(result["sha256"], hex::encode(Sha256::digest(&bytes)));
        let validated = Validator::new().unwrap().validate(&bytes, true).unwrap();
        assert_eq!(validated.component_count, 1);
        assert_eq!(validated.version, "1.6");

        assert_eq!(
            entries(&report.directory),
            [
                "host.packages.sbom.cdx.json",
                "host.packages.sbom.stderr.log",
                "manifest.json"
            ]
        );

        assert_private(&root, 0o700);
        assert_private(&root.join(".lock"), 0o600);
        assert_private(&report.directory, 0o700);
        for name in entries(&report.directory) {
            assert_private(&report.directory.join(name), 0o600);
        }
    }

    #[test]
    fn invalid_collector_output_is_not_published_and_candidates_are_removed() {
        let temporary = tempfile::tempdir().unwrap();
        for (name, fixture) in [
            ("malformed", "{not-json"),
            (
                "schema",
                r#"{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"not-a-component-type","name":"bad"}]}"#,
            ),
            (
                "empty",
                r#"{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}"#,
            ),
        ] {
            let executable = script(temporary.path(), name, &format!("printf '%s' '{fixture}'"));
            let config = command_config(&[("invalid", &executable)]);

            let report = execute(
                &config,
                &temporary.path().join(format!("output-{name}")),
                false,
            );

            assert!(report.unsuccessful, "{name}");
            let document = manifest(&report.directory);
            assert_eq!(document["results"].as_array().unwrap().len(), 1);
            assert_failed(&document["results"][0]);
            // Collection succeeded, so its effective scope survives validation failure.
            assert_eq!(document["results"][0]["target"], "dir:/");
            assert_eq!(
                document["results"][0]["failure"],
                json!({"kind": "validation"})
            );
            assert_eq!(
                entries(&report.directory),
                ["host.invalid.sbom.stderr.log", "manifest.json"]
            );
        }
    }

    #[test]
    fn failed_job_preserves_stderr_and_does_not_prevent_the_next_job() {
        let temporary = tempfile::tempdir().unwrap();
        let first = script(
            temporary.path(),
            "failure",
            &format!("printf '%s' '{BOM}'\nprintf 'first collector failed\\n' >&2\nexit 7"),
        );
        let second = script(
            temporary.path(),
            "success",
            &format!("printf 'second collector ran\\n' >&2\nprintf '%s' '{BOM}'"),
        );
        let config = command_config(&[("first", &first), ("second", &second)]);

        let report = execute(&config, &temporary.path().join("output"), false);

        assert!(report.unsuccessful);
        let document = manifest(&report.directory);
        let results = document["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["inventory"], "first");
        assert_failed(&results[0]);
        assert_eq!(
            results[0]["failure"],
            json!({"kind": "process-exit", "exitCode": 7})
        );

        assert_eq!(results[1]["inventory"], "second");
        assert_eq!(results[1]["status"], "collected");
        assert_eq!(results[1]["findings"], 1);
        assert_eq!(results[1]["artifact"], "host.second.sbom.cdx.json");
        assert_eq!(
            fs::read(report.directory.join("host.second.sbom.cdx.json")).unwrap(),
            BOM.as_bytes()
        );

        assert_eq!(
            fs::read_to_string(report.directory.join("host.first.sbom.stderr.log")).unwrap(),
            "first collector failed\n"
        );
        assert_eq!(
            fs::read_to_string(report.directory.join("host.second.sbom.stderr.log")).unwrap(),
            "second collector ran\n"
        );
        assert_eq!(
            entries(&report.directory),
            [
                "host.first.sbom.stderr.log",
                "host.second.sbom.cdx.json",
                "host.second.sbom.stderr.log",
                "manifest.json"
            ]
        );
    }

    #[test]
    fn missing_certificates_retain_a_valid_empty_partial_artifact() {
        let temporary = tempfile::tempdir().unwrap();
        let missing = temporary.path().join("missing-certificates");
        let config = Config::parse(&json!({
            "version": 1,
            "output": {"directory": "unused-test-output"},
            "host": {"inventories": [{
                "name": "certificates", "kind": "cbom",
                "collector": {"enabled": true, "backend": "certificates", "certificates": {"paths": [missing]}},
            }]},
        }).to_string()).unwrap();

        let report = execute(&config, &temporary.path().join("output"), false);

        assert!(report.unsuccessful);
        let document = manifest(&report.directory);
        assert_eq!(document["results"].as_array().unwrap().len(), 1);
        let result = &document["results"][0];
        assert_eq!(result["status"], "partial");
        assert_eq!(result["backend"], "certificates");
        assert_eq!(result["coverage"], "declared-scope");
        assert_eq!(result["findings"], 0);
        assert_eq!(
            result["diagnostics"],
            json!([{"code": "missing-path", "path": missing}])
        );
        assert!(result.get("error").is_none());

        assert_eq!(result["artifact"], "host.certificates.cbom.cdx.json");
        let bytes = fs::read(report.directory.join("host.certificates.cbom.cdx.json")).unwrap();
        assert_eq!(result["sha256"], hex::encode(Sha256::digest(&bytes)));
        let validated = Validator::new().unwrap().validate(&bytes, false).unwrap();
        assert_eq!(validated.component_count, 0);
        assert_eq!(result["specVersion"], validated.version);
        assert_eq!(
            entries(&report.directory),
            [
                "host.certificates.cbom.cdx.json",
                "host.certificates.cbom.stderr.log",
                "manifest.json"
            ]
        );
    }

    #[test]
    fn pre_cancelled_scan_records_all_failures_without_launching_collectors() {
        let temporary = tempfile::tempdir().unwrap();
        let marker = temporary.path().join("launched");
        let executable = script(
            temporary.path(),
            "must-not-launch",
            &format!(
                "printf 'launched' > '{}'\nprintf '%s' '{BOM}'",
                marker.display(),
            ),
        );
        let config = command_config(&[("first", &executable), ("second", &executable)]);

        let report = execute(&config, &temporary.path().join("output"), true);

        assert!(report.unsuccessful);
        assert!(!marker.exists());
        let document = manifest(&report.directory);
        let results = document["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        for (result, name) in results.iter().zip(["first", "second"]) {
            assert_eq!(result["inventory"], name);
            assert_failed(result);
            assert_eq!(result["failure"], json!({"kind": "cancelled"}));
            assert_eq!(
                fs::read(
                    report
                        .directory
                        .join(format!("host.{name}.sbom.stderr.log"))
                )
                .unwrap(),
                b""
            );
        }
        assert_eq!(
            entries(&report.directory),
            [
                "host.first.sbom.stderr.log",
                "host.second.sbom.stderr.log",
                "manifest.json"
            ]
        );
    }

    #[test]
    fn timed_out_scan_persists_timeout_instead_of_cancellation() {
        let temporary = tempfile::tempdir().unwrap();
        let executable = script(
            temporary.path(),
            "timeout",
            "printf 'waiting\\n' >&2\nexec sleep 60",
        );
        let config = command_config(&[("slow", &executable)]);

        let report = Scan::new()
            .unwrap()
            .execute(
                &config.jobs,
                &temporary.path().join("output"),
                Duration::from_secs(1),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();

        assert!(report.unsuccessful);
        let document = manifest(&report.directory);
        assert_failed(&document["results"][0]);
        assert_eq!(
            document["results"][0]["failure"],
            json!({"kind": "timeout"})
        );
        assert_eq!(
            fs::read(report.directory.join("host.slow.sbom.stderr.log")).unwrap(),
            b"waiting\n"
        );
        assert_eq!(
            entries(&report.directory),
            ["host.slow.sbom.stderr.log", "manifest.json"]
        );
    }

    #[test]
    fn active_cancellation_after_readiness_persists_cancelled_and_stderr() {
        let temporary = tempfile::tempdir().unwrap();
        let ready = temporary.path().join("ready");
        let executable = script(
            temporary.path(),
            "cancel",
            &format!(
                "printf 'running\\n' >&2\nprintf ready > '{}'\nexec sleep 60",
                ready.display(),
            ),
        );
        let config = command_config(&[("active", &executable)]);
        let scan = Scan::new().unwrap();
        let root = temporary.path().join("output");
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);

        let report = std::thread::scope(|scope| {
            let worker =
                scope.spawn(|| scan.execute(&config.jobs, &root, Duration::from_secs(20), flag));

            let deadline = Instant::now() + Duration::from_secs(10);
            while !ready.exists() && Instant::now() < deadline && !worker.is_finished() {
                std::thread::sleep(Duration::from_millis(5));
            }
            let was_ready = ready.exists();
            // Always stop and join the worker, including when fixture startup failed.
            cancelled.store(true, Ordering::Relaxed);
            let result = worker.join().unwrap().unwrap();
            assert!(was_ready, "collector did not signal readiness");
            result
        });

        assert!(report.unsuccessful);
        let document = manifest(&report.directory);
        assert_eq!(document["results"].as_array().unwrap().len(), 1);
        assert_failed(&document["results"][0]);
        assert_eq!(
            document["results"][0]["failure"],
            json!({"kind": "cancelled"})
        );
        assert_eq!(
            fs::read(report.directory.join("host.active.sbom.stderr.log")).unwrap(),
            b"running\n"
        );
        assert_eq!(
            entries(&report.directory),
            ["host.active.sbom.stderr.log", "manifest.json"]
        );
    }

    #[test]
    fn oversized_scan_stdout_persists_stream_and_limit_without_an_artifact() {
        let temporary = tempfile::tempdir().unwrap();
        let executable = script(
            temporary.path(),
            "oversized",
            "printf 'large output\\n' >&2\nhead -c 67108865 /dev/zero",
        );
        let config = command_config(&[("large", &executable)]);

        let report = execute(&config, &temporary.path().join("output"), false);

        assert!(report.unsuccessful);
        let document = manifest(&report.directory);
        assert_failed(&document["results"][0]);
        assert_eq!(
            document["results"][0]["failure"],
            json!({
                "kind": "output-limit", "stream": "stdout", "limit": 67_108_864,
            })
        );
        assert_eq!(
            fs::read(report.directory.join("host.large.sbom.stderr.log")).unwrap(),
            b"large output\n"
        );
        assert_eq!(
            entries(&report.directory),
            ["host.large.sbom.stderr.log", "manifest.json"]
        );
    }

    #[test]
    fn relative_certificate_target_and_dot_path_record_the_effective_absolute_target() {
        let cwd = std::env::current_dir().unwrap();
        let temporary = tempfile::tempdir_in(&cwd).unwrap();
        let certificates = temporary.path().join("certificates");
        fs::create_dir(&certificates).unwrap();
        fs::write(
            certificates.join("cert.pem"),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/native-ec.pem"
            )),
        )
        .unwrap();
        let relative = certificates.strip_prefix(&cwd).unwrap();
        let config = Config::parse(&json!({
            "version": 1, "output": {"directory": "unused"},
            "applications": [{"name": "app", "target": {"type": "directory", "path": relative.join(".")},
                "cbom": {"enabled": true, "backend": "certificates", "certificates": {"paths": ["."]}}}],
        }).to_string()).unwrap();

        let report = execute(&config, &temporary.path().join("output"), false);

        assert!(!report.unsuccessful);
        let document = manifest(&report.directory);
        let result = &document["results"][0];
        assert_eq!(result["status"], "collected");
        assert_eq!(result["findings"], 1);
        assert_eq!(result["target"], certificates.to_str().unwrap());
        assert!(result.get("failure").is_none());
        let bytes = fs::read(report.directory.join("app.cbom.cdx.json")).unwrap();
        Validator::new().unwrap().validate(&bytes, false).unwrap();
    }

    #[test]
    fn non_utf8_certificate_paths_and_refused_symlink_preserve_partial_then_success() {
        let temporary = tempfile::tempdir().unwrap();
        let certificates = temporary
            .path()
            .join(OsString::from_vec(b"certificates-\xff".to_vec()));
        fs::create_dir(&certificates).unwrap();
        let certificate = certificates.join(OsString::from_vec(b"cert-\xfe.pem".to_vec()));
        let refused = certificates.join(OsString::from_vec(b"refused-\xfd.pem".to_vec()));
        fs::write(
            &certificate,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/native-ec.pem"
            )),
        )
        .unwrap();
        symlink(&certificate, &refused).unwrap();
        let certificate_job = Job::new(
            Scope::Application {
                name: Name::new("certs".into()).unwrap(),
                version: None,
            },
            None,
            InventoryKind::Cbom,
            Target::Directory(certificates.clone()),
            Backend::Certificates {
                paths: vec![".".into()],
                max_file_bytes: 4 << 20,
                include_identity: false,
            },
        )
        .unwrap();
        let executable = script(temporary.path(), "next", &format!("printf '%s' '{BOM}'"));
        let next = command_config(&[("next", &executable)]);
        let jobs = [certificate_job, next.jobs[0].clone()];

        let report = Scan::new()
            .unwrap()
            .execute(
                &jobs,
                &temporary.path().join("output"),
                Duration::from_secs(10),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();

        assert!(report.unsuccessful);
        let document = manifest(&report.directory);
        let results = document["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        let partial = &results[0];
        assert_eq!(partial["status"], "partial");
        assert_eq!(partial["findings"], 1);
        assert_eq!(partial["coverage"], "declared-scope");
        assert!(partial.get("failure").is_none());
        assert_eq!(
            partial["target"],
            format!(
                "bommer:unix-bytes:{}",
                hex::encode(certificates.as_os_str().as_bytes())
            )
        );
        assert_eq!(
            partial["diagnostics"],
            json!([{
                "code": "symlink-refused", "path": format!("bommer:unix-bytes:{}", hex::encode(refused.as_os_str().as_bytes())),
            }])
        );

        let bytes = fs::read(report.directory.join("certs.cbom.cdx.json")).unwrap();
        let validated = Validator::new().unwrap().validate(&bytes, false).unwrap();
        assert_eq!(validated.component_count, 3);
        let sources = partial["evidence"]["sources"].as_object().unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(
            &sources["certificate:sha256:39f41ff9385a90df31a90fc6c0c686cf2343dea2f18cd058339a0d00a07a51cb"],
            &json!([format!(
                "bommer:unix-bytes:{}",
                hex::encode(certificate.as_os_str().as_bytes())
            )])
        );

        assert_eq!(results[1]["status"], "collected");
        assert_eq!(results[1]["target"], "dir:/");
        assert_eq!(
            fs::read(report.directory.join("host.next.sbom.cdx.json")).unwrap(),
            BOM.as_bytes()
        );
        assert_eq!(
            entries(&report.directory),
            [
                "certs.cbom.cdx.json",
                "certs.cbom.stderr.log",
                "host.next.sbom.cdx.json",
                "host.next.sbom.stderr.log",
                "manifest.json"
            ]
        );
    }

    #[test]
    fn prepared_git_exclusions_are_preserved_by_output_publication() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("repository");
        fs::create_dir(&target).unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["init", "--quiet"])
                .arg(&target)
                .status()
                .unwrap()
                .success()
        );
        fs::write(target.join(".gitignore"), "ignored.txt\n").unwrap();
        fs::write(target.join("ignored.txt"), "ignored fixture").unwrap();
        let config = Config::parse(&json!({
            "version": 1, "output": {"directory": "unused"},
            "applications": [{"name": "app", "target": {"type": "directory", "path": target},
                "sbom": {"enabled": true, "backend": "syft", "exclude": ["manual", "manual"], "respect_gitignore": true}}],
        }).to_string()).unwrap();
        let job = &config.jobs[0];
        let context =
            CollectionContext::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false)));

        let (_, arguments, exclusions, effective_target) =
            external::prepare(job, &context).unwrap();

        let expected = ["manual", "./.git", "./.git/**", "./ignored.txt"];
        assert_eq!(exclusions, expected);
        let argument_exclusions: Vec<_> = arguments
            .windows(2)
            .filter(|pair| pair[0] == "--exclude")
            .map(|pair| pair[1].to_str().unwrap())
            .collect();
        assert_eq!(argument_exclusions, expected);

        let output = RunOutput::create(&temporary.path().join("output")).unwrap();
        let mut candidate = output.candidate().unwrap();
        candidate.write_all(BOM.as_bytes()).unwrap();
        let artifact = output.publish(job, candidate, BOM.as_bytes()).unwrap();
        let outcome = CollectionOutcome {
            scope: ExecutionScope {
                target: Some(effective_target),
                exclusions: Some(exclusions),
            },
            ..CollectionOutcome::external()
        };
        let mut result = JobResult::pending(job).unwrap();
        result.complete(outcome, artifact, "1.6", 1, true);
        result.finish().unwrap();
        let mut checkpoint = Manifest::new();
        checkpoint.record(result);
        output.checkpoint(&checkpoint).unwrap();

        let document = manifest(output.directory());
        let result = &document["results"][0];
        assert_eq!(result["exclude"], json!(expected));
        assert_eq!(result["respectGitignore"], true);
        assert_eq!(result["target"], target.to_str().unwrap());
        assert_eq!(result["status"], "collected");
        assert!(result.get("failure").is_none());
    }

    // Public P-384 fixture from x509-parser's MIT/Apache-2.0 no_extensions.pem.
    const CERTIFICATE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/native-ec.pem"
    ));

    const IMPORT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/native-import.json"
    ));

    const APP: &str = "/nix/store/00000000000000000000000000000000-app-with-dashes-1.2-bin";

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

        assert_eq!(outcome.status, Status::Partial);
        assert_eq!(outcome.findings, 1);
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(outcome.diagnostics[0].code, DiagnosticCode::SymlinkRefused);

        let source_text = format!(
            "bommer:unix-bytes:{}",
            hex::encode(certificate_path.as_os_str().as_bytes())
        );
        let link_text = format!(
            "bommer:unix-bytes:{}",
            hex::encode(link_path.as_os_str().as_bytes())
        );
        let diagnostics = serde_json::to_value(&outcome.diagnostics).unwrap();
        assert_eq!(diagnostics[0]["path"], link_text);
        assert_eq!(
            outcome.evidence["sources"]["certificate:sha256:39f41ff9385a90df31a90fc6c0c686cf2343dea2f18cd058339a0d00a07a51cb"],
            json!([source_text])
        );
        assert_eq!(
            Validator::new()
                .unwrap()
                .validate(&output, false)
                .unwrap()
                .component_count,
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

        assert!(report.unsuccessful);
        let manifest: Value =
            serde_json::from_slice(&fs::read(report.directory.join("manifest.json")).unwrap())
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

            assert_eq!(outcome.status, Status::Collected);
            assert_eq!(outcome.findings, 1);
            let summary = Validator::new().unwrap().validate(&output, false).unwrap();
            assert_eq!(summary.component_count, 3);
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

            assert!(!report.unsuccessful);
            let manifest: Value =
                serde_json::from_slice(&fs::read(report.directory.join("manifest.json")).unwrap())
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

        assert_eq!(outcome.status, Status::Partial);
        assert_eq!(outcome.findings, 0);
        assert_eq!(outcome.diagnostics[0].code, DiagnosticCode::SymlinkRefused);
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

        assert!(!report.unsuccessful);
        let manifest: Value =
            serde_json::from_slice(&fs::read(report.directory.join("manifest.json")).unwrap())
                .unwrap();
        assert!(manifest["results"][0].get("target").is_none());
        assert_eq!(manifest["results"][0]["findings"], 1);
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
            Err(certificates::error::CertificateError::Interrupted(
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
            matches!(certificates::collect(&job, &context(), &mut Broken), Err(certificates::error::CertificateError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
    }
}
