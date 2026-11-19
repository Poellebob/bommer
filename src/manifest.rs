use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::collection::failure::Failure;
use crate::collection::outcome::{CollectionOutcome, Coverage, Diagnostic, ExecutionScope, Status};
use crate::job::{Backend, Job};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ManifestError {
    #[error("cannot format timestamp")]
    Timestamp(#[from] time::error::Format),
}

#[derive(Debug)]
pub(crate) struct ArtifactRecord {
    pub(crate) name: String,
    pub(crate) sha256: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct JobResult {
    name: String,
    kind: crate::job::InventoryKind,
    #[serde(skip_serializing_if = "String::is_empty")]
    target: String,
    #[serde(rename = "sourceVersion", skip_serializing_if = "Option::is_none")]
    source_version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    exclude: Vec<String>,
    #[serde(
        rename = "respectGitignore",
        skip_serializing_if = "std::ops::Not::not"
    )]
    respect_gitignore: bool,
    backend: String,
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact: Option<String>,
    #[serde(rename = "sha256", skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<Failure>,
    started: String,
    finished: String,
    scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory: Option<String>,
    #[serde(rename = "specVersion", skip_serializing_if = "Option::is_none")]
    spec_version: Option<String>,
    findings: usize,
    #[serde(rename = "collectorVersion", skip_serializing_if = "Option::is_none")]
    collector_version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    evidence: serde_json::Value,
    coverage: Coverage,
}

#[derive(Debug, Serialize)]
pub(crate) struct Manifest {
    version: u8,
    #[serde(rename = "bommerVersion")]
    bommer_version: String,
    validation: &'static str,
    results: Vec<JobResult>,
}

impl JobResult {
    pub(crate) fn pending(job: &Job) -> Result<Self, ManifestError> {
        let (exclude, respect_gitignore) = match &job.backend {
            Backend::Syft {
                exclusions,
                respect_gitignore,
            } => (exclusions.clone(), *respect_gitignore),
            _ => (vec![], false),
        };

        Ok(Self {
            name: job.scope.name().into(),
            kind: job.kind,
            target: job.target.display(),
            source_version: job.scope.version().map(Into::into),
            exclude,
            respect_gitignore,
            backend: job.backend.name().into(),
            status: Status::Failed,
            artifact: None,
            digest: None,
            error: None,
            failure: None,
            started: timestamp()?,
            finished: String::new(),
            scope: if job.scope.is_host() {
                "host"
            } else {
                "application"
            },
            inventory: job.inventory.as_ref().map(|name| name.as_str().into()),
            spec_version: None,
            findings: 0,
            collector_version: None,
            diagnostics: vec![],
            evidence: serde_json::Value::Null,
            coverage: Coverage::Unknown,
        })
    }

    fn observed_scope(&mut self, scope: ExecutionScope) {
        if let Some(exclusions) = scope.exclusions {
            self.exclude = exclusions;
        }
        if let Some(target) = scope.target {
            self.target = target;
        }
    }

    pub(crate) fn collected(&mut self, outcome: &mut CollectionOutcome) {
        self.observed_scope(std::mem::take(&mut outcome.scope));
    }

    pub(crate) fn complete(
        &mut self,
        mut outcome: CollectionOutcome,
        artifact: ArtifactRecord,
        spec_version: &str,
        count: usize,
        external: bool,
    ) {
        self.collected(&mut outcome);
        self.status = outcome.status;
        self.coverage = outcome.coverage;
        self.findings = if external { count } else { outcome.findings };
        self.diagnostics = outcome.diagnostics;
        self.collector_version = outcome.collector_version;
        self.evidence = outcome.evidence;
        self.artifact = Some(artifact.name);
        self.digest = Some(artifact.sha256);
        self.spec_version = Some(spec_version.into());
    }

    pub(crate) fn fail(
        &mut self,
        error: &dyn std::fmt::Display,
        failure: Failure,
        scope: ExecutionScope,
    ) {
        self.observed_scope(scope);
        self.error = Some(error.to_string());
        self.failure = Some(failure);
    }

    pub(crate) fn finish(&mut self) -> Result<(), ManifestError> {
        self.finished = timestamp()?;
        Ok(())
    }

    pub(crate) fn is_unsuccessful(&self) -> bool {
        matches!(self.status, Status::Failed | Status::Partial)
    }
}

impl Manifest {
    pub(crate) fn new() -> Self {
        Self {
            version: 2,
            bommer_version: env!("CARGO_PKG_VERSION").into(),
            validation: "json-schema-offline",
            results: vec![],
        }
    }

    pub(crate) fn record(&mut self, result: JobResult) {
        self.results.push(result);
    }

    pub(crate) fn is_unsuccessful(&self) -> bool {
        self.results.iter().any(JobResult::is_unsuccessful)
    }
}

fn timestamp() -> Result<String, ManifestError> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    use crate::collection::failure::{Failure, FailureKind};
    use crate::collection::outcome::{
        CollectionOutcome, Coverage, Diagnostic, DiagnosticCode, ExecutionScope,
    };
    use crate::job::{Backend, InventoryKind, Job, Name, Scope, Target};
    use crate::manifest::{ArtifactRecord, JobResult, Manifest};

    fn job() -> Job {
        Job::new(
            Scope::Application {
                name: Name::new("app".into()).unwrap(),
                version: Some("2.0".into()),
            },
            None,
            InventoryKind::Sbom,
            Target::Directory("/app".into()),
            Backend::Syft {
                exclusions: vec!["manual".into()],
                respect_gitignore: true,
            },
        )
        .unwrap()
    }

    fn artifact() -> ArtifactRecord {
        ArtifactRecord {
            name: "app.sbom.cdx.json".into(),
            sha256: "digest".into(),
        }
    }

    fn document(result: &JobResult) -> Value {
        serde_json::to_value(result).unwrap()
    }

    #[test]
    fn initial_manifest_and_pending_result_preserve_exact_wire_fields() {
        let manifest = Manifest::new();
        assert!(!manifest.is_unsuccessful());
        assert_eq!(
            serde_json::to_value(&manifest).unwrap(),
            json!({
                "version": 2, "bommerVersion": env!("CARGO_PKG_VERSION"),
                "validation": "json-schema-offline", "results": [],
            })
        );
        let result = JobResult::pending(&job()).unwrap();
        assert!(result.is_unsuccessful());
        let mut value = document(&result);
        OffsetDateTime::parse(value["started"].as_str().unwrap(), &Rfc3339).unwrap();
        value.as_object_mut().unwrap().remove("started");
        assert_eq!(
            value,
            json!({
                "name": "app", "kind": "sbom", "target": "/app", "sourceVersion": "2.0",
                "exclude": ["manual"], "respectGitignore": true, "backend": "syft",
                "status": "failed", "finished": "", "scope": "application",
                "findings": 0, "coverage": "unknown",
            })
        );
    }

    #[test]
    fn completion_moves_outcome_metadata_and_uses_validated_external_count() {
        let mut result = JobResult::pending(&job()).unwrap();
        let outcome = CollectionOutcome {
            collector_version: Some("syft/1".into()),
            evidence: json!({"source": "fixture"}),
            scope: ExecutionScope {
                target: Some("/effective".into()),
                exclusions: Some(vec!["observed".into()]),
            },
            ..CollectionOutcome::external()
        };
        result.complete(outcome, artifact(), "1.6", 7, true);
        result.finish().unwrap();
        assert!(!result.is_unsuccessful());
        let mut value = document(&result);
        for key in ["started", "finished"] {
            OffsetDateTime::parse(value[key].as_str().unwrap(), &Rfc3339).unwrap();
            value.as_object_mut().unwrap().remove(key);
        }
        assert_eq!(
            value,
            json!({
                "name": "app", "kind": "sbom", "target": "/effective", "sourceVersion": "2.0",
                "exclude": ["observed"], "respectGitignore": true, "backend": "syft",
                "status": "collected", "artifact": "app.sbom.cdx.json", "sha256": "digest",
                "scope": "application", "specVersion": "1.6", "findings": 7,
                "collectorVersion": "syft/1", "evidence": {"source": "fixture"}, "coverage": "unknown",
            })
        );
        let mut manifest = Manifest::new();
        manifest.record(result);
        assert!(!manifest.is_unsuccessful());
    }

    #[test]
    fn partial_completion_keeps_native_findings_diagnostics_and_coverage() {
        let mut result = JobResult::pending(&job()).unwrap();
        result.complete(
            CollectionOutcome::observed(
                2,
                Coverage::DeclaredScope,
                vec![Diagnostic::new(
                    DiagnosticCode::MissingPath,
                    Some("/missing".into()),
                )],
                json!({"sources": []}),
                Some("native/1".into()),
            ),
            artifact(),
            "1.6",
            9,
            false,
        );
        let value = document(&result);
        assert_eq!(value["status"], "partial");
        assert_eq!(value["findings"], 2);
        assert_eq!(value["coverage"], "declared-scope");
        assert_eq!(
            value["diagnostics"],
            json!([{"code": "missing-path", "path": "/missing"}])
        );
        assert_eq!(value["collectorVersion"], "native/1");
        assert_eq!(value["evidence"], json!({"sources": []}));
        assert_eq!(value["artifact"], "app.sbom.cdx.json");
        assert!(value.get("failure").is_none());
        assert!(value.get("error").is_none());
        assert!(result.is_unsuccessful());
        let mut manifest = Manifest::new();
        manifest.record(result);
        assert!(manifest.is_unsuccessful());
    }

    #[test]
    fn validation_failure_retains_observed_scope_without_success_metadata() {
        let mut result = JobResult::pending(&job()).unwrap();
        let mut outcome = CollectionOutcome {
            scope: ExecutionScope {
                target: Some("/observed".into()),
                exclusions: Some(vec!["effective".into()]),
            },
            ..CollectionOutcome::observed(
                3,
                Coverage::DeclaredScope,
                vec![],
                json!({"not": "published"}),
                Some("collector/1".into()),
            )
        };
        result.collected(&mut outcome);
        assert!(outcome.scope.target.is_none());
        assert!(outcome.scope.exclusions.is_none());
        result.fail(
            &"invalid artifact",
            Failure::new(FailureKind::Validation),
            ExecutionScope::default(),
        );
        result.finish().unwrap();
        let value = document(&result);
        assert_eq!(value["target"], "/observed");
        assert_eq!(value["exclude"], json!(["effective"]));
        assert_eq!(value["error"], "invalid artifact");
        assert_eq!(value["failure"], json!({"kind": "validation"}));
        assert_eq!(value["status"], "failed");
        assert_eq!(value["coverage"], "unknown");
        assert_eq!(value["findings"], 0);
        for key in [
            "artifact",
            "sha256",
            "specVersion",
            "collectorVersion",
            "evidence",
            "diagnostics",
        ] {
            assert!(value.get(key).is_none(), "unexpected field {key}");
        }
        let mut manifest = Manifest::new();
        manifest.record(result);
        assert!(manifest.is_unsuccessful());
    }

    #[test]
    fn collection_failure_records_effective_scope_and_structured_failure() {
        let mut result = JobResult::pending(&job()).unwrap();
        result.fail(
            &"collector failed",
            Failure::new(FailureKind::Collection),
            ExecutionScope {
                target: Some("/prepared".into()),
                exclusions: Some(vec!["prepared".into()]),
            },
        );
        let value = document(&result);
        assert_eq!(value["target"], "/prepared");
        assert_eq!(value["exclude"], json!(["prepared"]));
        assert_eq!(value["failure"], json!({"kind": "collection"}));
        assert_eq!(value["error"], "collector failed");
        assert!(result.is_unsuccessful());
    }

    #[test]
    fn observed_scope_distinguishes_absent_and_explicitly_empty_values() {
        let mut result = JobResult::pending(&job()).unwrap();
        result.collected(&mut CollectionOutcome::external());
        let value = document(&result);
        assert_eq!(value["target"], "/app");
        assert_eq!(value["exclude"], json!(["manual"]));
        result.collected(&mut CollectionOutcome {
            scope: ExecutionScope {
                target: Some(String::new()),
                exclusions: Some(vec![]),
            },
            ..CollectionOutcome::external()
        });
        let value = document(&result);
        assert!(value.get("target").is_none());
        assert!(value.get("exclude").is_none());
    }

    #[test]
    fn host_no_findings_omits_optional_fields_and_is_successful() {
        let job = Job::new(
            Scope::Host,
            Some(Name::new("hardware".into()).unwrap()),
            InventoryKind::Hbom,
            Target::Host,
            Backend::Hbom,
        )
        .unwrap();
        let mut result = JobResult::pending(&job).unwrap();
        result.complete(
            CollectionOutcome::observed(0, Coverage::Unknown, vec![], Value::Null, None),
            artifact(),
            "1.6",
            0,
            false,
        );
        let mut value = document(&result);
        value.as_object_mut().unwrap().remove("started");
        assert_eq!(
            value,
            json!({
                "name": "host", "kind": "hbom", "backend": "hbom", "status": "no-findings",
                "artifact": "app.sbom.cdx.json", "sha256": "digest", "finished": "",
                "scope": "host", "inventory": "hardware", "specVersion": "1.6",
                "findings": 0, "coverage": "unknown",
            })
        );
        assert!(!result.is_unsuccessful());
    }
}
