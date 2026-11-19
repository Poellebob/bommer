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
