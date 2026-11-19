use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempDir};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::model::{Backend, CollectionOutcome, Coverage, Diagnostic, Failure, Job, Status};

#[derive(Debug, thiserror::Error)]
pub(crate) enum OutputError {
    #[error("another scan holds the output lock")]
    Locked,
    #[error("output I/O failed")]
    Io(#[from] io::Error),

    #[error("cannot serialize manifest")]
    Serialize(#[from] serde_json::Error),
    #[error("cannot format timestamp")]
    Timestamp(#[from] time::error::Format),
}

pub(crate) fn timestamp() -> Result<String, OutputError> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

pub(crate) struct RunOutput {
    _lock: File,
    directory: PathBuf,
}

impl RunOutput {
    pub(crate) fn create(root: &Path) -> Result<Self, OutputError> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)?;

        // Refuse a leaf symlink instead of locking an attacker-selected file.
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(root.join(".lock"))?;
        match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => return Err(OutputError::Locked),
            Err(error) => return Err(OutputError::Io(error.into())),
        }

        let prefix = OffsetDateTime::now_utc().format(time::macros::format_description!(
            "[year][month][day]T[hour][minute][second]Z-"
        ))?;
        let directory = tempfile::Builder::new().prefix(&prefix).tempdir_in(root)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;

        // Keep even an interrupted run for inspection. Individual temporary artifacts are RAII-owned.
        let directory = TempDir::keep(directory);

        Ok(Self {
            _lock: lock,
            directory,
        })
    }

    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn candidate(&self) -> Result<NamedTempFile, OutputError> {
        Ok(tempfile::Builder::new()
            .prefix(".bom-")
            .tempfile_in(&self.directory)?)
    }

    pub(crate) fn log(&self, job: &Job) -> Result<File, OutputError> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.directory.join(format!("{}.stderr.log", job.stem())))?)
    }

    pub(crate) fn publish(
        &self,
        job: &Job,
        mut candidate: NamedTempFile,
        bytes: &[u8],
    ) -> Result<PublishedArtifact, OutputError> {
        candidate.flush()?;
        candidate.as_file().sync_all()?;

        let name = format!("{}.cdx.json", job.stem());
        let sha256 = hex::encode(Sha256::digest(bytes));
        candidate
            .persist_noclobber(self.directory.join(&name))
            .map_err(|error| error.error)?;

        Ok(PublishedArtifact { name, sha256 })
    }

    pub(crate) fn checkpoint(&self, manifest: &Manifest) -> Result<(), OutputError> {
        let mut temporary = tempfile::Builder::new()
            .prefix(".manifest-")
            .tempfile_in(&self.directory)?;
        serde_json::to_writer_pretty(&mut temporary, manifest)?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;

        temporary
            .persist(self.directory.join("manifest.json"))
            .map_err(|error| error.error)?;
        File::open(&self.directory)?.sync_all()?;

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct PublishedArtifact {
    name: String,
    sha256: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct JobResult {
    name: String,
    kind: crate::model::InventoryKind,
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

impl JobResult {
    pub(crate) fn pending(job: &Job) -> Result<Self, OutputError> {
        let (exclude, respect_gitignore) = match job.backend() {
            Backend::Syft {
                exclusions,
                respect_gitignore,
            } => (exclusions.clone(), *respect_gitignore),
            _ => (vec![], false),
        };

        Ok(Self {
            name: job.scope().name().into(),
            kind: job.kind(),
            target: job.target().display(),
            source_version: job.scope().version().map(Into::into),
            exclude,
            respect_gitignore,
            backend: job.backend().name().into(),
            status: Status::Failed,
            artifact: None,
            digest: None,
            error: None,
            failure: None,
            started: timestamp()?,
            finished: String::new(),
            scope: if job.scope().is_host() {
                "host"
            } else {
                "application"
            },
            inventory: job.inventory().map(|name| name.as_str().into()),
            spec_version: None,
            findings: 0,
            collector_version: None,
            diagnostics: vec![],
            evidence: serde_json::Value::Null,
            coverage: Coverage::Unknown,
        })
    }

    pub(crate) fn complete(
        &mut self,
        outcome: CollectionOutcome,
        artifact: PublishedArtifact,
        spec_version: &str,
        count: usize,
        external: bool,
    ) {
        self.status = outcome.status();
        self.coverage = outcome.coverage();
        self.findings = if external { count } else { outcome.findings() };
        self.diagnostics = outcome.diagnostics().to_vec();
        self.collector_version = outcome.collector_version().map(Into::into);
        self.evidence = outcome.evidence().clone();
        self.observed_scope(&outcome);

        self.artifact = Some(artifact.name);
        self.digest = Some(artifact.sha256);
        self.spec_version = Some(spec_version.into());
    }

    pub(crate) fn fail(&mut self, error: &dyn std::fmt::Display, failure: Failure) {
        self.error = Some(error.to_string());
        self.failure = Some(failure);
    }

    pub(crate) fn execution_scope(&mut self, target: &str, exclusions: &[String]) {
        self.target = target.into();
        self.exclude = exclusions.to_vec();
    }

    pub(crate) fn observed_scope(&mut self, outcome: &CollectionOutcome) {
        if let Some(exclusions) = outcome.exclusions() {
            self.exclude = exclusions.to_vec();
        }

        if let Some(target) = outcome.target() {
            self.target = target.into();
        }
    }

    pub(crate) fn finish(&mut self) -> Result<(), OutputError> {
        self.finished = timestamp()?;
        Ok(())
    }

    pub(crate) fn is_unsuccessful(&self) -> bool {
        matches!(self.status, Status::Failed | Status::Partial)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Manifest {
    version: u8,
    #[serde(rename = "bommerVersion")]
    bommer_version: String,
    validation: &'static str,
    results: Vec<JobResult>,
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
