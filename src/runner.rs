use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;

use crate::bom::{ValidationError, Validator};
use crate::collectors::{self, CollectionError};
use crate::model::{CollectionContext, Failure, FailureKind, Interrupted, Job, Status};
use crate::output::{JobResult, Manifest, OutputError, RunOutput};

#[derive(Debug, thiserror::Error)]
pub(crate) enum RunError {
    #[error(transparent)]
    Output(#[from] OutputError),
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

#[derive(Debug)]
pub(crate) struct RunReport {
    directory: PathBuf,
    unsuccessful: bool,
}

impl RunReport {
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }
    pub(crate) fn is_unsuccessful(&self) -> bool {
        self.unsuccessful
    }
}

pub(crate) struct Runner {
    validator: Validator,
}

pub(crate) struct Readiness {
    name: String,
    result: Result<(), CollectionError>,
}

impl Readiness {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn result(&self) -> &Result<(), CollectionError> {
        &self.result
    }
}

pub(crate) struct DoctorReport {
    results: Vec<Readiness>,
}

impl DoctorReport {
    pub(crate) fn check(jobs: &[Job]) -> Self {
        Self {
            results: jobs
                .iter()
                .map(|job| Readiness {
                    name: job.stem(),
                    result: collectors::check(job),
                })
                .collect(),
        }
    }
    pub(crate) fn results(&self) -> &[Readiness] {
        &self.results
    }
    pub(crate) fn is_unsuccessful(&self) -> bool {
        self.results.iter().any(|result| result.result.is_err())
    }
}

impl Runner {
    pub(crate) fn new() -> Result<Self, RunError> {
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
    ) -> Result<RunReport, RunError> {
        let output = RunOutput::create(root)?;
        let mut manifest = Manifest::new();
        output.checkpoint(&manifest)?;
        for job in jobs {
            let mut result = JobResult::pending(job)?;
            let context = CollectionContext::new(timeout, Arc::clone(&cancelled));
            let mut candidate = output.candidate()?;
            let mut stderr = output.log(job)?;
            let collected = (|| -> Result<_, JobFailure> {
                let outcome = collectors::collect(job, &context, &mut candidate, &mut stderr)?;
                result.observed_scope(&outcome);
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
                let summary = self
                    .validator
                    .validate(&bytes, !job.backend().is_native())?;
                if summary.component_count() == 0 && outcome.status() == Status::Collected {
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
                        summary.spec_version(),
                        summary.component_count(),
                        !job.backend().is_native(),
                    );
                }
                Err(error) => {
                    if let JobFailure::Collection(error) = &error
                        && let Some((target, exclusions)) = error.execution_scope()
                    {
                        result.execution_scope(target, exclusions);
                    }
                    result.fail(&error, error.details());
                }
            }
            result.finish()?;
            manifest.record(result);
            output.checkpoint(&manifest)?;
        }
        Ok(RunReport {
            directory: output.directory().into(),
            unsuccessful: manifest.is_unsuccessful(),
        })
    }
}
