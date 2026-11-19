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
