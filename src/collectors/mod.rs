pub(crate) mod certificates;
pub(crate) mod external;
pub(crate) mod import;
pub(crate) mod nix;

use crate::model::{
    Backend, CollectionContext, CollectionOutcome, Failure, FailureKind, Interrupted, Job,
};
use crate::process::{ProcessError, Stream};
use std::io::Write;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CollectionError {
    #[error(transparent)]
    External(#[from] external::ExternalError),
    #[error(transparent)]
    Nix(#[from] nix::NixError),
    #[error(transparent)]
    Certificates(#[from] certificates::CertificateError),
    #[error(transparent)]
    Import(#[from] import::ImportError),
    #[error(transparent)]
    Interrupted(#[from] Interrupted),
}

impl CollectionError {
    pub(crate) fn execution_scope(&self) -> Option<(&str, &[String])> {
        match self {
            Self::External(external::ExternalError::Execution {
                target, exclusions, ..
            }) => Some((target, exclusions)),
            _ => None,
        }
    }
    pub(crate) fn details(&self) -> Failure {
        let interruption = match self {
            Self::Interrupted(error)
            | Self::Nix(nix::NixError::Interrupted(error))
            | Self::Certificates(certificates::CertificateError::Interrupted(error))
            | Self::Import(import::ImportError::Interrupted(error)) => Some(error),
            _ => None,
        };
        if let Some(error) = interruption {
            return Failure::new(match error {
                Interrupted::Cancelled => FailureKind::Cancelled,
                Interrupted::Timeout => FailureKind::Timeout,
            });
        }
        // Classify sources, not Display strings; raw collector stderr never enters this path.
        let mut error: &(dyn std::error::Error + 'static) = self;
        loop {
            if let Some(error) = error.downcast_ref::<ProcessError>() {
                return match error {
                    ProcessError::Cancelled => Failure::new(FailureKind::Cancelled),
                    ProcessError::Timeout => Failure::new(FailureKind::Timeout),
                    ProcessError::Exit { code } => Failure::exited(*code),
                    ProcessError::OutputLimit { stream, limit } => Failure::limited(
                        match stream {
                            Stream::Stdout => "stdout",
                            Stream::Stderr => "stderr",
                        },
                        *limit,
                    ),
                    ProcessError::Spawn { .. } | ProcessError::MissingExecutable { .. } => {
                        Failure::new(FailureKind::Spawn)
                    }
                    ProcessError::Io(_) => Failure::new(FailureKind::Io),
                };
            }
            if let Some(error) = error.downcast_ref::<Interrupted>() {
                return Failure::new(match error {
                    Interrupted::Cancelled => FailureKind::Cancelled,
                    Interrupted::Timeout => FailureKind::Timeout,
                });
            }
            if error.is::<std::io::Error>() {
                return Failure::new(FailureKind::Io);
            }
            match error.source() {
                Some(source) => error = source,
                None => return Failure::new(FailureKind::Collection),
            }
        }
    }
}

pub(crate) fn check(job: &Job) -> Result<(), CollectionError> {
    match job.backend() {
        Backend::Nix { .. } => nix::check(job).map_err(Into::into),
        Backend::Certificates { .. } => certificates::check(job).map_err(Into::into),
        Backend::Import { .. } => import::check(job).map_err(Into::into),
        _ => external::check(job).map_err(Into::into),
    }
}

pub(crate) fn collect(
    job: &Job,
    context: &CollectionContext,
    output: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<CollectionOutcome, CollectionError> {
    context.check()?;
    match job.backend() {
        Backend::Nix { .. } => nix::collect(job, context, output).map_err(Into::into),
        Backend::Certificates { .. } => {
            certificates::collect(job, context, output).map_err(Into::into)
        }
        Backend::Import { .. } => import::collect(job, context, output).map_err(Into::into),
        _ => external::collect(job, context, output, stderr).map_err(Into::into),
    }
}
