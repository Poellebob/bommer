use std::fs::File;
use std::path::PathBuf;

use crate::model::{Coverage, Diagnostic, Status};

#[derive(Debug)]
pub(crate) struct RunOutput {
    lock: File,
    directory: PathBuf,
}

#[derive(Debug)]
pub(crate) struct PublishedArtifact {
    path: PathBuf,
    sha256: [u8; 32],
}

#[derive(Debug)]
pub(crate) struct JobResult {
    status: Status,
    coverage: Coverage,
    diagnostics: Vec<Diagnostic>,
    artifact: Option<PublishedArtifact>,
}

#[derive(Debug)]
pub(crate) struct Manifest {
    results: Vec<JobResult>,
}

#[derive(Debug)]
pub(crate) enum OutputError {
    Locked {
        directory: PathBuf,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}
