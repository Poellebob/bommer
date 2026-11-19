use std::io;
use std::path::PathBuf;

use thiserror::Error;

use crate::collection_context::Interrupted;

#[derive(Debug, Error)]
pub(crate) enum CertificateError {
    #[error("invalid certificate options")]
    Options,
    #[error("invalid certificate application target")]
    InvalidTarget { path: PathBuf },
    #[error(transparent)]
    Interrupted(#[from] Interrupted),
    #[error("certificate inventory I/O failed")]
    Io(#[from] io::Error),
}
