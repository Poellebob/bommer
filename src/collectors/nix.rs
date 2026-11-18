use crate::process::ProcessError;

#[derive(Debug)]
pub(crate) enum NixError {
    InvalidRoot { path: std::path::PathBuf },
    Process(ProcessError),
    InvalidMetadata,
    IncompleteClosure { missing: std::path::PathBuf },
}
