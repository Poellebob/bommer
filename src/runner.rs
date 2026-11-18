#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunStatus {
    Complete,
    Incomplete,
    Cancelled,
}

#[derive(Debug)]
pub(crate) struct RunReport {
    directory: std::path::PathBuf,
    status: RunStatus,
}

// Execution will compose collectors, validation, and publication here.
