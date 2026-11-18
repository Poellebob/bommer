use crate::process::ProcessError;

#[derive(Debug)]
pub(crate) enum ExternalError {
    MissingExecutable { executable: std::ffi::OsString },
    Process(ProcessError),
    UnsupportedTarget,
}
