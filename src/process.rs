use std::ffi::OsString;
use std::num::NonZeroUsize;
use std::time::Duration;

#[derive(Debug)]
pub(crate) struct ProcessPolicy {
    timeout: Duration,
    stdout_limit: NonZeroUsize,
    stderr_limit: NonZeroUsize,
}

#[derive(Debug)]
pub(crate) enum ProcessError {
    Spawn {
        executable: OsString,
        source: std::io::Error,
    },
    Exit {
        code: Option<i32>,
    },
    Timeout,
    Cancelled,
    OutputLimit {
        stream: Stream,
        limit: usize,
    },
    Io(std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
}
