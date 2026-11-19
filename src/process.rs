use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::fs::{Access, OFlags, access, fcntl_getfl, fcntl_setfl};
use rustix::process::{Pid, Signal, kill_process_group};
use thiserror::Error;

const BOM_LIMIT: usize = 64 << 20;
const LOG_LIMIT: usize = 1 << 20;

#[derive(Debug, Clone)]
pub(crate) struct CommandSpec {
    executable: OsString,
    arguments: Vec<OsString>,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub(crate) enum CommandError {
    #[error("command requires an executable")]
    EmptyExecutable,
}

#[derive(Debug, Error)]
pub(crate) enum ProcessError {
    #[error("cannot execute {executable:?}")]
    Spawn {
        executable: OsString,
        #[source]
        source: io::Error,
    },
    #[error("executable not found: {executable:?}")]
    MissingExecutable { executable: OsString },

    #[error("process exited unsuccessfully ({code:?})")]
    Exit { code: Option<i32> },
    #[error("process timed out")]
    Timeout,
    #[error("process cancelled")]
    Cancelled,
    #[error("{stream:?} exceeded {limit} bytes")]
    OutputLimit { stream: Stream, limit: usize },

    #[error("process I/O failed")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
}

#[derive(Debug, Default)]
pub(crate) struct ProcessOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

// Keep the group identity even after the direct child has been reaped: descendants
// can still hold our pipes open. Drop also covers errors and unwinding.
struct ProcessGuard {
    child: Child,
    group: Pid,
}

pub(crate) struct Process;

impl CommandSpec {
    pub(crate) fn new(
        executable: OsString,
        arguments: Vec<OsString>,
    ) -> Result<Self, CommandError> {
        if executable.is_empty() {
            return Err(CommandError::EmptyExecutable);
        }

        Ok(Self {
            executable,
            arguments,
        })
    }

    pub(crate) fn executable(&self) -> &OsStr {
        &self.executable
    }

    pub(crate) fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
}

impl ProcessOutput {
    pub(crate) fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub(crate) fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = kill_process_group(self.group, Signal::KILL);
        let _ = self.child.wait();
    }
}

impl Process {
    pub(crate) fn find_executable(executable: &OsStr) -> Result<PathBuf, ProcessError> {
        let valid = |path: &PathBuf| path.is_file() && access(path, Access::EXEC_OK).is_ok();
        if executable.as_encoded_bytes().contains(&b'/') {
            let path = PathBuf::from(executable);
            if valid(&path) {
                return Ok(path);
            }
        } else if !executable.is_empty()
            && let Some(paths) = std::env::var_os("PATH")
        {
            for directory in std::env::split_paths(&paths) {
                let path = directory.join(executable);
                if valid(&path) {
                    return Ok(path);
                }
            }
        }

        Err(ProcessError::MissingExecutable {
            executable: executable.to_owned(),
        })
    }

    pub(crate) fn capture(
        executable: &OsStr,
        arguments: &[OsString],
        deadline: Instant,
        cancelled: &AtomicBool,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> Result<ProcessOutput, ProcessError> {
        let mut output = ProcessOutput::default();
        Self::capture_into(
            executable,
            arguments,
            deadline,
            cancelled,
            stdout_limit,
            stderr_limit,
            &mut output,
        )?;

        Ok(output)
    }

    fn capture_into(
        executable: &OsStr,
        arguments: &[OsString],
        deadline: Instant,
        cancelled: &AtomicBool,
        stdout_limit: usize,
        stderr_limit: usize,
        output: &mut ProcessOutput,
    ) -> Result<(), ProcessError> {
        check_interruption(deadline, cancelled)?;

        let child = Command::new(executable)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|source| ProcessError::Spawn {
                executable: executable.to_owned(),
                source,
            })?;
        let group = Pid::from_raw(child.id() as i32).expect("child has a positive PID");
        let mut guard = ProcessGuard { child, group };

        let mut stdout = guard.child.stdout.take().expect("stdout is piped");
        let mut stderr = guard.child.stderr.take().expect("stderr is piped");
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        let (mut stdout_done, mut stderr_done) = (false, false);
        let mut status = None;

        let result = (|| loop {
            check_interruption(deadline, cancelled)?;

            let mut progress = false;
            if !stdout_done {
                progress |= drain(
                    &mut stdout,
                    &mut output.stdout,
                    stdout_limit,
                    Stream::Stdout,
                    &mut stdout_done,
                )?;
            }
            if !stderr_done {
                progress |= drain(
                    &mut stderr,
                    &mut output.stderr,
                    stderr_limit,
                    Stream::Stderr,
                    &mut stderr_done,
                )?;
            }

            if status.is_none() {
                status = guard.child.try_wait()?;
            }
            if let Some(status) = status
                && stdout_done
                && stderr_done
            {
                return if status.success() {
                    Ok(())
                } else {
                    Err(ProcessError::Exit {
                        code: status.code(),
                    })
                };
            }

            if !progress {
                std::thread::sleep(Duration::from_millis(5));
            }
        })();

        if result.is_err() {
            // Stop writers before draining diagnostics already queued at cancellation.
            // Nonblocking reads also bound cleanup if a detached descendant holds a pipe.
            drop(guard);
            while !stderr_done {
                match drain(
                    &mut stderr,
                    &mut output.stderr,
                    stderr_limit,
                    Stream::Stderr,
                    &mut stderr_done,
                ) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => break,
                }
            }
        }

        result
    }

    pub(crate) fn stream(
        executable: &OsStr,
        arguments: &[OsString],
        deadline: Instant,
        cancelled: &AtomicBool,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
    ) -> Result<(), ProcessError> {
        // Writers need not be Send. Capture is bounded and the group is cleaned
        // up before either caller-owned writer can fail or panic.
        let mut output = ProcessOutput::default();
        let result = Self::capture_into(
            executable,
            arguments,
            deadline,
            cancelled,
            BOM_LIMIT,
            LOG_LIMIT,
            &mut output,
        );

        let log_result = stderr.write_all(output.stderr());
        // Preserve the process failure even if its diagnostic writer also fails.
        result?;
        log_result?;

        check_interruption(deadline, cancelled)?;
        stdout.write_all(output.stdout())?;

        Ok(())
    }
}

fn check_interruption(deadline: Instant, cancelled: &AtomicBool) -> Result<(), ProcessError> {
    if cancelled.load(Ordering::Relaxed) {
        Err(ProcessError::Cancelled)
    } else if Instant::now() >= deadline {
        Err(ProcessError::Timeout)
    } else {
        Ok(())
    }
}

fn nonblocking(pipe: &impl AsFd) -> io::Result<()> {
    let flags = fcntl_getfl(pipe)?;
    fcntl_setfl(pipe, flags | OFlags::NONBLOCK)?;
    Ok(())
}

fn drain(
    pipe: &mut impl Read,
    output: &mut Vec<u8>,
    limit: usize,
    stream: Stream,
    done: &mut bool,
) -> Result<bool, ProcessError> {
    let mut buffer = [0; 16 * 1024];
    match pipe.read(&mut buffer) {
        Ok(0) => {
            *done = true;
            Ok(true)
        }
        Ok(count) => {
            let remaining = limit.saturating_sub(output.len());
            output.extend_from_slice(&buffer[..count.min(remaining)]);
            if count > remaining {
                return Err(ProcessError::OutputLimit { stream, limit });
            }

            Ok(true)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(ProcessError::Io(error)),
    }
}
