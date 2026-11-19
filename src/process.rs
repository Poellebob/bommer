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
    pub(crate) arguments: Vec<OsString>,
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
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
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

        let log_result = stderr.write_all(&output.stderr);
        // Preserve the process failure even if its diagnostic writer also fails.
        result?;
        log_result?;

        check_interruption(deadline, cancelled)?;
        stdout.write_all(&output.stdout)?;

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

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use crate::process::{CommandError, CommandSpec, Process, ProcessError, Stream};

    #[test]
    fn command_construction_preserves_literal_arguments() {
        let executable = std::ffi::OsString::from("scanner");
        let arguments = vec!["a b".into(), "$(touch unexpected)".into(), "*.json".into()];

        let command = CommandSpec::new(executable, arguments).unwrap();

        assert_eq!(command.executable(), "scanner");
        assert_eq!(command.arguments, &["a b", "$(touch unexpected)", "*.json"]);
    }

    #[test]
    fn commands_require_an_executable() {
        let executable = std::ffi::OsString::new();
        let arguments = vec!["scan".into()];

        assert!(matches!(
            CommandSpec::new(executable, arguments),
            Err(CommandError::EmptyExecutable)
        ));
    }

    #[test]
    fn capture_preserves_both_pipes_and_literal_arguments() {
        let arguments = [
            "-c",
            "printf '%s' \"$1\"; printf 'diagnostic' >&2",
            "fixture",
            "$HOME; * space",
        ]
        .map(OsString::from);

        let output = Process::capture(
            OsStr::new("/bin/sh"),
            &arguments,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            1024,
            1024,
        )
        .unwrap();

        assert_eq!(output.stdout, b"$HOME; * space");
        assert_eq!(output.stderr, b"diagnostic");
    }

    #[test]
    fn capture_drains_large_pipes_without_deadlock() {
        let arguments = [
            "-c",
            "i=0; while [ $i -lt 20000 ]; do printf 'abcd'; printf 'efgh' >&2; i=$((i+1)); done",
        ]
        .map(OsString::from);

        let output = Process::capture(
            OsStr::new("/bin/sh"),
            &arguments,
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
            80000,
            80000,
        )
        .unwrap();

        assert_eq!(output.stdout, b"abcd".repeat(20000));
        assert_eq!(output.stderr, b"efgh".repeat(20000));
    }

    #[test]
    fn capture_enforces_each_limit_and_exit_status() {
        for (script, stdout_limit, stderr_limit, stream) in [
            ("printf abc", 2, 10, Stream::Stdout),
            ("printf abc >&2", 10, 2, Stream::Stderr),
        ] {
            let error = Process::capture(
                OsStr::new("/bin/sh"),
                &["-c".into(), script.into()],
                Instant::now() + Duration::from_secs(5),
                &AtomicBool::new(false),
                stdout_limit,
                stderr_limit,
            )
            .unwrap_err();

            assert!(
                matches!(error, ProcessError::OutputLimit { stream: actual, limit: 2 } if actual == stream)
            );
        }

        let error = Process::capture(
            OsStr::new("/bin/sh"),
            &["-c".into(), "exit 7".into()],
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            0,
            0,
        )
        .unwrap_err();

        assert!(matches!(error, ProcessError::Exit { code: Some(7) }));
    }

    #[test]
    fn interrupted_capture_does_not_start_executable() {
        for cancelled in [false, true] {
            let error = Process::capture(
                OsStr::new("/nonexistent/collector"),
                &[],
                Instant::now(),
                &AtomicBool::new(cancelled),
                0,
                0,
            )
            .unwrap_err();

            assert!(matches!(
                (cancelled, error),
                (true, ProcessError::Cancelled) | (false, ProcessError::Timeout)
            ));
        }
    }

    #[test]
    fn timeout_kills_descendants_holding_pipes_after_parent_exit() {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("pid");
        let script = "sleep 60 & printf '%s' $! > \"$1\"; exit 0";

        let error = Process::capture(
            OsStr::new("/bin/sh"),
            &[
                "-c".into(),
                script.into(),
                "fixture".into(),
                pid_path.as_os_str().to_owned(),
            ],
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
            100,
            100,
        )
        .unwrap_err();

        assert!(matches!(error, ProcessError::Timeout));

        let pid: i32 = std::fs::read_to_string(pid_path).unwrap().parse().unwrap();
        // A killed orphan can remain a zombie until the system's reaper runs.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Ok(stat) if stat.rsplit_once(") ").unwrap().1.starts_with('Z') => break,
                result => {
                    assert!(
                        Instant::now() < deadline,
                        "descendant remains running: {result:?}"
                    );
                    std::thread::yield_now();
                }
            }
        }
    }

    #[test]
    fn stream_accepts_non_send_writers_and_propagates_write_errors() {
        struct Broken(std::rc::Rc<()>);

        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                let _ = &self.0;
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let error = Process::stream(
            OsStr::new("/bin/sh"),
            &["-c".into(), "printf abc".into()],
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            &mut Broken(std::rc::Rc::new(())),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(
            matches!(error, ProcessError::Io(source) if source.kind() == io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn stream_preserves_stderr_and_exit_status_without_publishing_stdout() {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());

        let error = Process::stream(
            OsStr::new("/bin/sh"),
            &[
                "-c".into(),
                "printf candidate; printf 'fixture failure\n' >&2; exit 7".into(),
            ],
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            &mut stdout,
            &mut stderr,
        )
        .unwrap_err();

        assert!(matches!(error, ProcessError::Exit { code: Some(7) }));
        assert_eq!(stderr, b"fixture failure\n");
        assert!(stdout.is_empty());
    }

    #[test]
    fn stream_preserves_stderr_on_timeout() {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());

        let error = Process::stream(
            OsStr::new("/bin/sh"),
            &[
                "-c".into(),
                "printf 'fixture pending\n' >&2; exec sleep 60".into(),
            ],
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
            &mut stdout,
            &mut stderr,
        )
        .unwrap_err();

        assert!(matches!(error, ProcessError::Timeout));
        assert_eq!(stderr, b"fixture pending\n");
        assert!(stdout.is_empty());
    }

    #[test]
    fn stream_preserves_only_bounded_stderr_on_log_overflow() {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());

        let error = Process::stream(
            OsStr::new("/bin/sh"),
            &["-c".into(), "head -c 1048577 /dev/zero >&2".into()],
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            &mut stdout,
            &mut stderr,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProcessError::OutputLimit {
                stream: Stream::Stderr,
                limit: 1_048_576
            }
        ));
        assert_eq!(stderr, vec![0; 1_048_576]);
        assert!(stdout.is_empty());
    }

    #[test]
    fn executable_preflight_rejects_non_executable_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("not-executable");
        std::fs::write(&path, b"fixture").unwrap();

        assert!(matches!(
            Process::find_executable(path.as_os_str()),
            Err(ProcessError::MissingExecutable { .. })
        ));
        assert!(
            Process::find_executable(OsStr::new("/bin/sh"))
                .unwrap()
                .is_file()
        );
    }

    #[test]
    fn cancellation_stops_a_running_group_after_readiness() {
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let cancelled = AtomicBool::new(false);

        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                Process::capture(
                    OsStr::new("/bin/sh"),
                    &[
                        "-c".into(),
                        "printf ready > \"$1\"; exec sleep 60".into(),
                        "fixture".into(),
                        ready.as_os_str().to_owned(),
                    ],
                    Instant::now() + Duration::from_secs(5),
                    &cancelled,
                    100,
                    100,
                )
            });

            let deadline = Instant::now() + Duration::from_secs(3);
            while !ready.exists() {
                assert!(Instant::now() < deadline);
                std::thread::yield_now();
            }

            cancelled.store(true, Ordering::Relaxed);

            assert!(matches!(
                worker.join().unwrap(),
                Err(ProcessError::Cancelled)
            ));
        });
    }

    #[test]
    fn stream_refuses_an_oversized_bom_without_publishing_prefix() {
        let mut output = Vec::new();

        let error = Process::stream(
            OsStr::new("/bin/sh"),
            &["-c".into(), "head -c 67108865 /dev/zero".into()],
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
            &mut output,
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProcessError::OutputLimit {
                stream: Stream::Stdout,
                limit: 67_108_864
            }
        ));
        assert!(output.is_empty());
    }
}
