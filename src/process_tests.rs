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
    assert_eq!(
        command.arguments(),
        &["a b", "$(touch unexpected)", "*.json"]
    );
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

    assert_eq!(output.stdout(), b"$HOME; * space");
    assert_eq!(output.stderr(), b"diagnostic");
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

    assert_eq!(output.stdout(), b"abcd".repeat(20000));
    assert_eq!(output.stderr(), b"efgh".repeat(20000));
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
