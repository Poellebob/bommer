use std::ffi::OsString;
use std::path::PathBuf;

use clap::Parser;

use crate::{Args, Command, InventoryFilter};

fn parse(input: &[&str]) -> Result<Args, clap::Error> {
    Args::try_parse_from(
        std::iter::once(OsString::from("bommer")).chain(input.iter().map(OsString::from)),
    )
}

#[test]
fn cli_defaults_and_explicit_selectors() {
    for (command, expect_doctor) in [("scan", false), ("doctor", true)] {
        let args = parse(&[command]).unwrap();

        match &args.command {
            Command::Scan(options) if !expect_doctor => {
                assert_eq!(options.config, PathBuf::from("/etc/bommer/config.yaml"));
                assert_eq!(options.only, None);
                assert_eq!(options.application, None);
            }
            Command::Doctor(options) if expect_doctor => {
                assert_eq!(options.config, PathBuf::from("/etc/bommer/config.yaml"));
                assert_eq!(options.only, None);
                assert_eq!(options.application, None);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    let args = parse(&[
        "scan",
        "--config",
        "local.yaml",
        "--only",
        "cbom",
        "--application",
        "api",
    ])
    .unwrap();

    match &args.command {
        Command::Scan(options) => {
            assert_eq!(options.config, PathBuf::from("local.yaml"));
            assert_eq!(options.only, Some(InventoryFilter::Cbom));
            assert_eq!(options.application.as_deref(), Some("api"));
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let args = parse(&["doctor", "--only=sbom", "--config=other.yaml"]).unwrap();

    match &args.command {
        Command::Doctor(options) => {
            assert_eq!(options.config, PathBuf::from("other.yaml"));
            assert_eq!(options.only, Some(InventoryFilter::Sbom));
            assert_eq!(options.application, None);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let args = parse(&["scan", "--only", "hbom"]).unwrap();

    match &args.command {
        Command::Scan(options) => {
            assert_eq!(options.only, Some(InventoryFilter::Hbom));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn help_and_version_are_typed_clap_errors() {
    for input in [
        vec!["--help"],
        vec!["-h"],
        vec!["help"],
        vec!["scan", "--help"],
        vec!["doctor", "-h"],
        vec!["help", "scan"],
        vec!["help", "doctor"],
        vec!["version", "--help"],
        vec!["help", "version"],
    ] {
        let error = parse(&input).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    let error = parse(&["--version"]).unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);

    assert!(matches!(
        parse(&["version"]).unwrap(),
        Args {
            command: Command::Version
        }
    ));
}

#[test]
fn invalid_arguments_are_typed_usage_errors() {
    for input in [
        vec!["unknown"],
        vec!["scan", "--unexpected"],
        vec!["doctor", "positional"],
        vec!["scan", "--config"],
        vec!["scan", "--only", "unknown"],
        vec!["version", "extra"],
        vec!["help", "unknown"],
        vec!["help", "scan", "extra"],
        vec!["--config", "local.yaml", "scan"],
    ] {
        let error = parse(&input).unwrap_err();
        assert_eq!(error.exit_code(), 2);
    }
}

#[cfg(unix)]
#[test]
fn config_paths_preserve_non_unicode_bytes() {
    use std::os::unix::ffi::OsStringExt;

    let path = OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', 0xff]);

    let args = Args::try_parse_from([
        OsString::from("bommer"),
        OsString::from("scan"),
        OsString::from("--config"),
        path.clone(),
    ])
    .unwrap();

    match args.command {
        Command::Scan(options) => assert_eq!(options.config, path),
        other => panic!("unexpected command: {other:?}"),
    }
}
