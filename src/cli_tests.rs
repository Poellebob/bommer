use std::ffi::OsString;
use std::path::PathBuf;

use crate::cli::{CliError, Only, Request};

#[test]
fn cli_defaults_and_explicit_selectors() {
    for (command, doctor) in [("scan", false), ("doctor", true)] {
        let actual = Request::parse([OsString::from(command)]).unwrap();
        let expected = if doctor {
            Request::Doctor {
                config: PathBuf::from("/etc/bommer/config.yaml"),
                only: None,
                application: None,
            }
        } else {
            Request::Scan {
                config: PathBuf::from("/etc/bommer/config.yaml"),
                only: None,
                application: None,
            }
        };
        assert_eq!(actual, expected);
    }
    assert_eq!(
        Request::parse(
            [
                "scan",
                "--config",
                "local.yaml",
                "--only",
                "cbom",
                "--application",
                "api"
            ]
            .map(OsString::from)
        )
        .unwrap(),
        Request::Scan {
            config: "local.yaml".into(),
            only: Some(Only::Cbom),
            application: Some("api".into())
        }
    );
    assert_eq!(
        Request::parse(["doctor", "--only=sbom", "--config=other.yaml"].map(OsString::from))
            .unwrap(),
        Request::Doctor {
            config: "other.yaml".into(),
            only: Some(Only::Sbom),
            application: None
        }
    );
    assert!(matches!(
        Request::parse(["scan", "--only", "hbom"].map(OsString::from)),
        Ok(Request::Scan {
            only: Some(Only::Hbom),
            ..
        })
    ));
}

#[test]
fn help_and_version_are_successful_requests() {
    for input in [
        vec![],
        vec!["help"],
        vec!["--help"],
        vec!["-h"],
        vec!["scan", "--help"],
        vec!["doctor", "-h"],
        vec!["help", "scan"],
        vec!["help", "doctor"],
        vec!["version", "--help"],
        vec!["help", "version"],
    ] {
        assert_eq!(
            Request::parse(input.into_iter().map(OsString::from)).unwrap(),
            Request::Help
        );
    }
    for input in [vec!["version"], vec!["--version"]] {
        assert_eq!(
            Request::parse(input.into_iter().map(OsString::from)).unwrap(),
            Request::Version
        );
    }
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
        let error = Request::parse(input.into_iter().map(OsString::from)).unwrap_err();
        assert!(matches!(error, CliError::Arguments(_)));
        assert_eq!(error.exit_code(), 2);
    }
}

#[cfg(unix)]
#[test]
fn config_paths_preserve_non_unicode_bytes() {
    use std::os::unix::ffi::OsStringExt;
    let path = OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', 0xff]);
    let request = Request::parse([
        OsString::from("scan"),
        OsString::from("--config"),
        path.clone(),
    ])
    .unwrap();
    assert!(matches!(request, Request::Scan { config, .. } if config == path));
}
