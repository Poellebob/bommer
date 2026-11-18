use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::{Value, json};

fn run(arguments: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bommer"))
        .args(arguments)
        .output()
        .unwrap()
}

fn scan(config: &Path, command: &str) -> Output {
    run(&[command.as_ref(), "--config".as_ref(), config.as_os_str()])
}

#[test]
fn binary_preserves_import_bytes_and_reports_usage_and_partial_exit_codes() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.json");
    let bytes = b"{\n \"bomFormat\": \"CycloneDX\", \"specVersion\": \"1.6\", \"version\": 1, \"components\": []\n}\n";
    fs::write(&source, bytes).unwrap();
    let config = directory.path().join("config.json");
    fs::write(
        &config,
        json!({
            "version": 1,
            "output": {"directory": directory.path().join("output")},
            "host": {"inventories": [{"name": "imported", "kind": "cbom", "collector": {
                "enabled": true, "backend": "import", "import": {"path": source}
            }}]}
        })
        .to_string(),
    )
    .unwrap();
    let output = scan(&config, "scan");
    assert_eq!(output.status.code(), Some(0));
    let run_directory = std::path::PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    assert_eq!(
        fs::read(run_directory.join("host.imported.cbom.cdx.json")).unwrap(),
        bytes
    );
    let manifest: Value =
        serde_json::from_slice(&fs::read(run_directory.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["results"][0]["status"], "no-findings");
    assert_eq!(
        manifest["results"][0]["coverage"],
        "producer-declared-unverified"
    );

    let invalid = run(&["scan".as_ref(), "--only".as_ref(), "invalid".as_ref()]);
    assert_eq!(invalid.status.code(), Some(2));
    let missing = directory.path().join("absent.yaml");
    assert_eq!(scan(&missing, "scan").status.code(), Some(2));

    fs::write(&config, json!({
        "version": 1,
        "output": {"directory": directory.path().join("partial")},
        "host": {"inventories": [{"name": "certificates", "kind": "cbom", "collector": {
            "enabled": true, "backend": "certificates", "certificates": {"paths": [directory.path().join("missing.pem")]}
        }}]}
    }).to_string()).unwrap();
    let partial = scan(&config, "scan");
    assert_eq!(partial.status.code(), Some(1));
    let run_directory = std::path::PathBuf::from(String::from_utf8(partial.stdout).unwrap().trim());
    let manifest: Value =
        serde_json::from_slice(&fs::read(run_directory.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["results"][0]["status"], "partial");
    assert!(
        run_directory
            .join("host.certificates.cbom.cdx.json")
            .is_file()
    );
}

#[test]
fn doctor_checks_readiness_without_running_collector_or_creating_output() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("executed");
    let root = directory.path().join("output");
    let config = directory.path().join("config.json");
    fs::write(
        &config,
        json!({
            "version": 1,
            "output": {"directory": root},
            "host": {"sbom": {"enabled": true, "backend": "command", "command": [
                "/bin/sh", "-c", "touch \"$1\"", "collector", marker
            ]}}
        })
        .to_string(),
    )
    .unwrap();
    assert_eq!(scan(&config, "doctor").status.code(), Some(0));
    assert!(!marker.exists());
    assert!(!root.exists());
}
