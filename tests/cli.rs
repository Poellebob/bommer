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

fn run_with_config(config_path: &Path, command: &str) -> Output {
    run(&[
        command.as_ref(),
        "--config".as_ref(),
        config_path.as_os_str(),
    ])
}

#[test]
fn help_shows_usage_commands_and_examples() {
    let output = run(&["--help".as_ref()]);

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("Commands:"));
    assert!(stdout.contains("Examples:"));
    assert!(stdout.contains("bommer scan --config"));
    assert!(stdout.contains("--only"));
    assert!(stdout.contains("--application"));

    let output = run(&["-h".as_ref()]);

    assert_eq!(output.status.code(), Some(0));

    let output = run(&["scan".as_ref(), "--help".as_ref()]);

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--only"));
    assert!(stdout.contains("--application"));

    let output = run(&["help".as_ref()]);

    assert_eq!(output.status.code(), Some(0));
    assert!(!output.stdout.is_empty());
}

#[test]
fn binary_preserves_import_bytes_and_reports_usage_and_partial_exit_codes() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.json");
    let source_bytes = b"{\n \"bomFormat\": \"CycloneDX\", \"specVersion\": \"1.6\", \"version\": 1, \"components\": []\n}\n";
    fs::write(&source_path, source_bytes).unwrap();

    let config_path = directory.path().join("config.json");
    fs::write(
        &config_path,
        json!({
            "version": 1,
            "output": {"directory": directory.path().join("output")},
            "host": {"inventories": [{"name": "imported", "kind": "cbom", "collector": {
                "enabled": true, "backend": "import", "import": {"path": source_path}
            }}]}
        })
        .to_string(),
    )
    .unwrap();

    let output = run_with_config(&config_path, "scan");

    assert_eq!(output.status.code(), Some(0));
    let run_directory = std::path::PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    assert_eq!(
        fs::read(run_directory.join("host.imported.cbom.cdx.json")).unwrap(),
        source_bytes
    );

    let manifest: Value =
        serde_json::from_slice(&fs::read(run_directory.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["results"][0]["status"], "no-findings");
    assert_eq!(
        manifest["results"][0]["coverage"],
        "producer-declared-unverified"
    );

    let invalid_selection = run(&["scan".as_ref(), "--only".as_ref(), "invalid".as_ref()]);

    assert_eq!(invalid_selection.status.code(), Some(2));

    let missing_config_path = directory.path().join("absent.yaml");

    assert_eq!(
        run_with_config(&missing_config_path, "scan").status.code(),
        Some(2)
    );

    fs::write(&config_path, json!({
        "version": 1,
        "output": {"directory": directory.path().join("partial")},
        "host": {"inventories": [{"name": "certificates", "kind": "cbom", "collector": {
            "enabled": true, "backend": "certificates", "certificates": {"paths": [directory.path().join("missing.pem")]}
        }}]}
    }).to_string()).unwrap();

    let partial_output = run_with_config(&config_path, "scan");

    assert_eq!(partial_output.status.code(), Some(1));
    let run_directory =
        std::path::PathBuf::from(String::from_utf8(partial_output.stdout).unwrap().trim());
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
    let execution_marker_path = directory.path().join("executed");
    let output_directory = directory.path().join("output");
    let config_path = directory.path().join("config.json");
    fs::write(
        &config_path,
        json!({
            "version": 1,
            "output": {"directory": output_directory},
            "host": {"sbom": {"enabled": true, "backend": "command", "command": [
                "/bin/sh", "-c", "touch \"$1\"", "collector", execution_marker_path
            ]}}
        })
        .to_string(),
    )
    .unwrap();

    let output = run_with_config(&config_path, "doctor");

    assert_eq!(output.status.code(), Some(0));
    assert!(!execution_marker_path.exists());
    assert!(!output_directory.exists());
}

#[test]
fn scan_and_doctor_reject_invalid_selections_without_creating_output() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.json");
    fs::write(
        &source_path,
        b"{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"version\":1,\"components\":[]}",
    )
    .unwrap();

    let output_directory = directory.path().join("output");
    let config_path = directory.path().join("config.json");
    fs::write(
        &config_path,
        json!({
            "version": 1,
            "output": {"directory": output_directory},
            "host": {"inventories": [{"name": "imported", "kind": "cbom", "collector": {
                "enabled": true, "backend": "import", "import": {"path": source_path}
            }}]}
        })
        .to_string(),
    )
    .unwrap();

    let readiness_output = run_with_config(&config_path, "doctor");

    assert_eq!(readiness_output.status.code(), Some(0));
    assert!(readiness_output.stderr.is_empty());
    assert!(!output_directory.exists());

    for command in ["scan", "doctor"] {
        let unknown_application = run(&[
            command.as_ref(),
            "--config".as_ref(),
            config_path.as_os_str(),
            "--application".as_ref(),
            "unknown-app".as_ref(),
        ]);

        assert_eq!(unknown_application.status.code(), Some(2), "{command}");
        assert!(unknown_application.stdout.is_empty(), "{command}");
        assert!(!unknown_application.stderr.is_empty(), "{command}");
        assert!(!output_directory.exists(), "{command}: unknown application");

        let invalid_application = run(&[
            command.as_ref(),
            "--config".as_ref(),
            config_path.as_os_str(),
            "--application".as_ref(),
            "invalid/name".as_ref(),
        ]);

        assert_eq!(invalid_application.status.code(), Some(2), "{command}");
        assert!(invalid_application.stdout.is_empty(), "{command}");
        assert!(!invalid_application.stderr.is_empty(), "{command}");
        assert!(
            !output_directory.exists(),
            "{command}: invalid application name"
        );

        let nonmatching_inventory = run(&[
            command.as_ref(),
            "--config".as_ref(),
            config_path.as_os_str(),
            "--only".as_ref(),
            "sbom".as_ref(),
        ]);

        assert_eq!(nonmatching_inventory.status.code(), Some(2), "{command}");
        assert!(nonmatching_inventory.stdout.is_empty(), "{command}");
        assert!(!nonmatching_inventory.stderr.is_empty(), "{command}");
        assert!(
            !output_directory.exists(),
            "{command}: nonmatching inventory filter"
        );
    }
}

#[test]
fn doctor_reports_missing_collector_without_creating_output() {
    let directory = tempfile::tempdir().unwrap();
    let executable_path = directory.path().join("missing-collector");
    let output_directory = directory.path().join("output");
    let config_path = directory.path().join("config.json");
    fs::write(
        &config_path,
        json!({
            "version": 1,
            "output": {"directory": output_directory},
            "host": {"sbom": {"enabled": true, "backend": "command", "command": [
                executable_path
            ]}}
        })
        .to_string(),
    )
    .unwrap();

    let output = run_with_config(&config_path, "doctor");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    assert!(!output_directory.exists());
    assert!(!executable_path.exists());
}

#[test]
fn scan_and_doctor_sanitize_control_characters_in_missing_config_errors() {
    let directory = tempfile::tempdir().unwrap();
    let missing_config_path = directory.path().join("missing\n\r\t\x1b[31m.yaml");

    for command in ["scan", "doctor"] {
        let output = run_with_config(&missing_config_path, command);

        assert_eq!(output.status.code(), Some(2), "{command}");
        assert!(output.stdout.is_empty(), "{command}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        let diagnostic = stderr.strip_suffix('\n').unwrap();
        assert!(!diagnostic.is_empty(), "{command}");
        assert!(!diagnostic.contains('\n'), "{command}");
        assert!(!diagnostic.contains('\x1b'), "{command}");
        assert!(!diagnostic.chars().any(char::is_control), "{command}");
    }
}
