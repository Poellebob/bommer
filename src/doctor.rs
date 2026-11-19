//! Check collector readiness without executing collections.

use crate::collectors::{self, CollectionError};
use crate::job::Job;

pub(crate) struct Readiness {
    pub(crate) name: String,
    pub(crate) result: Result<(), CollectionError>,
}

pub(crate) struct Report {
    pub(crate) results: Vec<Readiness>,
}

impl Report {
    pub(crate) fn is_unsuccessful(&self) -> bool {
        self.results.iter().any(|result| result.result.is_err())
    }
}

pub(crate) fn check(jobs: &[Job]) -> Report {
    Report {
        results: jobs
            .iter()
            .map(|job| Readiness {
                name: job.stem(),
                result: collectors::check(job),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use serde_json::json;

    use crate::collectors::{CollectionError, external::ExternalError};
    use crate::config::Config;
    use crate::doctor;
    use crate::process::ProcessError;

    fn command_config(executable: &Path) -> Config {
        Config::parse(
            &json!({
                "version": 1,
                "output": {"directory": "unused-test-output"},
                "host": {"inventories": [{
                    "name": "packages",
                    "kind": "sbom",
                    "collector": {"enabled": true, "backend": "command", "command": [executable]},
                }]},
            })
            .to_string(),
        )
        .unwrap()
    }

    #[test]
    fn ready_executable_is_checked_without_execution() {
        let temporary = tempfile::tempdir().unwrap();
        let marker = temporary.path().join("launched");
        let executable = temporary.path().join("collector");
        fs::write(
            &executable,
            format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let config = command_config(&executable);

        let report = doctor::check(&config.jobs);

        assert!(!report.is_unsuccessful());
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].name, "host.packages.sbom");
        assert!(matches!(report.results[0].result, Ok(())));
        assert!(!marker.exists());
    }

    #[test]
    fn missing_executable_retains_typed_readiness_error() {
        let temporary = tempfile::tempdir().unwrap();
        let missing = temporary.path().join("missing-collector");
        let config = command_config(&missing);

        let report = doctor::check(&config.jobs);

        assert!(report.is_unsuccessful());
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].name, "host.packages.sbom");
        assert!(matches!(
            &report.results[0].result,
            Err(CollectionError::External(ExternalError::Process(
                ProcessError::MissingExecutable { executable }
            ))) if executable == missing.as_os_str()
        ));
    }
}
