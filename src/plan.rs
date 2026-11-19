//! Select configured jobs and reject empty or conflicting execution plans.

use std::collections::HashSet;

use thiserror::Error;

use crate::config::Config;
use crate::job::{InventoryKind, Job, Name};

#[derive(Debug, Default)]
pub(crate) struct Selection {
    pub(crate) kind: Option<InventoryKind>,
    pub(crate) application: Option<Name>,
}

#[derive(Debug)]
pub(crate) struct Plan {
    pub(crate) jobs: Vec<Job>,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub(crate) enum PlanError {
    #[error("unknown application {name:?}")]
    UnknownApplication { name: Name },
    #[error("no enabled collectors match the selection")]
    EmptySelection,
    #[error("artifact name collision: {name}")]
    ArtifactCollision { name: String },
}

impl Plan {
    pub(crate) fn build(configuration: &Config, selection: &Selection) -> Result<Self, PlanError> {
        if let Some(name) = &selection.application
            && !configuration.applications.contains(name)
        {
            return Err(PlanError::UnknownApplication { name: name.clone() });
        }

        let mut jobs = Vec::new();
        let mut stems = HashSet::new();
        for job in &configuration.jobs {
            if selection.kind.is_some_and(|kind| kind != job.kind)
                || selection
                    .application
                    .as_ref()
                    .is_some_and(|name| job.scope.is_host() || job.scope.name() != name.as_str())
            {
                continue;
            }

            let stem = job.stem();
            if !stems.insert(stem.clone()) {
                return Err(PlanError::ArtifactCollision { name: stem });
            }
            jobs.push(job.clone());
        }

        if jobs.is_empty() {
            return Err(PlanError::EmptySelection);
        }

        Ok(Self { jobs })
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::job::{Backend, InventoryKind, Name, Target};
    use crate::plan::{Plan, PlanError, Selection};

    const BASE: &str = "version: 1\noutput: {directory: /tmp/inventories}\n";

    #[test]
    fn planning_preserves_order_metadata_and_selection() {
        let configuration = Config::parse(&format!("{BASE}host:\n  hbom: {{enabled: true, backend: hbom}}\n  sbom: {{enabled: true, backend: syft}}\n  inventories:\n    - name: certs\n      kind: cbom\n      collector: {{enabled: true, backend: certificates, certificates: {{paths: [/etc/ssl]}}}}\napplications:\n  - name: api\n    version: '2.3'\n    target: {{type: container, image: example/api:2}}\n    sbom: {{enabled: true, backend: syft}}\n    cbom: {{enabled: true, backend: command, command: [scanner, '{{target}}']}}\n    inventories:\n      - name: producer\n        kind: cbom\n        collector: {{enabled: true, backend: import, import: {{path: producer.json}}}}\n")).unwrap();

        for (kind, application, expected) in [
            (
                None,
                None,
                vec![
                    "host.hbom",
                    "host.sbom",
                    "host.certs.cbom",
                    "api.sbom",
                    "api.cbom",
                    "api.producer.cbom",
                ],
            ),
            (
                Some(InventoryKind::Cbom),
                None,
                vec!["host.certs.cbom", "api.cbom", "api.producer.cbom"],
            ),
            (
                None,
                Some("api"),
                vec!["api.sbom", "api.cbom", "api.producer.cbom"],
            ),
            (
                Some(InventoryKind::Cbom),
                Some("api"),
                vec!["api.cbom", "api.producer.cbom"],
            ),
        ] {
            let selection = Selection {
                kind,
                application: application.map(|name| Name::new(name.into()).unwrap()),
            };
            let plan = Plan::build(&configuration, &selection).unwrap();

            assert_eq!(
                plan.jobs.iter().map(|job| job.stem()).collect::<Vec<_>>(),
                expected
            );
        }

        let job = &configuration.jobs[3];
        assert_eq!(job.scope.version(), Some("2.3"));
        assert!(matches!(&job.target, Target::RegistryImage(image) if image == "example/api:2"));
        assert!(matches!(configuration.jobs[1].target, Target::Host));

        let Backend::Command(specification) = &configuration.jobs[4].backend else {
            panic!("expected command");
        };

        assert_eq!(specification.executable(), "scanner");
        assert_eq!(
            specification.arguments,
            &[std::ffi::OsString::from("{target}")]
        );
    }

    #[test]
    fn disabled_application_is_known_but_has_empty_selection() {
        let configuration = Config::parse(&format!(
            "{BASE}applications: [{{name: off, target: {{type: directory, path: /app}}}}]\n"
        ))
        .unwrap();

        assert_eq!(
            configuration
                .applications
                .iter()
                .map(Name::as_str)
                .collect::<Vec<_>>(),
            ["off"]
        );

        for application in [None, Some("off")] {
            let selection = Selection {
                kind: None,
                application: application.map(|name| Name::new(name.into()).unwrap()),
            };

            assert!(matches!(
                Plan::build(&configuration, &selection),
                Err(PlanError::EmptySelection)
            ));
        }

        let selection = Selection {
            kind: None,
            application: Some(Name::new("missing".into()).unwrap()),
        };
        assert!(
            matches!(Plan::build(&configuration, &selection), Err(PlanError::UnknownApplication { name }) if name.as_str() == "missing")
        );
    }
}
