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
    pub(crate) fn build(config: &Config, selection: &Selection) -> Result<Self, PlanError> {
        if let Some(name) = &selection.application
            && !config.applications.contains(name)
        {
            return Err(PlanError::UnknownApplication { name: name.clone() });
        }

        let mut jobs = Vec::new();
        let mut stems = HashSet::new();
        for job in &config.jobs {
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
