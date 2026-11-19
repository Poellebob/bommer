//! Check collector readiness without executing collections.

use crate::collectors::{self, CollectionError};
use crate::model::Job;

pub(crate) struct Readiness {
    name: String,
    result: Result<(), CollectionError>,
}

impl Readiness {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn result(&self) -> &Result<(), CollectionError> {
        &self.result
    }
}

pub(crate) struct Report {
    results: Vec<Readiness>,
}

impl Report {
    pub(crate) fn results(&self) -> &[Readiness] {
        &self.results
    }

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
