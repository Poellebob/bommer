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
