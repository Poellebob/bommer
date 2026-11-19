use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use thiserror::Error;

#[derive(Debug, Clone)]
pub(crate) struct CollectionContext {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum Interrupted {
    #[error("collection cancelled")]
    Cancelled,
    #[error("collection timed out")]
    Timeout,
}

impl CollectionContext {
    pub(crate) fn new(timeout: Duration, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            cancelled,
        }
    }

    pub(crate) fn check(&self) -> Result<(), Interrupted> {
        if self.cancelled.load(Ordering::Relaxed) {
            Err(Interrupted::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(Interrupted::Timeout)
        } else {
            Ok(())
        }
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn cancelled(&self) -> &AtomicBool {
        &self.cancelled
    }
}
