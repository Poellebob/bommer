use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use crate::collection::context::{CollectionContext, Interrupted};

#[test]
fn active_context_shares_cancellation_and_preserves_deadline() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let before = Instant::now();
    let timeout = Duration::from_secs(60);
    let context = CollectionContext::new(timeout, Arc::clone(&cancelled));
    let cloned = context.clone();

    assert_eq!(context.check(), Ok(()));
    assert!(context.deadline >= before + timeout);
    assert!(context.deadline <= Instant::now() + timeout);
    assert_eq!(cloned.deadline, context.deadline);
    assert!(Arc::ptr_eq(&context.cancelled, &cancelled));

    cancelled.store(true, Ordering::Relaxed);
    assert_eq!(context.check(), Err(Interrupted::Cancelled));
    assert_eq!(cloned.check(), Err(Interrupted::Cancelled));
}

#[test]
fn cancellation_takes_precedence_over_expired_deadline() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let context = CollectionContext::new(Duration::ZERO, Arc::clone(&cancelled));

    assert_eq!(context.check(), Err(Interrupted::Timeout));
    cancelled.store(true, Ordering::Relaxed);
    assert_eq!(context.check(), Err(Interrupted::Cancelled));
    cancelled.store(false, Ordering::Relaxed);
    assert_eq!(context.check(), Err(Interrupted::Timeout));
}
