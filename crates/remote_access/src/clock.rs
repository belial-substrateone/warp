//! Injectable wall clock so expiry and lockout logic is testable.
use std::time::{SystemTime, UNIX_EPOCH};

/// Source of the current time, in whole seconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now_unix(&self) -> i64;
}

/// The real clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// A manually advanced clock for tests.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct ManualClock(std::sync::atomic::AtomicI64);

#[cfg(any(test, feature = "test-util"))]
impl ManualClock {
    pub fn new(start_unix: i64) -> Self {
        Self(std::sync::atomic::AtomicI64::new(start_unix))
    }

    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn set(&self, unix: i64) {
        self.0.store(unix, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clock for ManualClock {
    fn now_unix(&self) -> i64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_after_2024() {
        assert!(SystemClock.now_unix() > 1_700_000_000);
    }

    #[test]
    fn manual_clock_advances() {
        let c = ManualClock::new(100);
        c.advance(5);
        assert_eq!(c.now_unix(), 105);
        c.set(7);
        assert_eq!(c.now_unix(), 7);
    }
}
