//! Deterministic time abstraction.
//!
//! Session expiry, approval windows, and transport reconnect backoff all
//! read time through [`Clock`] rather than calling `OffsetDateTime::now_utc()`
//! directly, so tests can advance time deterministically instead of
//! sleeping.

#[cfg(any(test, feature = "test-util"))]
use std::sync::Mutex;

use time::OffsetDateTime;

/// A source of the current time.
pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

/// Production clock backed by the system wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Test-only clock that only advances when told to.
#[cfg(any(test, feature = "test-util"))]
pub struct FakeClock {
    current: Mutex<OffsetDateTime>,
}

#[cfg(any(test, feature = "test-util"))]
impl FakeClock {
    pub fn new_at(instant: OffsetDateTime) -> Self {
        Self {
            current: Mutex::new(instant),
        }
    }

    /// Advances the clock by `delta`. `delta` may be negative to rewind in
    /// a test scenario, though production callers never need to.
    pub fn advance(&self, delta: time::Duration) {
        let mut current = self.current.lock().expect("fake clock mutex poisoned");
        *current += delta;
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clock for FakeClock {
    fn now(&self) -> OffsetDateTime {
        *self.current.lock().expect("fake clock mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_advances_deterministically() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let t0 = clock.now();
        clock.advance(time::Duration::seconds(60));
        let t1 = clock.now();
        assert_eq!(t1 - t0, time::Duration::seconds(60));
    }

    #[test]
    fn fake_clock_does_not_advance_on_its_own() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let t0 = clock.now();
        let t1 = clock.now();
        assert_eq!(t0, t1);
    }

    #[test]
    fn system_clock_reports_a_recent_time() {
        let clock = SystemClock;
        let now = clock.now();
        assert!(now.year() >= 2026);
    }
}
