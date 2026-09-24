//! Exponential backoff with jitter for transport reconnects, and a
//! [`Transport`] decorator that applies it. Reconnecting restores transport
//! connectivity only — it never re-derives session authorization (see
//! `docs/architecture/session-lifecycle.md`).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use companion_core::TransportState;
use companion_protocol::Envelope;

use crate::error::TransportError;
use crate::transport::{Transport, TransportHealth};

#[derive(Debug, Clone)]
pub struct BackoffPolicy {
    pub base: Duration,
    pub factor: f64,
    pub max: Duration,
    /// `None` means retry forever.
    pub max_attempts: Option<u32>,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_millis(250),
            factor: 2.0,
            max: Duration::from_secs(30),
            max_attempts: None,
        }
    }
}

impl BackoffPolicy {
    /// The base exponential delay for `attempt` (0-indexed), capped at
    /// `max`. Deterministic and jitter-free — see [`jittered_delay`] for
    /// the version reconnect logic actually sleeps on.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let exponent = attempt.min(32); // guard against float overflow on pathological inputs
        let raw_ms = self.base.as_millis() as f64 * self.factor.powi(exponent as i32);
        let capped_ms = raw_ms.min(self.max.as_millis() as f64);
        Duration::from_millis(capped_ms as u64)
    }
}

/// Applies a deterministic pseudo-random ±20% jitter to `delay`, seeded by
/// `seed` (callers pass the attempt count so repeated attempts don't
/// produce the exact same jittered value). Not cryptographic — jitter here
/// only needs to avoid synchronized thundering-herd reconnects, not resist
/// prediction.
pub fn jittered_delay(delay: Duration, seed: u32) -> Duration {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    let hashed = hasher.finish();
    // Map the hash to a fraction in [-0.2, 0.2].
    let unit = (hashed % 1000) as f64 / 1000.0; // [0, 1)
    let fraction = (unit - 0.5) * 0.4; // [-0.2, 0.2)

    let base_ms = delay.as_millis() as f64;
    let jittered_ms = (base_ms * (1.0 + fraction)).max(0.0);
    Duration::from_millis(jittered_ms as u64)
}

/// Wraps an inner [`Transport`] with automatic reconnect on connect
/// failure, using exponential backoff with jitter. It never busy-loops:
/// every retry passes through [`tokio::time::sleep`].
pub struct ReconnectingTransport<T: Transport> {
    inner: T,
    policy: BackoffPolicy,
    state: Mutex<TransportState>,
    attempts_made: AtomicU32,
}

impl<T: Transport> ReconnectingTransport<T> {
    pub fn new(inner: T, policy: BackoffPolicy) -> Self {
        Self {
            inner,
            policy,
            state: Mutex::new(TransportState::Disconnected),
            attempts_made: AtomicU32::new(0),
        }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn attempts_made(&self) -> u32 {
        self.attempts_made.load(Ordering::SeqCst)
    }

    /// Connects, retrying with backoff on failure, until success or
    /// `max_attempts` is exhausted.
    pub async fn connect_with_retry(&self) -> Result<(), TransportError> {
        let mut attempt: u32 = 0;
        loop {
            *self.state.lock().expect("mutex poisoned") = TransportState::Connecting;
            self.attempts_made.fetch_add(1, Ordering::SeqCst);

            match self.inner.connect().await {
                Ok(()) => {
                    *self.state.lock().expect("mutex poisoned") = TransportState::Connected;
                    return Ok(());
                }
                Err(e) => {
                    let exhausted = self
                        .policy
                        .max_attempts
                        .is_some_and(|max| attempt + 1 >= max);
                    if exhausted {
                        *self.state.lock().expect("mutex poisoned") = TransportState::Failed;
                        return Err(e);
                    }
                    *self.state.lock().expect("mutex poisoned") = TransportState::Reconnecting;
                    let delay = jittered_delay(self.policy.delay_for_attempt(attempt), attempt);
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl<T: Transport> Transport for ReconnectingTransport<T> {
    async fn connect(&self) -> Result<(), TransportError> {
        self.connect_with_retry().await
    }

    async fn disconnect(&self) -> Result<(), TransportError> {
        let result = self.inner.disconnect().await;
        *self.state.lock().expect("mutex poisoned") = TransportState::Disconnected;
        result
    }

    async fn send(&self, envelope: Envelope) -> Result<(), TransportError> {
        self.inner.send(envelope).await
    }

    async fn receive(&self) -> Result<Envelope, TransportError> {
        self.inner.receive().await
    }

    fn state(&self) -> TransportState {
        *self.state.lock().expect("mutex poisoned")
    }

    async fn health(&self) -> TransportHealth {
        self.inner.health().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockTransport;

    #[test]
    fn delay_grows_exponentially_and_caps_at_max() {
        let policy = BackoffPolicy {
            base: Duration::from_millis(100),
            factor: 2.0,
            max: Duration::from_secs(2),
            max_attempts: None,
        };
        assert_eq!(policy.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(policy.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_millis(400));
        // 100 * 2^5 = 3200ms, capped at 2000ms.
        assert_eq!(policy.delay_for_attempt(5), Duration::from_millis(2000));
    }

    #[test]
    fn jitter_stays_within_twenty_percent_bounds() {
        let base = Duration::from_millis(1000);
        for seed in 0..50 {
            let jittered = jittered_delay(base, seed);
            assert!(
                jittered.as_millis() >= 800 && jittered.as_millis() <= 1200,
                "seed {seed}: {jittered:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_never_busy_loops_and_eventually_succeeds() {
        let mock = MockTransport::new();
        mock.fail_next_connects(4);
        let policy = BackoffPolicy {
            base: Duration::from_millis(50),
            factor: 2.0,
            max: Duration::from_secs(5),
            max_attempts: None,
        };
        let transport = ReconnectingTransport::new(mock, policy);

        let start = tokio::time::Instant::now();
        transport.connect_with_retry().await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(transport.state(), TransportState::Connected);
        assert_eq!(transport.attempts_made(), 5, "4 failures + 1 success");
        // Virtual time must have actually advanced through the backoff
        // delays (50 + 100 + 200 + 400 = 750ms of sleeping), proving this
        // is not a busy loop that ignores the delay.
        assert!(
            elapsed >= Duration::from_millis(750),
            "elapsed {elapsed:?} looks like a busy loop"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn max_attempts_is_honored_and_reports_failure() {
        let mock = MockTransport::new();
        mock.fail_next_connects(100);
        let policy = BackoffPolicy {
            base: Duration::from_millis(10),
            factor: 2.0,
            max: Duration::from_secs(1),
            max_attempts: Some(3),
        };
        let transport = ReconnectingTransport::new(mock, policy);

        let result = transport.connect_with_retry().await;
        assert!(result.is_err());
        assert_eq!(transport.attempts_made(), 3);
        assert_eq!(transport.state(), TransportState::Failed);
    }
}
