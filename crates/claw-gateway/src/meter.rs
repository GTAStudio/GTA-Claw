//! In-flight request accounting, so a graceful stop can wait for real work.
//!
//! A composition root drains its ingress between quiescing and stopping it, and
//! a drain that cannot observe anything reports a clean drain of nothing
//! forever. That is indistinguishable from a drain that works, which is why the
//! count is taken here rather than assumed.
//!
//! The depth is published through a [`watch`] channel rather than polled. A
//! waiter therefore observes every transition to zero without a sleep loop, and
//! cannot miss the transition that happens between its own load and its own
//! await.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::timeout;

/// Counts requests currently being served and requests already answered.
#[derive(Clone, Debug)]
pub struct RequestMeter {
    depth: Arc<watch::Sender<u64>>,
    completed: Arc<AtomicU64>,
}

impl RequestMeter {
    /// Creates a meter with nothing in flight.
    #[must_use]
    pub fn new() -> Self {
        Self {
            depth: Arc::new(watch::Sender::new(0)),
            completed: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Marks one request as started, returning the guard that ends it.
    ///
    /// The count is released by [`Drop`], so a request whose connection future
    /// is cancelled part-way through is still subtracted. Decrementing after
    /// the dispatch instead would leave a permanent phantom in the depth and a
    /// drain would then never finish.
    #[must_use]
    pub fn begin(&self) -> RequestGuard {
        self.depth.send_modify(|depth| *depth += 1);

        RequestGuard {
            depth: Arc::clone(&self.depth),
            completed: Arc::clone(&self.completed),
            answered: false,
        }
    }

    /// Returns how many requests are being served right now.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        *self.depth.borrow()
    }

    /// Returns how many requests have been answered since the server started.
    #[must_use]
    pub fn completed(&self) -> u64 {
        self.completed.load(Ordering::SeqCst)
    }

    /// Waits up to `grace` for every in-flight request to finish.
    ///
    /// Returns how many were still in flight when it stopped waiting, which is
    /// zero for a complete drain.
    pub async fn drain(&self, grace: Duration) -> u64 {
        let mut depth = self.depth.subscribe();

        let _ = timeout(grace, async {
            while *depth.borrow_and_update() > 0 {
                if depth.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;

        self.in_flight()
    }
}

impl Default for RequestMeter {
    fn default() -> Self {
        Self::new()
    }
}

/// Holds one request's place in the in-flight count.
#[derive(Debug)]
pub struct RequestGuard {
    depth: Arc<watch::Sender<u64>>,
    completed: Arc<AtomicU64>,
    answered: bool,
}

impl RequestGuard {
    /// Records that the request produced an answer.
    ///
    /// A request that never reaches this — because the connection was dropped
    /// mid-dispatch — is still removed from the depth, but is not counted as
    /// completed. The two counters therefore disagree exactly when work was
    /// abandoned, which is the distinction a drain report exists to make.
    pub const fn answered(&mut self) {
        self.answered = true;
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if self.answered {
            self.completed.fetch_add(1, Ordering::SeqCst);
        }

        self.depth
            .send_modify(|depth| *depth = depth.saturating_sub(1));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::RequestMeter;

    #[tokio::test]
    async fn a_guard_dropped_without_an_answer_leaves_the_depth_but_not_the_completed_count() {
        let meter = RequestMeter::new();

        let guard = meter.begin();
        assert_eq!(meter.in_flight(), 1);
        assert_eq!(meter.completed(), 0);

        drop(guard);

        assert_eq!(meter.in_flight(), 0, "an abandoned request still unwinds");
        assert_eq!(
            meter.completed(),
            0,
            "an abandoned request must not be counted as answered"
        );
    }

    #[tokio::test]
    async fn an_answered_request_raises_the_completed_count_exactly_once() {
        let meter = RequestMeter::new();

        for _ in 0..3 {
            let mut guard = meter.begin();
            guard.answered();
            drop(guard);
        }

        assert_eq!(meter.in_flight(), 0);
        assert_eq!(meter.completed(), 3);
    }

    #[tokio::test]
    async fn a_drain_returns_only_after_the_last_request_releases() {
        let meter = RequestMeter::new();
        let first = meter.begin();
        let second = meter.begin();
        assert_eq!(meter.in_flight(), 2);

        let releasing = {
            let meter = meter.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                drop(first);
                tokio::time::sleep(Duration::from_millis(20)).await;
                drop(second);
                meter.in_flight()
            })
        };

        let started = std::time::Instant::now();
        let remaining = meter.drain(Duration::from_secs(5)).await;
        let waited = started.elapsed();

        assert_eq!(remaining, 0, "the drain waited for both requests");
        assert!(
            waited >= Duration::from_millis(40),
            "the drain returned after {waited:?}, which is before the second release could \
             possibly have happened, so it did not wait for the work it claims to have drained"
        );
        assert_eq!(
            releasing.await.expect("the releasing task finishes"),
            0,
            "both guards were released"
        );
    }

    #[tokio::test]
    async fn a_drain_that_times_out_reports_what_is_still_running() {
        let meter = RequestMeter::new();
        let _stuck = meter.begin();

        let remaining = meter.drain(Duration::from_millis(50)).await;

        assert_eq!(
            remaining, 1,
            "a bounded drain reports the work it gave up on rather than claiming success"
        );
    }
}
