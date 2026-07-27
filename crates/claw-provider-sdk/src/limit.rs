//! Per-provider concurrency limits.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::{ErrorKind, Operation, ProviderError};

/// Largest concurrency limit a provider may be configured with.
pub const MAX_CONCURRENCY: usize = 4_096;

#[derive(Debug)]
struct Slot {
    limit: usize,
    semaphore: Arc<Semaphore>,
}

impl Slot {
    fn new(limit: usize) -> Self {
        let limit = limit.clamp(1, MAX_CONCURRENCY);
        Self {
            limit,
            semaphore: Arc::new(Semaphore::new(limit)),
        }
    }
}

/// A fixed table of per-provider concurrency limits.
///
/// The table is immutable after construction, so a provider can never silently
/// gain unlimited concurrency at runtime. Providers without an explicit override
/// share one default slot pool.
#[derive(Debug)]
pub struct ConcurrencyLimiter {
    overrides: BTreeMap<String, Slot>,
    shared: Slot,
}

impl ConcurrencyLimiter {
    /// Builds a limiter with a shared default limit and per-provider overrides.
    ///
    /// Every limit is clamped into the range `1..=MAX_CONCURRENCY`, see
    /// [`MAX_CONCURRENCY`]. A duplicated provider entry keeps the last value.
    #[must_use]
    pub fn new(default_limit: usize, overrides: &[(&str, usize)]) -> Self {
        let mut table = BTreeMap::new();
        for (provider, limit) in overrides {
            table.insert((*provider).to_owned(), Slot::new(*limit));
        }
        Self {
            overrides: table,
            shared: Slot::new(default_limit),
        }
    }

    fn slot(&self, provider: &str) -> &Slot {
        self.overrides.get(provider).unwrap_or(&self.shared)
    }

    /// Returns the effective limit for `provider`.
    #[must_use]
    pub fn limit_for(&self, provider: &str) -> usize {
        self.slot(provider).limit
    }

    /// Returns the number of free slots for `provider`.
    #[must_use]
    pub fn available(&self, provider: &str) -> usize {
        self.slot(provider).semaphore.available_permits()
    }

    /// Returns the number of permits currently held for `provider`.
    #[must_use]
    pub fn in_flight(&self, provider: &str) -> usize {
        let slot = self.slot(provider);
        slot.limit
            .saturating_sub(slot.semaphore.available_permits())
    }

    /// Waits for a slot for `provider`.
    ///
    /// The returned permit releases its slot when it is dropped, including on
    /// the error and cancellation paths of whatever the caller does with it, so
    /// a failed request never leaks concurrency.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorKind::Transport`] error when the semaphore has been
    /// closed, which only happens during shutdown.
    pub async fn acquire(
        &self,
        provider: &str,
        operation: Operation,
    ) -> Result<ConcurrencyPermit, ProviderError> {
        let semaphore = Arc::clone(&self.slot(provider).semaphore);
        let permit = semaphore.acquire_owned().await.map_err(|_closed| {
            ProviderError::new(
                ErrorKind::Transport,
                provider,
                operation,
                "provider concurrency limiter is shut down",
            )
        })?;
        Ok(ConcurrencyPermit { _permit: permit })
    }
}

/// A held concurrency slot, released on drop.
#[derive(Debug)]
pub struct ConcurrencyPermit {
    _permit: OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    #[test]
    fn limits_are_clamped_into_the_supported_range() {
        let limiter = ConcurrencyLimiter::new(0, &[("openai", 0), ("anthropic", 10_000)]);
        assert_eq!(limiter.limit_for("openai"), 1);
        assert_eq!(limiter.limit_for("anthropic"), MAX_CONCURRENCY);
        assert_eq!(limiter.limit_for("unlisted"), 1);
    }

    #[test]
    fn overrides_do_not_affect_the_shared_default_pool() {
        let limiter = ConcurrencyLimiter::new(3, &[("openai", 1)]);
        assert_eq!(limiter.limit_for("openai"), 1);
        assert_eq!(limiter.limit_for("groq"), 3);
        assert_eq!(limiter.available("openai"), 1);
        assert_eq!(limiter.available("groq"), 3);
    }

    #[tokio::test]
    async fn permits_are_accounted_and_released_on_drop() {
        let limiter = ConcurrencyLimiter::new(4, &[("openai", 2)]);
        let first = limiter
            .acquire("openai", Operation::Complete)
            .await
            .expect("first permit");
        assert_eq!(limiter.in_flight("openai"), 1);
        assert_eq!(limiter.available("openai"), 1);

        let second = limiter
            .acquire("openai", Operation::Complete)
            .await
            .expect("second permit");
        assert_eq!(limiter.in_flight("openai"), 2);
        assert_eq!(limiter.available("openai"), 0);
        assert_eq!(limiter.in_flight("groq"), 0);

        drop(first);
        assert_eq!(limiter.available("openai"), 1);
        drop(second);
        assert_eq!(limiter.available("openai"), 2);
        assert_eq!(limiter.in_flight("openai"), 0);
    }

    #[tokio::test]
    async fn a_third_caller_waits_until_a_slot_is_released() {
        let limiter = Arc::new(ConcurrencyLimiter::new(8, &[("openai", 2)]));
        let held = vec![
            limiter
                .acquire("openai", Operation::Complete)
                .await
                .expect("permit"),
            limiter
                .acquire("openai", Operation::Complete)
                .await
                .expect("permit"),
        ];
        let entered = Arc::new(AtomicUsize::new(0));

        let waiter = tokio::spawn({
            let limiter = Arc::clone(&limiter);
            let entered = Arc::clone(&entered);
            async move {
                let permit = limiter
                    .acquire("openai", Operation::Complete)
                    .await
                    .expect("permit");
                entered.fetch_add(1, Ordering::SeqCst);
                drop(permit);
            }
        });

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(entered.load(Ordering::SeqCst), 0);
        assert_eq!(limiter.available("openai"), 0);

        drop(held);
        tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter is admitted once a slot frees")
            .expect("waiter joins");
        assert_eq!(entered.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_providers_do_not_block_each_other() {
        let limiter = ConcurrencyLimiter::new(8, &[("openai", 1), ("anthropic", 1)]);
        let openai = limiter
            .acquire("openai", Operation::Complete)
            .await
            .expect("permit");
        let anthropic = tokio::time::timeout(
            Duration::from_millis(200),
            limiter.acquire("anthropic", Operation::Complete),
        )
        .await
        .expect("anthropic has its own pool")
        .expect("permit");
        assert_eq!(limiter.available("openai"), 0);
        assert_eq!(limiter.available("anthropic"), 0);
        drop(openai);
        drop(anthropic);
    }
}
