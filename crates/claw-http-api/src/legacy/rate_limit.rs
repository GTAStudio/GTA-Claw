//! Bounded token-bucket storage for the legacy Teams route.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{PortError, PortErrorKind};

pub(super) struct RateLimiter {
    max_tokens: f64,
    refill_per_second: f64,
    max_clients: usize,
    idle_timeout: Duration,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub(super) fn new(max_per_minute: u32, max_clients: usize, idle_timeout: Duration) -> Self {
        Self {
            max_tokens: f64::from(max_per_minute),
            refill_per_second: f64::from(max_per_minute) / 60.0,
            max_clients,
            idle_timeout,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn is_allowed(&self, client: &str) -> Result<bool, PortError> {
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "rate limiter unavailable"))?;
        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) < self.idle_timeout);
        if let Some(bucket) = buckets.get_mut(client) {
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
            bucket.tokens = self
                .max_tokens
                .min(elapsed.mul_add(self.refill_per_second, bucket.tokens));
            bucket.last_refill = now;
            let allowed = bucket.tokens >= 1.0;
            if allowed {
                bucket.tokens -= 1.0;
            }
            drop(buckets);
            return Ok(allowed);
        }
        if buckets.len() >= self.max_clients {
            drop(buckets);
            return Ok(false);
        }
        buckets.insert(
            client.to_owned(),
            Bucket {
                tokens: self.max_tokens - 1.0,
                last_refill: now,
            },
        );
        drop(buckets);
        Ok(true)
    }
}
