//! Bounded per-peer request rate limiting.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::json;

use crate::http_support::json_response;

const WINDOW: Duration = Duration::from_secs(60);
const TOKEN_SCALE: u128 = 60_000_000_000;
const MAX_CLIENTS: usize = 4_096;

#[derive(Clone)]
pub(crate) struct RateLimiter {
    shared: Arc<Mutex<LimiterState>>,
    requests_per_minute: u32,
    max_clients: usize,
    trust_proxy: bool,
}

struct LimiterState {
    buckets: HashMap<IpAddr, Bucket>,
    last_cleanup: Instant,
}

struct Bucket {
    credits: u128,
    last_refill: Instant,
    last_seen: Instant,
}

impl RateLimiter {
    pub(crate) fn new(requests_per_minute: NonZeroU32, trust_proxy: bool) -> Self {
        Self::new_at(
            requests_per_minute,
            MAX_CLIENTS,
            trust_proxy,
            Instant::now(),
        )
    }

    fn new_at(
        requests_per_minute: NonZeroU32,
        max_clients: usize,
        trust_proxy: bool,
        now: Instant,
    ) -> Self {
        debug_assert!(max_clients > 0);
        Self {
            shared: Arc::new(Mutex::new(LimiterState {
                buckets: HashMap::new(),
                last_cleanup: now,
            })),
            requests_per_minute: requests_per_minute.get(),
            max_clients,
            trust_proxy,
        }
    }

    fn is_allowed(&self, socket_peer: IpAddr, headers: &HeaderMap) -> bool {
        let peer = client_ip(socket_peer, headers, self.trust_proxy);
        self.is_allowed_at(peer, Instant::now())
    }

    fn is_allowed_at(&self, peer: IpAddr, now: Instant) -> bool {
        let mut state = self.lock();
        if now.saturating_duration_since(state.last_cleanup) >= WINDOW {
            state
                .buckets
                .retain(|_, bucket| now.saturating_duration_since(bucket.last_seen) < WINDOW);
            state.last_cleanup = now;
        }

        if let Some(bucket) = state.buckets.get_mut(&peer) {
            let capacity = u128::from(self.requests_per_minute) * TOKEN_SCALE;
            let refill = now
                .saturating_duration_since(bucket.last_refill)
                .as_nanos()
                .saturating_mul(u128::from(self.requests_per_minute));
            bucket.credits = capacity.min(bucket.credits.saturating_add(refill));
            bucket.last_refill = now;
            bucket.last_seen = now;
            if bucket.credits < TOKEN_SCALE {
                return false;
            }
            bucket.credits -= TOKEN_SCALE;
            return true;
        }

        if state.buckets.len() >= self.max_clients {
            state
                .buckets
                .retain(|_, bucket| now.saturating_duration_since(bucket.last_seen) < WINDOW);
            if state.buckets.len() >= self.max_clients
                && let Some(oldest) = state
                    .buckets
                    .iter()
                    .min_by_key(|(ip, bucket)| (bucket.last_seen, **ip))
                    .map(|(ip, _)| *ip)
            {
                state.buckets.remove(&oldest);
            }
        }

        let capacity = u128::from(self.requests_per_minute) * TOKEN_SCALE;
        state.buckets.insert(
            peer,
            Bucket {
                credits: capacity - TOKEN_SCALE,
                last_refill: now,
                last_seen: now,
            },
        );
        true
    }

    fn lock(&self) -> MutexGuard<'_, LimiterState> {
        self.shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub(crate) async fn enforce(
    State(limiter): State<RateLimiter>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if is_probe(request.uri().path()) || limiter.is_allowed(peer.ip(), request.headers()) {
        return next.run(request).await;
    }
    json_response(
        StatusCode::TOO_MANY_REQUESTS,
        json!({"error":"Too many requests"}),
    )
}

fn is_probe(path: &str) -> bool {
    matches!(path, "/health" | "/healthz" | "/ready" | "/readyz")
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4),
        ipv4 => ipv4,
    }
}

fn client_ip(socket_peer: IpAddr, headers: &HeaderMap, trust_proxy: bool) -> IpAddr {
    if trust_proxy
        && let Some(forwarded) = headers
            .get(header::HeaderName::from_static("x-forwarded-for"))
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse::<IpAddr>().ok())
    {
        return normalize_ip(forwarded);
    }
    normalize_ip(socket_peer)
}

#[cfg(test)]
mod tests {
    use super::{RateLimiter, WINDOW};
    use std::net::{IpAddr, Ipv4Addr};
    use std::num::NonZeroU32;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn token_refill_uses_a_deterministic_sixty_second_oracle() {
        let start = Instant::now();
        let limiter = RateLimiter::new_at(NonZeroU32::new(2).expect("non-zero"), 4, false, start);
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);

        assert!(limiter.is_allowed_at(peer, start));
        assert!(limiter.is_allowed_at(peer, start));
        assert!(!limiter.is_allowed_at(peer, start));
        assert!(!limiter.is_allowed_at(
            peer,
            start + Duration::from_secs(29) + Duration::from_millis(999)
        ));
        assert!(limiter.is_allowed_at(peer, start + Duration::from_secs(30)));
        assert!(!limiter.is_allowed_at(peer, start + Duration::from_secs(30)));
        assert!(limiter.is_allowed_at(peer, start + WINDOW));
        assert!(!limiter.is_allowed_at(peer, start + WINDOW));
        assert!(limiter.is_allowed_at(peer, start + WINDOW + WINDOW));
        assert!(limiter.is_allowed_at(peer, start + WINDOW + WINDOW));
        assert!(!limiter.is_allowed_at(peer, start + WINDOW + WINDOW));
    }

    #[test]
    fn stale_cleanup_and_oldest_eviction_keep_the_map_bounded() {
        let start = Instant::now();
        let limiter = RateLimiter::new_at(NonZeroU32::new(1).expect("non-zero"), 2, false, start);
        let first = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let second = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let third = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));

        assert!(limiter.is_allowed_at(first, start));
        assert!(limiter.is_allowed_at(second, start + Duration::from_secs(1)));
        assert!(limiter.is_allowed_at(third, start + Duration::from_secs(2)));
        assert_eq!(limiter.lock().buckets.len(), 2);
        assert!(!limiter.lock().buckets.contains_key(&first));

        assert!(limiter.is_allowed_at(first, start + WINDOW + Duration::from_secs(2)));
        let state = limiter.lock();
        assert_eq!(state.buckets.len(), 1);
        assert!(state.buckets.contains_key(&first));
    }

    #[test]
    fn concurrent_requests_cannot_overdraw_a_peer_budget() {
        let start = Instant::now();
        let limiter = RateLimiter::new_at(NonZeroU32::new(4).expect("non-zero"), 4, false, start);
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let barrier = Arc::new(Barrier::new(16));

        let allowed = thread::scope(|scope| {
            let handles = (0..16)
                .map(|_| {
                    let limiter = limiter.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        limiter.is_allowed_at(peer, start)
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("worker completes"))
                .filter(|allowed| *allowed)
                .count()
        });

        assert_eq!(allowed, 4);
    }
}
