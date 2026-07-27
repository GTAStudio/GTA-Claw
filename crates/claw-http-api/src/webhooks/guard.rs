//! Configurable-path admission guard in front of the TaskFlow webhook route.
//!
//! The frozen route `POST /plugins/webhooks/{routeId}` already authenticates a
//! shared secret and bounds its request body, but a webhook URL is a bearer
//! credential that gets pasted into third-party systems. Those systems retry
//! at least once, they are configured by hand, and they are frequently pointed
//! at the wrong tenant. Three properties the upstream extension has are missing
//! from the frozen route on its own:
//!
//! * an operator-chosen **path**, so a route can be moved off the guessable
//!   default without renaming the route itself;
//! * a **session binding**, so one route can only ever drive the one agent
//!   session it was provisioned for;
//! * **replay suppression**, so a duplicated delivery is answered once.
//!
//! [`WebhookGuard`] adds all three in one admission decision and then forwards
//! the surviving request to the frozen dispatcher, which keeps the secret,
//! body-limit and TaskFlow action contracts as the single source of truth.
//!
//! The guard deliberately also covers the canonical `/plugins/webhooks/{id}`
//! path of every route it knows about. Guarding only the custom path would
//! leave the default path as an unguarded bypass of the very checks the guard
//! exists to add.

use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::uri::PathAndQuery;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::http_support::json_response;

/// Header carrying the route shared secret when `Authorization` is not used.
pub const WEBHOOK_SECRET_HEADER: &str = "x-openclaw-webhook-secret";
/// Header carrying the unique delivery identifier used for replay suppression.
pub const WEBHOOK_DELIVERY_HEADER: &str = "x-openclaw-webhook-delivery";
/// Header carrying the delivery Unix timestamp, in whole seconds.
pub const WEBHOOK_TIMESTAMP_HEADER: &str = "x-openclaw-webhook-timestamp";
/// Header carrying the agent session key a delivery claims to target.
pub const WEBHOOK_SESSION_HEADER: &str = "x-openclaw-session-key";

/// Canonical path prefix of the frozen webhook dispatcher.
const CANONICAL_PATH_PREFIX: &str = "/plugins/webhooks/";

const MAX_ROUTE_ID_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 512;
const MAX_DELIVERY_ID_BYTES: usize = 128;
const DEFAULT_REPLAY_WINDOW: Duration = Duration::from_secs(300);
const DEFAULT_MAX_TRACKED_DELIVERIES: usize = 4096;
const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;

/// Reason a configured webhook path was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PathRejection {
    /// The path was empty or only whitespace.
    Empty,
    /// The path did not start with `/`.
    NotAbsolute,
    /// The path was longer than the accepted maximum.
    TooLong,
    /// The path carried a query string or fragment.
    QueryOrFragment,
    /// The path contained a byte outside printable US-ASCII.
    UnsupportedCharacter,
    /// The path contained an empty segment such as `/a//b`.
    EmptySegment,
    /// The path contained a `.` or `..` segment.
    RelativeSegment,
    /// The path contained a percent escape, which cannot be matched literally.
    PercentEncoded,
    /// The path resolved to the site root.
    Root,
}

impl fmt::Display for PathRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Empty => "path is empty",
            Self::NotAbsolute => "path must start with '/'",
            Self::TooLong => "path is too long",
            Self::QueryOrFragment => "path must not carry a query or fragment",
            Self::UnsupportedCharacter => "path must be printable US-ASCII",
            Self::EmptySegment => "path must not contain an empty segment",
            Self::RelativeSegment => "path must not contain a '.' or '..' segment",
            Self::PercentEncoded => "path must not be percent-encoded",
            Self::Root => "path must name at least one segment",
        };
        formatter.write_str(text)
    }
}

/// Reason a set of webhook route bindings could not be resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WebhookConfigError {
    /// A route identifier was empty, too long, or not `[A-Za-z0-9._-]+`.
    InvalidRouteId {
        /// The rejected identifier, as configured.
        route_id: String,
    },
    /// Two bindings declared the same route identifier.
    DuplicateRouteId {
        /// The repeated identifier.
        route_id: String,
    },
    /// A route declared an empty session key, so it would bind to nothing.
    EmptySessionKey {
        /// The route that omitted its session key.
        route_id: String,
    },
    /// A route declared a session key that cannot be carried as a header value.
    InvalidSessionKey {
        /// The route that declared the session key.
        route_id: String,
    },
    /// A route declared an empty secret, so every caller would authenticate.
    EmptySecret {
        /// The route that omitted its secret.
        route_id: String,
    },
    /// A route declared a path that is not a usable literal route.
    InvalidPath {
        /// The route that declared the path.
        route_id: String,
        /// The rejected path, as configured.
        path: String,
        /// Why the path was refused.
        reason: PathRejection,
    },
    /// Two routes resolved to the same served path.
    PathConflict {
        /// The contested path.
        path: String,
        /// The route that claimed the path second.
        route_id: String,
        /// The route that already held the path.
        existing_route_id: String,
    },
}

impl fmt::Display for WebhookConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRouteId { route_id } => {
                write!(
                    formatter,
                    "webhooks.routes.{route_id} has an invalid route id"
                )
            }
            Self::DuplicateRouteId { route_id } => {
                write!(formatter, "webhooks.routes.{route_id} is declared twice")
            }
            Self::EmptySessionKey { route_id } => {
                write!(
                    formatter,
                    "webhooks.routes.{route_id}.sessionKey must not be empty"
                )
            }
            Self::InvalidSessionKey { route_id } => {
                write!(
                    formatter,
                    "webhooks.routes.{route_id}.sessionKey is not a usable header value"
                )
            }
            Self::EmptySecret { route_id } => {
                write!(
                    formatter,
                    "webhooks.routes.{route_id}.secret must not be empty"
                )
            }
            Self::InvalidPath {
                route_id,
                path,
                reason,
            } => {
                write!(
                    formatter,
                    "webhooks.routes.{route_id}.path ({path}) is invalid: {reason}"
                )
            }
            Self::PathConflict {
                path,
                route_id,
                existing_route_id,
            } => {
                write!(
                    formatter,
                    "webhooks.routes.{route_id}.path conflicts with routes.{existing_route_id}.path ({path})"
                )
            }
        }
    }
}

impl Error for WebhookConfigError {}

/// One webhook route as an operator declares it.
#[derive(Clone, Debug)]
pub struct WebhookRouteBinding {
    route_id: String,
    path: Option<String>,
    session_key: String,
    secret_digest: [u8; 32],
    secret_present: bool,
    enabled: bool,
}

impl WebhookRouteBinding {
    /// Declares a route served at the canonical path with the given secret.
    ///
    /// The plaintext secret is hashed immediately and never retained.
    #[must_use]
    pub fn new(route_id: impl Into<String>, session_key: impl Into<String>, secret: &str) -> Self {
        Self {
            route_id: route_id.into(),
            path: None,
            session_key: session_key.into(),
            secret_digest: secret_digest(secret),
            secret_present: !secret.trim().is_empty(),
            enabled: true,
        }
    }

    /// Serves the route at an operator-chosen path instead of the default.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Enables or disables the route without removing its declaration.
    #[must_use]
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// One webhook route after validation, as it is actually served.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedWebhookRoute {
    route_id: String,
    path: String,
    session_key: String,
    secret_digest: [u8; 32],
}

impl ResolvedWebhookRoute {
    /// Returns the route identifier the frozen dispatcher receives.
    #[must_use]
    pub fn route_id(&self) -> &str {
        &self.route_id
    }

    /// Returns the operator-chosen path this route is served at.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the single agent session this route is bound to.
    #[must_use]
    pub fn session_key(&self) -> &str {
        &self.session_key
    }
}

/// Replay-suppression bounds shared by every guarded route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayPolicy {
    /// Accepted absolute clock skew, and the retention of one remembered delivery.
    ///
    /// One value governs both on purpose: a delivery may only be forgotten once
    /// replaying it would be refused as stale anyway.
    pub window: Duration,
    /// Hard ceiling on simultaneously remembered deliveries.
    pub max_tracked: usize,
}

impl Default for ReplayPolicy {
    fn default() -> Self {
        Self {
            window: DEFAULT_REPLAY_WINDOW,
            max_tracked: DEFAULT_MAX_TRACKED_DELIVERIES,
        }
    }
}

/// Validated guard configuration covering every served webhook path.
#[derive(Clone, Debug)]
pub struct WebhookGuardConfig {
    routes: BTreeMap<String, ResolvedWebhookRoute>,
    max_body_bytes: usize,
    replay: ReplayPolicy,
}

impl WebhookGuardConfig {
    /// Validates route declarations and resolves the paths they are served at.
    ///
    /// A disabled route is dropped before its path is considered, so disabling a
    /// route also frees the path it used to hold.
    pub fn resolve(
        bindings: impl IntoIterator<Item = WebhookRouteBinding>,
    ) -> Result<Self, WebhookConfigError> {
        let mut routes: BTreeMap<String, ResolvedWebhookRoute> = BTreeMap::new();
        let mut claimed_route_ids: BTreeMap<String, ()> = BTreeMap::new();

        for binding in bindings {
            let route_id = normalize_route_id(&binding.route_id).ok_or_else(|| {
                WebhookConfigError::InvalidRouteId {
                    route_id: binding.route_id.clone(),
                }
            })?;
            if claimed_route_ids.insert(route_id.clone(), ()).is_some() {
                return Err(WebhookConfigError::DuplicateRouteId { route_id });
            }
            if !binding.enabled {
                continue;
            }
            let session_key = binding.session_key.trim();
            if session_key.is_empty() {
                return Err(WebhookConfigError::EmptySessionKey { route_id });
            }
            if HeaderValue::from_str(session_key).is_err() {
                return Err(WebhookConfigError::InvalidSessionKey { route_id });
            }
            if !binding.secret_present {
                return Err(WebhookConfigError::EmptySecret { route_id });
            }
            let canonical = format!("{CANONICAL_PATH_PREFIX}{route_id}");
            let declared = binding.path.clone().unwrap_or_else(|| canonical.clone());
            let path = normalize_webhook_path(&declared).map_err(|reason| {
                WebhookConfigError::InvalidPath {
                    route_id: route_id.clone(),
                    path: declared.clone(),
                    reason,
                }
            })?;
            let resolved = ResolvedWebhookRoute {
                route_id: route_id.clone(),
                path: path.clone(),
                session_key: session_key.to_owned(),
                secret_digest: binding.secret_digest,
            };
            for served in [path, canonical] {
                if let Some(existing) = routes.get(&served) {
                    if existing.route_id == resolved.route_id {
                        continue;
                    }
                    return Err(WebhookConfigError::PathConflict {
                        path: served,
                        route_id: resolved.route_id.clone(),
                        existing_route_id: existing.route_id.clone(),
                    });
                }
                routes.insert(served, resolved.clone());
            }
        }

        Ok(Self {
            routes,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            replay: ReplayPolicy::default(),
        })
    }

    /// Replaces the maximum accepted webhook request body size.
    #[must_use]
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// Replaces the replay-suppression policy.
    #[must_use]
    pub fn with_replay_policy(mut self, replay: ReplayPolicy) -> Self {
        self.replay = replay;
        self
    }

    /// Returns the maximum accepted webhook request body size.
    #[must_use]
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Returns the replay-suppression policy.
    #[must_use]
    pub fn replay_policy(&self) -> ReplayPolicy {
        self.replay
    }

    /// Returns the route served at `path`, if the guard covers it.
    #[must_use]
    pub fn route_at(&self, path: &str) -> Option<&ResolvedWebhookRoute> {
        self.routes.get(lookup_key(path))
    }

    /// Returns every path the guard covers, in lexicographic order.
    pub fn served_paths(&self) -> impl Iterator<Item = &str> {
        self.routes.keys().map(String::as_str)
    }
}

/// Reason a delivery was refused before it reached the TaskFlow dispatcher.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WebhookRejection {
    /// The request used a method other than `POST`.
    MethodNotAllowed,
    /// No enabled route is served at the request path.
    UnknownRoute,
    /// No shared secret was presented.
    MissingSecret,
    /// The presented shared secret did not match the route secret.
    SecretMismatch,
    /// The `Content-Length` the caller declared exceeds the route body limit.
    DeclaredBodyTooLarge {
        /// Bytes the caller declared.
        declared_bytes: u64,
        /// Bytes the route accepts.
        limit_bytes: usize,
    },
    /// The streamed body exceeded the route body limit.
    BodyTooLarge {
        /// Bytes the route accepts.
        limit_bytes: usize,
    },
    /// The delivery identifier header was absent.
    MissingDeliveryId,
    /// The delivery identifier was empty, oversized, or not printable US-ASCII.
    MalformedDeliveryId,
    /// The delivery timestamp header was absent.
    MissingTimestamp,
    /// The delivery timestamp was not a whole number of seconds.
    MalformedTimestamp,
    /// The delivery timestamp fell outside the accepted window.
    TimestampOutsideWindow {
        /// Signed difference, in seconds, between now and the delivery timestamp.
        skew_seconds: i64,
        /// Accepted absolute skew, in seconds.
        tolerance_seconds: u64,
    },
    /// This delivery identifier was already accepted inside the replay window.
    ReplayedDelivery {
        /// The repeated delivery identifier.
        delivery_id: String,
    },
    /// The replay ledger is full of unexpired deliveries, so the guard failed closed.
    ReplayLedgerExhausted,
    /// The delivery claimed a session other than the one the route is bound to.
    SessionMismatch {
        /// The session the route is bound to. Never sent to the caller.
        expected: String,
        /// The session the caller claimed. Never sent to the caller.
        presented: String,
    },
}

impl WebhookRejection {
    /// Returns the HTTP status this rejection is answered with.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::UnknownRoute => StatusCode::NOT_FOUND,
            Self::MissingSecret | Self::SecretMismatch => StatusCode::UNAUTHORIZED,
            Self::DeclaredBodyTooLarge { .. } | Self::BodyTooLarge { .. } => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            Self::MissingDeliveryId
            | Self::MalformedDeliveryId
            | Self::MissingTimestamp
            | Self::MalformedTimestamp => StatusCode::BAD_REQUEST,
            Self::TimestampOutsideWindow { .. } | Self::SessionMismatch { .. } => {
                StatusCode::FORBIDDEN
            }
            Self::ReplayedDelivery { .. } => StatusCode::CONFLICT,
            Self::ReplayLedgerExhausted => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Returns the stable machine-readable code sent to the caller.
    ///
    /// Both authentication failures deliberately share one code, so the wire
    /// response never distinguishes "no secret" from "wrong secret".
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MethodNotAllowed => "method_not_allowed",
            Self::UnknownRoute => "not_found",
            Self::MissingSecret | Self::SecretMismatch => "unauthorized",
            Self::DeclaredBodyTooLarge { .. } | Self::BodyTooLarge { .. } => "payload_too_large",
            Self::MissingDeliveryId => "missing_delivery_id",
            Self::MalformedDeliveryId => "invalid_delivery_id",
            Self::MissingTimestamp => "missing_delivery_timestamp",
            Self::MalformedTimestamp => "invalid_delivery_timestamp",
            Self::TimestampOutsideWindow { .. } => "stale_delivery",
            Self::ReplayedDelivery { .. } => "replayed_delivery",
            Self::ReplayLedgerExhausted => "replay_ledger_exhausted",
            Self::SessionMismatch { .. } => "session_mismatch",
        }
    }

    /// Returns the human-readable message sent to the caller.
    ///
    /// The message never repeats caller-controlled or route-owned values, so a
    /// rejection cannot be used to enumerate secrets, sessions, or route ids.
    #[must_use]
    pub fn wire_message(&self) -> &'static str {
        match self {
            Self::MethodNotAllowed => "method not allowed",
            Self::UnknownRoute => "not found",
            Self::MissingSecret | Self::SecretMismatch => "unauthorized",
            Self::DeclaredBodyTooLarge { .. } | Self::BodyTooLarge { .. } => "payload too large",
            Self::MissingDeliveryId => "delivery id required",
            Self::MalformedDeliveryId => "delivery id invalid",
            Self::MissingTimestamp => "delivery timestamp required",
            Self::MalformedTimestamp => "delivery timestamp invalid",
            Self::TimestampOutsideWindow { .. } => "delivery timestamp outside accepted window",
            Self::ReplayedDelivery { .. } => "delivery already accepted",
            Self::ReplayLedgerExhausted => "replay ledger unavailable",
            Self::SessionMismatch { .. } => "session not bound to this route",
        }
    }
}

impl fmt::Display for WebhookRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.wire_message())
    }
}

impl Error for WebhookRejection {}

impl IntoResponse for WebhookRejection {
    fn into_response(self) -> Response {
        let mut response = json_response(
            self.status(),
            json!({"ok": false, "code": self.code(), "error": self.wire_message()}),
        );
        if matches!(self, Self::MethodNotAllowed) {
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("POST"));
        }
        response
    }
}

/// A delivery that passed every guard check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedWebhook {
    /// Route identifier the frozen dispatcher must be given.
    pub route_id: String,
    /// Session the delivery is bound to, regardless of what the caller claimed.
    pub session_key: String,
    /// Maximum body size the delivery may still stream.
    pub max_body_bytes: usize,
}

impl AdmittedWebhook {
    /// Rewrites the session header the dispatcher will see to the bound key.
    ///
    /// The header is set, never appended, so a delivery can never reach the
    /// dispatcher carrying two session keys — one the guard checked and one it
    /// never saw. A caller that presents no session header is bound just as
    /// firmly as one that presents the correct key.
    ///
    /// Session keys are validated as header values when the route is resolved,
    /// so this cannot fail.
    pub fn seal_session_binding(&self, headers: &mut HeaderMap) {
        let value = HeaderValue::from_str(&self.session_key)
            .expect("resolved session keys are valid header values");
        headers.insert(HeaderName::from_static(WEBHOOK_SESSION_HEADER), value);
    }
}

/// Source of wall-clock time for delivery-timestamp checks.
pub trait WebhookClock: fmt::Debug + Send + Sync {
    /// Returns the current Unix time in whole seconds.
    fn unix_seconds(&self) -> i64;
}

/// Wall-clock source backed by the host clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemWebhookClock;

impl WebhookClock for SystemWebhookClock {
    fn unix_seconds(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
            .unwrap_or(0)
    }
}

#[derive(Debug, Default)]
struct ReplayLedger {
    seen: HashMap<(String, String), i64>,
}

impl ReplayLedger {
    fn admit(
        &mut self,
        route_id: &str,
        delivery_id: &str,
        expires_at: i64,
        now: i64,
        max_tracked: usize,
    ) -> Result<(), WebhookRejection> {
        self.seen
            .retain(|_, entry_expires_at| *entry_expires_at > now);
        let key = (route_id.to_owned(), delivery_id.to_owned());
        if self.seen.contains_key(&key) {
            return Err(WebhookRejection::ReplayedDelivery {
                delivery_id: delivery_id.to_owned(),
            });
        }
        if self.seen.len() >= max_tracked {
            return Err(WebhookRejection::ReplayLedgerExhausted);
        }
        self.seen.insert(key, expires_at);
        Ok(())
    }
}

/// Admission guard for every configured webhook path.
#[derive(Debug)]
pub struct WebhookGuard {
    config: WebhookGuardConfig,
    clock: Arc<dyn WebhookClock>,
    ledger: Mutex<ReplayLedger>,
}

impl WebhookGuard {
    /// Builds a guard driven by the host clock.
    #[must_use]
    pub fn new(config: WebhookGuardConfig) -> Self {
        Self::with_clock(config, Arc::new(SystemWebhookClock))
    }

    /// Builds a guard driven by an injected clock.
    #[must_use]
    pub fn with_clock(config: WebhookGuardConfig, clock: Arc<dyn WebhookClock>) -> Self {
        Self {
            config,
            clock,
            ledger: Mutex::new(ReplayLedger::default()),
        }
    }

    /// Returns the resolved configuration this guard enforces.
    #[must_use]
    pub fn config(&self) -> &WebhookGuardConfig {
        &self.config
    }

    /// Decides whether one delivery may reach the TaskFlow dispatcher.
    ///
    /// The checks are ordered so that a caller can only reach a more expensive
    /// stage by passing every cheaper one: an unauthenticated caller can never
    /// place an entry in the replay ledger, and a caller that fails the session
    /// binding never consumes its delivery identifier.
    pub fn admit(
        &self,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        declared_body_bytes: Option<u64>,
    ) -> Result<AdmittedWebhook, WebhookRejection> {
        let route = self
            .config
            .route_at(path)
            .ok_or(WebhookRejection::UnknownRoute)?;
        if method != Method::POST {
            return Err(WebhookRejection::MethodNotAllowed);
        }
        let limit_bytes = self.config.max_body_bytes;
        if let Some(declared_bytes) = declared_body_bytes
            && declared_bytes > limit_bytes as u64
        {
            return Err(WebhookRejection::DeclaredBodyTooLarge {
                declared_bytes,
                limit_bytes,
            });
        }

        let presented_secret = presented_secret(headers);
        if presented_secret.is_empty() {
            return Err(WebhookRejection::MissingSecret);
        }
        if !secret_matches(&route.secret_digest, presented_secret) {
            return Err(WebhookRejection::SecretMismatch);
        }

        let delivery_id = header_str(headers, WEBHOOK_DELIVERY_HEADER)
            .ok_or(WebhookRejection::MissingDeliveryId)?;
        if !is_valid_delivery_id(delivery_id) {
            return Err(WebhookRejection::MalformedDeliveryId);
        }
        let timestamp = header_str(headers, WEBHOOK_TIMESTAMP_HEADER)
            .ok_or(WebhookRejection::MissingTimestamp)?
            .parse::<i64>()
            .map_err(|_| WebhookRejection::MalformedTimestamp)?;
        let now = self.clock.unix_seconds();
        let tolerance_seconds =
            i64::try_from(self.config.replay.window.as_secs()).unwrap_or(i64::MAX);
        let skew_seconds = now.saturating_sub(timestamp);
        if skew_seconds.saturating_abs() > tolerance_seconds {
            return Err(WebhookRejection::TimestampOutsideWindow {
                skew_seconds,
                tolerance_seconds: self.config.replay.window.as_secs(),
            });
        }

        if let Some(presented_session) = header_str(headers, WEBHOOK_SESSION_HEADER)
            && !session_matches(&route.session_key, presented_session)
        {
            return Err(WebhookRejection::SessionMismatch {
                expected: route.session_key.clone(),
                presented: presented_session.to_owned(),
            });
        }

        let expires_at = timestamp.saturating_add(tolerance_seconds);
        self.ledger
            .lock()
            .map_err(|_| WebhookRejection::ReplayLedgerExhausted)?
            .admit(
                &route.route_id,
                delivery_id,
                expires_at,
                now,
                self.config.replay.max_tracked,
            )?;

        Ok(AdmittedWebhook {
            route_id: route.route_id.clone(),
            session_key: route.session_key.clone(),
            max_body_bytes: limit_bytes,
        })
    }
}

/// Wraps `inner` so every guarded webhook path is admitted before dispatch.
pub(crate) fn guard_router(inner: Router, guard: WebhookGuard) -> Router {
    Router::new()
        .fallback_service(inner)
        .layer(middleware::from_fn_with_state(Arc::new(guard), enforce))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(self), geolocation=()"),
        ))
}

async fn enforce(State(guard): State<Arc<WebhookGuard>>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    if guard.config.route_at(&path).is_none() {
        return next.run(request).await;
    }
    let declared_body_bytes = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    let admitted = match guard.admit(
        request.method(),
        &path,
        request.headers(),
        declared_body_bytes,
    ) {
        Ok(admitted) => admitted,
        Err(rejection) => return rejection.into_response(),
    };

    let (mut parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, admitted.max_body_bytes).await else {
        return WebhookRejection::BodyTooLarge {
            limit_bytes: admitted.max_body_bytes,
        }
        .into_response();
    };

    admitted.seal_session_binding(&mut parts.headers);
    parts.headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string())
            .expect("byte length renders as a header value"),
    );
    parts.uri = dispatch_uri(&parts.uri, &admitted.route_id);
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

fn dispatch_uri(original: &Uri, route_id: &str) -> Uri {
    let mut parts = original.clone().into_parts();
    let path_and_query = match original.query() {
        Some(query) => format!("{CANONICAL_PATH_PREFIX}{route_id}?{query}"),
        None => format!("{CANONICAL_PATH_PREFIX}{route_id}"),
    };
    parts.path_and_query = Some(
        PathAndQuery::try_from(path_and_query)
            .expect("validated route ids and queries form a path"),
    );
    Uri::from_parts(parts).expect("rewriting only the path preserves URI validity")
}

/// Returns the SHA-256 digest of a webhook secret.
///
/// Only the digest is retained, and every comparison is made over two fixed
/// 32-byte digests, so comparison time cannot depend on the secret length or on
/// the position of the first differing byte.
#[must_use]
fn secret_digest(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

fn secret_matches(expected: &[u8; 32], presented: &str) -> bool {
    let presented = secret_digest(presented);
    bool::from(expected.ct_eq(&presented))
}

fn session_matches(expected: &str, presented: &str) -> bool {
    let expected = secret_digest(expected);
    let presented = secret_digest(presented.trim());
    bool::from(expected.ct_eq(&presented))
}

fn presented_secret(headers: &HeaderMap) -> &str {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        && let Some((scheme, token)) = value.split_once(' ')
        && scheme.eq_ignore_ascii_case("bearer")
        && !token.trim().is_empty()
    {
        return token.trim();
    }
    header_str(headers, WEBHOOK_SECRET_HEADER).unwrap_or("")
}

fn header_str<'headers>(headers: &'headers HeaderMap, name: &str) -> Option<&'headers str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn is_valid_delivery_id(delivery_id: &str) -> bool {
    !delivery_id.is_empty()
        && delivery_id.len() <= MAX_DELIVERY_ID_BYTES
        && delivery_id.bytes().all(|byte| byte.is_ascii_graphic())
}

fn normalize_route_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_ROUTE_ID_BYTES {
        return None;
    }
    if trimmed == "." || trimmed == ".." {
        return None;
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(trimmed.to_owned())
}

fn normalize_webhook_path(raw: &str) -> Result<String, PathRejection> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PathRejection::Empty);
    }
    if trimmed.len() > MAX_PATH_BYTES {
        return Err(PathRejection::TooLong);
    }
    if trimmed.contains(['?', '#']) {
        return Err(PathRejection::QueryOrFragment);
    }
    if !trimmed.starts_with('/') {
        return Err(PathRejection::NotAbsolute);
    }
    if !trimmed.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(PathRejection::UnsupportedCharacter);
    }
    let core = trimmed.strip_suffix('/').unwrap_or(trimmed);
    if core.is_empty() {
        return Err(PathRejection::Root);
    }
    for segment in core.split('/').skip(1) {
        if segment.is_empty() {
            return Err(PathRejection::EmptySegment);
        }
        if segment == "." || segment == ".." {
            return Err(PathRejection::RelativeSegment);
        }
        if segment.contains('%') {
            return Err(PathRejection::PercentEncoded);
        }
    }
    Ok(core.to_owned())
}

fn lookup_key(path: &str) -> &str {
    match path.strip_suffix('/') {
        Some(stripped) if !stripped.is_empty() => stripped,
        _ => path,
    }
}
