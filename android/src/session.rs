//! Shared attempt bookkeeping and Gateway client configuration for Android.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use claw_gateway_client::{
    AuthorizationExpectation, ClientLimits, ClientMetadata, ClientTimeouts, GatewayClientConfig,
    GatewayCredential, ReconnectPolicy,
};
use claw_protocol::gateway::{ClientId, ClientMode, Name};
use claw_security::authorization::{Role, Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;

use crate::onboarding::ConnectRequest;

/// Longest accepted Gateway client metadata string, in bytes.
const MAX_METADATA_BYTES: usize = 64;

/// Records which connection attempt currently owns the single Gateway socket.
///
/// The controller commits to a generation here *before* it awaits the transport.
/// Ownership is handed back by [`AttemptLease`]'s `Drop`, so cancelling the task
/// — which drops the future at whatever suspension point it reached — releases
/// the slot just as reliably as running to completion.
#[derive(Debug, Default)]
pub struct AttemptSlot {
    active: Mutex<Option<u64>>,
}

impl AttemptSlot {
    /// Creates an idle slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active: Mutex::new(None),
        }
    }

    /// Takes ownership for `generation`, or returns `None` if the slot is busy.
    ///
    /// The lease is `'static` so a spawned task can hold it across `.await`.
    #[must_use]
    pub fn acquire(self: &Arc<Self>, generation: u64) -> Option<AttemptLease> {
        let mut active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        if active.is_some() {
            return None;
        }
        *active = Some(generation);
        Some(AttemptLease {
            slot: Arc::clone(self),
            generation,
        })
    }

    /// Returns the generation currently owning the slot.
    #[must_use]
    pub fn active_generation(&self) -> Option<u64> {
        *self.active.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns whether no attempt owns the slot.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.active_generation().is_none()
    }

    fn release(&self, generation: u64) {
        let mut active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        if *active == Some(generation) {
            *active = None;
        }
    }
}

/// Ownership of [`AttemptSlot`] for one generation, released on drop.
#[derive(Debug)]
pub struct AttemptLease {
    slot: Arc<AttemptSlot>,
    generation: u64,
}

impl AttemptLease {
    /// Returns the generation this lease owns.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for AttemptLease {
    fn drop(&mut self) {
        self.slot.release(self.generation);
    }
}

/// Returns the Gateway client identity this app declares on every connection.
///
/// `ClientId::Android` is the wire identity `openclaw-android`, and this is the
/// first in-tree client to declare it.
#[must_use]
pub fn android_client_metadata() -> ClientMetadata {
    ClientMetadata {
        id: ClientId::Android,
        display_name: Name::new("GTA Claw Android", MAX_METADATA_BYTES).ok(),
        version: Name::new(env!("CARGO_PKG_VERSION"), MAX_METADATA_BYTES)
            .expect("package version is non-empty and short"),
        platform: Name::new(std::env::consts::OS, MAX_METADATA_BYTES)
            .expect("target OS is non-empty and short"),
        device_family: Name::new("android", MAX_METADATA_BYTES).ok(),
        model_identifier: None,
        mode: ClientMode::Ui,
        instance_id: None,
    }
}

/// Builds the transport configuration for one validated request.
///
/// The plaintext opt-in is taken from the request rather than recomputed, so the
/// value the operator agreed to is the value the transport enforces.
#[must_use]
pub fn build_client_config(
    request: ConnectRequest,
    identity: Arc<DeviceIdentity>,
) -> GatewayClientConfig {
    let (url, token, allow_insecure_remote_ws) = request.into_parts();
    let mut config = GatewayClientConfig::new(url, identity);
    config.credential = token.map_or(GatewayCredential::None, GatewayCredential::Token);
    config.role = Role::Operator;
    config.scopes = ScopeSet::from_scopes([Scope::OperatorRead]);
    config.authorization_expectation = AuthorizationExpectation::ExactRequested;
    config.client = android_client_metadata();
    config.allow_insecure_remote_ws = allow_insecure_remote_ws;
    // Handsets have far less memory headroom than the desktop shell and roam
    // between radios, so the queues are smaller and the timeouts are longer.
    config.limits = ClientLimits {
        max_in_flight_requests: 4,
        command_queue_capacity: 8,
        outbound_queue_bytes: 32 * 1024,
        event_queue_capacity: 16,
        event_queue_bytes: 64 * 1024,
        completed_id_capacity: 32,
    };
    config.timeouts = ClientTimeouts {
        connect: Duration::from_secs(15),
        authentication: Duration::from_secs(15),
        request: Duration::from_secs(20),
        shutdown: Duration::from_secs(3),
    };
    config.reconnect = ReconnectPolicy::Bounded {
        max_attempts: 4,
        initial_delay: Duration::from_millis(500),
        max_delay: Duration::from_secs(8),
        max_jitter: Duration::from_millis(250),
    };
    config
}

#[cfg(test)]
mod tests {
    use std::future::{Future, pending};
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    use claw_gateway_client::{AuthorizationExpectation, GatewayCredential};
    use claw_protocol::gateway::{ClientId, ClientMode};
    use claw_security::authorization::{Role, Scope, ScopeSet};
    use claw_security::identity::DeviceIdentity;
    use getrandom::SysRng;
    use getrandom::rand_core::UnwrapErr;

    use crate::onboarding::ConnectRequest;

    use super::{AttemptSlot, android_client_metadata, build_client_config};

    fn test_identity() -> Arc<DeviceIdentity> {
        let mut rng = UnwrapErr(SysRng);
        Arc::new(DeviceIdentity::generate(&mut rng))
    }

    /// Mirrors the controller's shape: commit the slot, then suspend.
    async fn hold_lease(slot: Arc<AttemptSlot>, generation: u64) {
        let Some(_lease) = slot.acquire(generation) else {
            return;
        };
        pending::<()>().await;
    }

    #[test]
    fn dropping_a_suspended_attempt_future_releases_the_slot() {
        let slot = Arc::new(AttemptSlot::new());
        // `Box::pin` rather than `pin!`: dropping a `Pin<&mut F>` is a no-op, so
        // a stack-pinned future would leave the real future alive and the test
        // would prove nothing.
        let mut future = Box::pin(hold_lease(Arc::clone(&slot), 7));
        let mut context = Context::from_waker(Waker::noop());

        let polled = future.as_mut().poll(&mut context);

        assert_eq!(
            polled,
            Poll::Pending,
            "the attempt future must suspend while holding the slot, got {polled:?}"
        );
        assert_eq!(
            slot.active_generation(),
            Some(7),
            "the slot must be committed before the await, got {:?}",
            slot.active_generation()
        );

        // Drop the suspended future outright rather than driving it to completion:
        // this is what task cancellation actually does.
        drop(future);

        assert_eq!(
            slot.active_generation(),
            None,
            "dropping the suspended future must release the slot, got {:?}",
            slot.active_generation()
        );
        assert!(
            slot.is_idle(),
            "the slot must report idle after release, got {:?}",
            slot.active_generation()
        );
    }

    #[test]
    fn a_busy_slot_refuses_a_second_attempt() {
        let slot = Arc::new(AttemptSlot::new());
        let first = slot.acquire(1).expect("the idle slot must grant a lease");

        let second = slot.acquire(2);

        assert!(
            second.is_none(),
            "a busy slot must refuse a second lease, active generation was {:?}",
            slot.active_generation()
        );
        assert_eq!(
            first.generation(),
            1,
            "the first lease must retain its generation, got {first:?}"
        );

        drop(first);

        assert!(
            slot.acquire(2).is_some(),
            "the slot must be reusable after release, active generation was {:?}",
            slot.active_generation()
        );
    }

    #[test]
    fn a_late_release_does_not_evict_the_current_owner() {
        let slot = Arc::new(AttemptSlot::new());
        let first = slot.acquire(1).expect("the idle slot must grant a lease");
        drop(first);
        let second = slot
            .acquire(2)
            .expect("the released slot must grant a lease");

        assert_eq!(
            slot.active_generation(),
            Some(2),
            "generation 2 must own the slot, got {:?}",
            slot.active_generation()
        );

        drop(second);
    }

    #[test]
    fn the_client_declares_the_android_wire_identity() {
        let metadata = android_client_metadata();

        assert_eq!(
            metadata.id,
            ClientId::Android,
            "the Android app must declare ClientId::Android, got {:?}",
            metadata.id
        );
        assert_eq!(
            metadata.mode,
            ClientMode::Ui,
            "the Android app is an interactive UI client, got {:?}",
            metadata.mode
        );
        assert_eq!(
            metadata.id.as_str(),
            "openclaw-android",
            "the wire identity must be openclaw-android, got {:?}",
            metadata.id.as_str()
        );
    }

    #[test]
    fn the_plaintext_opt_in_reaches_the_transport_configuration() {
        for accepted in [false, true] {
            let request = ConnectRequest::prepare("ws://gateway.example.com", "", accepted);
            let Ok(request) = request else {
                assert!(
                    !accepted,
                    "the opt-in must make remote plaintext acceptable, got {request:?}"
                );
                continue;
            };

            let config = build_client_config(request, test_identity());

            assert_eq!(
                config.allow_insecure_remote_ws, accepted,
                "the transport must enforce exactly the operator's choice ({accepted}), got {}",
                config.allow_insecure_remote_ws
            );
        }
    }

    #[test]
    fn a_supplied_token_becomes_a_token_credential() {
        let request = ConnectRequest::prepare("wss://gateway.example.com", "shared-token", false)
            .expect("a valid request");

        let config = build_client_config(request, test_identity());

        assert!(
            matches!(config.credential, GatewayCredential::Token(_)),
            "a supplied token must become a Token credential, got {:?}",
            config.credential
        );
    }

    #[test]
    fn an_absent_token_leaves_device_policy_in_charge() {
        let request =
            ConnectRequest::prepare("wss://gateway.example.com", "   ", false).expect("valid");

        let config = build_client_config(request, test_identity());

        assert!(
            matches!(config.credential, GatewayCredential::None),
            "a blank token must not fabricate a credential, got {:?}",
            config.credential
        );
    }

    #[test]
    fn the_configuration_requests_exactly_the_authorization_it_will_verify() {
        let request =
            ConnectRequest::prepare("wss://gateway.example.com", "", false).expect("valid");

        let config = build_client_config(request, test_identity());

        assert_eq!(
            config.role,
            Role::Operator,
            "the Android client is an operator, got {:?}",
            config.role
        );
        assert_eq!(
            config.scopes,
            ScopeSet::from_scopes([Scope::OperatorRead]),
            "the client must request only read scope, got {:?}",
            config.scopes
        );
        assert_eq!(
            config.authorization_expectation,
            AuthorizationExpectation::ExactRequested,
            "the client must reject a hello that grants something other than what it asked for, got {:?}",
            config.authorization_expectation
        );
    }

    #[test]
    fn the_configuration_validates_against_the_transport_policy() {
        let request =
            ConnectRequest::prepare("wss://gateway.example.com", "", false).expect("valid");

        let config = build_client_config(request, test_identity());
        let rendered = format!("{config:?}");

        assert!(
            !rendered.contains("REDACTED\", \"REDACTED"),
            "sanity: the Debug rendering must still be structured, got {rendered}"
        );
        assert!(
            rendered.contains("gateway.example.com"),
            "the Debug rendering must identify the endpoint host, got {rendered}"
        );
    }

    #[test]
    fn configuration_debug_never_reproduces_the_token() {
        let request =
            ConnectRequest::prepare("wss://gateway.example.com", "super-secret-token", false)
                .expect("valid");

        let config = build_client_config(request, test_identity());
        let rendered = format!("{config:?}");

        assert!(
            !rendered.contains("super-secret-token"),
            "the transport configuration Debug leaked the token: {rendered}"
        );
    }
}
