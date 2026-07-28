//! Durable Gateway device grants administered through authenticated HTTP RPC.
//!
//! Approved grants are atomically persisted before they enter the live
//! [`DeviceDirectory`]. Pending requests are a bounded ten-minute, process-local
//! handshake cache: a reconnect recreates one when needed, which keeps
//! authentication free of filesystem I/O and prevents abandoned requests from
//! permanently consuming pairing capacity.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use claw_config::write_bytes_atomically;
use claw_gateway::{
    AuthorizationSource, Clock, CredentialPolicy, DeviceDirectory, Grant, StaticAuthenticator,
};
use claw_http_api::{PortError, PortErrorKind};
use claw_protocol::gateway::{
    AuthenticationDecision, AuthenticationPort, AuthenticationRequest, ConnectErrorDetailCode,
    HandshakeRejection, OperatorScope, PairingRequiredCode, PairingRequiredDetails,
    PairingRequiredReason, Role,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::http_api::GatewayPairingAdmin;

const PAIRING_SCHEMA_VERSION: u32 = 1;
const MAX_PAIRING_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PAIRINGS: usize = 4096;
const MAX_PENDING_PAIRINGS: usize = 4096;
const MAX_SCOPES_PER_PAIRING: usize = 6;
const MAX_REQUEST_ID_BYTES: usize = 128;
const PENDING_PAIRING_TTL: Duration = Duration::from_mins(10);

static PENDING_REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static PAIRING_RUNTIMES: OnceLock<Mutex<BTreeMap<PathBuf, Weak<PairingRuntime>>>> = OnceLock::new();

const fn pairing_schema_version() -> u32 {
    PAIRING_SCHEMA_VERSION
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StoredPairing {
    device_id: String,
    role: Role,
    scopes: Vec<OperatorScope>,
}

#[derive(Clone, Debug)]
struct StoredPendingPairing {
    request_id: String,
    device_id: String,
    role: Role,
    scopes: Vec<OperatorScope>,
    created_at_ms: u64,
    refreshed_at_ms: u64,
}

#[derive(Debug, Default)]
struct PendingPairingState {
    queued: BTreeMap<String, StoredPendingPairing>,
    approving: BTreeMap<String, StoredPendingPairing>,
}

#[derive(Debug, Default)]
struct PairingRuntime {
    mutation_gate: Mutex<()>,
    pairings: Mutex<BTreeMap<String, StoredPairing>>,
    devices: DeviceDirectory,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingDocument {
    #[serde(default = "pairing_schema_version")]
    schema_version: u32,
    pairings: Vec<StoredPairing>,
}

#[derive(Debug)]
enum PendingRegistration {
    Granted,
    Pending(String),
}

#[cfg(test)]
#[derive(Debug)]
struct PairingTestPause {
    reached: std::sync::Barrier,
    release: std::sync::Barrier,
}

#[cfg(test)]
impl PairingTestPause {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            reached: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        })
    }

    fn pause(&self) {
        self.reached.wait();
        self.release.wait();
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct PairingTestHooks {
    approval_before_mutation: Mutex<Option<Arc<PairingTestPause>>>,
    approval_reserved: Mutex<Option<Arc<PairingTestPause>>>,
    remove_before_mutation: Mutex<Option<Arc<std::sync::Barrier>>>,
}

#[cfg(test)]
impl PairingTestHooks {
    fn pause_once(slot: &Mutex<Option<Arc<PairingTestPause>>>) {
        let pause = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(pause) = pause {
            pause.pause();
        }
    }

    fn wait_once(slot: &Mutex<Option<Arc<std::sync::Barrier>>>) {
        let barrier = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(barrier) = barrier {
            barrier.wait();
        }
    }
}

/// One durable pairing file and the live Gateway grant directory it feeds.
#[derive(Debug)]
pub struct GatewayPairingStore {
    path: PathBuf,
    mutation_lock_path: PathBuf,
    runtime: Arc<PairingRuntime>,
    pending: Mutex<PendingPairingState>,
    durability_warnings: AtomicU64,
    #[cfg(test)]
    test_hooks: PairingTestHooks,
}

impl GatewayPairingStore {
    /// Opens and validates the durable pairing file.
    ///
    /// # Errors
    ///
    /// Returns a safe error when the file cannot be read, contains malformed or
    /// duplicate grants, or cannot be initialized durably.
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<Self>, String> {
        let path = prepare_pairing_path(path.as_ref())?;
        let mutation_lock_path = pairing_lock_path(&path)?;
        let runtime = pairing_runtime(&mutation_lock_path);
        let initial_warnings = {
            let _process_lock = runtime
                .mutation_gate
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let _file_lock = acquire_pairing_lock(&mutation_lock_path)?;
            let (pairings, warnings) = load_or_initialize_pairings(&path)?;
            let mut held = runtime
                .pairings
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            reconcile_pairing_directory(&runtime.devices, &held, &pairings, None);
            *held = pairings;
            warnings
        };
        Ok(Arc::new(Self {
            path,
            mutation_lock_path,
            runtime,
            pending: Mutex::new(PendingPairingState::default()),
            durability_warnings: AtomicU64::new(initial_warnings as u64),
            #[cfg(test)]
            test_hooks: PairingTestHooks::default(),
        }))
    }

    /// Returns the live directory shared by handshake and connection policy.
    #[must_use]
    pub fn devices(&self) -> DeviceDirectory {
        self.runtime.devices.clone()
    }

    /// Returns the number of durable grants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.runtime
            .pairings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Reports whether no durable device grant exists.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn list(&self, node: bool) -> Value {
        let mut pending_state = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        prune_pending(&mut pending_state.queued, unix_millis());
        let pending = pending_state
            .queued
            .values()
            .filter(|pending| !node || pending.role == Role::Node)
            .map(|pending| render_pending(pending, node))
            .collect::<Vec<_>>();
        drop(pending_state);
        let pairings = self
            .runtime
            .pairings
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let paired = pairings
            .values()
            .filter(|pairing| !node || pairing.role == Role::Node)
            .map(|pairing| render_pairing(pairing, node))
            .collect::<Vec<_>>();
        drop(pairings);
        json!({
            "pending": pending,
            "paired": paired,
            "durabilityWarnings": self.durability_warnings.load(Ordering::Acquire),
        })
    }

    fn approve(&self, method: &str, params: Option<&Value>) -> Result<Value, PortError> {
        let request_id =
            exact_string_param(params, "requestId", valid_request_id).ok_or_else(|| {
                PortError::new(
                    PortErrorKind::InvalidRequest,
                    "pair approval requires a canonical requestId",
                )
            })?;
        let node = method.starts_with("node.");
        #[cfg(test)]
        PairingTestHooks::pause_once(&self.test_hooks.approval_before_mutation);
        self.with_durable_mutation(|| {
            let pending = {
                let mut pending_state = self.pending.lock().map_err(|_| {
                    PortError::new(PortErrorKind::Internal, "gateway pairing state unavailable")
                })?;
                prune_pending(&mut pending_state.queued, unix_millis());
                let pending = pending_state
                    .queued
                    .get(request_id)
                    .cloned()
                    .ok_or_else(|| {
                        PortError::new(PortErrorKind::InvalidRequest, "unknown requestId")
                    })?;
                if node && pending.role != Role::Node {
                    return Err(PortError::new(
                        PortErrorKind::InvalidRequest,
                        "pair approval request belongs to a different pairing surface",
                    ));
                }
                pending_state.queued.remove(request_id);
                pending_state
                    .approving
                    .insert(request_id.to_owned(), pending.clone());
                pending
            };
            #[cfg(test)]
            PairingTestHooks::pause_once(&self.test_hooks.approval_reserved);
            let result = self.commit_approval(request_id, node, &pending);
            if result.is_err() {
                self.restore_pending(pending);
            }
            result
        })
    }

    fn commit_approval(
        &self,
        request_id: &str,
        node: bool,
        pending: &StoredPendingPairing,
    ) -> Result<Value, PortError> {
        let mut candidate = load_pairings(&self.path)
            .map_err(|error| PortError::new(PortErrorKind::Unavailable, error))?;
        if !candidate.contains_key(&pending.device_id) && candidate.len() >= MAX_PAIRINGS {
            return Err(PortError::new(
                PortErrorKind::InvalidRequest,
                "gateway pairing capacity is exhausted",
            ));
        }
        let mut approved_scopes = pending.scopes.clone();
        if let Some(existing) = candidate.get(&pending.device_id)
            && existing.role == pending.role
        {
            approved_scopes.extend(existing.scopes.iter().copied());
            approved_scopes.sort_unstable();
            approved_scopes.dedup();
        }
        let pairing = StoredPairing {
            device_id: pending.device_id.clone(),
            role: pending.role,
            scopes: approved_scopes,
        };
        candidate.insert(pairing.device_id.clone(), pairing.clone());
        let mut held = self.runtime.pairings.lock().map_err(|_| {
            PortError::new(PortErrorKind::Internal, "gateway pairing state unavailable")
        })?;
        let warnings = persist_pairings(&self.path, &candidate)
            .map_err(|error| PortError::new(PortErrorKind::Unavailable, error))?;
        reconcile_pairing_directory(
            &self.runtime.devices,
            &held,
            &candidate,
            Some(&pairing.device_id),
        );
        let generation = self.runtime.devices.pair(
            pairing.device_id.clone(),
            Grant::new(pairing.role, pairing.scopes.iter().copied()),
        );
        *held = candidate;
        drop(held);
        self.complete_approval(request_id, &pairing);
        self.record_durability_warnings(warnings);
        let subject = render_pairing(&pairing, node);
        let mut payload = json!({
            "requestId": request_id,
            "generation": generation,
            "durable": warnings == 0,
        });
        payload[if node { "node" } else { "device" }] = subject;
        Ok(payload)
    }

    fn reject(&self, method: &str, params: Option<&Value>) -> Result<Value, PortError> {
        let request_id =
            exact_string_param(params, "requestId", valid_request_id).ok_or_else(|| {
                PortError::new(
                    PortErrorKind::InvalidRequest,
                    "pair rejection requires a canonical requestId",
                )
            })?;
        let node = method.starts_with("node.");
        let mut held = self.pending.lock().map_err(|_| {
            PortError::new(PortErrorKind::Internal, "gateway pairing state unavailable")
        })?;
        prune_pending(&mut held.queued, unix_millis());
        let pending =
            held.queued.get(request_id).cloned().ok_or_else(|| {
                PortError::new(PortErrorKind::InvalidRequest, "unknown requestId")
            })?;
        if node && pending.role != Role::Node {
            return Err(PortError::new(
                PortErrorKind::InvalidRequest,
                "pair rejection request belongs to a different pairing surface",
            ));
        }
        held.queued.remove(request_id);
        drop(held);
        let mut payload = json!({
            "requestId": request_id,
            "decision": "rejected",
        });
        payload[if node { "nodeId" } else { "deviceId" }] = json!(pending.device_id);
        Ok(payload)
    }

    fn remove(&self, method: &str, params: Option<&Value>) -> Result<Value, PortError> {
        let node = method.starts_with("node.");
        let key = if node { "nodeId" } else { "deviceId" };
        let device_id = exact_string_param(params, key, valid_device_id).ok_or_else(|| {
            PortError::new(
                PortErrorKind::InvalidRequest,
                format!("pair removal requires a canonical {key}"),
            )
        })?;
        #[cfg(test)]
        PairingTestHooks::wait_once(&self.test_hooks.remove_before_mutation);
        self.with_durable_mutation(|| {
            let mut candidate = load_pairings(&self.path)
                .map_err(|error| PortError::new(PortErrorKind::Unavailable, error))?;
            let pairing = candidate.get(device_id).ok_or_else(|| {
                PortError::new(PortErrorKind::InvalidRequest, format!("unknown {key}"))
            })?;
            if node && pairing.role != Role::Node {
                return Err(PortError::new(
                    PortErrorKind::InvalidRequest,
                    "pair removal target belongs to a different pairing surface",
                ));
            }
            let removed = candidate.remove(device_id).is_some();
            let mut held = self.runtime.pairings.lock().map_err(|_| {
                PortError::new(PortErrorKind::Internal, "gateway pairing state unavailable")
            })?;
            let warnings = persist_pairings(&self.path, &candidate)
                .map_err(|error| PortError::new(PortErrorKind::Unavailable, error))?;
            reconcile_pairing_directory(&self.runtime.devices, &held, &candidate, None);
            *held = candidate;
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            pending
                .queued
                .retain(|_, request| request.device_id != device_id);
            pending
                .approving
                .retain(|_, request| request.device_id != device_id);
            drop(pending);
            drop(held);
            self.record_durability_warnings(warnings);
            let mut payload = json!({
                "removed": removed,
                "durable": warnings == 0,
            });
            payload[key] = json!(device_id);
            Ok(payload)
        })
    }

    fn record_pending(
        &self,
        device_id: &str,
        role: Role,
        mut scopes: Vec<OperatorScope>,
    ) -> Result<PendingRegistration, String> {
        scopes.sort_unstable();
        scopes.dedup();
        validate_pending_fields(device_id, role, &scopes)?;
        if self.grant_satisfies(device_id, role, &scopes) {
            return Ok(PendingRegistration::Granted);
        }
        let mut held = self
            .pending
            .lock()
            .map_err(|_| "gateway pairing state unavailable".to_owned())?;
        let now_ms = unix_millis();
        prune_pending(&mut held.queued, now_ms);
        if self.grant_satisfies(device_id, role, &scopes) {
            return Ok(PendingRegistration::Granted);
        }
        if self.runtime.devices.current_grant(device_id).is_none()
            && self.runtime.devices.len() >= MAX_PAIRINGS
        {
            return Err("gateway pairing capacity is exhausted".to_owned());
        }
        if let Some(existing) = held.queued.values_mut().find(|existing| {
            existing.device_id == device_id && existing.role == role && existing.scopes == scopes
        }) {
            existing.refreshed_at_ms = now_ms;
            return Ok(PendingRegistration::Pending(existing.request_id.clone()));
        }
        if let Some(existing) = held.approving.values().find(|existing| {
            existing.device_id == device_id && existing.role == role && existing.scopes == scopes
        }) {
            return Ok(PendingRegistration::Pending(existing.request_id.clone()));
        }
        if held.queued.len().saturating_add(held.approving.len()) >= MAX_PENDING_PAIRINGS {
            return Err("gateway pending pairing capacity is exhausted".to_owned());
        }
        let request_id = next_request_id();
        held.queued.insert(
            request_id.clone(),
            StoredPendingPairing {
                request_id: request_id.clone(),
                device_id: device_id.to_owned(),
                role,
                scopes,
                created_at_ms: now_ms,
                refreshed_at_ms: now_ms,
            },
        );
        drop(held);
        Ok(PendingRegistration::Pending(request_id))
    }

    fn grant_satisfies(&self, device_id: &str, role: Role, scopes: &[OperatorScope]) -> bool {
        self.runtime
            .devices
            .current_grant(device_id)
            .is_some_and(|grant| {
                grant.role == role && scopes.iter().all(|scope| grant.scopes.contains(scope))
            })
    }

    fn complete_approval(&self, request_id: &str, pairing: &StoredPairing) {
        let mut held = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        held.approving.remove(request_id);
        held.queued.retain(|_, pending| {
            pending.device_id != pairing.device_id
                || pending.role != pairing.role
                || !pending
                    .scopes
                    .iter()
                    .all(|scope| pairing.scopes.contains(scope))
        });
    }

    fn restore_pending(&self, pending: StoredPendingPairing) {
        let now_ms = unix_millis();
        let mut held = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        held.approving.remove(&pending.request_id);
        if now_ms.saturating_sub(pending.refreshed_at_ms)
            > u64::try_from(PENDING_PAIRING_TTL.as_millis()).unwrap_or(u64::MAX)
        {
            return;
        }
        debug_assert!(
            held.queued.len().saturating_add(held.approving.len()) < MAX_PENDING_PAIRINGS
        );
        held.queued.insert(pending.request_id.clone(), pending);
    }

    fn with_durable_mutation<T>(
        &self,
        operation: impl FnOnce() -> Result<T, PortError>,
    ) -> Result<T, PortError> {
        let _process_lock = self
            .runtime
            .mutation_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let _file_lock = acquire_pairing_lock(&self.mutation_lock_path)
            .map_err(|error| PortError::new(PortErrorKind::Unavailable, error))?;
        operation()
    }

    fn record_durability_warnings(&self, warnings: usize) {
        self.durability_warnings.fetch_add(
            u64::try_from(warnings).unwrap_or(u64::MAX),
            Ordering::AcqRel,
        );
    }
}

impl GatewayPairingAdmin for GatewayPairingStore {
    fn dispatch(&self, method: &str, params: Option<&Value>) -> Result<Option<Value>, PortError> {
        let payload = match method {
            "device.pair.list" => {
                require_empty_params(params)?;
                self.list(false)
            }
            "node.pair.list" => {
                require_empty_params(params)?;
                self.list(true)
            }
            "device.pair.approve" | "node.pair.approve" => self.approve(method, params)?,
            "device.pair.reject" | "node.pair.reject" => self.reject(method, params)?,
            "device.pair.remove" | "node.pair.remove" => self.remove(method, params)?,
            _ => return Ok(None),
        };
        Ok(Some(payload))
    }
}

/// Authentication adapter that turns verified unpaired devices into durable
/// pending requests while delegating proof and grant validation.
pub struct GatewayPairingAuthenticator {
    inner: StaticAuthenticator,
    pairings: Arc<GatewayPairingStore>,
}

impl GatewayPairingAuthenticator {
    /// Creates an authenticator over the pairing store's live directory.
    #[must_use]
    pub fn new(
        credential: CredentialPolicy,
        clock: Arc<dyn Clock>,
        pairings: Arc<GatewayPairingStore>,
    ) -> Self {
        let inner = StaticAuthenticator::with_devices(credential, clock, pairings.devices());
        Self { inner, pairings }
    }
}

impl Debug for GatewayPairingAuthenticator {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayPairingAuthenticator")
            .field("inner", &self.inner)
            .field("pairings", &self.pairings.len())
            .finish()
    }
}

impl AuthenticationPort for GatewayPairingAuthenticator {
    fn authenticate(&self, request: AuthenticationRequest<'_>) -> AuthenticationDecision {
        let mut decision = self.inner.authenticate(request);
        for _ in 0..2 {
            let AuthenticationDecision::Rejected(rejection) = decision else {
                return decision;
            };
            let mut details = match rejection.code() {
                ConnectErrorDetailCode::PairingRequired => {
                    let Some(details) = rejection.pairing_details().cloned() else {
                        return AuthenticationDecision::Rejected(rejection);
                    };
                    details
                }
                ConnectErrorDetailCode::AuthScopeMismatch => {
                    let Some(details) =
                        scope_upgrade_details(request, &self.pairings.runtime.devices)
                    else {
                        return AuthenticationDecision::Rejected(rejection);
                    };
                    details
                }
                _ => return AuthenticationDecision::Rejected(rejection),
            };
            let Some(device_id) = details.device_id.as_deref() else {
                return AuthenticationDecision::Rejected(rejection);
            };
            let role = request.requested_role();
            let Some(scopes) = details.requested_scopes.as_deref().map(parse_scope_names) else {
                return AuthenticationDecision::Rejected(rejection);
            };
            let Ok(scopes) = scopes else {
                return AuthenticationDecision::Rejected(rejection);
            };
            match self.pairings.record_pending(device_id, role, scopes) {
                Ok(PendingRegistration::Pending(request_id)) => {
                    details.request_id = Some(request_id);
                    return AuthenticationDecision::Rejected(HandshakeRejection::pairing(
                        rejection.message(),
                        details,
                    ));
                }
                Ok(PendingRegistration::Granted) => {
                    decision = self.inner.authenticate(request);
                }
                Err(_) => return AuthenticationDecision::Rejected(rejection),
            }
        }
        decision
    }
}

fn scope_upgrade_details(
    request: AuthenticationRequest<'_>,
    devices: &DeviceDirectory,
) -> Option<PairingRequiredDetails> {
    let device_id = request.params().device.as_ref()?.id.as_str();
    let grant = devices.current_grant(device_id)?;
    let requested_scopes = request
        .params()
        .scopes
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();
    Some(PairingRequiredDetails {
        code: PairingRequiredCode::PairingRequired,
        reason: Some(PairingRequiredReason::ScopeUpgrade),
        request_id: None,
        remediation_hint: Some(
            "approve this scope upgrade with `device.pair.approve` on an operator session"
                .to_owned(),
        ),
        recommended_next_step: None,
        retryable: Some(false),
        pause_reconnect: Some(true),
        device_id: Some(device_id.to_owned()),
        requested_role: Some(request.requested_role().as_str().to_owned()),
        requested_scopes: Some(requested_scopes),
        approved_roles: Some(vec![grant.role.as_str().to_owned()]),
        approved_scopes: Some(
            grant
                .scopes
                .iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
        ),
    })
}

fn parse_scope_names(values: &[String]) -> Result<Vec<OperatorScope>, ()> {
    let mut scopes = Vec::with_capacity(values.len().min(MAX_SCOPES_PER_PAIRING));
    for value in values {
        let scope = OperatorScope::from_identity(value).ok_or(())?;
        if scopes.contains(&scope) {
            continue;
        }
        if scopes.len() >= MAX_SCOPES_PER_PAIRING {
            return Err(());
        }
        scopes.push(scope);
    }
    scopes.sort_unstable();
    Ok(scopes)
}

fn exact_string_param<'a>(
    params: Option<&'a Value>,
    key: &str,
    validate: impl FnOnce(&str) -> bool,
) -> Option<&'a str> {
    let params = params?.as_object()?;
    if params.len() != 1 {
        return None;
    }
    params.get(key)?.as_str().filter(|value| validate(value))
}

fn require_empty_params(params: Option<&Value>) -> Result<(), PortError> {
    if params.is_none_or(|params| params.as_object().is_some_and(serde_json::Map::is_empty)) {
        return Ok(());
    }
    Err(PortError::new(
        PortErrorKind::InvalidRequest,
        "pair list accepts no parameters",
    ))
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_BYTES
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn next_request_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let sequence = PENDING_REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{timestamp:032x}{sequence:016x}")
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn prune_pending(pending: &mut BTreeMap<String, StoredPendingPairing>, now_ms: u64) {
    let ttl_ms = u64::try_from(PENDING_PAIRING_TTL.as_millis()).unwrap_or(u64::MAX);
    pending.retain(|_, pending| now_ms.saturating_sub(pending.refreshed_at_ms) <= ttl_ms);
}

fn render_pending(pending: &StoredPendingPairing, node: bool) -> Value {
    let mut value = json!({
        "requestId": pending.request_id,
        "role": pending.role.as_str(),
        "ts": pending.created_at_ms,
        "scopes": pending
            .scopes
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>(),
    });
    value[if node { "nodeId" } else { "deviceId" }] = json!(pending.device_id);
    value
}

fn render_pairing(pairing: &StoredPairing, node: bool) -> Value {
    let mut value = json!({
        "role": pairing.role.as_str(),
        "scopes": pairing
            .scopes
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>(),
    });
    value[if node { "nodeId" } else { "deviceId" }] = json!(pairing.device_id);
    value
}

fn validate_pairing(pairing: &StoredPairing) -> Result<(), String> {
    if !valid_device_id(&pairing.device_id) || pairing.role == Role::Worker {
        return Err("gateway pairing file contains an invalid grant".to_owned());
    }
    if pairing.scopes.len() > MAX_SCOPES_PER_PAIRING {
        return Err("gateway pairing file contains too many scopes".to_owned());
    }
    let mut scopes = pairing.scopes.clone();
    scopes.sort_unstable();
    scopes.dedup();
    if scopes.len() != pairing.scopes.len() {
        return Err("gateway pairing file contains duplicate scopes".to_owned());
    }
    if pairing.role == Role::Node && !pairing.scopes.is_empty() {
        return Err("gateway node pairing carries operator scopes".to_owned());
    }
    Ok(())
}

fn reconcile_pairing_directory(
    devices: &DeviceDirectory,
    previous: &BTreeMap<String, StoredPairing>,
    current: &BTreeMap<String, StoredPairing>,
    preferred_device: Option<&str>,
) {
    for device_id in previous.keys() {
        if !current.contains_key(device_id) {
            devices.revoke(device_id);
        }
    }
    for (device_id, pairing) in current {
        if preferred_device == Some(device_id.as_str()) {
            continue;
        }
        if previous.get(device_id) != Some(pairing) {
            devices.pair(
                device_id.clone(),
                Grant::new(pairing.role, pairing.scopes.iter().copied()),
            );
        }
    }
}

fn validate_pending_fields(
    device_id: &str,
    role: Role,
    scopes: &[OperatorScope],
) -> Result<(), String> {
    if !valid_device_id(device_id) || role == Role::Worker {
        return Err("gateway pairing request contains an invalid grant".to_owned());
    }
    if scopes.len() > MAX_SCOPES_PER_PAIRING {
        return Err("gateway pairing file contains too many pending scopes".to_owned());
    }
    let mut canonical = scopes.to_vec();
    canonical.sort_unstable();
    canonical.dedup();
    if canonical.len() != scopes.len() {
        return Err("gateway pairing file contains duplicate pending scopes".to_owned());
    }
    if role == Role::Node && !scopes.is_empty() {
        return Err("gateway pending node pairing carries operator scopes".to_owned());
    }
    Ok(())
}

fn pairing_runtime(path: &Path) -> Arc<PairingRuntime> {
    let runtimes = PAIRING_RUNTIMES.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut runtimes = runtimes.lock().unwrap_or_else(PoisonError::into_inner);
    runtimes.retain(|_, runtime| runtime.strong_count() > 0);
    if let Some(runtime) = runtimes.get(path).and_then(Weak::upgrade) {
        return runtime;
    }
    let runtime = Arc::new(PairingRuntime::default());
    runtimes.insert(path.to_owned(), Arc::downgrade(&runtime));
    runtime
}

fn pairing_lock_path(path: &Path) -> Result<PathBuf, String> {
    let file_name = path
        .file_name()
        .ok_or_else(|| "gateway pairing path has no file name".to_owned())?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

fn load_or_initialize_pairings(
    path: &Path,
) -> Result<(BTreeMap<String, StoredPairing>, usize), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => load_pairings(path).map(|pairings| (pairings, 0)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let pairings = BTreeMap::new();
            let warnings = persist_pairings(path, &pairings)?;
            Ok((pairings, warnings))
        }
        Err(error) => Err(safe_io("inspect", &error)),
    }
}

fn load_pairings(path: &Path) -> Result<BTreeMap<String, StoredPairing>, String> {
    let bytes = read_pairing_file(path)?;
    let document: PairingDocument =
        serde_json::from_slice(&bytes).map_err(|_| "gateway pairing file is invalid".to_owned())?;
    if document.schema_version != PAIRING_SCHEMA_VERSION {
        return Err("gateway pairing file schema is unsupported".to_owned());
    }
    if document.pairings.len() > MAX_PAIRINGS {
        return Err("gateway pairing file contains too many grants".to_owned());
    }
    let mut pairings = BTreeMap::new();
    for mut pairing in document.pairings {
        validate_pairing(&pairing)?;
        pairing.scopes.sort_unstable();
        if pairings
            .insert(pairing.device_id.clone(), pairing)
            .is_some()
        {
            return Err("gateway pairing file contains a duplicate device".to_owned());
        }
    }
    Ok(pairings)
}

fn prepare_pairing_path(path: &Path) -> Result<PathBuf, String> {
    let file_name = path
        .file_name()
        .ok_or_else(|| "gateway pairing path has no file name".to_owned())?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| safe_io("create directory", &error))?;
    reject_link_or_non_file(path)?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|error| safe_io("canonicalize directory", &error))?;
    let resolved = canonical_parent.join(file_name);
    reject_link_or_non_file(&resolved)?;
    Ok(resolved)
}

fn reject_link_or_non_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_link_or_reparse(&metadata) => {
            Err("gateway pairing file must not be a symlink or reparse point".to_owned())
        }
        Ok(metadata) if !metadata.is_file() => {
            Err("gateway pairing path must be a regular file".to_owned())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(safe_io("inspect", &error)),
    }
}

fn valid_device_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn persist_pairings(
    path: &Path,
    pairings: &BTreeMap<String, StoredPairing>,
) -> Result<usize, String> {
    if pairings.len() > MAX_PAIRINGS {
        return Err("gateway pairing capacity is exhausted".to_owned());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "gateway pairing path has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| safe_io("create directory", &error))?;
    let document = PairingDocument {
        schema_version: PAIRING_SCHEMA_VERSION,
        pairings: pairings.values().cloned().collect(),
    };
    let bytes = serde_json::to_vec_pretty(&document)
        .map_err(|_| "gateway pairing file encoding failed".to_owned())?;
    if bytes.len() > MAX_PAIRING_FILE_BYTES {
        return Err("gateway pairing file exceeds its byte limit".to_owned());
    }
    write_bytes_atomically(path, &bytes)
        .map(|outcome| outcome.warnings.len())
        .map_err(|_| "gateway pairing publication failed".to_owned())
}

fn acquire_pairing_lock(path: &Path) -> Result<File, String> {
    let file = open_pairing_lock(path).map_err(|error| safe_io("open mutation lock", &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| safe_io("inspect mutation lock", &error))?;
    if is_link_or_reparse(&metadata) {
        return Err(
            "gateway pairing mutation lock must not be a symlink or reparse point".to_owned(),
        );
    }
    if !metadata.is_file() {
        return Err("gateway pairing mutation lock must be a regular file".to_owned());
    }
    File::lock(&file).map_err(|error| safe_io("lock mutations", &error))?;
    Ok(file)
}

#[cfg(unix)]
fn open_pairing_lock(path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};

    rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map(File::from)
    .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
}

#[cfg(windows)]
fn open_pairing_lock(path: &Path) -> io::Result<File> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_pairing_lock(path: &Path) -> io::Result<File> {
    use std::fs::OpenOptions;

    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
}

fn read_pairing_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| safe_io("inspect", &error))?;
    if is_link_or_reparse(&metadata) {
        return Err("gateway pairing file must not be a symlink or reparse point".to_owned());
    }
    if !metadata.is_file() {
        return Err("gateway pairing path must be a regular file".to_owned());
    }
    if metadata.len() > MAX_PAIRING_FILE_BYTES as u64 {
        return Err("gateway pairing file exceeds its byte limit".to_owned());
    }

    let file = open_pairing_read(path).map_err(|error| safe_io("open", &error))?;
    let opened = file
        .metadata()
        .map_err(|error| safe_io("inspect open file", &error))?;
    if is_link_or_reparse(&opened)
        || !opened.is_file()
        || opened.len() > MAX_PAIRING_FILE_BYTES as u64
    {
        return Err("gateway pairing file changed during open".to_owned());
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len())
            .unwrap_or(MAX_PAIRING_FILE_BYTES)
            .min(MAX_PAIRING_FILE_BYTES),
    );
    file.take((MAX_PAIRING_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| safe_io("read", &error))?;
    if bytes.len() > MAX_PAIRING_FILE_BYTES {
        return Err("gateway pairing file exceeds its byte limit".to_owned());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_pairing_read(path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};

    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
}

#[cfg(windows)]
fn open_pairing_read(path: &Path) -> io::Result<File> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_pairing_read(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(unix)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(any(unix, windows)))]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn safe_io(operation: &str, error: &io::Error) -> String {
    format!("gateway pairing {operation} failed ({:?})", error.kind())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use claw_gateway::AuthorizationSource;
    use claw_protocol::gateway::{OperatorScope, Role};
    use serde_json::json;

    use super::{
        GatewayPairingAdmin, GatewayPairingStore, MAX_PAIRING_FILE_BYTES, MAX_PAIRINGS,
        MAX_PENDING_PAIRINGS, MAX_SCOPES_PER_PAIRING, PAIRING_SCHEMA_VERSION, PENDING_PAIRING_TTL,
        PairingDocument, PairingTestPause, PendingRegistration, PortErrorKind, StoredPairing,
        StoredPendingPairing, parse_scope_names, unix_millis,
    };

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/pairing-tests");
            fs::create_dir_all(&base).expect("pairing test base created");
            let base = fs::canonicalize(base).expect("pairing test base canonicalized");
            let path = base.join(format!(
                "gta-claw-gateway-pairing-{label}-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("temporary root created");
            Self(path)
        }

        fn join(&self, path: impl AsRef<Path>) -> PathBuf {
            self.0.join(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn document(pairings: Vec<StoredPairing>) -> Vec<u8> {
        serde_json::to_vec(&PairingDocument {
            schema_version: PAIRING_SCHEMA_VERSION,
            pairings,
        })
        .expect("pairing document encodes")
    }

    fn operator_pairing(device: char, scopes: Vec<OperatorScope>) -> StoredPairing {
        StoredPairing {
            device_id: device.to_string().repeat(64),
            role: Role::Operator,
            scopes,
        }
    }

    fn pending_id(result: PendingRegistration) -> String {
        let PendingRegistration::Pending(request_id) = result else {
            panic!("test request must remain pending");
        };
        request_id
    }

    #[test]
    fn approved_pairing_survives_restart_and_can_be_revoked() {
        let root = TestRoot::new("restart");
        let path = root.join("pairings.json");
        let device_id = "a".repeat(64);
        let store = GatewayPairingStore::open(path.clone()).expect("store opens");
        let request_id = pending_id(
            store
                .record_pending(&device_id, Role::Operator, vec![OperatorScope::Read])
                .expect("pending request accepted"),
        );
        let approved = store
            .dispatch(
                "device.pair.approve",
                Some(&json!({"requestId":request_id})),
            )
            .expect("approval succeeds")
            .expect("method handled");
        assert_eq!(approved["device"]["deviceId"], device_id);
        assert_eq!(store.len(), 1);
        assert!(store.devices().current_grant(&device_id).is_some());
        assert!(matches!(
            store
                .record_pending(&device_id, Role::Operator, vec![OperatorScope::Read])
                .expect("current grant is observed"),
            PendingRegistration::Granted
        ));
        drop(store);

        let reopened = GatewayPairingStore::open(path).expect("store reopens");
        assert_eq!(reopened.len(), 1);
        assert!(reopened.devices().current_grant(&device_id).is_some());
        let removed = reopened
            .dispatch(
                "device.pair.remove",
                Some(&json!({"deviceId":"a".repeat(64)})),
            )
            .expect("removal succeeds")
            .expect("method handled");
        assert_eq!(removed["removed"], true);
        assert_eq!(reopened.len(), 0);
        assert_eq!(reopened.devices().current_grant(&device_id), None);
    }

    #[test]
    fn two_stores_revoke_then_approve_without_resurrecting_a_stale_grant() {
        let root = TestRoot::new("two-store-linearization");
        let path = root.join("pairings.json");
        let revoked_device = "a".repeat(64);
        let approved_device = "b".repeat(64);
        let revoker = GatewayPairingStore::open(path.clone()).expect("revoking store opens");
        let revoked_request = pending_id(
            revoker
                .record_pending(&revoked_device, Role::Operator, vec![OperatorScope::Read])
                .expect("initial request accepted"),
        );
        revoker
            .dispatch(
                "device.pair.approve",
                Some(&json!({"requestId":revoked_request})),
            )
            .expect("initial grant commits");
        let approver = GatewayPairingStore::open(path.clone()).expect("approving store opens");
        let approved_request = pending_id(
            approver
                .record_pending(&approved_device, Role::Operator, vec![OperatorScope::Write])
                .expect("second request accepted"),
        );
        let approval_pause = PairingTestPause::new();
        *approver
            .test_hooks
            .approval_before_mutation
            .lock()
            .expect("approval hook") = Some(Arc::clone(&approval_pause));
        let approving_store = Arc::clone(&approver);
        let approving = thread::spawn(move || {
            approving_store.dispatch(
                "device.pair.approve",
                Some(&json!({"requestId":approved_request})),
            )
        });

        approval_pause.reached.wait();
        let removed = revoker.dispatch(
            "device.pair.remove",
            Some(&json!({"deviceId":revoked_device})),
        );
        approval_pause.release.wait();
        let removed = removed
            .expect("revocation succeeds")
            .expect("removal method handled");
        let response = approving
            .join()
            .expect("approval thread joins")
            .expect("approval succeeds")
            .expect("approval method handled");

        assert_eq!(removed["removed"], true);
        assert_eq!(response["device"]["deviceId"], approved_device);
        assert_eq!(
            approver.devices().current_grant(&revoked_device),
            None,
            "the approving store reconciles the externally revoked grant"
        );
        assert!(approver.devices().current_grant(&approved_device).is_some());
        assert_eq!(revoker.devices().current_grant(&revoked_device), None);
        assert!(revoker.devices().current_grant(&approved_device).is_some());
        assert_eq!(revoker.len(), 1);
        let reopened = GatewayPairingStore::open(path).expect("store reopens");
        assert_eq!(reopened.devices().current_grant(&revoked_device), None);
        assert!(reopened.devices().current_grant(&approved_device).is_some());
        assert_eq!(reopened.len(), 1);
    }

    #[test]
    fn remove_waiting_on_scope_approval_cannot_be_resurrected() {
        let root = TestRoot::new("approval-remove-linearization");
        let path = root.join("pairings.json");
        let device_id = "d".repeat(64);
        let store = GatewayPairingStore::open(path.clone()).expect("store opens");
        let initial_request = pending_id(
            store
                .record_pending(&device_id, Role::Operator, vec![OperatorScope::Read])
                .expect("initial request accepted"),
        );
        store
            .dispatch(
                "device.pair.approve",
                Some(&json!({"requestId":initial_request})),
            )
            .expect("initial grant commits");
        let upgrade_request = pending_id(
            store
                .record_pending(&device_id, Role::Operator, vec![OperatorScope::Write])
                .expect("scope upgrade accepted"),
        );
        let approval_pause = PairingTestPause::new();
        *store
            .test_hooks
            .approval_reserved
            .lock()
            .expect("approval hook") = Some(Arc::clone(&approval_pause));
        let remove_started = Arc::new(Barrier::new(2));
        *store
            .test_hooks
            .remove_before_mutation
            .lock()
            .expect("remove hook") = Some(Arc::clone(&remove_started));

        let approving_store = Arc::clone(&store);
        let approving = thread::spawn(move || {
            approving_store.dispatch(
                "device.pair.approve",
                Some(&json!({"requestId":upgrade_request})),
            )
        });
        approval_pause.reached.wait();
        let removing_store = Arc::clone(&store);
        let removing_device = device_id.clone();
        let removing = thread::spawn(move || {
            removing_store.dispatch(
                "device.pair.remove",
                Some(&json!({"deviceId":removing_device})),
            )
        });
        remove_started.wait();
        approval_pause.release.wait();

        approving
            .join()
            .expect("approval thread joins")
            .expect("scope approval succeeds")
            .expect("approval method handled");
        let removed = removing
            .join()
            .expect("removal thread joins")
            .expect("removal succeeds")
            .expect("removal method handled");
        assert_eq!(removed["removed"], true);
        assert_eq!(store.devices().current_grant(&device_id), None);
        assert!(store.is_empty());
        let pending = store.pending.lock().expect("pending state");
        assert!(
            pending
                .queued
                .values()
                .all(|request| request.device_id != device_id)
        );
        assert!(
            pending
                .approving
                .values()
                .all(|request| request.device_id != device_id)
        );
        drop(pending);
        let reopened = GatewayPairingStore::open(path).expect("store reopens");
        assert_eq!(reopened.devices().current_grant(&device_id), None);
        assert!(reopened.is_empty());
    }

    #[test]
    fn oversized_pairing_file_is_refused_before_json_decode() {
        let root = TestRoot::new("oversized");
        let path = root.join("pairings.json");
        fs::write(&path, vec![b' '; MAX_PAIRING_FILE_BYTES + 1]).expect("oversized file written");

        let error = GatewayPairingStore::open(path).expect_err("oversized file refused");

        assert_eq!(error, "gateway pairing file exceeds its byte limit");
    }

    #[test]
    fn pairing_record_and_scope_counts_are_bounded() {
        let root = TestRoot::new("bounds");
        let path = root.join("pairings.json");
        let pairings = (0..=MAX_PAIRINGS)
            .map(|index| StoredPairing {
                device_id: format!("{index:064x}"),
                role: Role::Node,
                scopes: Vec::new(),
            })
            .collect();
        fs::write(&path, document(pairings)).expect("record-bound fixture written");
        assert_eq!(
            GatewayPairingStore::open(path.clone()).expect_err("record bound enforced"),
            "gateway pairing file contains too many grants"
        );

        fs::write(
            &path,
            document(vec![operator_pairing('a', vec![OperatorScope::Read; 7])]),
        )
        .expect("scope-bound fixture written");
        assert_eq!(
            GatewayPairingStore::open(path).expect_err("scope bound enforced"),
            "gateway pairing file contains too many scopes"
        );
    }

    #[test]
    fn repeated_wire_scopes_are_canonicalized_before_the_unique_limit() {
        let scopes = vec!["operator.read".to_owned(); MAX_SCOPES_PER_PAIRING + 1];

        assert_eq!(
            parse_scope_names(&scopes).expect("duplicate scopes are canonicalized"),
            vec![OperatorScope::Read]
        );
    }

    #[cfg(unix)]
    #[test]
    fn destination_symlink_is_refused_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new("destination-link");
        let target = root.join("target.json");
        let path = root.join("pairings.json");
        let original = document(Vec::new());
        fs::write(&target, &original).expect("target written");
        symlink(&target, &path).expect("destination link created");

        let error = GatewayPairingStore::open(path).expect_err("destination link refused");

        assert_eq!(
            error,
            "gateway pairing file must not be a symlink or reparse point"
        );
        assert_eq!(fs::read(target).expect("target remains readable"), original);
    }

    #[cfg(unix)]
    #[test]
    fn no_follow_open_refuses_a_final_component_symlink() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new("no-follow-open");
        let target = root.join("target.json");
        let path = root.join("pairings.json");
        fs::write(&target, document(Vec::new())).expect("target written");
        symlink(&target, &path).expect("destination link created");

        super::open_pairing_read(&path).expect_err("no-follow open refuses the link");
    }

    #[cfg(unix)]
    #[test]
    fn obsolete_fixed_temporary_symlink_is_never_followed() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new("temporary-link");
        let path = root.join("pairings.json");
        let store = GatewayPairingStore::open(path.clone()).expect("store opens");
        let sentinel = root.join("sentinel");
        fs::write(&sentinel, b"unchanged").expect("sentinel written");
        let obsolete_temporary = path.with_extension("json.tmp");
        symlink(&sentinel, &obsolete_temporary).expect("obsolete temporary link created");
        let request_id = pending_id(
            store
                .record_pending(&"a".repeat(64), Role::Operator, vec![OperatorScope::Read])
                .expect("pending request accepted"),
        );

        store
            .dispatch(
                "device.pair.approve",
                Some(&json!({"requestId":request_id})),
            )
            .expect("unique temporary publication succeeds");

        assert_eq!(
            fs::read(&sentinel).expect("sentinel remains readable"),
            b"unchanged"
        );
        assert!(
            fs::symlink_metadata(obsolete_temporary)
                .expect("obsolete link remains")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_publication_preserves_durable_and_live_grants() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new("failed-publication");
        let path = root.join("pairings.json");
        let durable = root.join("durable.json");
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let store = GatewayPairingStore::open(path.clone()).expect("store opens");
        let first_request = pending_id(
            store
                .record_pending(&first, Role::Operator, vec![OperatorScope::Read])
                .expect("first pending request accepted"),
        );
        store
            .dispatch(
                "device.pair.approve",
                Some(&json!({"requestId":first_request})),
            )
            .expect("first grant commits");
        let second_request = pending_id(
            store
                .record_pending(&second, Role::Operator, vec![OperatorScope::Write])
                .expect("second pending request accepted"),
        );
        let committed = fs::read(&path).expect("committed bytes read");
        fs::rename(&path, &durable).expect("committed file retained");
        symlink(&durable, &path).expect("unsafe destination planted");

        let error = store
            .dispatch(
                "device.pair.approve",
                Some(&json!({"requestId":second_request})),
            )
            .expect_err("unsafe publication refused");

        assert_eq!(error.kind, PortErrorKind::Unavailable);
        assert_eq!(
            fs::read(&durable).expect("old durable bytes remain"),
            committed
        );
        assert_eq!(store.len(), 1);
        assert!(store.devices().current_grant(&first).is_some());
        assert_eq!(store.devices().current_grant(&second), None);
        let pending = store
            .dispatch("device.pair.list", Some(&json!({})))
            .expect("pending list succeeds")
            .expect("method handled");
        assert_eq!(pending["pending"][0]["requestId"], second_request);
    }

    #[test]
    fn reject_and_remove_keep_pending_and_paired_contracts_distinct() {
        let root = TestRoot::new("contracts");
        let path = root.join("pairings.json");
        let store = GatewayPairingStore::open(path).expect("store opens");
        let device_id = "c".repeat(64);
        let rejected_request = pending_id(
            store
                .record_pending(&device_id, Role::Operator, vec![OperatorScope::Read])
                .expect("pending request accepted"),
        );

        let rejected = store
            .dispatch(
                "device.pair.reject",
                Some(&json!({"requestId":rejected_request})),
            )
            .expect("rejection succeeds")
            .expect("method handled");
        assert_eq!(rejected["decision"], "rejected");
        assert_eq!(store.len(), 0);
        assert!(store.devices().is_empty());

        let approved_request = pending_id(
            store
                .record_pending(&device_id, Role::Operator, vec![OperatorScope::Read])
                .expect("replacement request accepted"),
        );
        let direct = store
            .dispatch("device.pair.approve", Some(&json!({"deviceId":device_id})))
            .expect_err("approval never accepts an arbitrary device grant");
        assert_eq!(direct.kind, PortErrorKind::InvalidRequest);
        store
            .dispatch(
                "device.pair.approve",
                Some(&json!({"requestId":approved_request})),
            )
            .expect("approval succeeds");
        assert_eq!(store.len(), 1);
        let scope_upgrade = pending_id(
            store
                .record_pending(&device_id, Role::Operator, vec![OperatorScope::Write])
                .expect("scope upgrade request accepted"),
        );
        store
            .dispatch(
                "device.pair.approve",
                Some(&json!({"requestId":scope_upgrade})),
            )
            .expect("scope upgrade can be approved");
        let grant = store
            .devices()
            .current_grant(&device_id)
            .expect("upgraded grant is live");
        assert!(grant.scopes.contains(&OperatorScope::Read));
        assert!(grant.scopes.contains(&OperatorScope::Write));

        let invalid = store
            .dispatch(
                "device.pair.reject",
                Some(&json!({"requestId":approved_request})),
            )
            .expect_err("reject never aliases remove");
        assert_eq!(invalid.kind, PortErrorKind::InvalidRequest);
        assert_eq!(store.len(), 1);
        let _node_upgrade = pending_id(
            store
                .record_pending(&device_id, Role::Node, Vec::new())
                .expect("node-role request accepted"),
        );
        let removed = store
            .dispatch("device.pair.remove", Some(&json!({"deviceId":device_id})))
            .expect("remove succeeds")
            .expect("method handled");
        assert_eq!(removed["removed"], true);
        assert!(store.devices().is_empty());
        let node_list = store
            .dispatch("node.pair.list", Some(&json!({})))
            .expect("node list succeeds")
            .expect("method handled");
        assert_eq!(node_list["pending"], json!([]));
    }

    #[test]
    fn node_pairing_uses_request_id_and_node_id_contracts() {
        let root = TestRoot::new("node-contract");
        let path = root.join("pairings.json");
        let store = GatewayPairingStore::open(path).expect("store opens");
        let node_id = "d".repeat(64);
        let request_id = pending_id(
            store
                .record_pending(&node_id, Role::Node, Vec::new())
                .expect("node request accepted"),
        );

        let approved = store
            .dispatch(
                "device.pair.approve",
                Some(&json!({"requestId":request_id})),
            )
            .expect("device approval accepts a node-role request")
            .expect("method handled");
        assert_eq!(approved["device"]["deviceId"], node_id);
        let wrong_key = store
            .dispatch("node.pair.remove", Some(&json!({"deviceId":node_id})))
            .expect_err("node removal requires nodeId");
        assert_eq!(wrong_key.kind, PortErrorKind::InvalidRequest);

        let removed = store
            .dispatch("device.pair.remove", Some(&json!({"deviceId":node_id})))
            .expect("device removal accepts a node-role grant")
            .expect("method handled");
        assert_eq!(removed["removed"], true);
        assert_eq!(removed["deviceId"], node_id);
        assert!(store.devices().is_empty());

        let second_node = "f".repeat(64);
        let second_request = pending_id(
            store
                .record_pending(&second_node, Role::Node, Vec::new())
                .expect("second node request accepted"),
        );
        let approved = store
            .dispatch(
                "node.pair.approve",
                Some(&json!({"requestId":second_request})),
            )
            .expect("node approval succeeds")
            .expect("method handled");
        assert_eq!(approved["node"]["nodeId"], second_node);
        let removed = store
            .dispatch("node.pair.remove", Some(&json!({"nodeId":second_node})))
            .expect("node removal succeeds")
            .expect("method handled");
        assert_eq!(removed["removed"], true);
        assert_eq!(removed["nodeId"], second_node);
    }

    #[test]
    fn expired_pending_requests_are_pruned_before_listing_and_capacity_checks() {
        let root = TestRoot::new("pending-expiry");
        let path = root.join("pairings.json");
        let store = GatewayPairingStore::open(path).expect("store opens");
        let device_id = "e".repeat(64);
        let expired_id = pending_id(
            store
                .record_pending(&device_id, Role::Operator, vec![OperatorScope::Read])
                .expect("pending request accepted"),
        );
        {
            let mut state = store.pending.lock().expect("pairing state");
            let pending = state
                .queued
                .get_mut(&expired_id)
                .expect("pending request exists");
            let ttl_ms = u64::try_from(PENDING_PAIRING_TTL.as_millis()).expect("bounded TTL");
            pending.refreshed_at_ms = unix_millis().saturating_sub(ttl_ms.saturating_add(1));
            drop(state);
        }

        let expired = store
            .dispatch(
                "device.pair.approve",
                Some(&json!({"requestId":expired_id})),
            )
            .expect_err("expired request is not approvable");
        assert_eq!(expired.kind, PortErrorKind::InvalidRequest);
        let list = store
            .dispatch("device.pair.list", Some(&json!({})))
            .expect("list succeeds")
            .expect("method handled");
        assert_eq!(list["pending"], json!([]));

        let replacement = pending_id(
            store
                .record_pending(&device_id, Role::Operator, vec![OperatorScope::Read])
                .expect("expired capacity is reclaimed"),
        );
        assert_ne!(replacement, expired_id);
    }

    #[test]
    fn pending_requests_are_retryable_process_state_not_durable_grants() {
        let root = TestRoot::new("pending-restart");
        let path = root.join("pairings.json");
        let store = GatewayPairingStore::open(path.clone()).expect("store opens");
        let request_id = pending_id(
            store
                .record_pending(&"1".repeat(64), Role::Operator, vec![OperatorScope::Read])
                .expect("pending request accepted"),
        );
        assert!(!request_id.is_empty());
        drop(store);

        let reopened = GatewayPairingStore::open(path).expect("store reopens");
        let list = reopened
            .dispatch("device.pair.list", Some(&json!({})))
            .expect("list succeeds")
            .expect("method handled");
        assert_eq!(list["pending"], json!([]));
        assert!(reopened.is_empty());
    }

    #[test]
    fn approval_reservations_keep_pending_capacity_hard_bounded() {
        let root = TestRoot::new("pending-approval-capacity");
        let path = root.join("pairings.json");
        let store = GatewayPairingStore::open(path).expect("store opens");
        let now_ms = unix_millis();
        let approving = StoredPendingPairing {
            request_id: "approval-reservation".to_owned(),
            device_id: "a".repeat(64),
            role: Role::Operator,
            scopes: vec![OperatorScope::Read],
            created_at_ms: now_ms,
            refreshed_at_ms: now_ms,
        };
        {
            let mut state = store.pending.lock().expect("pairing state");
            state
                .approving
                .insert(approving.request_id.clone(), approving.clone());
            for index in 0..(MAX_PENDING_PAIRINGS - 1) {
                let request_id = format!("queued-{index}");
                state.queued.insert(
                    request_id.clone(),
                    StoredPendingPairing {
                        request_id,
                        device_id: format!("{index:064x}"),
                        role: Role::Operator,
                        scopes: vec![OperatorScope::Read],
                        created_at_ms: now_ms,
                        refreshed_at_ms: now_ms,
                    },
                );
            }
            drop(state);
        }

        let error = store
            .record_pending(&"f".repeat(64), Role::Operator, vec![OperatorScope::Read])
            .expect_err("an in-flight approval keeps its capacity reservation");
        assert_eq!(error, "gateway pending pairing capacity is exhausted");

        store.restore_pending(approving.clone());
        let state = store.pending.lock().expect("pairing state");
        assert!(state.approving.is_empty());
        assert!(state.queued.contains_key(&approving.request_id));
        assert_eq!(state.queued.len(), MAX_PENDING_PAIRINGS);
        drop(state);
    }

    #[test]
    fn differing_request_waits_behind_an_inflight_approval() {
        let root = TestRoot::new("pending-approval-successor");
        let path = root.join("pairings.json");
        let store = GatewayPairingStore::open(path).expect("store opens");
        let device_id = "b".repeat(64);
        let approving_id = pending_id(
            store
                .record_pending(&device_id, Role::Operator, vec![OperatorScope::Read])
                .expect("initial request accepted"),
        );
        let approving = {
            let mut state = store.pending.lock().expect("pairing state");
            let approving = state
                .queued
                .remove(&approving_id)
                .expect("request is queued");
            state
                .approving
                .insert(approving_id.clone(), approving.clone());
            drop(state);
            approving
        };

        let successor_id = pending_id(
            store
                .record_pending(&device_id, Role::Operator, vec![OperatorScope::Write])
                .expect("different request accepted as successor"),
        );
        assert_ne!(successor_id, approving_id);

        store.restore_pending(approving);
        {
            let mut state = store.pending.lock().expect("pairing state");
            assert!(state.queued.contains_key(&approving_id));
            assert!(state.queued.contains_key(&successor_id));
            let approving = state
                .queued
                .remove(&approving_id)
                .expect("restored request remains approvable");
            state.approving.insert(approving_id.clone(), approving);
            drop(state);
        }
        store.complete_approval(
            &approving_id,
            &StoredPairing {
                device_id,
                role: Role::Operator,
                scopes: vec![OperatorScope::Read],
            },
        );
        let state = store.pending.lock().expect("pairing state");
        assert!(state.approving.is_empty());
        assert!(state.queued.contains_key(&successor_id));
        drop(state);
    }

    #[test]
    fn unversioned_pairing_documents_migrate_as_schema_one() {
        let root = TestRoot::new("unversioned");
        let path = root.join("pairings.json");
        fs::write(&path, br#"{"pairings":[]}"#).expect("legacy document written");

        let store = GatewayPairingStore::open(path).expect("legacy document accepted");

        assert!(store.is_empty());
    }
}
