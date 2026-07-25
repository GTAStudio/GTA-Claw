use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use serde_json::{Value, json};

use crate::endpoint::ConnectionId;
use crate::protocol::{CdpRequest, ExtensionMessage, RelayTab};

const BROWSER_TARGET_ID: &str = "openclaw-extension-relay";
const BROWSER_CONTEXT_ID: &str = "openclaw-extension-context";
const DEFAULT_PENDING_LIMIT: usize = 256;

/// Shared page target exposed through CDP discovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetInfo {
    /// Synthetic or Chrome target identity.
    pub target_id: String,
    /// CDP target type.
    #[serde(rename = "type")]
    pub kind: String,
    /// Current title.
    pub title: String,
    /// Current URL.
    pub url: String,
    /// Stable synthetic browser context.
    pub browser_context_id: String,
    /// Whether the relay debugger is attached.
    pub attached: bool,
    /// Shared pages never expose opener reachability.
    pub can_access_opener: bool,
}

#[derive(Clone, Debug)]
struct TargetState {
    tab: RelayTab,
    target_id: String,
    attach_seq: Option<u64>,
    detach_seq: Option<u64>,
    session: Option<SessionState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SessionState {
    id: u64,
    owner: ConnectionId,
    attach_seq: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ChildSessionState {
    tab_id: u64,
    owner: ConnectionId,
    root_attach_seq: u64,
    parent_session_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingKind {
    Attach { tab_id: u64, respond: bool },
    Cdp { tab_id: u64 },
    Detach { tab_id: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingCommand {
    client: ConnectionId,
    request_id: u64,
    response_session_id: Option<String>,
    kind: PendingKind,
}

/// Command sent from the bridge to the paired extension.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum ExtensionCommand {
    /// Attach `chrome.debugger` to one shared tab.
    Attach {
        /// Relay command sequence.
        seq: u64,
        /// Chrome tab identity.
        tab_id: u64,
    },
    /// Detach `chrome.debugger`.
    Detach {
        /// Relay command sequence.
        seq: u64,
        /// Chrome tab identity.
        tab_id: u64,
    },
    /// Forward an explicitly policy-allowed CDP command.
    Cdp {
        /// Relay command sequence.
        seq: u64,
        /// Chrome tab identity.
        tab_id: u64,
        /// Optional Chrome child session.
        #[serde(skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
        /// Exact allowed CDP method.
        method: String,
        /// Optional CDP parameters.
        #[serde(skip_serializing_if = "Option::is_none")]
        params: Option<Value>,
    },
    /// App-level keepalive.
    Ping,
}

/// Standard CDP error object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CdpErrorObject {
    /// JSON-RPC-compatible CDP error code.
    pub code: i64,
    /// Non-secret failure message.
    pub message: String,
}

/// Response delivered to one isolated CDP connection.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CdpResponse {
    /// Request identity.
    pub id: u64,
    /// Flattened debugger session, when the request was session-scoped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Result object on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error object on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CdpErrorObject>,
}

/// Event delivered to one isolated CDP connection.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CdpEvent {
    /// Flattened debugger session, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Exact CDP event method.
    pub method: String,
    /// Event parameters.
    pub params: Value,
}

/// Observable bridge action for a WebSocket adapter.
#[derive(Clone, Debug, PartialEq)]
pub enum BridgeEffect {
    /// Send a command to the authenticated extension connection.
    ToExtension(ExtensionCommand),
    /// Send a response to exactly one CDP connection.
    ToCdp {
        /// Destination connection.
        connection: ConnectionId,
        /// Response frame.
        response: CdpResponse,
    },
    /// Send an event to exactly one CDP connection.
    EventToCdp {
        /// Destination connection.
        connection: ConnectionId,
        /// Event frame.
        event: CdpEvent,
    },
    /// Close the extension transport because safe debugger cleanup is impossible.
    CloseExtension {
        /// Destination extension connection.
        connection: ConnectionId,
        /// RFC 6455 close code.
        code: u16,
        /// Stable reason.
        reason: &'static str,
    },
    /// Close one CDP connection without closing the browser.
    CloseCdp {
        /// Destination connection.
        connection: ConnectionId,
        /// RFC 6455 close code.
        code: u16,
        /// Stable reason.
        reason: &'static str,
    },
}

/// Policy-bounded CDP bridge for one extension profile.
#[derive(Debug)]
pub struct CdpBridge {
    extension: Option<ConnectionId>,
    extension_hello_seen: bool,
    browser_version: String,
    user_agent: String,
    targets: BTreeMap<u64, TargetState>,
    clients: BTreeSet<ConnectionId>,
    browser_sessions: BTreeMap<String, ConnectionId>,
    child_sessions: BTreeMap<String, ChildSessionState>,
    auto_attach: BTreeSet<ConnectionId>,
    pending: BTreeMap<u64, PendingCommand>,
    abandoned: BTreeMap<u64, Option<u64>>,
    cleanup_detaches: BTreeMap<u64, u64>,
    pending_limit: usize,
    next_command: u64,
    next_session: u64,
}

impl Default for CdpBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl CdpBridge {
    /// Creates a disconnected bridge.
    #[must_use]
    pub fn new() -> Self {
        Self {
            extension: None,
            extension_hello_seen: false,
            browser_version: "Chrome/unknown".to_owned(),
            user_agent: "unknown".to_owned(),
            targets: BTreeMap::new(),
            clients: BTreeSet::new(),
            browser_sessions: BTreeMap::new(),
            child_sessions: BTreeMap::new(),
            auto_attach: BTreeSet::new(),
            pending: BTreeMap::new(),
            abandoned: BTreeMap::new(),
            cleanup_detaches: BTreeMap::new(),
            pending_limit: DEFAULT_PENDING_LIMIT,
            next_command: 1,
            next_session: 1,
        }
    }

    /// Creates a disconnected bridge with explicit pending-work and child-session bounds.
    pub fn with_pending_limit(pending_limit: usize) -> Result<Self, BridgeError> {
        if pending_limit == 0 {
            return Err(BridgeError::InvalidPendingLimit);
        }
        Ok(Self {
            pending_limit,
            ..Self::new()
        })
    }

    /// Attaches the newest authenticated extension connection.
    ///
    /// Any previous extension lifecycle is terminated before the new
    /// connection may send its mandatory hello.
    pub fn connect_extension(&mut self, connection: ConnectionId) -> Vec<BridgeEffect> {
        let effects = self.disconnect_extension();
        self.extension = Some(connection);
        self.extension_hello_seen = false;
        effects
    }

    /// Attaches one authenticated CDP client.
    pub fn connect_cdp(&mut self, connection: ConnectionId) -> Result<(), BridgeError> {
        if !self.clients.insert(connection) {
            return Err(BridgeError::DuplicateConnection);
        }
        Ok(())
    }

    /// Processes one strictly decoded extension message.
    pub fn receive_extension(
        &mut self,
        connection: ConnectionId,
        message: ExtensionMessage,
    ) -> Result<Vec<BridgeEffect>, BridgeError> {
        if self.extension != Some(connection) {
            return Err(BridgeError::UnknownExtensionConnection);
        }
        if !self.extension_hello_seen {
            let ExtensionMessage::Hello {
                user_agent,
                browser_version,
                extension_version: _,
                tabs,
            } = message
            else {
                return Err(BridgeError::HelloRequired);
            };
            self.extension_hello_seen = true;
            self.user_agent = user_agent;
            self.browser_version = browser_version;
            return self.sync_tabs(tabs);
        }
        match message {
            ExtensionMessage::Hello {
                user_agent: _,
                browser_version: _,
                extension_version: _,
                tabs: _,
            } => Err(BridgeError::DuplicateHello),
            ExtensionMessage::Tabs { tabs } => self.sync_tabs(tabs),
            ExtensionMessage::CdpEvent {
                tab_id,
                session_id,
                method,
                params,
            } => self.forward_event(tab_id, session_id, method, params),
            ExtensionMessage::Result { seq, result } => self.complete(seq, Ok(result)),
            ExtensionMessage::Error { seq, message } => self.complete(seq, Err(message)),
            ExtensionMessage::Detached { tab_id, reason: _ } => {
                self.clear_quarantine_for_tab(tab_id);
                let mut effects = self.fail_pending_for_tab(tab_id, "Chrome target detached");
                effects.extend(self.detach_tab(tab_id));
                Ok(effects)
            }
            ExtensionMessage::Pong => Ok(Vec::new()),
        }
    }

    /// Processes one strictly decoded CDP request.
    pub fn receive_cdp(
        &mut self,
        connection: ConnectionId,
        request: CdpRequest,
    ) -> Result<Vec<BridgeEffect>, BridgeError> {
        if !self.clients.contains(&connection) {
            return Err(BridgeError::UnknownCdpConnection);
        }
        if let Some(session_id) = request.session_id.clone()
            && self.browser_sessions.get(&session_id) == Some(&connection)
        {
            return self.receive_browser_cdp(connection, request);
        }
        if let Some(session_id) = request.session_id.clone() {
            return self.receive_session_cdp(connection, &session_id, request);
        }
        self.receive_browser_cdp(connection, request)
    }

    /// Handles abrupt extension/browser death and announces every detached page.
    pub fn disconnect_extension(&mut self) -> Vec<BridgeEffect> {
        if self.extension.take().is_none() {
            return Vec::new();
        }
        self.extension_hello_seen = false;
        let pending = std::mem::take(&mut self.pending);
        self.abandoned.clear();
        self.cleanup_detaches.clear();
        self.child_sessions.clear();
        let mut effects = pending
            .into_values()
            .filter(|pending| {
                self.clients.contains(&pending.client)
                    && !matches!(
                        pending.kind,
                        PendingKind::Attach {
                            tab_id: _,
                            respond: false
                        }
                    )
            })
            .map(|pending| BridgeEffect::ToCdp {
                connection: pending.client,
                response: CdpResponse {
                    id: pending.request_id,
                    session_id: pending.response_session_id,
                    result: None,
                    error: Some(CdpErrorObject {
                        code: -32000,
                        message: "Chrome extension disconnected".to_owned(),
                    }),
                },
            })
            .collect::<Vec<_>>();
        let tab_ids = self.targets.keys().copied().collect::<Vec<_>>();
        for tab_id in tab_ids {
            effects.extend(self.detach_tab(tab_id));
        }
        self.targets.clear();
        effects
    }

    /// Removes one CDP client and detaches only sessions it owned.
    pub fn disconnect_cdp(&mut self, connection: ConnectionId) -> Vec<BridgeEffect> {
        if !self.clients.remove(&connection) {
            return Vec::new();
        }
        let mut effects = Vec::new();
        self.auto_attach.remove(&connection);
        self.browser_sessions
            .retain(|_, owner| *owner != connection);
        self.child_sessions
            .retain(|_, session| session.owner != connection);
        let abandoned = self
            .pending
            .iter()
            .filter_map(|(seq, pending)| (pending.client == connection).then_some(*seq))
            .collect::<Vec<_>>();
        for seq in abandoned {
            let Some(pending) = self.pending.remove(&seq) else {
                break;
            };
            self.release_attach_reservation(seq, &pending.kind);
            self.release_detach_reservation(seq, &pending.kind);
            match pending.kind {
                PendingKind::Attach { tab_id, respond: _ } => {
                    effects.extend(self.abandon_sequence(seq, Some(tab_id)));
                }
                PendingKind::Cdp { tab_id: _ } => {}
                PendingKind::Detach { tab_id } => {
                    if let Err(reason) = self.promote_detach_to_cleanup(seq, tab_id) {
                        return self.fail_closed_extension(reason);
                    }
                }
            }
            if self.extension.is_none() {
                break;
            }
        }
        let tab_ids = self
            .targets
            .iter()
            .filter_map(|(tab_id, target)| {
                target
                    .session
                    .filter(|session| session.owner == connection)
                    .map(|_| *tab_id)
            })
            .collect::<Vec<_>>();
        for tab_id in tab_ids {
            if let Some(target) = self.targets.get_mut(&tab_id) {
                target.session = None;
            }
            if self.extension_hello_seen {
                match self.schedule_cleanup_detach(tab_id, false) {
                    Ok(effect) => effects.push(effect),
                    Err(reason) => return self.fail_closed_extension(reason),
                }
            }
        }
        effects
    }

    /// Expires pending work or a late-response tombstone after the adapter's timeout.
    pub fn expire_command(&mut self, seq: u64) -> Result<Vec<BridgeEffect>, BridgeError> {
        if self.cleanup_detaches.contains_key(&seq) {
            return Ok(self.fail_closed_extension("Chrome debugger cleanup timed out"));
        }
        if let Some(&tab_id) = self.abandoned.get(&seq) {
            return match tab_id {
                Some(tab_id)
                    if self.extension_hello_seen
                        && self.can_cleanup_abandoned_attach(seq, tab_id) =>
                {
                    let effect = match self.schedule_cleanup_detach(tab_id, true) {
                        Ok(effect) => effect,
                        Err(reason) => return Ok(self.fail_closed_extension(reason)),
                    };
                    self.abandoned.remove(&seq);
                    Ok(vec![effect])
                }
                Some(_) | None => {
                    self.abandoned.remove(&seq);
                    Ok(Vec::new())
                }
            };
        }
        let Some(pending) = self.pending.remove(&seq) else {
            return if seq < self.next_command {
                Ok(Vec::new())
            } else {
                Err(BridgeError::UnknownCommandSequence)
            };
        };
        self.release_attach_reservation(seq, &pending.kind);
        self.release_detach_reservation(seq, &pending.kind);
        let mut effects = match &pending.kind {
            PendingKind::Attach { tab_id, respond: _ } => self.abandon_sequence(seq, Some(*tab_id)),
            PendingKind::Cdp { tab_id: _ } => Vec::new(),
            PendingKind::Detach { tab_id } => {
                if let Err(reason) = self.promote_detach_to_cleanup(seq, *tab_id) {
                    self.fail_closed_extension(reason)
                } else {
                    Vec::new()
                }
            }
        };
        if matches!(
            pending.kind,
            PendingKind::Attach {
                tab_id: _,
                respond: false
            }
        ) || !self.clients.contains(&pending.client)
        {
            return Ok(effects);
        }
        effects.push(BridgeEffect::ToCdp {
            connection: pending.client,
            response: CdpResponse {
                id: pending.request_id,
                session_id: pending.response_session_id,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "extension relay command timed out".to_owned(),
                }),
            },
        });
        Ok(effects)
    }

    /// Returns current shared targets in stable tab order.
    #[must_use]
    pub fn targets(&self) -> Vec<TargetInfo> {
        self.targets.values().map(target_info).collect()
    }

    fn receive_session_cdp(
        &mut self,
        connection: ConnectionId,
        session_id: &str,
        request: CdpRequest,
    ) -> Result<Vec<BridgeEffect>, BridgeError> {
        let (tab_id, chrome_session_id) =
            if let Some(child) = self.child_sessions.get(session_id).cloned() {
                let valid_root = self.targets.get(&child.tab_id).is_some_and(|target| {
                    target.session.is_some_and(|root| {
                        root.owner == child.owner && root.attach_seq == child.root_attach_seq
                    })
                });
                if !valid_root {
                    self.remove_child_session_tree(session_id);
                    return Ok(vec![error_effect(
                        connection,
                        &request,
                        CdpError::SessionNotFound,
                    )]);
                }
                if child.owner != connection {
                    return Ok(vec![error_effect(
                        connection,
                        &request,
                        CdpError::SessionNotFound,
                    )]);
                }
                (child.tab_id, Some(session_id.to_owned()))
            } else {
                let Some((tab_id, _)) = self.targets.iter().find(|(_, target)| {
                    target.session.is_some_and(|session| {
                        session.owner == connection && session_name(session.id) == session_id
                    })
                }) else {
                    return Ok(vec![error_effect(
                        connection,
                        &request,
                        CdpError::SessionNotFound,
                    )]);
                };
                (*tab_id, None)
            };
        if !allowed_session_command(&request.method) {
            return Ok(vec![error_effect(
                connection,
                &request,
                CdpError::MethodNotAllowed,
            )]);
        };
        let seq = self.reserve_pending(connection, &request, PendingKind::Cdp { tab_id })?;
        Ok(vec![BridgeEffect::ToExtension(ExtensionCommand::Cdp {
            seq,
            tab_id,
            session_id: chrome_session_id,
            method: request.method,
            params: request.params,
        })])
    }

    fn receive_browser_cdp(
        &mut self,
        connection: ConnectionId,
        request: CdpRequest,
    ) -> Result<Vec<BridgeEffect>, BridgeError> {
        match request.method.as_str() {
            "Browser.getVersion" => Ok(vec![success_effect(
                connection,
                &request,
                json!({
                    "protocolVersion": "1.3",
                    "product": self.browser_version,
                    "revision": "gta-claw-extension-relay",
                    "userAgent": self.user_agent,
                    "jsVersion": ""
                }),
            )]),
            "Browser.close" => Ok(vec![
                success_effect(connection, &request, json!({})),
                BridgeEffect::CloseCdp {
                    connection,
                    code: 1000,
                    reason: "Browser.close",
                },
            ]),
            "Target.setDiscoverTargets" => {
                Ok(vec![success_effect(connection, &request, json!({}))])
            }
            "Browser.setDownloadBehavior" => Ok(vec![error_effect(
                connection,
                &request,
                CdpError::MethodNotAllowed,
            )]),
            "Target.attachToBrowserTarget" => {
                let session_id = browser_session_name(self.next_session);
                self.next_session = self
                    .next_session
                    .checked_add(1)
                    .ok_or(BridgeError::SequenceExhausted)?;
                self.browser_sessions.insert(session_id.clone(), connection);
                Ok(vec![success_effect(
                    connection,
                    &request,
                    json!({ "sessionId": session_id }),
                )])
            }
            "Target.setAutoAttach" => {
                let enabled = request
                    .params
                    .as_ref()
                    .and_then(|params| params.get("autoAttach"))
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                if !enabled {
                    self.auto_attach.remove(&connection);
                    return Ok(vec![success_effect(connection, &request, json!({}))]);
                }
                let abandoned_tabs = self.abandoned_attach_tabs();
                let tab_ids = self
                    .targets
                    .iter()
                    .filter_map(|(tab_id, target)| {
                        (target.session.is_none()
                            && target.attach_seq.is_none()
                            && !abandoned_tabs.contains(tab_id))
                        .then_some(*tab_id)
                    })
                    .collect::<Vec<_>>();
                self.preflight_pending(tab_ids.len())?;
                self.auto_attach.insert(connection);
                let mut effects = vec![success_effect(connection, &request, json!({}))];
                for tab_id in tab_ids {
                    let seq = self.reserve_attach_fields(connection, 0, None, tab_id, false)?;
                    effects.push(BridgeEffect::ToExtension(ExtensionCommand::Attach {
                        seq,
                        tab_id,
                    }));
                }
                Ok(effects)
            }
            "Target.getTargets" => Ok(vec![success_effect(
                connection,
                &request,
                json!({ "targetInfos": self.targets() }),
            )]),
            "Target.getTargetInfo" => {
                let target_id = request
                    .params
                    .as_ref()
                    .and_then(|params| params.get("targetId"))
                    .and_then(Value::as_str);
                if target_id.is_none() || target_id == Some(BROWSER_TARGET_ID) {
                    return Ok(vec![success_effect(
                        connection,
                        &request,
                        json!({
                            "targetInfo": {
                                "targetId": BROWSER_TARGET_ID,
                                "type": "browser",
                                "title": "GTA-Claw Extension Relay",
                                "url": "",
                                "attached": true,
                                "canAccessOpener": false
                            }
                        }),
                    )]);
                }
                let found = self
                    .targets
                    .values()
                    .find(|target| Some(target.target_id.as_str()) == target_id);
                match found {
                    Some(target) => Ok(vec![success_effect(
                        connection,
                        &request,
                        json!({ "targetInfo": target_info(target) }),
                    )]),
                    None => Ok(vec![error_effect(
                        connection,
                        &request,
                        CdpError::TargetNotFound,
                    )]),
                }
            }
            "Target.attachToTarget" => {
                let target_id = request
                    .params
                    .as_ref()
                    .and_then(|params| params.get("targetId"))
                    .and_then(Value::as_str);
                let Some(tab_id) = self.targets.iter().find_map(|(tab_id, target)| {
                    (Some(target.target_id.as_str()) == target_id).then_some(*tab_id)
                }) else {
                    return Ok(vec![error_effect(
                        connection,
                        &request,
                        CdpError::TargetNotFound,
                    )]);
                };
                if self
                    .targets
                    .get(&tab_id)
                    .is_some_and(|target| target.detach_seq.is_some())
                {
                    return Ok(vec![error_effect(
                        connection,
                        &request,
                        CdpError::DetachAlreadyPending,
                    )]);
                }
                if let Some(session) = self.targets.get(&tab_id).and_then(|target| target.session) {
                    if session.owner != connection {
                        return Ok(vec![error_effect(
                            connection,
                            &request,
                            CdpError::TargetAlreadyAttached,
                        )]);
                    }
                    return Ok(vec![success_effect(
                        connection,
                        &request,
                        json!({ "sessionId": session_name(session.id) }),
                    )]);
                }
                if self
                    .targets
                    .get(&tab_id)
                    .is_some_and(|target| target.attach_seq.is_some())
                    || self.has_abandoned_attach(tab_id)
                {
                    return Ok(vec![error_effect(
                        connection,
                        &request,
                        CdpError::TargetAlreadyAttached,
                    )]);
                }
                let seq = self.reserve_attach_fields(
                    connection,
                    request.id,
                    request.session_id.clone(),
                    tab_id,
                    true,
                )?;
                Ok(vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
                    seq,
                    tab_id,
                })])
            }
            "Target.detachFromTarget" => {
                let session_id = request
                    .params
                    .as_ref()
                    .and_then(|params| params.get("sessionId"))
                    .and_then(Value::as_str);
                if let Some(session_id) = session_id
                    && self.browser_sessions.get(session_id) == Some(&connection)
                {
                    self.browser_sessions.remove(session_id);
                    return Ok(vec![success_effect(connection, &request, json!({}))]);
                }
                let Some(tab_id) = self.targets.iter().find_map(|(tab_id, target)| {
                    target.session.and_then(|session| {
                        (session.owner == connection
                            && Some(session_name(session.id).as_str()) == session_id)
                            .then_some(*tab_id)
                    })
                }) else {
                    return Ok(vec![error_effect(
                        connection,
                        &request,
                        CdpError::SessionNotFound,
                    )]);
                };
                Ok(self.request_detach(connection, request.id, request.session_id.clone(), tab_id))
            }
            _ => Ok(vec![error_effect(
                connection,
                &request,
                CdpError::MethodNotAllowed,
            )]),
        }
    }

    fn reserve_pending(
        &mut self,
        client: ConnectionId,
        request: &CdpRequest,
        kind: PendingKind,
    ) -> Result<u64, BridgeError> {
        self.reserve_pending_fields(client, request.id, request.session_id.clone(), kind)
    }

    fn reserve_pending_fields(
        &mut self,
        client: ConnectionId,
        request_id: u64,
        response_session_id: Option<String>,
        kind: PendingKind,
    ) -> Result<u64, BridgeError> {
        if self.extension.is_none() || !self.extension_hello_seen {
            return Err(BridgeError::ExtensionUnavailable);
        }
        self.preflight_pending(1)?;
        let seq = self.next_command;
        self.next_command = self
            .next_command
            .checked_add(1)
            .ok_or(BridgeError::SequenceExhausted)?;
        self.pending.insert(
            seq,
            PendingCommand {
                client,
                request_id,
                response_session_id,
                kind,
            },
        );
        Ok(seq)
    }

    fn reserve_attach_fields(
        &mut self,
        client: ConnectionId,
        request_id: u64,
        response_session_id: Option<String>,
        tab_id: u64,
        respond: bool,
    ) -> Result<u64, BridgeError> {
        let target = self.targets.get(&tab_id).ok_or(BridgeError::UnknownTab)?;
        if target.session.is_some()
            || target.attach_seq.is_some()
            || self.has_abandoned_attach(tab_id)
        {
            return Err(BridgeError::TargetAttachmentReserved);
        }
        let seq = self.reserve_pending_fields(
            client,
            request_id,
            response_session_id,
            PendingKind::Attach { tab_id, respond },
        )?;
        self.targets
            .get_mut(&tab_id)
            .ok_or(BridgeError::UnknownTab)?
            .attach_seq = Some(seq);
        Ok(seq)
    }

    fn preflight_pending(&self, additional: usize) -> Result<(), BridgeError> {
        self.preflight_pending_after_reaping(0, additional)
    }

    fn preflight_pending_after_reaping(
        &self,
        reaped: usize,
        additional: usize,
    ) -> Result<(), BridgeError> {
        let total = self
            .pending
            .len()
            .checked_sub(reaped)
            .ok_or(BridgeError::PendingLimit)?
            .checked_add(additional)
            .ok_or(BridgeError::PendingLimit)?;
        if total > self.pending_limit {
            return Err(BridgeError::PendingLimit);
        }
        let additional = u64::try_from(additional).map_err(|_| BridgeError::SequenceExhausted)?;
        self.next_command
            .checked_add(additional)
            .ok_or(BridgeError::SequenceExhausted)?;
        Ok(())
    }

    fn complete(
        &mut self,
        seq: u64,
        result: Result<Option<Value>, String>,
    ) -> Result<Vec<BridgeEffect>, BridgeError> {
        if self.cleanup_detaches.contains_key(&seq) {
            if result.is_ok() {
                self.cleanup_detaches.remove(&seq);
                return Ok(Vec::new());
            }
            return Ok(self.fail_closed_extension("Chrome debugger cleanup failed"));
        }
        if let Some(&tab_id) = self.abandoned.get(&seq) {
            return match tab_id {
                Some(tab_id)
                    if result.is_ok()
                        && self.extension_hello_seen
                        && self.can_cleanup_abandoned_attach(seq, tab_id) =>
                {
                    let effect = match self.schedule_cleanup_detach(tab_id, true) {
                        Ok(effect) => effect,
                        Err(reason) => return Ok(self.fail_closed_extension(reason)),
                    };
                    self.abandoned.remove(&seq);
                    Ok(vec![effect])
                }
                Some(_) | None => {
                    self.abandoned.remove(&seq);
                    Ok(Vec::new())
                }
            };
        }
        let Some(pending) = self.pending.remove(&seq) else {
            return if seq < self.next_command {
                Ok(Vec::new())
            } else {
                Err(BridgeError::UnknownCommandSequence)
            };
        };
        self.release_attach_reservation(seq, &pending.kind);
        self.release_detach_reservation(seq, &pending.kind);
        if result.is_err()
            && matches!(
                pending.kind,
                PendingKind::Attach {
                    tab_id: _,
                    respond: false
                }
            )
        {
            return Ok(Vec::new());
        }
        let response = match result {
            Err(message) => CdpResponse {
                id: pending.request_id,
                session_id: pending.response_session_id,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message,
                }),
            },
            Ok(result) => match pending.kind {
                PendingKind::Attach { tab_id, respond } => {
                    let session_id = self.next_session;
                    self.next_session = self
                        .next_session
                        .checked_add(1)
                        .ok_or(BridgeError::SequenceExhausted)?;
                    self.remove_child_sessions_for_tab(tab_id);
                    let target = self
                        .targets
                        .get_mut(&tab_id)
                        .ok_or(BridgeError::TargetDiedDuringCommand)?;
                    if let Some(target_id) = result
                        .as_ref()
                        .and_then(|value| value.get("targetId"))
                        .and_then(Value::as_str)
                    {
                        target.target_id = target_id.to_owned();
                    }
                    target.session = Some(SessionState {
                        id: session_id,
                        owner: pending.client,
                        attach_seq: seq,
                    });
                    let session_name = session_name(session_id);
                    let mut effects = vec![BridgeEffect::EventToCdp {
                        connection: pending.client,
                        event: CdpEvent {
                            session_id: None,
                            method: "Target.attachedToTarget".to_owned(),
                            params: json!({
                                "sessionId": session_name,
                                "targetInfo": target_info(target),
                                "waitingForDebugger": false
                            }),
                        },
                    }];
                    if respond {
                        effects.push(BridgeEffect::ToCdp {
                            connection: pending.client,
                            response: CdpResponse {
                                id: pending.request_id,
                                session_id: pending.response_session_id,
                                result: Some(json!({ "sessionId": session_name })),
                                error: None,
                            },
                        });
                    }
                    return Ok(effects);
                }
                PendingKind::Cdp { tab_id: _ } => CdpResponse {
                    id: pending.request_id,
                    session_id: pending.response_session_id,
                    result: Some(result.unwrap_or_else(|| json!({}))),
                    error: None,
                },
                PendingKind::Detach { tab_id } => {
                    self.remove_child_sessions_for_tab(tab_id);
                    if let Some(target) = self.targets.get_mut(&tab_id) {
                        target.session = None;
                    }
                    CdpResponse {
                        id: pending.request_id,
                        session_id: pending.response_session_id,
                        result: Some(json!({})),
                        error: None,
                    }
                }
            },
        };
        Ok(vec![BridgeEffect::ToCdp {
            connection: pending.client,
            response,
        }])
    }

    fn sync_tabs(&mut self, tabs: Vec<RelayTab>) -> Result<Vec<BridgeEffect>, BridgeError> {
        let incoming = tabs.iter().map(|tab| tab.tab_id).collect::<BTreeSet<_>>();
        let removed = self
            .targets
            .keys()
            .filter(|tab_id| !incoming.contains(tab_id))
            .copied()
            .collect::<Vec<_>>();
        let new_tab_ids = tabs
            .iter()
            .filter_map(|tab| {
                (!self.targets.contains_key(&tab.tab_id) && !self.has_abandoned_attach(tab.tab_id))
                    .then_some(tab.tab_id)
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if self.auto_attach.first().is_some() {
            let reaped = self
                .pending
                .values()
                .filter(|pending| removed.contains(&pending_tab_id(&pending.kind)))
                .count();
            self.preflight_pending_after_reaping(reaped, new_tab_ids.len())?;
        }
        let mut effects = Vec::new();
        for tab_id in removed {
            self.clear_quarantine_for_tab(tab_id);
            effects.extend(self.fail_pending_for_tab(tab_id, "Chrome target closed"));
            if self.extension.is_none() {
                return Ok(effects);
            }
            effects.extend(self.detach_tab(tab_id));
            self.targets.remove(&tab_id);
        }
        for tab in tabs {
            self.targets
                .entry(tab.tab_id)
                .and_modify(|target| target.tab = tab.clone())
                .or_insert_with(|| TargetState {
                    target_id: format!("tab-{}", tab.tab_id),
                    tab,
                    attach_seq: None,
                    detach_seq: None,
                    session: None,
                });
        }
        if let Some(connection) = self.auto_attach.first().copied() {
            for tab_id in new_tab_ids {
                let seq = self.reserve_attach_fields(connection, 0, None, tab_id, false)?;
                effects.push(BridgeEffect::ToExtension(ExtensionCommand::Attach {
                    seq,
                    tab_id,
                }));
            }
        }
        Ok(effects)
    }

    fn fail_pending_for_tab(&mut self, tab_id: u64, message: &str) -> Vec<BridgeEffect> {
        let sequences = self
            .pending
            .iter()
            .filter_map(|(seq, pending)| {
                let pending_tab = match pending.kind {
                    PendingKind::Attach { tab_id, respond: _ }
                    | PendingKind::Cdp { tab_id }
                    | PendingKind::Detach { tab_id } => tab_id,
                };
                (pending_tab == tab_id).then_some(*seq)
            })
            .collect::<Vec<_>>();
        let mut effects = Vec::new();
        for seq in sequences {
            let Some(pending) = self.pending.remove(&seq) else {
                break;
            };
            self.release_attach_reservation(seq, &pending.kind);
            self.release_detach_reservation(seq, &pending.kind);
            if self.clients.contains(&pending.client)
                && !matches!(
                    pending.kind,
                    PendingKind::Attach {
                        tab_id: _,
                        respond: false
                    }
                )
            {
                effects.push(BridgeEffect::ToCdp {
                    connection: pending.client,
                    response: CdpResponse {
                        id: pending.request_id,
                        session_id: pending.response_session_id,
                        result: None,
                        error: Some(CdpErrorObject {
                            code: -32000,
                            message: message.to_owned(),
                        }),
                    },
                });
            }
            if self.extension.is_none() {
                break;
            }
        }
        effects
    }

    fn abandon_sequence(&mut self, seq: u64, attached_tab: Option<u64>) -> Vec<BridgeEffect> {
        let Some(quarantine_count) = self
            .abandoned
            .len()
            .checked_add(self.cleanup_detaches.len())
        else {
            return self.fail_closed_extension("relay cleanup quarantine count overflowed");
        };
        if quarantine_count >= self.pending_limit {
            return self.fail_closed_extension("relay cleanup quarantine limit reached");
        }
        self.abandoned.insert(seq, attached_tab);
        Vec::new()
    }

    fn abandoned_attach_tabs(&self) -> BTreeSet<u64> {
        self.abandoned
            .values()
            .filter_map(|tab_id| *tab_id)
            .chain(self.cleanup_detaches.values().copied())
            .collect()
    }

    fn has_abandoned_attach(&self, tab_id: u64) -> bool {
        self.abandoned
            .values()
            .any(|abandoned_tab| *abandoned_tab == Some(tab_id))
            || self
                .cleanup_detaches
                .values()
                .any(|cleanup_tab| *cleanup_tab == tab_id)
    }

    fn can_cleanup_abandoned_attach(&self, seq: u64, tab_id: u64) -> bool {
        self.targets.get(&tab_id).is_none_or(|target| {
            !target
                .attach_seq
                .is_some_and(|current_seq| current_seq > seq)
                && !target
                    .session
                    .is_some_and(|session| session.attach_seq > seq)
        })
    }

    fn clear_quarantine_for_tab(&mut self, tab_id: u64) {
        self.abandoned
            .retain(|_, abandoned_tab| *abandoned_tab != Some(tab_id));
        self.cleanup_detaches
            .retain(|_, cleanup_tab| *cleanup_tab != tab_id);
    }

    fn release_attach_reservation(&mut self, seq: u64, kind: &PendingKind) {
        let PendingKind::Attach { tab_id, respond: _ } = kind else {
            return;
        };
        if let Some(target) = self.targets.get_mut(tab_id)
            && target.attach_seq == Some(seq)
        {
            target.attach_seq = None;
        }
    }

    fn release_detach_reservation(&mut self, seq: u64, kind: &PendingKind) {
        let PendingKind::Detach { tab_id } = kind else {
            return;
        };
        if let Some(target) = self.targets.get_mut(tab_id)
            && target.detach_seq == Some(seq)
        {
            target.detach_seq = None;
        }
    }

    fn schedule_cleanup_detach(
        &mut self,
        tab_id: u64,
        replaces_quarantine: bool,
    ) -> Result<BridgeEffect, &'static str> {
        self.ensure_cleanup_capacity(replaces_quarantine)?;
        let seq = self.next_command;
        self.next_command = self
            .next_command
            .checked_add(1)
            .ok_or("relay cleanup sequence exhausted")?;
        self.cleanup_detaches.insert(seq, tab_id);
        Ok(BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq,
            tab_id,
        }))
    }

    fn promote_detach_to_cleanup(&mut self, seq: u64, tab_id: u64) -> Result<(), &'static str> {
        self.ensure_cleanup_capacity(false)?;
        self.cleanup_detaches.insert(seq, tab_id);
        self.remove_child_sessions_for_tab(tab_id);
        if let Some(target) = self.targets.get_mut(&tab_id) {
            target.session = None;
        }
        Ok(())
    }

    fn ensure_cleanup_capacity(&self, replaces_quarantine: bool) -> Result<(), &'static str> {
        let quarantine_count = self
            .abandoned
            .len()
            .checked_add(self.cleanup_detaches.len())
            .ok_or("relay cleanup quarantine count overflowed")?;
        let required_count = if replaces_quarantine {
            quarantine_count
        } else {
            quarantine_count
                .checked_add(1)
                .ok_or("relay cleanup quarantine count overflowed")?
        };
        if required_count > self.pending_limit {
            return Err("relay cleanup quarantine limit reached");
        }
        Ok(())
    }

    fn fail_closed_extension(&mut self, reason: &'static str) -> Vec<BridgeEffect> {
        let connection = self.extension;
        let mut effects = self.disconnect_extension();
        if let Some(connection) = connection {
            effects.insert(
                0,
                BridgeEffect::CloseExtension {
                    connection,
                    code: 1011,
                    reason,
                },
            );
        }
        effects
    }

    fn forward_event(
        &mut self,
        tab_id: u64,
        child_session_id: Option<String>,
        method: String,
        params: Option<Value>,
    ) -> Result<Vec<BridgeEffect>, BridgeError> {
        if !allowed_event(&method) {
            return Err(BridgeError::ExtensionEventNotAllowed);
        }
        let target = self.targets.get(&tab_id).ok_or(BridgeError::UnknownTab)?;
        let session = target.session.ok_or(BridgeError::TabNotAttached)?;
        let is_detach_event =
            method == "Target.detachedFromTarget" || method == "Inspector.detached";
        if let Some(source_session_id) = child_session_id.as_deref() {
            if self.child_sessions.contains_key(source_session_id) {
                self.validate_child_session(source_session_id, tab_id, session)?;
            } else if !is_detach_event {
                return Ok(Vec::new());
            }
        }
        let params = params.unwrap_or_else(|| json!({}));
        if method == "Target.attachedToTarget" {
            let announced_session_id = params
                .get("sessionId")
                .and_then(Value::as_str)
                .ok_or(BridgeError::InvalidChildSessionId)?;
            self.register_child_session(
                announced_session_id,
                tab_id,
                session,
                child_session_id.clone(),
            )?;
        } else if method == "Target.detachedFromTarget" {
            let detached_session_id = params
                .get("sessionId")
                .and_then(Value::as_str)
                .ok_or(BridgeError::InvalidChildSessionId)?;
            if self.child_sessions.contains_key(detached_session_id) {
                self.validate_child_session(detached_session_id, tab_id, session)?;
                self.remove_child_session_tree(detached_session_id);
            }
        } else if method == "Inspector.detached"
            && let Some(detached_session_id) = child_session_id.as_deref()
        {
            self.remove_child_session_tree(detached_session_id);
        }
        Ok(vec![BridgeEffect::EventToCdp {
            connection: session.owner,
            event: CdpEvent {
                session_id: Some(child_session_id.unwrap_or_else(|| session_name(session.id))),
                method,
                params,
            },
        }])
    }

    fn register_child_session(
        &mut self,
        child_session_id: &str,
        tab_id: u64,
        root: SessionState,
        parent_session_id: Option<String>,
    ) -> Result<(), BridgeError> {
        if child_session_id.is_empty() || child_session_id.starts_with("gta-claw-") {
            return Err(BridgeError::InvalidChildSessionId);
        }
        let state = ChildSessionState {
            tab_id,
            owner: root.owner,
            root_attach_seq: root.attach_seq,
            parent_session_id,
        };
        if let Some(existing) = self.child_sessions.get(child_session_id) {
            return if *existing == state {
                Ok(())
            } else {
                Err(BridgeError::ChildSessionCollision)
            };
        }
        if self.child_sessions.len() >= self.pending_limit {
            return Ok(());
        }
        self.child_sessions
            .insert(child_session_id.to_owned(), state);
        Ok(())
    }

    fn validate_child_session(
        &self,
        child_session_id: &str,
        tab_id: u64,
        root: SessionState,
    ) -> Result<(), BridgeError> {
        let child = self
            .child_sessions
            .get(child_session_id)
            .ok_or(BridgeError::ChildSessionNotFound)?;
        if child.tab_id != tab_id
            || child.owner != root.owner
            || child.root_attach_seq != root.attach_seq
        {
            return Err(BridgeError::ChildSessionNotFound);
        }
        Ok(())
    }

    fn remove_child_sessions_for_tab(&mut self, tab_id: u64) {
        self.child_sessions
            .retain(|_, child| child.tab_id != tab_id);
    }

    fn remove_child_session_tree(&mut self, child_session_id: &str) {
        let mut removed = BTreeSet::from([child_session_id.to_owned()]);
        loop {
            let previous_len = removed.len();
            for (session_id, child) in &self.child_sessions {
                if child
                    .parent_session_id
                    .as_ref()
                    .is_some_and(|parent| removed.contains(parent))
                {
                    removed.insert(session_id.clone());
                }
            }
            if removed.len() == previous_len {
                break;
            }
        }
        self.child_sessions
            .retain(|session_id, _| !removed.contains(session_id));
    }

    fn detach_tab(&mut self, tab_id: u64) -> Vec<BridgeEffect> {
        self.remove_child_sessions_for_tab(tab_id);
        let Some(target) = self.targets.get_mut(&tab_id) else {
            return Vec::new();
        };
        let Some(session) = target.session.take() else {
            return Vec::new();
        };
        vec![BridgeEffect::EventToCdp {
            connection: session.owner,
            event: CdpEvent {
                session_id: None,
                method: "Target.detachedFromTarget".to_owned(),
                params: json!({
                    "sessionId": session_name(session.id),
                    "targetId": target.target_id
                }),
            },
        }]
    }

    fn request_detach(
        &mut self,
        connection: ConnectionId,
        request_id: u64,
        response_session_id: Option<String>,
        tab_id: u64,
    ) -> Vec<BridgeEffect> {
        if self
            .targets
            .get(&tab_id)
            .is_some_and(|target| target.detach_seq.is_some())
        {
            return vec![BridgeEffect::ToCdp {
                connection,
                response: CdpResponse {
                    id: request_id,
                    session_id: response_session_id,
                    result: None,
                    error: Some(CdpError::DetachAlreadyPending.object()),
                },
            }];
        }
        let Ok(seq) = self.reserve_pending_fields(
            connection,
            request_id,
            response_session_id.clone(),
            PendingKind::Detach { tab_id },
        ) else {
            return vec![BridgeEffect::ToCdp {
                connection,
                response: CdpResponse {
                    id: request_id,
                    session_id: response_session_id,
                    result: None,
                    error: Some(CdpErrorObject {
                        code: -32000,
                        message: "relay cannot queue detach command".to_owned(),
                    }),
                },
            }];
        };
        if let Some(target) = self.targets.get_mut(&tab_id) {
            target.detach_seq = Some(seq);
        }
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq,
            tab_id,
        })]
    }
}

fn session_name(id: u64) -> String {
    format!("gta-claw-tab-{id}")
}

fn browser_session_name(id: u64) -> String {
    format!("gta-claw-browser-{id}")
}

fn pending_tab_id(kind: &PendingKind) -> u64 {
    match kind {
        PendingKind::Attach { tab_id, respond: _ }
        | PendingKind::Cdp { tab_id }
        | PendingKind::Detach { tab_id } => *tab_id,
    }
}

fn target_info(target: &TargetState) -> TargetInfo {
    TargetInfo {
        target_id: target.target_id.clone(),
        kind: "page".to_owned(),
        title: target.tab.title.clone(),
        url: target.tab.url.clone(),
        browser_context_id: BROWSER_CONTEXT_ID.to_owned(),
        attached: target.session.is_some(),
        can_access_opener: false,
    }
}

fn success_effect(connection: ConnectionId, request: &CdpRequest, result: Value) -> BridgeEffect {
    BridgeEffect::ToCdp {
        connection,
        response: CdpResponse {
            id: request.id,
            session_id: request.session_id.clone(),
            result: Some(result),
            error: None,
        },
    }
}

fn error_effect(connection: ConnectionId, request: &CdpRequest, error: CdpError) -> BridgeEffect {
    BridgeEffect::ToCdp {
        connection,
        response: CdpResponse {
            id: request.id,
            session_id: request.session_id.clone(),
            result: None,
            error: Some(error.object()),
        },
    }
}

fn allowed_session_command(method: &str) -> bool {
    const ALLOWED: &[&str] = &[
        "Accessibility.getFullAXTree",
        "DOM.getDocument",
        "DOM.getOuterHTML",
        "DOM.getTextContent",
        "DOM.querySelector",
        "DOM.querySelectorAll",
        "DOM.requestNode",
        "DOM.resolveNode",
        "Emulation.clearDeviceMetricsOverride",
        "Emulation.setDeviceMetricsOverride",
        "Input.dispatchKeyEvent",
        "Input.dispatchMouseEvent",
        "Input.insertText",
        "Log.enable",
        "Network.disable",
        "Network.enable",
        "Network.getResponseBody",
        "Network.setCacheDisabled",
        "Page.addScriptToEvaluateOnNewDocument",
        "Page.captureScreenshot",
        "Page.enable",
        "Page.getFrameTree",
        "Page.navigate",
        "Page.reload",
        "Page.setLifecycleEventsEnabled",
        "Runtime.callFunctionOn",
        "Runtime.enable",
        "Runtime.evaluate",
        "Runtime.getProperties",
        "Runtime.releaseObject",
        "Runtime.runIfWaitingForDebugger",
        "Target.setAutoAttach",
    ];
    ALLOWED.binary_search(&method).is_ok()
}

fn allowed_event(method: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "Accessibility.",
        "DOM.",
        "Inspector.",
        "Network.",
        "Page.",
        "Runtime.",
        "Target.",
    ];
    PREFIXES.iter().any(|prefix| method.starts_with(prefix))
}

/// Stable CDP policy error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CdpError {
    /// Target does not exist or was not shared.
    TargetNotFound,
    /// Session does not exist or belongs to another connection.
    SessionNotFound,
    /// Target is attached by another connection.
    TargetAlreadyAttached,
    /// A detach command is already in flight for the target.
    DetachAlreadyPending,
    /// Method is not in the explicit bridge policy.
    MethodNotAllowed,
}

impl CdpError {
    fn object(self) -> CdpErrorObject {
        let (code, message) = match self {
            Self::TargetNotFound => (-32602, "target not found"),
            Self::SessionNotFound => (-32001, "session not found"),
            Self::TargetAlreadyAttached => (-32000, "target is attached by another connection"),
            Self::DetachAlreadyPending => (-32000, "target detach is already pending"),
            Self::MethodNotAllowed => (-32601, "CDP method is not allowed by relay policy"),
        };
        CdpErrorObject {
            code,
            message: message.to_owned(),
        }
    }
}

/// Bridge lifecycle or routing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeError {
    /// In-flight command bound must be positive.
    InvalidPendingLimit,
    /// Connection was attached twice.
    DuplicateConnection,
    /// Frame did not come from the active extension.
    UnknownExtensionConnection,
    /// Extension's first frame must be hello.
    HelloRequired,
    /// Extension sent hello more than once.
    DuplicateHello,
    /// CDP connection is not attached.
    UnknownCdpConnection,
    /// No paired extension is ready.
    ExtensionUnavailable,
    /// Target was reserved or attached before an attach command could be queued.
    TargetAttachmentReserved,
    /// Process-local sequence was exhausted.
    SequenceExhausted,
    /// In-flight extension command bound was reached.
    PendingLimit,
    /// Extension response sequence was not pending.
    UnknownCommandSequence,
    /// Target vanished while an extension command was in flight.
    TargetDiedDuringCommand,
    /// Extension sent an event outside the explicit event policy.
    ExtensionEventNotAllowed,
    /// Extension referenced a tab it did not share.
    UnknownTab,
    /// Extension referenced a tab with no debugger session.
    TabNotAttached,
    /// Extension referenced a child session outside the target's current root session.
    ChildSessionNotFound,
    /// Extension announced an empty or relay-reserved child session identifier.
    InvalidChildSessionId,
    /// Extension reused a child session identifier for a different root session.
    ChildSessionCollision,
}

impl Display for BridgeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPendingLimit => "pending command limit must be positive",
            Self::DuplicateConnection => "relay connection is already attached",
            Self::UnknownExtensionConnection => "unknown extension connection",
            Self::HelloRequired => "extension hello is required as the first frame",
            Self::DuplicateHello => "extension hello was already received",
            Self::UnknownCdpConnection => "unknown CDP connection",
            Self::ExtensionUnavailable => "Chrome extension is not connected",
            Self::TargetAttachmentReserved => "target attachment is already reserved",
            Self::SequenceExhausted => "relay sequence exhausted",
            Self::PendingLimit => "relay pending command limit reached",
            Self::UnknownCommandSequence => "unknown extension command sequence",
            Self::TargetDiedDuringCommand => "target died while command was in flight",
            Self::ExtensionEventNotAllowed => "extension CDP event is not allowed",
            Self::UnknownTab => "extension referenced an unknown tab",
            Self::TabNotAttached => "extension referenced an unattached tab",
            Self::ChildSessionNotFound => "extension referenced an unknown child session",
            Self::InvalidChildSessionId => "extension sent an invalid child session identifier",
            Self::ChildSessionCollision => "extension reused a child session identifier",
        })
    }
}

impl Error for BridgeError {}
