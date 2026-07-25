//! The approval broker that gates tool execution on operator decisions.
//!
//! The broker owns three things a tool executor must not: the set of outstanding requests, the
//! per-session memory of "always allow"/"always deny" answers, and the deadline after which an
//! unanswered request is withdrawn. Every deadline is measured with [`ClockPort`], so tests
//! drive expiry deterministically instead of sleeping.

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use claw_application::model::approval::{
    ApprovalDecision, ApprovalOutcome, ApprovalRequest, ApprovalWithdrawal,
};
use claw_application::model::ids::{ApprovalId, ToolCallId, TurnId};
use claw_application::ports::approval::ApprovalPort;
use claw_application::ports::clock::ClockPort;
use claw_application::ports::{PortError, PortFuture};
use claw_domain::SessionId;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// A failure raised while brokering an approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalError {
    /// The approval presentation adapter failed.
    Port(PortError),
    /// No request with that identifier is outstanding.
    Unknown(ApprovalId),
    /// The clock produced a deadline that cannot be represented.
    DeadlineOverflow,
    /// The broker could not mint an identifier for the request.
    Identifier(&'static str),
}

impl Display for ApprovalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Port(error) => write!(formatter, "approval port failed: {error}"),
            Self::Unknown(id) => write!(formatter, "approval {id} is not outstanding"),
            Self::DeadlineOverflow => formatter.write_str("approval deadline overflowed the clock"),
            Self::Identifier(reason) => write!(formatter, "approval identifier rejected: {reason}"),
        }
    }
}

impl Error for ApprovalError {}

impl From<PortError> for ApprovalError {
    fn from(value: PortError) -> Self {
        Self::Port(value)
    }
}

/// The request the caller hands to [`ApprovalBroker::request`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalTicket {
    /// The session asking for permission.
    pub session_id: SessionId,
    /// The turn asking for permission.
    pub turn: TurnId,
    /// The tool call awaiting permission.
    pub call_id: ToolCallId,
    /// The tool that would run.
    pub tool_name: String,
    /// The JSON arguments the tool would receive.
    pub arguments: String,
}

struct Pending {
    request: ApprovalRequest,
    responder: oneshot::Sender<ApprovalDecision>,
}

#[derive(Default)]
struct BrokerState {
    pending: HashMap<ApprovalId, Pending>,
    remembered: HashMap<(String, String), ApprovalDecision>,
    abandoned: Vec<ApprovalId>,
    next_id: u64,
}

fn lock_state(state: &Mutex<BrokerState>) -> std::sync::MutexGuard<'_, BrokerState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Retracts a registered request when [`ApprovalBroker::request`] is dropped instead of resolved.
///
/// `request` inserts the pending entry before awaiting the operator, and a future may be dropped
/// at any await point. Without this guard the entry would outlive its waiter forever: it would
/// still be listed by [`ApprovalBroker::outstanding`], and [`ApprovalBroker::resolve`] would
/// accept it and record an "always allow" memory for a tool call that no longer exists.
///
/// [`Drop`] cannot run the asynchronous [`ApprovalPort::withdraw`] notification, so the guard
/// records the identifier in `abandoned` and [`ApprovalBroker::withdraw_all`] tells the adapter
/// about it. `request` disarms the guard on every path that removes the entry deliberately.
struct PendingGuard {
    state: Arc<Mutex<BrokerState>>,
    approval_id: ApprovalId,
    armed: bool,
}

impl PendingGuard {
    /// Hands ownership of the pending entry back to the caller.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = lock_state(&self.state);
        if state.pending.remove(&self.approval_id).is_some() {
            state.abandoned.push(self.approval_id.clone());
        }
    }
}

/// Brokers tool approval decisions between the runtime and its operators.
#[derive(Clone)]
pub struct ApprovalBroker {
    state: Arc<Mutex<BrokerState>>,
    approvals: Arc<dyn ApprovalPort>,
    clock: Arc<dyn ClockPort>,
    timeout: Duration,
}

impl fmt::Debug for ApprovalBroker {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalBroker")
            .field("timeout", &self.timeout)
            .field("outstanding", &self.outstanding().len())
            .finish_non_exhaustive()
    }
}

impl ApprovalBroker {
    /// Creates a broker that withdraws unanswered requests after `timeout` of clock time.
    #[must_use]
    pub fn new(
        approvals: Arc<dyn ApprovalPort>,
        clock: Arc<dyn ClockPort>,
        timeout: Duration,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(BrokerState::default())),
            approvals,
            clock,
            timeout,
        }
    }

    /// Returns every outstanding request, oldest identifier first.
    #[must_use]
    pub fn outstanding(&self) -> Vec<ApprovalRequest> {
        let state = self.lock();
        let mut requests: Vec<ApprovalRequest> = state
            .pending
            .values()
            .map(|pending| pending.request.clone())
            .collect();
        requests.sort_by(|left, right| {
            left.requested_at
                .cmp(&right.requested_at)
                .then_with(|| left.approval_id.cmp(&right.approval_id))
        });
        requests
    }

    /// Returns the decision remembered for a tool in a session, if any.
    #[must_use]
    pub fn remembered(&self, session_id: &SessionId, tool_name: &str) -> Option<ApprovalDecision> {
        self.lock()
            .remembered
            .get(&(session_id.as_str().to_owned(), tool_name.to_owned()))
            .copied()
    }

    /// Forgets a remembered decision so the next call asks again.
    pub fn forget(&self, session_id: &SessionId, tool_name: &str) -> bool {
        self.lock()
            .remembered
            .remove(&(session_id.as_str().to_owned(), tool_name.to_owned()))
            .is_some()
    }

    /// Answers one outstanding request.
    ///
    /// A [`crate::command::OperatorScope::Approvals`]-scoped caller supplies the decision; the
    /// broker stores it when the decision's scope says to remember it, and then wakes the waiter.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::Unknown`] when no such request is outstanding, which includes the
    /// case where the request was already withdrawn by a timeout or cancellation.
    pub fn resolve(
        &self,
        approval_id: &ApprovalId,
        decision: ApprovalDecision,
    ) -> Result<(), ApprovalError> {
        let pending = {
            let mut state = self.lock();
            let pending = state
                .pending
                .remove(approval_id)
                .ok_or_else(|| ApprovalError::Unknown(approval_id.clone()))?;
            if decision.scope.is_remembered() {
                state.remembered.insert(
                    (
                        pending.request.session_id.as_str().to_owned(),
                        pending.request.tool_name.clone(),
                    ),
                    decision,
                );
            }
            pending
        };

        // The waiter may already be gone if its turn was cancelled between our removal above and
        // its own cleanup; the decision is still recorded, so dropping the send is correct.
        let _ = pending.responder.send(decision);
        Ok(())
    }

    /// Withdraws every outstanding request, waking each waiter with `reason`.
    ///
    /// Requests whose waiter was dropped rather than cancelled are retracted from the broker at
    /// drop time but cannot be reported to the adapter from a synchronous [`Drop`]; they are
    /// notified here as well, so no presented request is left un-dismissed after a shutdown.
    ///
    /// # Errors
    ///
    /// Returns the first [`PortError`] raised while notifying the presentation adapter. Every
    /// request is removed from the broker regardless.
    pub async fn withdraw_all(&self, reason: ApprovalWithdrawal) -> Result<(), ApprovalError> {
        let drained: Vec<ApprovalId> = {
            let mut state = self.lock();
            let mut ids: Vec<ApprovalId> = state.pending.keys().cloned().collect();
            state.pending.clear();
            ids.append(&mut state.abandoned);
            ids
        };

        let mut first_error = None;
        for id in drained {
            if let Err(error) = self.approvals.withdraw(&id, reason).await
                && first_error.is_none()
            {
                first_error = Some(ApprovalError::Port(error));
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    /// Requests permission to run a tool and waits for the answer.
    ///
    /// Returns immediately with a remembered decision when one exists. Otherwise the request is
    /// presented through [`ApprovalPort`] and the call waits until an operator answers, the
    /// clock passes the deadline, or `cancel` fires.
    ///
    /// Dropping the returned future retracts the request from the broker, so an abandoned waiter
    /// cannot leave a resolvable entry behind.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::Port`] when the presentation adapter fails, and
    /// [`ApprovalError::DeadlineOverflow`] when the deadline cannot be represented.
    pub async fn request(
        &self,
        ticket: ApprovalTicket,
        cancel: &CancellationToken,
    ) -> Result<ApprovalOutcome, ApprovalError> {
        if let Some(decision) = self.remembered(&ticket.session_id, &ticket.tool_name) {
            return Ok(ApprovalOutcome::Decided {
                decision,
                remembered: true,
            });
        }

        let requested_at = self.clock.now();
        let expires_at = requested_at
            .checked_add(self.timeout)
            .ok_or(ApprovalError::DeadlineOverflow)?;

        let (approval_id, receiver, request) = {
            let mut state = self.lock();
            state.next_id = state.next_id.saturating_add(1);
            let approval_id = ApprovalId::new(format!("approval-{}", state.next_id))
                .map_err(|error| ApprovalError::Identifier(error.reason()))?;
            let request = ApprovalRequest {
                approval_id: approval_id.clone(),
                session_id: ticket.session_id,
                turn: ticket.turn,
                call_id: ticket.call_id,
                tool_name: ticket.tool_name,
                arguments: ticket.arguments,
                requested_at,
                expires_at,
            };
            let (responder, receiver) = oneshot::channel();
            state.pending.insert(
                approval_id.clone(),
                Pending {
                    request: request.clone(),
                    responder,
                },
            );
            (approval_id, receiver, request)
        };

        // Armed for exactly the window in which this future owns the pending entry.
        let mut guard = PendingGuard {
            state: Arc::clone(&self.state),
            approval_id: approval_id.clone(),
            armed: true,
        };

        if let Err(error) = self.approvals.present(request).await {
            guard.disarm();
            self.discard(&approval_id);
            return Err(ApprovalError::Port(error));
        }

        let outcome = tokio::select! {
            biased;
            decided = receiver => decided.ok(),
            () = cancel.cancelled() => None,
            () = self.clock.sleep_until(expires_at) => None,
        };

        match outcome {
            Some(decision) => {
                // `resolve` already removed the entry when it woke this waiter.
                guard.disarm();
                self.approvals.settle(&approval_id).await?;
                Ok(ApprovalOutcome::Decided {
                    decision,
                    remembered: false,
                })
            }
            None => {
                guard.disarm();
                let still_pending = self.discard(&approval_id);
                let reason = if cancel.is_cancelled() {
                    ApprovalWithdrawal::Cancelled
                } else {
                    ApprovalWithdrawal::TimedOut
                };
                if still_pending {
                    self.approvals.withdraw(&approval_id, reason).await?;
                }
                Ok(ApprovalOutcome::Withdrawn { reason })
            }
        }
    }

    fn discard(&self, approval_id: &ApprovalId) -> bool {
        self.lock().pending.remove(approval_id).is_some()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BrokerState> {
        lock_state(&self.state)
    }
}

/// An [`ApprovalPort`] that drops every notification.
///
/// Useful for headless hosts that surface approvals through another channel entirely.
#[derive(Clone, Copy, Debug, Default)]
pub struct SilentApprovalPort;

impl ApprovalPort for SilentApprovalPort {
    fn present(&self, _request: ApprovalRequest) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn settle(&self, _approval_id: &ApprovalId) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn withdraw(
        &self,
        _approval_id: &ApprovalId,
        _reason: ApprovalWithdrawal,
    ) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(std::future::ready(Ok(())))
    }
}
