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
    // Runtime TTL, LRU, reload, and terminal-destruction paths clear this through
    // `forget_session`, so its ownership matches the bounded conversation registry.
    remembered: HashMap<(String, String), ApprovalDecision>,
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
/// The retraction and the notification both happen here, synchronously. [`Drop`] cannot await, so
/// an invariant whose only enforcement is asynchronous is unenforced under cancellation; that is
/// why [`ApprovalPort::abandon`] is not a future. `request` disarms the guard on every path that
/// removes the entry deliberately.
struct PendingGuard {
    state: Arc<Mutex<BrokerState>>,
    approvals: Arc<dyn ApprovalPort>,
    approval_id: ApprovalId,
    armed: bool,
}

impl PendingGuard {
    /// Hands ownership of the pending entry back to the caller.
    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // The lock is released before the port is called: `abandon` is arbitrary adapter code and
        // may re-enter the broker, which would deadlock this non-reentrant mutex.
        let removed = {
            let mut state = lock_state(&self.state);
            state.pending.remove(&self.approval_id).is_some()
        };
        if removed {
            self.approvals.abandon(&self.approval_id);
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
        // Counting under the lock beats cloning every pending request just to measure it, and the
        // lock is released before any formatting happens.
        let outstanding = self.lock().pending.len();
        formatter
            .debug_struct("ApprovalBroker")
            .field("timeout", &self.timeout)
            .field("outstanding", &outstanding)
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
        // The clone-out happens under the lock; the sort does not.
        let mut requests: Vec<ApprovalRequest> = {
            let state = self.lock();
            state
                .pending
                .values()
                .map(|pending| pending.request.clone())
                .collect()
        };
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
        // The key is built before the lock is taken: this runs for every approval-gated tool call.
        let key = (session_id.as_str().to_owned(), tool_name.to_owned());
        self.lock().remembered.get(&key).copied()
    }

    /// Forgets a remembered decision so the next call asks again.
    ///
    /// Returns whether a decision was actually forgotten.
    #[must_use]
    pub fn forget(&self, session_id: &SessionId, tool_name: &str) -> bool {
        let key = (session_id.as_str().to_owned(), tool_name.to_owned());
        self.lock().remembered.remove(&key).is_some()
    }

    /// Forgets every remembered decision owned by one conversation session.
    ///
    /// Returns the number of decisions removed. Runtime TTL, LRU, reload, and
    /// terminal-destruction paths all call this, so remembered approval state is
    /// bounded by the same ownership policy as model selection.
    #[must_use]
    pub fn forget_session(&self, session_id: &SessionId) -> usize {
        let before;
        let after;
        {
            let mut state = self.lock();
            before = state.remembered.len();
            state
                .remembered
                .retain(|(owned_session, _), _| owned_session != session_id.as_str());
            after = state.remembered.len();
        }
        before.saturating_sub(after)
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
    /// Abandoned requests are not reported here: the private `PendingGuard` retracts and dismisses them
    /// synchronously at drop time, so by the time this runs they are already gone. Nothing is
    /// accumulated between a drop and a shutdown, which is why the broker keeps no orphan list.
    ///
    /// # Errors
    ///
    /// Returns the first [`PortError`] raised while notifying the presentation adapter. Every
    /// request is removed from the broker regardless.
    pub async fn withdraw_all(&self, reason: ApprovalWithdrawal) -> Result<(), ApprovalError> {
        let drained: Vec<ApprovalId> = {
            let mut state = self.lock();
            let ids: Vec<ApprovalId> = state.pending.keys().cloned().collect();
            state.pending.clear();
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
    /// Dropping the returned future retracts the request from the broker and dismisses it through
    /// [`ApprovalPort::abandon`] before the drop returns, so an abandoned waiter can neither leave
    /// a resolvable entry behind nor leave a prompt on an operator's screen.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::Port`] when the presentation adapter fails,
    /// [`ApprovalError::DeadlineOverflow`] when the deadline cannot be represented, and
    /// [`ApprovalError::Identifier`] when the broker's identifier counter cannot advance — the
    /// request is refused rather than issued an identifier that is already in use.
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

        // Only the counter bump needs the lock; minting the identifier, building the request and
        // allocating the channel all happen outside it.
        //
        // `checked_add`, not `saturating_add`: a saturated counter re-mints an identifier that is
        // already in `pending`, and the insert below would then evict a live waiter. That waiter's
        // responder would drop, so its call would report a withdrawal that no operator and no
        // timeout ever caused, and the guard it holds would retract the *new* request instead.
        // Exhausting a u64 is unreachable in practice, which is exactly why the failure has to be
        // loud: an unreachable branch that silently corrupts is worse than one that refuses.
        let ordinal = {
            let mut state = self.lock();
            let ordinal = state
                .next_id
                .checked_add(1)
                .ok_or(ApprovalError::Identifier(
                    "the broker has exhausted its identifier space",
                ))?;
            state.next_id = ordinal;
            ordinal
        };
        let approval_id = ApprovalId::new(format!("approval-{ordinal}"))
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
        self.lock().pending.insert(
            approval_id.clone(),
            Pending {
                request: request.clone(),
                responder,
            },
        );

        // Armed for exactly the window in which this future owns the pending entry.
        let mut guard = PendingGuard {
            state: Arc::clone(&self.state),
            approvals: Arc::clone(&self.approvals),
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

        // Both outcomes below take deliberate ownership of the pending entry — one because
        // `resolve` already removed it, the other because this path removes it itself — so the
        // guard's unwind-time retraction is no longer wanted on either.
        guard.disarm();

        let Some(decision) = outcome else {
            let still_pending = self.discard(&approval_id);
            let reason = if cancel.is_cancelled() {
                ApprovalWithdrawal::Cancelled
            } else {
                ApprovalWithdrawal::TimedOut
            };
            if still_pending {
                self.approvals.withdraw(&approval_id, reason).await?;
            }
            return Ok(ApprovalOutcome::Withdrawn { reason });
        };

        // `resolve` already removed the entry when it woke this waiter.
        self.approvals.settle(&approval_id).await?;
        Ok(ApprovalOutcome::Decided {
            decision,
            remembered: false,
        })
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

    fn abandon(&self, _approval_id: &ApprovalId) {}
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use claw_application::model::ids::{ToolCallId, TurnId};
    use claw_application::model::time::Timestamp;
    use claw_application::ports::PortFuture;
    use claw_application::ports::clock::ClockPort;
    use claw_domain::SessionId;
    use tokio_util::sync::CancellationToken;

    use super::{ApprovalBroker, ApprovalError, ApprovalTicket, SilentApprovalPort, lock_state};

    /// A clock that never moves, so a request that reaches its deadline never resolves.
    struct FrozenClock;

    impl ClockPort for FrozenClock {
        fn now(&self) -> Timestamp {
            Timestamp::EPOCH
        }

        fn sleep(&self, _duration: Duration) -> PortFuture<'_, ()> {
            Box::pin(std::future::pending())
        }
    }

    fn broker() -> ApprovalBroker {
        ApprovalBroker::new(
            Arc::new(SilentApprovalPort),
            Arc::new(FrozenClock),
            Duration::from_secs(30),
        )
    }

    fn ticket() -> ApprovalTicket {
        ApprovalTicket {
            session_id: SessionId::new("exhaustion").expect("the test session id is valid"),
            turn: TurnId::FIRST,
            call_id: ToolCallId::new("call-1").expect("the test call id is valid"),
            tool_name: "shell".to_owned(),
            arguments: "{}".to_owned(),
        }
    }

    #[tokio::test]
    async fn an_exhausted_identifier_space_is_refused_instead_of_reusing_an_identifier() {
        let broker = broker();
        // Reaching this by making requests would take 2^64 of them; the counter is set directly
        // so the branch is actually executed rather than merely reasoned about.
        lock_state(&broker.state).next_id = u64::MAX;

        let refused = broker
            .request(ticket(), &CancellationToken::new())
            .await
            .expect_err("a counter that cannot advance must refuse the request");

        assert!(
            matches!(refused, ApprovalError::Identifier(_)),
            "expected an identifier refusal, got {refused}"
        );
        assert!(
            broker.outstanding().is_empty(),
            "a refused request must not leave a waiter that a later request could evict"
        );
    }

    #[tokio::test]
    async fn identifiers_advance_by_one_per_request() {
        use std::future::Future as _;

        let broker = broker();
        lock_state(&broker.state).next_id = 41;

        let cancel = CancellationToken::new();
        let mut waiting = Box::pin(broker.request(ticket(), &cancel));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(
            waiting.as_mut().poll(&mut context).is_pending(),
            "a presented request waits for an answer"
        );

        assert_eq!(
            broker.outstanding()[0].approval_id.as_str(),
            "approval-42",
            "the minted ordinal must be the incremented counter, not the one before it"
        );
        assert_eq!(lock_state(&broker.state).next_id, 42);
    }
}
