//! Fail-closed method policy for the Admin HTTP RPC surface.
//!
//! The policy answers one question — *may this caller invoke this method over
//! HTTP?* — in three ordered gates, each of which denies by default:
//!
//! 1. the method must appear verbatim on the allowlist;
//! 2. the frozen Gateway registry must define it;
//! 3. the registry classification must be an operator scope, and the caller
//!    must satisfy that scope under `claw-security`.
//!
//! Nothing reaches the Gateway without passing all three, so an unrecognised or
//! newly introduced method is refused rather than dispatched.

use std::sync::Arc;

use claw_protocol::gateway::{MethodScope, PluginLookup, resolve_gateway_method};
use claw_security::authorization::Scope;

use crate::admin::ADMIN_HTTP_RPC_METHODS;
use crate::admin_rpc::error::AdminRpcError;

/// The set of Gateway methods reachable through `POST /api/v1/admin/rpc`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminMethodPolicy {
    methods: Arc<[String]>,
}

impl Default for AdminMethodPolicy {
    fn default() -> Self {
        Self::frozen()
    }
}

impl AdminMethodPolicy {
    /// Returns the frozen upstream Admin HTTP RPC allowlist.
    #[must_use]
    pub fn frozen() -> Self {
        Self::new(ADMIN_HTTP_RPC_METHODS.iter().copied())
    }

    /// Builds a policy over an explicit method set.
    ///
    /// A narrower or deliberately malformed set is how the ordered gates are
    /// exercised independently; production wiring uses [`Self::frozen`].
    #[must_use]
    pub fn new(methods: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            methods: methods.into_iter().map(Into::into).collect(),
        }
    }

    /// Returns the allowlisted methods in their frozen order.
    #[must_use]
    pub fn methods(&self) -> &[String] {
        &self.methods
    }

    /// Reports whether `method` appears verbatim on the allowlist.
    ///
    /// Comparison is exact and ordinal: a differently cased or whitespace-padded
    /// name is a different method and is not allowed.
    #[must_use]
    pub fn allows(&self, method: &str) -> bool {
        self.methods.iter().any(|allowed| allowed == method)
    }

    /// Resolves the operator scope `method` requires, or the reason it is refused.
    ///
    /// # Errors
    ///
    /// Returns [`AdminRpcError::MethodNotAllowlisted`] when the method is not on
    /// the allowlist, [`AdminRpcError::MethodNotRegistered`] when the frozen
    /// registry does not define it, and
    /// [`AdminRpcError::MethodNotOperatorSurface`] when its classification is
    /// not an operator scope.
    pub fn required_scope(&self, method: &str) -> Result<Scope, AdminRpcError> {
        if !self.allows(method) {
            return Err(AdminRpcError::MethodNotAllowlisted {
                method: method.to_owned(),
            });
        }
        let descriptor = resolve_gateway_method(method, PluginLookup::Deny).map_err(|_| {
            AdminRpcError::MethodNotRegistered {
                method: method.to_owned(),
            }
        })?;
        match descriptor.scope() {
            MethodScope::Operator(scope) => Ok(operator_scope_to_security(scope)),
            MethodScope::Dynamic | MethodScope::Node => {
                Err(AdminRpcError::MethodNotOperatorSurface {
                    method: method.to_owned(),
                })
            }
        }
    }
}

/// Translates a frozen protocol operator scope into its security-crate identity.
#[must_use]
pub const fn operator_scope_to_security(scope: claw_protocol::gateway::OperatorScope) -> Scope {
    use claw_protocol::gateway::OperatorScope as ProtocolScope;
    match scope {
        ProtocolScope::Admin => Scope::OperatorAdmin,
        ProtocolScope::Read => Scope::OperatorRead,
        ProtocolScope::Write => Scope::OperatorWrite,
        ProtocolScope::Approvals => Scope::OperatorApprovals,
        ProtocolScope::Pairing => Scope::OperatorPairing,
        ProtocolScope::TalkSecrets => Scope::OperatorTalkSecrets,
    }
}
