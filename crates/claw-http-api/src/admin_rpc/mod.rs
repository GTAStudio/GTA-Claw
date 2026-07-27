//! Authenticated Admin HTTP RPC dispatch, method policy and error mapping.
//!
//! This module implements the dispatch half of `POST /api/v1/admin/rpc`. It is
//! split from the credential scheme on purpose:
//!
//! - **Authentication is injected.** [`AdminRpcAuthenticator`] hands the
//!   surface an [`AdminRpcCaller`] that some other layer already verified. The
//!   default is [`DenyAllAuthenticator`], so a service assembled without an
//!   authentication implementation refuses every request rather than serving it
//!   anonymously.
//! - **Method policy is fail-closed.** [`AdminMethodPolicy`] admits only
//!   methods that appear verbatim on the allowlist, that the frozen Gateway
//!   registry defines, and whose registry classification is an operator scope.
//!   Anything else — an unknown name, a plugin name, a node-only or
//!   dynamically scoped method — is refused without reaching the Gateway.
//! - **Error mapping is exhaustive per class.** Each variant of
//!   [`AdminRpcError`] names its own status and stable code, and only a Gateway
//!   failure code outside the frozen table becomes a `500`.

mod caller;
mod error;
mod policy;
mod service;

pub use caller::{
    AdminRpcAuthRejection, AdminRpcAuthenticator, AdminRpcCaller, DenyAllAuthenticator,
    FnAuthenticator,
};
pub use error::{AdminRpcEnvelope, AdminRpcError, dispatch_status};
pub use policy::{AdminMethodPolicy, operator_scope_to_security};
pub use service::{ADMIN_RPC_PATH, AdminRpcLimits, AdminRpcService};
