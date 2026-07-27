//! The authenticated-caller seam for the Admin HTTP RPC surface.
//!
//! This module deliberately owns no credential scheme. Dispatch, method policy
//! and error mapping treat "the caller is authenticated and carries an admin
//! identity" as an *injected input*, so the credential format can be replaced
//! without touching the policy or the mapping table.

use std::fmt::{self, Debug, Formatter};

use axum::http::HeaderMap;
use claw_security::authorization::{Role, ScopeSet};

/// An admin caller whose credential some other layer has already verified.
///
/// Constructing one is an assertion that authentication already succeeded. The
/// dispatch surface never manufactures a caller of its own, so a request that
/// produces no `AdminRpcCaller` can only be rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminRpcCaller {
    subject: String,
    role: Role,
    scopes: ScopeSet,
}

impl AdminRpcCaller {
    /// Records an already-authenticated caller and the authority it was granted.
    #[must_use]
    pub fn new(subject: impl Into<String>, role: Role, scopes: ScopeSet) -> Self {
        Self {
            subject: subject.into(),
            role,
            scopes,
        }
    }

    /// Returns the stable, non-secret caller identifier used for auditing.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the authenticated role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns the granted operator scope set.
    #[must_use]
    pub const fn scopes(&self) -> ScopeSet {
        self.scopes
    }
}

/// Why a request produced no authenticated admin caller.
///
/// The variants exist so an authenticator can report precisely why it refused.
/// They deliberately do **not** change the response: every rejection renders the
/// identical `401`, so the surface never becomes an oracle for which
/// credentials exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminRpcAuthRejection {
    /// No admin credential was presented at all.
    Missing,
    /// A credential was presented and did not verify.
    Invalid,
}

/// Authenticates an Admin HTTP RPC request on behalf of the dispatch surface.
///
/// This is the single seam through which an authentication implementation is
/// attached. An implementation must be fail-closed: it returns a caller only
/// when a credential actually verified.
pub trait AdminRpcAuthenticator: Send + Sync {
    /// Returns the verified caller, or the reason the request is unauthenticated.
    ///
    /// # Errors
    ///
    /// Returns [`AdminRpcAuthRejection`] when no credential verifies.
    fn authenticate(&self, headers: &HeaderMap) -> Result<AdminRpcCaller, AdminRpcAuthRejection>;
}

/// An authenticator that refuses every request.
///
/// This is the default a service is built with, so a surface wired up without
/// an authentication implementation denies traffic instead of serving it
/// unauthenticated.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllAuthenticator;

impl AdminRpcAuthenticator for DenyAllAuthenticator {
    fn authenticate(&self, _headers: &HeaderMap) -> Result<AdminRpcCaller, AdminRpcAuthRejection> {
        Err(AdminRpcAuthRejection::Missing)
    }
}

/// An authenticator built from a caller-supplied closure.
///
/// This keeps the dispatch surface usable before a full credential store
/// exists, and keeps callers from having to declare a type per scenario.
pub struct FnAuthenticator<F>(F);

impl<F> FnAuthenticator<F>
where
    F: Fn(&HeaderMap) -> Result<AdminRpcCaller, AdminRpcAuthRejection> + Send + Sync,
{
    /// Wraps a closure as an authenticator.
    #[must_use]
    pub const fn new(authenticate: F) -> Self {
        Self(authenticate)
    }
}

impl<F> Debug for FnAuthenticator<F> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("FnAuthenticator")
    }
}

impl<F> AdminRpcAuthenticator for FnAuthenticator<F>
where
    F: Fn(&HeaderMap) -> Result<AdminRpcCaller, AdminRpcAuthRejection> + Send + Sync,
{
    fn authenticate(&self, headers: &HeaderMap) -> Result<AdminRpcCaller, AdminRpcAuthRejection> {
        (self.0)(headers)
    }
}
