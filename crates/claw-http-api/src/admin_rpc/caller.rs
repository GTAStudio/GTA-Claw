//! The authenticated-caller seam for the Admin HTTP RPC surface.
//!
//! This module deliberately owns no credential scheme. Dispatch, method policy
//! and error mapping treat "the caller is authenticated and carries an admin
//! identity" as an *injected input*, so the credential format can be replaced
//! without touching the policy or the mapping table.

use std::fmt::{self, Debug, Formatter};

use axum::http::HeaderMap;
use axum::http::header;
use claw_security::authorization::{Role, ScopeSet};

use crate::auth::BearerAuthenticator;

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

/// Adapts the HTTP crate's pre-hashed bearer credential store to Admin RPC.
///
/// The resulting caller subject is a stable SHA-256 identifier, never the
/// presented token. This is the production bridge used by [`crate::HttpApi`].
#[derive(Clone, Debug)]
pub struct BearerAdminRpcAuthenticator {
    authenticator: BearerAuthenticator,
}

impl BearerAdminRpcAuthenticator {
    /// Creates an Admin RPC authenticator over an existing bearer store.
    #[must_use]
    pub const fn new(authenticator: BearerAuthenticator) -> Self {
        Self { authenticator }
    }
}

impl AdminRpcAuthenticator for BearerAdminRpcAuthenticator {
    fn authenticate(&self, headers: &HeaderMap) -> Result<AdminRpcCaller, AdminRpcAuthRejection> {
        let principal = self
            .authenticator
            .authenticate_headers(headers)
            .ok_or_else(|| {
                if headers.contains_key(header::AUTHORIZATION) {
                    AdminRpcAuthRejection::Invalid
                } else {
                    AdminRpcAuthRejection::Missing
                }
            })?;
        Ok(AdminRpcCaller::new(
            hex_subject(&principal.subject),
            principal.role,
            principal.scopes,
        ))
    }
}

fn hex_subject(subject: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(subject.len() * 2);
    for byte in subject {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
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
