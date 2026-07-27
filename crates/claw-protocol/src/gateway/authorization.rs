use std::error::Error;
use std::fmt::{self, Display, Formatter};

use super::{
    GatewayMethod, MethodScope, OperatorScope, PluginLookup, RegistryError, Role,
    resolve_gateway_method,
};

/// Successful authorization decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// The role and effective scopes authorize dispatch.
    Allowed,
}

/// Authorizes a resolved method with role checks before scope checks.
///
/// `resolved_dynamic_scopes` must be supplied for methods classified as
/// [`MethodScope::Dynamic`]; it is never defaulted.
///
/// # Errors
///
/// - [`AuthorizationError::WorkerNotAdmitted`] — `role` is [`Role::Worker`],
///   which belongs to the closed worker protocol and never reaches ordinary
///   Gateway RPC.
/// - [`AuthorizationError::RoleMismatch`] — the method is node-scoped and the
///   caller is not a node, or the method is operator- or dynamically scoped and
///   the caller is not an operator.
/// - [`AuthorizationError::UnresolvedDynamicScope`] — the method is
///   [`MethodScope::Dynamic`] and `resolved_dynamic_scopes` is `None`, so no
///   runtime resolver answered for it.
/// - [`AuthorizationError::EmptyDynamicScope`] — a resolver answered with an
///   empty scope set, which would otherwise authorize the method for free.
/// - [`AuthorizationError::MissingScope`] — `granted_scopes` lacks a required
///   scope. [`OperatorScope::Admin`] satisfies everything and
///   [`OperatorScope::Write`] satisfies [`OperatorScope::Read`]; no other
///   implication exists.
pub fn authorize(
    role: Role,
    method: GatewayMethod<'_>,
    granted_scopes: &[OperatorScope],
    resolved_dynamic_scopes: Option<&[OperatorScope]>,
) -> Result<AuthorizationDecision, AuthorizationError> {
    if role == Role::Worker {
        return Err(AuthorizationError::WorkerNotAdmitted);
    }

    // Upstream exposes health to both ordinary gateway roles before method-scope checks.
    if matches!(method, GatewayMethod::Core(core) if core.name() == "health") {
        return Ok(AuthorizationDecision::Allowed);
    }

    let scope = method.scope();
    match scope {
        MethodScope::Node if role != Role::Node => {
            return Err(AuthorizationError::RoleMismatch {
                required: Role::Node,
                actual: role,
            });
        }
        MethodScope::Operator(_) | MethodScope::Dynamic if role != Role::Operator => {
            return Err(AuthorizationError::RoleMismatch {
                required: Role::Operator,
                actual: role,
            });
        }
        MethodScope::Node | MethodScope::Operator(_) | MethodScope::Dynamic => {}
    }

    if scope == MethodScope::Node {
        return Ok(AuthorizationDecision::Allowed);
    }

    let static_required;
    let required = match scope {
        MethodScope::Operator(scope) => {
            static_required = [scope];
            static_required.as_slice()
        }
        MethodScope::Dynamic => {
            let scopes = resolved_dynamic_scopes.ok_or_else(|| {
                AuthorizationError::UnresolvedDynamicScope {
                    method: method.identity().to_owned(),
                }
            })?;
            if scopes.is_empty() {
                return Err(AuthorizationError::EmptyDynamicScope {
                    method: method.identity().to_owned(),
                });
            }
            scopes
        }
        MethodScope::Node => unreachable!("node methods returned after the role check"),
    };

    if granted_scopes.contains(&OperatorScope::Admin) {
        return Ok(AuthorizationDecision::Allowed);
    }
    for required in required {
        let satisfied = granted_scopes.contains(required)
            || (*required == OperatorScope::Read && granted_scopes.contains(&OperatorScope::Write));
        if !satisfied {
            return Err(AuthorizationError::MissingScope {
                method: method.identity().to_owned(),
                required: *required,
            });
        }
    }
    Ok(AuthorizationDecision::Allowed)
}

/// Resolves and authorizes an exact method identity.
///
/// Unknown methods and plugin methods without explicit [`PluginLookup::Allow`]
/// fail closed before dispatch.
///
/// # Errors
///
/// Returns [`AuthorizationError::Registry`] wrapping
/// [`RegistryError::UnknownMethod`] when `method_name` is neither a frozen core
/// method nor a method in an explicitly permitted plugin registry, and
/// otherwise every rejection listed for [`authorize`].
pub fn authorize_named(
    role: Role,
    method_name: &str,
    plugin_lookup: PluginLookup<'_>,
    granted_scopes: &[OperatorScope],
    resolved_dynamic_scopes: Option<&[OperatorScope]>,
) -> Result<AuthorizationDecision, AuthorizationError> {
    let method =
        resolve_gateway_method(method_name, plugin_lookup).map_err(AuthorizationError::Registry)?;
    authorize(role, method, granted_scopes, resolved_dynamic_scopes)
}

/// A fail-closed role, scope, dynamic resolution, or registry denial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationError {
    /// Closed worker sessions cannot call ordinary Gateway RPC.
    WorkerNotAdmitted,
    /// Method role and authenticated role differ.
    RoleMismatch {
        /// Required role.
        required: Role,
        /// Actual role.
        actual: Role,
    },
    /// The caller omitted a required dynamic scope result.
    UnresolvedDynamicScope {
        /// Exact method identity.
        method: String,
    },
    /// A dynamic resolver returned no required scopes.
    EmptyDynamicScope {
        /// Exact method identity.
        method: String,
    },
    /// The caller lacks the required operator scope.
    MissingScope {
        /// Exact method identity.
        method: String,
        /// Required scope.
        required: OperatorScope,
    },
    /// Method lookup failed closed.
    Registry(RegistryError),
}

impl Display for AuthorizationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkerNotAdmitted => {
                formatter.write_str("worker role is not admitted to ordinary Gateway RPC")
            }
            Self::RoleMismatch { required, actual } => write!(
                formatter,
                "method requires {} role; authenticated as {}",
                required.as_str(),
                actual.as_str()
            ),
            Self::UnresolvedDynamicScope { method } => {
                write!(formatter, "dynamic scope for `{method}` was not resolved")
            }
            Self::EmptyDynamicScope { method } => {
                write!(
                    formatter,
                    "dynamic scope for `{method}` resolved to an empty set"
                )
            }
            Self::MissingScope { method, required } => {
                write!(formatter, "`{method}` requires {}", required.as_str())
            }
            Self::Registry(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for AuthorizationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Registry(error) => Some(error),
            _ => None,
        }
    }
}
