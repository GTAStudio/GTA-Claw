//! The gateway authorization matrix over the closed role and scope registries.
//!
//! [`crate::authorization`] owns the closed [`Role`] and [`Scope`] registries
//! and the handshake-level policy. This module owns the per-method half of the
//! same contract: it maps the frozen `scope` classification that every gateway
//! method carries in `compat/upstream/inventories/gateway-protocol.json` onto a
//! deny-by-default decision for one caller, and every decision names the gate
//! that made it.
//!
//! The rules are exactly those pinned by the frozen baseline:
//!
//! - `role=worker` speaks the separate closed worker protocol and is never
//!   admitted to ordinary gateway RPC, whatever scopes it presents.
//! - The role gate runs before the scope gate. A node-plane method admits only
//!   `role=node`; an operator-plane method admits only `role=operator`.
//! - `health` is the one method both ordinary gateway roles reach before any
//!   scope check.
//! - `operator.admin` satisfies every operator scope and `operator.write`
//!   satisfies `operator.read`. The closed set carries no other implication,
//!   and `operator.talk.secrets` is carried by no method at this baseline.
//! - A method whose scope is resolved at runtime is denied until that
//!   resolution is supplied, and an empty resolution is a denial rather than a
//!   pass.
//!
//! Membership in the registry describes authorization metadata only. Nothing
//! here claims that any of the 278 gateway method behaviours are implemented.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::authorization::{RegistryError, Role, RoleScopeError, Scope, ScopeSet};

/// Frozen inventory classification naming the node plane.
pub const NODE_PLANE_CLASSIFICATION: &str = "node";
/// Frozen inventory classification naming a runtime-resolved operator scope.
pub const DYNAMIC_CLASSIFICATION: &str = "dynamic";
/// The one method admitted on both ordinary gateway planes before scope checks.
pub const DUAL_PLANE_METHOD: &str = "health";

/// What one gateway method requires of its caller.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodRequirement {
    /// Reachable by both ordinary gateway roles before any scope check.
    DualPlane,
    /// Node-plane method; no operator scope participates in the decision.
    NodePlane,
    /// Operator-plane method gated on exactly one closed operator scope.
    OperatorScope(Scope),
    /// Operator-plane method whose required scopes are resolved per call.
    DynamicOperatorScope,
}

impl MethodRequirement {
    /// Parses the frozen `scope` classification of one inventory method row.
    ///
    /// This reads the classification alone and never applies the
    /// [`DUAL_PLANE_METHOD`] exception; use [`method_requirement`] for a whole
    /// row. An unrecognised classification is rejected rather than normalised.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::UnknownScope`] when `classification` is neither
    /// [`NODE_PLANE_CLASSIFICATION`], [`DYNAMIC_CLASSIFICATION`], nor one of the
    /// six frozen operator scopes in [`Scope::ALL`]. A corrupt or newly added
    /// classification therefore fails closed instead of resolving to some
    /// weaker requirement.
    pub fn parse(classification: &str) -> Result<Self, RegistryError> {
        match classification {
            NODE_PLANE_CLASSIFICATION => Ok(Self::NodePlane),
            DYNAMIC_CLASSIFICATION => Ok(Self::DynamicOperatorScope),
            scope => Scope::parse(scope).map(Self::OperatorScope),
        }
    }

    /// Reports whether this requirement is decided on the operator plane.
    #[must_use]
    pub const fn is_operator_plane(self) -> bool {
        matches!(self, Self::OperatorScope(_) | Self::DynamicOperatorScope)
    }
}

/// Resolves the effective requirement of one frozen inventory method row.
///
/// The classification is parsed first, so a corrupt classification is rejected
/// even for the dual-plane method.
///
/// # Errors
///
/// Returns [`RegistryError::UnknownScope`] when `classification` is not one the
/// closed registry recognises, exactly as [`MethodRequirement::parse`] does.
/// This is checked before the [`DUAL_PLANE_METHOD`] exception, so naming the
/// dual-plane method cannot rescue an unreadable row.
pub fn method_requirement(
    method: &str,
    classification: &str,
) -> Result<MethodRequirement, RegistryError> {
    let requirement = MethodRequirement::parse(classification)?;
    if method == DUAL_PLANE_METHOD {
        return Ok(MethodRequirement::DualPlane);
    }
    Ok(requirement)
}

/// A caller presenting an authenticated role and its closed granted scope set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Principal {
    /// Authenticated role.
    pub role: Role,
    /// Closed set of granted operator scopes.
    pub granted_scopes: ScopeSet,
}

impl Principal {
    /// Builds a principal without asserting the role/scope pairing.
    ///
    /// [`validate_principal`] decides whether the pairing is admissible at all.
    /// Method authorization deliberately does not depend on that check, so a
    /// node that somehow presented operator scopes is still refused every
    /// operator-plane method by the role gate.
    #[must_use]
    pub const fn new(role: Role, granted_scopes: ScopeSet) -> Self {
        Self {
            role,
            granted_scopes,
        }
    }
}

/// Parses an untrusted scope list through the closed registry.
///
/// The set is closed: a single unrecognised member rejects the whole list
/// rather than being dropped, so an unknown scope can never be silently
/// tolerated alongside recognised ones.
///
/// # Errors
///
/// Returns [`RegistryError::UnknownScope`] for the first value outside
/// [`Scope::ALL`], in iteration order. Recognised members parsed before it are
/// discarded with it: the caller receives no partially accepted scope set.
pub fn parse_granted_scopes<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<ScopeSet, RegistryError> {
    // Collecting straight into the bitset avoids the intermediate `Vec` this
    // used to build per handshake; `Result` still short-circuits on the first
    // unknown scope, so the rejected value is unchanged.
    values.into_iter().map(Scope::parse).collect()
}

/// Parses an untrusted handshake identity through both closed registries.
///
/// # Errors
///
/// - [`RegistryError::UnknownRole`] when `role` is not `operator`, `node`, or
///   `worker`. The role is parsed first, so a handshake that is wrong about
///   both role and scopes reports the role.
/// - [`RegistryError::UnknownScope`] when any member of `granted_scopes` is
///   outside [`Scope::ALL`], as described on [`parse_granted_scopes`].
pub fn parse_principal<'a>(
    role: &str,
    granted_scopes: impl IntoIterator<Item = &'a str>,
) -> Result<Principal, RegistryError> {
    let role = Role::parse(role)?;
    Ok(Principal::new(role, parse_granted_scopes(granted_scopes)?))
}

/// Rejects a handshake that pairs a non-operator role with operator scopes.
///
/// # Errors
///
/// Returns [`RoleScopeError::OperatorScopesRequireOperatorRole`] when the
/// principal's role is [`Role::Node`] or [`Role::Worker`] and its granted set
/// is not empty.
#[must_use = "an ignored principal check silently admits an over-scoped handshake"]
pub fn validate_principal(principal: Principal) -> Result<(), RoleScopeError> {
    crate::authorization::validate_role_scopes(principal.role, principal.granted_scopes)
}

/// Returns the granted scope that satisfies `required`, if any.
///
/// The answer is deterministic rather than merely present: the exact scope wins,
/// then `operator.write` standing in for `operator.read`, then the blanket
/// `operator.admin`. Reporting *which* scope satisfied a call is what lets an
/// audit distinguish an exact grant from an administrative override.
#[must_use]
pub fn satisfying_scope(granted: ScopeSet, required: Scope) -> Option<Scope> {
    if granted.contains(required) {
        Some(required)
    } else if required == Scope::OperatorRead && granted.contains(Scope::OperatorWrite) {
        Some(Scope::OperatorWrite)
    } else if granted.contains(Scope::OperatorAdmin) {
        Some(Scope::OperatorAdmin)
    } else {
        None
    }
}

/// Why a gateway call was admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MethodGrant {
    /// Both ordinary gateway roles reach this method before any scope check.
    DualPlane,
    /// The node plane admitted `role=node`.
    NodePlane,
    /// A granted operator scope satisfied the method's static requirement.
    OperatorScope {
        /// Scope the method requires.
        required: Scope,
        /// Granted scope that satisfied it.
        satisfied_by: Scope,
    },
    /// Every scope of a runtime resolution was satisfied.
    DynamicOperatorScopes,
}

/// Why a gateway call was refused. Every refusal names the gate that refused it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MethodDenial {
    /// `role=worker` runs the closed worker protocol, not ordinary gateway RPC.
    WorkerNotAdmitted,
    /// The method's plane requires a different role.
    RoleMismatch {
        /// Role the plane requires.
        required: Role,
        /// Role the caller authenticated as.
        actual: Role,
    },
    /// No granted scope satisfies a required scope.
    ScopeNotGranted {
        /// The first required scope, in frozen ordinal order, that is unmet.
        required: Scope,
    },
    /// A runtime-resolved method was authorized without its resolution.
    UnresolvedDynamicScope,
    /// A runtime resolver returned no required scopes.
    EmptyDynamicScope,
}

impl Display for MethodDenial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkerNotAdmitted => {
                formatter.write_str("worker role is not admitted to ordinary gateway RPC")
            }
            Self::RoleMismatch { required, actual } => write!(
                formatter,
                "method requires role={required}; authenticated as role={actual}"
            ),
            Self::ScopeNotGranted { required } => {
                write!(formatter, "method requires scope {required}")
            }
            Self::UnresolvedDynamicScope => {
                formatter.write_str("runtime scope resolution was not supplied")
            }
            Self::EmptyDynamicScope => formatter.write_str("runtime scope resolution was empty"),
        }
    }
}

impl Error for MethodDenial {}

/// Authorizes one gateway method call, deny by default.
///
/// `dynamic_resolution` is consulted only by
/// [`MethodRequirement::DynamicOperatorScope`] and is never defaulted: a
/// missing resolution denies, and so does an empty one.
///
/// # Errors
///
/// - [`MethodDenial::WorkerNotAdmitted`] when the principal holds
///   [`Role::Worker`], whatever the method or its scopes.
/// - [`MethodDenial::RoleMismatch`] when a node-plane method is called by a
///   non-node, or an operator-plane method by a non-operator. The role gate
///   runs before the scope gate, so an over-scoped node is still refused here.
/// - [`MethodDenial::ScopeNotGranted`] when no granted scope satisfies the
///   required one under the rules in [`satisfying_scope`]. For a dynamic
///   method this names the first unsatisfied scope in frozen ordinal order.
/// - [`MethodDenial::UnresolvedDynamicScope`] when the method's scope is
///   resolved at runtime but `dynamic_resolution` is [`None`].
/// - [`MethodDenial::EmptyDynamicScope`] when the runtime resolution is present
///   but empty; an empty requirement is a denial, never a free pass.
pub fn authorize_method(
    principal: Principal,
    requirement: MethodRequirement,
    dynamic_resolution: Option<ScopeSet>,
) -> Result<MethodGrant, MethodDenial> {
    if principal.role == Role::Worker {
        return Err(MethodDenial::WorkerNotAdmitted);
    }
    match requirement {
        MethodRequirement::DualPlane => Ok(MethodGrant::DualPlane),
        MethodRequirement::NodePlane if principal.role == Role::Node => Ok(MethodGrant::NodePlane),
        MethodRequirement::NodePlane => Err(MethodDenial::RoleMismatch {
            required: Role::Node,
            actual: principal.role,
        }),
        MethodRequirement::OperatorScope(_) | MethodRequirement::DynamicOperatorScope
            if principal.role != Role::Operator =>
        {
            Err(MethodDenial::RoleMismatch {
                required: Role::Operator,
                actual: principal.role,
            })
        }
        MethodRequirement::OperatorScope(required) => {
            satisfying_scope(principal.granted_scopes, required)
                .map(|satisfied_by| MethodGrant::OperatorScope {
                    required,
                    satisfied_by,
                })
                .ok_or(MethodDenial::ScopeNotGranted { required })
        }
        MethodRequirement::DynamicOperatorScope => {
            let resolved = dynamic_resolution.ok_or(MethodDenial::UnresolvedDynamicScope)?;
            if resolved.is_empty() {
                return Err(MethodDenial::EmptyDynamicScope);
            }
            for required in resolved.iter() {
                if satisfying_scope(principal.granted_scopes, required).is_none() {
                    return Err(MethodDenial::ScopeNotGranted { required });
                }
            }
            Ok(MethodGrant::DynamicOperatorScopes)
        }
    }
}

/// Authorizes one frozen inventory method row for one principal.
///
/// Resolution of the row and authorization of the caller fail closed
/// independently: an unrecognised classification is a [`RegistryError`], not a
/// denial that a caller could mistake for a scope problem.
///
/// # Errors
///
/// The outer [`Err`] is a [`RegistryError::UnknownScope`] from
/// [`method_requirement`]: the row itself could not be read, so no decision was
/// made about the caller at all. The inner [`Err`] is a [`MethodDenial`] from
/// [`authorize_method`], which describes the caller. Callers must not collapse
/// the two — an unreadable row is an inventory defect, not an under-scoped
/// principal.
pub fn authorize_inventory_method(
    principal: Principal,
    method: &str,
    classification: &str,
    dynamic_resolution: Option<ScopeSet>,
) -> Result<Result<MethodGrant, MethodDenial>, RegistryError> {
    let requirement = method_requirement(method, classification)?;
    Ok(authorize_method(principal, requirement, dynamic_resolution))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirement_parsing_is_closed_over_the_frozen_classifications() {
        assert_eq!(
            MethodRequirement::parse("node"),
            Ok(MethodRequirement::NodePlane)
        );
        assert_eq!(
            MethodRequirement::parse("dynamic"),
            Ok(MethodRequirement::DynamicOperatorScope)
        );
        assert_eq!(
            MethodRequirement::parse("operator.read"),
            Ok(MethodRequirement::OperatorScope(Scope::OperatorRead))
        );
        for rejected in [
            "",
            " node",
            "Node",
            "worker",
            "operator",
            "operator.superuser",
        ] {
            assert_eq!(
                MethodRequirement::parse(rejected),
                Err(RegistryError::UnknownScope),
                "`{rejected}` must not resolve to a requirement"
            );
        }
    }

    #[test]
    fn dual_plane_exception_never_rescues_a_corrupt_classification() {
        assert_eq!(
            method_requirement("health", "operator.read"),
            Ok(MethodRequirement::DualPlane)
        );
        assert_eq!(
            method_requirement("health", "operator.superuser"),
            Err(RegistryError::UnknownScope)
        );
        assert_eq!(
            method_requirement("status", "operator.read"),
            Ok(MethodRequirement::OperatorScope(Scope::OperatorRead))
        );
    }

    #[test]
    fn unknown_identities_reject_the_whole_principal() {
        assert_eq!(
            parse_granted_scopes(["operator.read", "operator.superuser"]),
            Err(RegistryError::UnknownScope)
        );
        assert_eq!(
            parse_principal("Operator", ["operator.read"]).err(),
            Some(RegistryError::UnknownRole)
        );
        let principal = parse_principal("operator", ["operator.read", "operator.read"])
            .expect("frozen identities");
        assert_eq!(
            principal.granted_scopes,
            ScopeSet::from_scopes([Scope::OperatorRead])
        );
    }
}
