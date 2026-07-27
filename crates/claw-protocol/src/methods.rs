//! Pinned Gateway core method catalog projections and drift verification.
//!
//! The catalog itself is generated at build time from the validator-owned
//! inventory `compat/upstream/inventories/gateway-protocol.json`, which pins
//! `src/gateway/methods/core-descriptors.ts` and
//! `src/gateway/server-methods-list.ts` at
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`.
//!
//! This module never restates the catalog. It exposes the projections callers
//! need over the generated data — the conservative advertised method list, scope
//! grouping and exact lookup — plus [`verify_pinned_methods`], which compares the
//! generated catalog against externally supplied pinned rows and reports the
//! first exact difference. Catalog membership describes wire compatibility and
//! authorization metadata; it does not claim any method behaviour is implemented.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::gateway::{MethodScope, OperatorScope, core_methods, resolve_core_method};

/// Wire identity of the node-role-only method classification.
pub const NODE_SCOPE_IDENTITY: &str = "node";
/// Wire identity of the classification whose operator scope is caller-resolved.
pub const DYNAMIC_SCOPE_IDENTITY: &str = "dynamic";

/// An owned view of one generated core method descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MethodDescriptor {
    name: &'static str,
    scope: MethodScope,
    advertised: bool,
}

impl MethodDescriptor {
    /// Returns the exact, case-sensitive method identity.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the frozen authorization classification.
    #[must_use]
    pub const fn scope(self) -> MethodScope {
        self.scope
    }

    /// Returns the exact wire identity of this method's classification.
    #[must_use]
    pub const fn scope_identity(self) -> &'static str {
        scope_identity(self.scope)
    }

    /// Reports whether this method appears in the conservative hello method list.
    #[must_use]
    pub const fn advertised(self) -> bool {
        self.advertised
    }
}

/// Returns the exact wire identity for an authorization classification.
#[must_use]
pub const fn scope_identity(scope: MethodScope) -> &'static str {
    match scope {
        MethodScope::Operator(scope) => scope.as_str(),
        MethodScope::Node => NODE_SCOPE_IDENTITY,
        MethodScope::Dynamic => DYNAMIC_SCOPE_IDENTITY,
    }
}

/// Parses an exact, case-sensitive classification identity from the closed set.
#[must_use]
pub fn parse_scope_identity(identity: &str) -> Option<MethodScope> {
    match identity {
        NODE_SCOPE_IDENTITY => Some(MethodScope::Node),
        DYNAMIC_SCOPE_IDENTITY => Some(MethodScope::Dynamic),
        operator => OperatorScope::from_identity(operator).map(MethodScope::Operator),
    }
}

/// Returns every generated core method descriptor in canonical inventory order.
pub fn descriptors() -> impl Iterator<Item = MethodDescriptor> {
    core_methods().iter().map(|method| MethodDescriptor {
        name: method.name(),
        scope: method.scope(),
        advertised: method.advertised(),
    })
}

/// Returns the number of generated core methods.
#[must_use]
pub const fn method_count() -> usize {
    core_methods().len()
}

/// Returns the number of methods carried by the conservative hello method list.
#[must_use]
pub fn advertised_count() -> usize {
    descriptors()
        .filter(|descriptor| descriptor.advertised())
        .count()
}

/// Returns the advertised hello method names in canonical inventory order.
pub fn advertised_method_names() -> impl Iterator<Item = &'static str> {
    descriptors()
        .filter(|descriptor| descriptor.advertised())
        .map(MethodDescriptor::name)
}

/// Returns the callable-but-unadvertised method names in canonical order.
///
/// Advertisement controls hello-list visibility only; an unadvertised method is
/// still a member of the catalog and is still resolved by [`descriptor`].
pub fn unadvertised_method_names() -> impl Iterator<Item = &'static str> {
    descriptors()
        .filter(|descriptor| !descriptor.advertised())
        .map(MethodDescriptor::name)
}

/// Resolves one method descriptor by exact ordinal UTF-8 identity.
#[must_use]
pub fn descriptor(name: &str) -> Option<MethodDescriptor> {
    resolve_core_method(name).map(|method| MethodDescriptor {
        name: method.name(),
        scope: method.scope(),
        advertised: method.advertised(),
    })
}

/// Returns every method carrying exactly this classification.
pub fn methods_in_scope(scope: MethodScope) -> impl Iterator<Item = MethodDescriptor> {
    descriptors().filter(move |descriptor| descriptor.scope() == scope)
}

/// Returns how many methods carry exactly this classification.
#[must_use]
pub fn scope_method_count(scope: MethodScope) -> usize {
    methods_in_scope(scope).count()
}

/// One externally pinned method row supplied to [`verify_pinned_methods`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedMethod<'a> {
    /// Exact, case-sensitive method identity.
    pub name: &'a str,
    /// Exact classification identity, such as `operator.read` or `node`.
    pub scope: &'a str,
    /// Whether the pinned row appears in the hello method list.
    pub advertised: bool,
}

/// The first exact difference between the generated catalog and pinned rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MethodCatalogDrift {
    /// The catalog and the pinned rows have different lengths.
    Count {
        /// Number of generated methods.
        generated: usize,
        /// Number of pinned rows.
        pinned: usize,
    },
    /// A pinned row named a classification outside the closed set.
    UnknownScope {
        /// Pinned method identity carrying the unknown classification.
        name: String,
        /// The rejected classification identity.
        scope: String,
    },
    /// A pinned row repeated an identity already supplied.
    DuplicateName {
        /// The repeated identity.
        name: String,
    },
    /// Canonical order or membership diverged at this position.
    Name {
        /// Zero-based canonical position.
        position: usize,
        /// Generated identity at that position.
        generated: &'static str,
        /// Pinned identity at that position.
        pinned: String,
    },
    /// A method's classification diverged.
    Scope {
        /// The method identity.
        name: &'static str,
        /// Generated classification identity.
        generated: &'static str,
        /// Pinned classification identity.
        pinned: String,
    },
    /// A method's advertised flag diverged.
    Advertised {
        /// The method identity.
        name: &'static str,
        /// Generated advertised flag.
        generated: bool,
        /// Pinned advertised flag.
        pinned: bool,
    },
    /// A generated method could not be resolved back by its own identity.
    Unresolvable {
        /// The unresolvable identity.
        name: &'static str,
    },
}

impl Display for MethodCatalogDrift {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count { generated, pinned } => write!(
                formatter,
                "catalog holds {generated} methods; pinned inventory holds {pinned}"
            ),
            Self::UnknownScope { name, scope } => {
                write!(
                    formatter,
                    "pinned method `{name}` names unknown scope `{scope}`"
                )
            }
            Self::DuplicateName { name } => {
                write!(formatter, "pinned method `{name}` is supplied twice")
            }
            Self::Name {
                position,
                generated,
                pinned,
            } => write!(
                formatter,
                "method {position} is `{generated}` in the catalog and `{pinned}` in the pinned inventory"
            ),
            Self::Scope {
                name,
                generated,
                pinned,
            } => write!(
                formatter,
                "method `{name}` is scoped `{generated}` in the catalog and `{pinned}` in the pinned inventory"
            ),
            Self::Advertised {
                name,
                generated,
                pinned,
            } => write!(
                formatter,
                "method `{name}` is advertised={generated} in the catalog and advertised={pinned} in the pinned inventory"
            ),
            Self::Unresolvable { name } => {
                write!(
                    formatter,
                    "catalog method `{name}` does not resolve by identity"
                )
            }
        }
    }
}

impl Error for MethodCatalogDrift {}

/// Compares the generated catalog against pinned rows, position by position.
///
/// Every generated method must appear at the same canonical position, with the
/// same classification and the same advertised flag, and must resolve back by
/// its own identity. The comparison is exact and ordinal; the first difference
/// is reported rather than a summary, so drift names the row that moved.
///
/// # Errors
///
/// Returns the first [`MethodCatalogDrift`] observed.
pub fn verify_pinned_methods<'a, I>(pinned: I) -> Result<(), MethodCatalogDrift>
where
    I: IntoIterator<Item = PinnedMethod<'a>>,
{
    let generated = core_methods();
    let pinned = pinned.into_iter().collect::<Vec<_>>();
    if pinned.len() != generated.len() {
        return Err(MethodCatalogDrift::Count {
            generated: generated.len(),
            pinned: pinned.len(),
        });
    }

    let mut seen = BTreeSet::new();
    for (position, row) in pinned.iter().enumerate() {
        let entry = generated[position];
        let scope =
            parse_scope_identity(row.scope).ok_or_else(|| MethodCatalogDrift::UnknownScope {
                name: row.name.to_owned(),
                scope: row.scope.to_owned(),
            })?;
        if !seen.insert(row.name) {
            return Err(MethodCatalogDrift::DuplicateName {
                name: row.name.to_owned(),
            });
        }
        if entry.name() != row.name {
            return Err(MethodCatalogDrift::Name {
                position,
                generated: entry.name(),
                pinned: row.name.to_owned(),
            });
        }
        if entry.scope() != scope {
            return Err(MethodCatalogDrift::Scope {
                name: entry.name(),
                generated: scope_identity(entry.scope()),
                pinned: row.scope.to_owned(),
            });
        }
        if entry.advertised() != row.advertised {
            return Err(MethodCatalogDrift::Advertised {
                name: entry.name(),
                generated: entry.advertised(),
                pinned: row.advertised,
            });
        }
        if resolve_core_method(entry.name()).map(|method| method.name()) != Some(entry.name()) {
            return Err(MethodCatalogDrift::Unresolvable { name: entry.name() });
        }
    }
    Ok(())
}
