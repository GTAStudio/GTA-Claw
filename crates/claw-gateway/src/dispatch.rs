//! Method dispatch registry covering every frozen core Gateway method.
//!
//! The registry is built directly from
//! [`claw_protocol::gateway::core_methods`], so its key set is exactly the
//! frozen catalog: no method can be silently missing and no unknown method can
//! be added. Methods this server really implements carry a handler; every other
//! catalogued method answers with
//! [`DispatchError::NotImplemented`](crate::error::DispatchError::NotImplemented).

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use claw_protocol::gateway::{
    GatewayMethod, MethodScope, OperatorScope, Role, authorize, core_methods, resolve_core_method,
};
use serde_json::Value;

use crate::clock::Clock;
use crate::directory::ConnectionDirectory;
use crate::error::DispatchError;
use crate::events::{ConnectionId, EventBus, TopicFilter};
use crate::store::GatewayStore;

/// Boxed future returned by a [`MethodHandler`].
pub type MethodFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, DispatchError>> + Send + 'a>>;

/// Everything a handler may touch while serving one request.
pub struct MethodContext<'a> {
    /// Exact catalogued method identity being served.
    pub method: &'static str,
    /// Server-assigned connection identity of the caller.
    pub connection: ConnectionId,
    /// Authenticated role of the caller.
    pub role: Role,
    /// Effective closed operator scopes of the caller.
    pub scopes: &'a [OperatorScope],
    /// Verified device wire identity of the caller.
    pub device_id: &'a str,
    /// Persistence port.
    pub store: &'a dyn GatewayStore,
    /// Event fan-out bus.
    pub events: &'a EventBus,
    /// Wall-clock port.
    pub clock: &'a dyn Clock,
    /// Live authenticated connection directory.
    pub directory: &'a ConnectionDirectory,
    /// This connection's mutable event topic filter.
    pub filter: &'a Mutex<TopicFilter>,
    /// Server version reported by informational methods.
    pub server_version: &'a str,
}

impl Debug for MethodContext<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MethodContext")
            .field("method", &self.method)
            .field("connection", &self.connection)
            .field("role", &self.role)
            .field("scopes", &self.scopes)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// Behavior for one catalogued Gateway method.
pub trait MethodHandler: Debug + Send + Sync {
    /// Serves one authorized request.
    ///
    /// Authorization has already succeeded when this runs; handlers must still
    /// validate their own parameters strictly.
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a>;
}

/// Supplies the operator scopes required by a [`MethodScope::Dynamic`] method.
pub trait DynamicScopeResolver: Debug + Send + Sync {
    /// Returns the required scopes, or `None` when the method cannot be resolved.
    ///
    /// Returning `None` or an empty vector fails the call closed.
    fn resolve(&self, method: &str, params: &Value) -> Option<Vec<OperatorScope>>;
}

/// Conservative built-in resolver for the four frozen dynamic methods.
///
/// The frozen inventory classifies these four as `dynamic` without recording
/// the runtime rule upstream uses, so this resolver applies the strictest
/// defensible mapping: creation and mutation require write, deletion and
/// plugin-driven session actions require admin.
#[derive(Clone, Copy, Debug, Default)]
pub struct StaticDynamicScopes;

impl DynamicScopeResolver for StaticDynamicScopes {
    fn resolve(&self, method: &str, _params: &Value) -> Option<Vec<OperatorScope>> {
        match method {
            "sessions.create" | "sessions.patch" => Some(vec![OperatorScope::Write]),
            "sessions.delete" | "plugins.sessionAction" => Some(vec![OperatorScope::Admin]),
            _ => None,
        }
    }
}

/// Returns the wire identity of a frozen authorization classification.
#[must_use]
pub const fn scope_identity(scope: MethodScope) -> &'static str {
    match scope {
        MethodScope::Operator(scope) => scope.as_str(),
        MethodScope::Node => "node",
        MethodScope::Dynamic => "dynamic",
    }
}

#[derive(Debug)]
struct Entry {
    scope: MethodScope,
    advertised: bool,
    handler: Option<Arc<dyn MethodHandler>>,
}

/// Registry of every frozen core method and its optional behavior.
#[derive(Debug)]
pub struct MethodRegistry {
    entries: BTreeMap<&'static str, Entry>,
    dynamic: Arc<dyn DynamicScopeResolver>,
}

impl MethodRegistry {
    /// Builds a registry containing every frozen core method with no behavior.
    #[must_use]
    pub fn new() -> Self {
        Self::with_dynamic_resolver(Arc::new(StaticDynamicScopes))
    }

    /// Builds a registry with an explicit dynamic scope resolver.
    #[must_use]
    pub fn with_dynamic_resolver(dynamic: Arc<dyn DynamicScopeResolver>) -> Self {
        let entries = core_methods()
            .iter()
            .map(|method| {
                (
                    method.name(),
                    Entry {
                        scope: method.scope(),
                        advertised: method.advertised(),
                        handler: None,
                    },
                )
            })
            .collect();
        Self { entries, dynamic }
    }

    /// Attaches behavior to one catalogued method.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::UnknownMethod`] when `name` is not in the frozen
    /// catalog, which keeps the registry key set exactly equal to the catalog.
    pub fn register(
        &mut self,
        name: &str,
        handler: Arc<dyn MethodHandler>,
    ) -> Result<(), DispatchError> {
        let entry = self
            .entries
            .get_mut(name)
            .ok_or_else(|| DispatchError::UnknownMethod(name.to_owned()))?;
        entry.handler = Some(handler);
        Ok(())
    }

    /// Returns every catalogued method identity in canonical order.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.entries.keys().copied().collect()
    }

    /// Returns the identities that carry real behavior, in canonical order.
    #[must_use]
    pub fn implemented_names(&self) -> Vec<&'static str> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.handler.is_some())
            .map(|(name, _)| *name)
            .collect()
    }

    /// Returns the advertised identities, in canonical order.
    #[must_use]
    pub fn advertised_names(&self) -> Vec<&'static str> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.advertised)
            .map(|(name, _)| *name)
            .collect()
    }

    /// Returns the frozen classification of one catalogued method.
    #[must_use]
    pub fn scope_of(&self, name: &str) -> Option<MethodScope> {
        self.entries.get(name).map(|entry| entry.scope)
    }

    /// Returns the number of catalogued methods.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Reports whether the registry is empty, which never happens in practice.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Authorizes one call without running its handler.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::UnknownMethod`] for identities outside the
    /// frozen catalog and [`DispatchError::Unauthorized`] for role, scope, or
    /// dynamic-resolution denials.
    pub fn authorize_call(
        &self,
        role: Role,
        scopes: &[OperatorScope],
        method: &str,
        params: &Value,
    ) -> Result<(), DispatchError> {
        let core = resolve_core_method(method)
            .ok_or_else(|| DispatchError::UnknownMethod(method.to_owned()))?;
        let resolved = if core.scope() == MethodScope::Dynamic {
            self.dynamic.resolve(method, params)
        } else {
            None
        };
        authorize(role, GatewayMethod::Core(core), scopes, resolved.as_deref())?;
        Ok(())
    }

    /// Authorizes and serves one request.
    ///
    /// # Errors
    ///
    /// Returns the typed dispatch failure that must be rendered as a Gateway
    /// `res` error payload.
    pub async fn dispatch(
        &self,
        context: MethodContext<'_>,
        params: Value,
    ) -> Result<Value, DispatchError> {
        let method = context.method;
        self.authorize_call(context.role, context.scopes, method, &params)?;
        let entry = self
            .entries
            .get(method)
            .ok_or_else(|| DispatchError::UnknownMethod(method.to_owned()))?;
        let Some(handler) = entry.handler.as_ref() else {
            return Err(DispatchError::NotImplemented {
                method: method.to_owned(),
                scope: scope_identity(entry.scope),
            });
        };
        let handler = Arc::clone(handler);
        handler.handle(context, params).await
    }

    /// Resolves a catalogued identity to its `'static` name.
    ///
    /// Handlers receive `&'static str` method names so that error payloads can
    /// never echo attacker-controlled text for a catalogued method.
    #[must_use]
    pub fn canonical_name(&self, name: &str) -> Option<&'static str> {
        self.entries.get_key_value(name).map(|(name, _)| *name)
    }
}

impl Default for MethodRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claw_protocol::gateway::AuthorizationError;

    #[derive(Debug)]
    struct Echo;

    impl MethodHandler for Echo {
        fn handle<'a>(&'a self, _context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
            Box::pin(async move { Ok(params) })
        }
    }

    #[test]
    fn registry_key_set_equals_the_frozen_catalog() {
        let registry = MethodRegistry::new();
        let mut frozen: Vec<&'static str> =
            core_methods().iter().map(|method| method.name()).collect();
        frozen.sort_unstable();
        assert_eq!(registry.names(), frozen);
        assert_eq!(registry.len(), frozen.len());
    }

    #[test]
    fn registering_an_uncatalogued_method_is_refused() {
        let mut registry = MethodRegistry::new();
        let error = registry
            .register("sessions.definitelyNotReal", Arc::new(Echo))
            .expect_err("uncatalogued method");
        assert_eq!(
            error,
            DispatchError::UnknownMethod("sessions.definitelyNotReal".to_owned())
        );
        assert!(registry.implemented_names().is_empty());
    }

    #[test]
    fn scope_identities_cover_all_three_classifications() {
        assert_eq!(
            scope_identity(MethodScope::Operator(OperatorScope::Approvals)),
            "operator.approvals"
        );
        assert_eq!(scope_identity(MethodScope::Node), "node");
        assert_eq!(scope_identity(MethodScope::Dynamic), "dynamic");
    }

    #[test]
    fn static_dynamic_resolver_pins_exactly_the_four_dynamic_methods() {
        let resolver = StaticDynamicScopes;
        let params = Value::Null;
        assert_eq!(
            resolver.resolve("sessions.create", &params),
            Some(vec![OperatorScope::Write])
        );
        assert_eq!(
            resolver.resolve("sessions.patch", &params),
            Some(vec![OperatorScope::Write])
        );
        assert_eq!(
            resolver.resolve("sessions.delete", &params),
            Some(vec![OperatorScope::Admin])
        );
        assert_eq!(
            resolver.resolve("plugins.sessionAction", &params),
            Some(vec![OperatorScope::Admin])
        );
        assert_eq!(resolver.resolve("sessions.list", &params), None);

        let dynamic: Vec<&'static str> = core_methods()
            .iter()
            .filter(|method| method.scope() == MethodScope::Dynamic)
            .map(|method| method.name())
            .collect();
        for name in &dynamic {
            assert!(
                resolver.resolve(name, &params).is_some(),
                "dynamic method `{name}` has no resolver mapping"
            );
        }
        assert_eq!(dynamic.len(), 4);
    }

    #[test]
    fn dynamic_methods_fail_closed_when_the_resolver_abstains() {
        #[derive(Debug)]
        struct Abstain;
        impl DynamicScopeResolver for Abstain {
            fn resolve(&self, _method: &str, _params: &Value) -> Option<Vec<OperatorScope>> {
                None
            }
        }

        let registry = MethodRegistry::with_dynamic_resolver(Arc::new(Abstain));
        let error = registry
            .authorize_call(
                Role::Operator,
                &[OperatorScope::Admin],
                "sessions.create",
                &Value::Null,
            )
            .expect_err("unresolved dynamic scope");
        assert_eq!(
            error,
            DispatchError::Unauthorized(AuthorizationError::UnresolvedDynamicScope {
                method: "sessions.create".to_owned(),
            })
        );
    }

    #[test]
    fn empty_dynamic_resolution_is_also_refused() {
        #[derive(Debug)]
        struct Empty;
        impl DynamicScopeResolver for Empty {
            fn resolve(&self, _method: &str, _params: &Value) -> Option<Vec<OperatorScope>> {
                Some(Vec::new())
            }
        }

        let registry = MethodRegistry::with_dynamic_resolver(Arc::new(Empty));
        let error = registry
            .authorize_call(
                Role::Operator,
                &[OperatorScope::Admin],
                "sessions.delete",
                &Value::Null,
            )
            .expect_err("empty dynamic scope");
        assert_eq!(
            error,
            DispatchError::Unauthorized(AuthorizationError::EmptyDynamicScope {
                method: "sessions.delete".to_owned(),
            })
        );
    }

    #[test]
    fn unknown_methods_are_refused_before_authorization() {
        let registry = MethodRegistry::new();
        let error = registry
            .authorize_call(
                Role::Operator,
                &[OperatorScope::Admin],
                "nope",
                &Value::Null,
            )
            .expect_err("unknown method");
        assert_eq!(error, DispatchError::UnknownMethod("nope".to_owned()));
    }

    #[test]
    fn canonical_name_returns_the_frozen_static_identity() {
        let registry = MethodRegistry::new();
        assert_eq!(
            registry.canonical_name("sessions.list"),
            Some("sessions.list")
        );
        assert_eq!(registry.canonical_name("sessions.List"), None);
    }

    #[test]
    fn advertised_and_catalogued_counts_match_the_frozen_descriptors() {
        let registry = MethodRegistry::new();
        let advertised = core_methods()
            .iter()
            .filter(|method| method.advertised())
            .count();
        assert_eq!(registry.advertised_names().len(), advertised);
        assert!(advertised < registry.len());
    }
}
