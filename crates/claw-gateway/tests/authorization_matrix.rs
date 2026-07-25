//! The authorization matrix over the *entire* frozen method catalog.
//!
//! `tests/authorization.rs` proves the rules on hand-picked representatives.
//! This file removes the sampling: it reads
//! `compat/upstream/inventories/gateway-protocol.json` directly, classifies all
//! 278 methods from the frozen `scope` column, and runs every role against
//! every one of the 64 operator-scope subsets for every method.
//!
//! A per-method scope table is exactly the kind of thing that drifts silently,
//! so nothing here is sampled and nothing here is produced by calling the code
//! under test. The expectation is an independent restatement of the documented
//! rules; the frozen file supplies the inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use claw_gateway::error::DispatchError;
use claw_gateway::methods;
use claw_protocol::gateway::{AuthorizationError, OperatorScope, Role};
use serde::Deserialize;
use serde_json::json;

/// Every closed operator scope, in the frozen registry order.
const ALL_SCOPES: [OperatorScope; 6] = [
    OperatorScope::Admin,
    OperatorScope::Read,
    OperatorScope::Write,
    OperatorScope::Approvals,
    OperatorScope::Pairing,
    OperatorScope::TalkSecrets,
];

/// The one method identity that is exempt from scope checks.
///
/// Transcribed from `claw_protocol::gateway::authorization`, which admits
/// `health` for any non-worker role before any scope is consulted.
const SCOPE_EXEMPT_METHOD: &str = "health";

/// How this server resolves the four `scope=dynamic` catalog entries.
///
/// Transcribed from the documented `StaticDynamicScopes` policy in
/// `claw_gateway::dispatch`; deliberately restated here rather than imported so
/// that a change to that policy has to be made twice, on purpose.
const DYNAMIC_RESOLUTION: [(&str, OperatorScope); 4] = [
    ("sessions.create", OperatorScope::Write),
    ("sessions.patch", OperatorScope::Write),
    ("sessions.delete", OperatorScope::Admin),
    ("plugins.sessionAction", OperatorScope::Admin),
];

/// What the authorization rules say must happen for one call.
#[derive(Debug, Eq, PartialEq)]
enum Verdict {
    Allowed,
    WorkerNotAdmitted,
    RoleMismatch(Role),
    MissingScope(OperatorScope),
}

/// How one method is classified, derived from the frozen `scope` column.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Class {
    /// Admitted for any non-worker role without consulting scopes.
    HealthBypass,
    /// `scope=node`.
    Node,
    /// `scope=operator.*`.
    Operator(OperatorScope),
    /// `scope=dynamic`, resolved by this server to a concrete scope.
    Dynamic(OperatorScope),
}

#[derive(Debug, Deserialize)]
struct Inventory {
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Item {
    id: String,
    kind: String,
    #[serde(default)]
    scope: Option<String>,
}

fn inventory() -> Inventory {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("compat")
        .join("upstream")
        .join("inventories")
        .join("gateway-protocol.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "frozen inventory at {} is readable: {error}",
            path.display()
        )
    });
    // The frozen inventories are checked in with a UTF-8 byte-order mark.
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    serde_json::from_str(raw).expect("the frozen inventory is valid JSON")
}

/// Classifies every catalogued method straight from the frozen file.
fn frozen_classification() -> BTreeMap<String, Class> {
    let dynamic: BTreeMap<&str, OperatorScope> = DYNAMIC_RESOLUTION.into_iter().collect();
    let mut classified = BTreeMap::new();
    for item in inventory()
        .items
        .into_iter()
        .filter(|it| it.kind == "method")
    {
        let scope = item
            .scope
            .as_deref()
            .unwrap_or_else(|| panic!("frozen method `{}` declares no scope", item.id));
        let class = if item.id == SCOPE_EXEMPT_METHOD {
            Class::HealthBypass
        } else {
            match scope {
                "node" => Class::Node,
                "operator.read" => Class::Operator(OperatorScope::Read),
                "operator.write" => Class::Operator(OperatorScope::Write),
                "operator.admin" => Class::Operator(OperatorScope::Admin),
                "operator.approvals" => Class::Operator(OperatorScope::Approvals),
                "operator.pairing" => Class::Operator(OperatorScope::Pairing),
                "operator.talkSecrets" => Class::Operator(OperatorScope::TalkSecrets),
                "dynamic" => Class::Dynamic(*dynamic.get(item.id.as_str()).unwrap_or_else(|| {
                    panic!("dynamic method `{}` has no documented resolution", item.id)
                })),
                other => panic!(
                    "frozen method `{}` declares unknown scope `{other}`",
                    item.id
                ),
            }
        };
        let previous = classified.insert(item.id.clone(), class);
        assert!(previous.is_none(), "duplicate frozen method `{}`", item.id);
    }
    classified
}

/// Independent restatement of the authorization rules.
fn expected(role: Role, granted: &[OperatorScope], class: Class) -> Verdict {
    if role == Role::Worker {
        return Verdict::WorkerNotAdmitted;
    }
    let required = match class {
        Class::HealthBypass => return Verdict::Allowed,
        Class::Node => {
            return if role == Role::Node {
                Verdict::Allowed
            } else {
                Verdict::RoleMismatch(Role::Node)
            };
        }
        Class::Operator(scope) | Class::Dynamic(scope) => scope,
    };
    if role != Role::Operator {
        return Verdict::RoleMismatch(Role::Operator);
    }
    let holds = granted.contains(&OperatorScope::Admin)
        || granted.contains(&required)
        || (required == OperatorScope::Read && granted.contains(&OperatorScope::Write));
    if holds {
        Verdict::Allowed
    } else {
        Verdict::MissingScope(required)
    }
}

fn verdict_of(result: Result<(), DispatchError>) -> Verdict {
    match result {
        Ok(()) => Verdict::Allowed,
        Err(DispatchError::Unauthorized(AuthorizationError::WorkerNotAdmitted)) => {
            Verdict::WorkerNotAdmitted
        }
        Err(DispatchError::Unauthorized(AuthorizationError::RoleMismatch { required, .. })) => {
            Verdict::RoleMismatch(required)
        }
        Err(DispatchError::Unauthorized(AuthorizationError::MissingScope { required, .. })) => {
            Verdict::MissingScope(required)
        }
        Err(other) => panic!("unexpected authorization outcome: {other}"),
    }
}

/// Expands `bits` into the corresponding subset of the six operator scopes.
fn subset(bits: u8) -> Vec<OperatorScope> {
    ALL_SCOPES
        .iter()
        .enumerate()
        .filter(|(index, _)| bits & (1 << index) != 0)
        .map(|(_, scope)| *scope)
        .collect()
}

/// Renders a scope set for assertion messages.
fn names(scopes: &[OperatorScope]) -> Vec<&'static str> {
    scopes.iter().copied().map(OperatorScope::as_str).collect()
}

#[test]
fn the_frozen_classification_still_has_the_shape_this_matrix_was_written_against() {
    let classified = frozen_classification();
    assert_eq!(classified.len(), 278);

    let mut counts: BTreeMap<Class, usize> = BTreeMap::new();
    for class in classified.values() {
        *counts.entry(*class).or_default() += 1;
    }

    // Transcribed from the frozen `scope` column, with `health` lifted out of
    // `operator.read` (97 declared, 96 after the exemption).
    let mut written: BTreeMap<Class, usize> = BTreeMap::new();
    written.insert(Class::HealthBypass, 1);
    written.insert(Class::Node, 9);
    written.insert(Class::Operator(OperatorScope::Read), 96);
    written.insert(Class::Operator(OperatorScope::Write), 59);
    written.insert(Class::Operator(OperatorScope::Admin), 86);
    written.insert(Class::Operator(OperatorScope::Approvals), 11);
    written.insert(Class::Operator(OperatorScope::Pairing), 12);
    written.insert(Class::Dynamic(OperatorScope::Write), 2);
    written.insert(Class::Dynamic(OperatorScope::Admin), 2);

    assert_eq!(counts, written);
    assert_eq!(written.values().sum::<usize>(), 278);
}

#[test]
fn the_matrix_covers_exactly_the_methods_the_server_registers() {
    let frozen: BTreeSet<String> = frozen_classification().into_keys().collect();
    let registered: BTreeSet<String> = methods::registry()
        .expect("every handler installs")
        .names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        frozen.difference(&registered).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "frozen methods this matrix would silently skip"
    );
    assert_eq!(
        registered.difference(&frozen).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "registered methods absent from the frozen classification"
    );
}

#[test]
fn every_catalogued_method_obeys_the_rules_for_every_role_and_scope_subset() {
    let registry = methods::registry().expect("every handler installs");
    let classified = frozen_classification();
    let params = json!({});
    let mut allowed = 0_usize;
    let mut denied = 0_usize;
    let mut checked_methods: BTreeSet<&str> = BTreeSet::new();

    for role in [Role::Operator, Role::Node, Role::Worker] {
        for bits in 0_u8..64 {
            let granted = subset(bits);
            for (method, class) in &classified {
                let actual = verdict_of(registry.authorize_call(role, &granted, method, &params));
                let expected = expected(role, &granted, *class);
                assert_eq!(
                    actual,
                    expected,
                    "role={} scopes={:?} method={method} class={class:?}",
                    role.as_str(),
                    names(&granted)
                );
                checked_methods.insert(method.as_str());
                if actual == Verdict::Allowed {
                    allowed += 1;
                } else {
                    denied += 1;
                }
            }
        }
    }

    // 3 roles x 64 subsets x 278 methods, with no method skipped.
    assert_eq!(checked_methods.len(), 278);
    assert_eq!(allowed + denied, 3 * 64 * 278);
    assert_eq!(allowed + denied, 53_376);
    // The matrix must actually exercise denials, not just accept everything.
    assert!(
        denied > allowed,
        "expected the matrix to be denial-heavy: {allowed} allowed vs {denied} denied"
    );
    // And it must actually exercise admissions, so a fail-closed regression that
    // denied everything could not pass this test either.
    assert!(allowed > 0);
}

#[test]
fn no_catalogued_method_is_reachable_by_a_worker() {
    let registry = methods::registry().expect("every handler installs");
    let params = json!({});
    let mut refused = 0_usize;
    for method in frozen_classification().keys() {
        let error = registry
            .authorize_call(Role::Worker, &ALL_SCOPES, method, &params)
            .expect_err("workers are never admitted to ordinary Gateway RPC");
        assert_eq!(
            error,
            DispatchError::Unauthorized(AuthorizationError::WorkerNotAdmitted),
            "`{method}` refused a worker for the wrong reason"
        );
        assert_eq!(error.wire_code(), "UNAUTHORIZED");
        refused += 1;
    }
    assert_eq!(refused, 278);
}

#[test]
fn no_operator_scoped_method_is_reachable_by_a_node_holding_every_scope() {
    let registry = methods::registry().expect("every handler installs");
    let params = json!({});
    let mut refused = 0_usize;
    for (method, class) in frozen_classification() {
        let result = registry.authorize_call(Role::Node, &ALL_SCOPES, &method, &params);
        match class {
            Class::Node | Class::HealthBypass => {
                result.unwrap_or_else(|error| {
                    panic!("`{method}` must stay open to its own role: {error}")
                });
            }
            Class::Operator(_) | Class::Dynamic(_) => {
                let error = result.expect_err("operator-scoped work is closed to nodes");
                assert_eq!(
                    error,
                    DispatchError::Unauthorized(AuthorizationError::RoleMismatch {
                        required: Role::Operator,
                        actual: Role::Node,
                    }),
                    "`{method}` refused a node for the wrong reason"
                );
                refused += 1;
            }
        }
    }
    assert_eq!(refused, 278 - 9 - 1);
}

#[test]
fn no_node_scoped_method_is_reachable_by_an_operator_holding_every_scope() {
    let registry = methods::registry().expect("every handler installs");
    let params = json!({});
    let mut refused = 0_usize;
    for (method, class) in frozen_classification() {
        if class != Class::Node {
            continue;
        }
        let error = registry
            .authorize_call(Role::Operator, &ALL_SCOPES, &method, &params)
            .expect_err("node-scoped work is closed to operators");
        assert_eq!(
            error,
            DispatchError::Unauthorized(AuthorizationError::RoleMismatch {
                required: Role::Node,
                actual: Role::Operator,
            }),
            "`{method}` refused an operator for the wrong reason"
        );
        refused += 1;
    }
    assert_eq!(refused, 9);
}

#[test]
fn talk_secrets_alone_unlocks_no_catalogued_method() {
    let registry = methods::registry().expect("every handler installs");
    let params = json!({});
    let mut reachable = Vec::new();
    for method in frozen_classification().keys() {
        if registry
            .authorize_call(
                Role::Operator,
                &[OperatorScope::TalkSecrets],
                method,
                &params,
            )
            .is_ok()
        {
            reachable.push(method.clone());
        }
    }
    // `health` is the documented scope-check exemption; the frozen catalog
    // requires `operator.talkSecrets` for zero of its 278 methods, so nothing
    // else may open up.
    assert_eq!(reachable, vec!["health".to_owned()]);
}
