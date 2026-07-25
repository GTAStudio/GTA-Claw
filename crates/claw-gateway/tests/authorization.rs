//! Role and scope authorization, exhaustively.
//!
//! The expectations here are written from the frozen scope column and the
//! documented implication rules (`operator.admin` satisfies everything;
//! `operator.write` additionally satisfies `operator.read`). They are never
//! produced by calling the code under test.

use claw_gateway::error::DispatchError;
use claw_gateway::events::{EventVisibility, event_visibility};
use claw_gateway::methods;
use claw_protocol::gateway::{AuthorizationError, OperatorScope, Role};
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

/// What the authorization rules say must happen for one call.
#[derive(Debug, Eq, PartialEq)]
enum Verdict {
    Allowed,
    WorkerNotAdmitted,
    RoleMismatch(Role),
    MissingScope(OperatorScope),
}

/// How one representative method is classified by the frozen inventory.
#[derive(Clone, Copy, Debug)]
enum Class {
    /// Exempt from scope checks for both ordinary roles.
    HealthBypass,
    /// `kind=method, scope=node` in the frozen inventory.
    Node,
    /// `kind=method, scope=operator.*` in the frozen inventory.
    Operator(OperatorScope),
    /// `kind=method, scope=dynamic`; this server resolves it to one scope.
    Dynamic(OperatorScope),
}

/// Representative methods, one per frozen classification.
///
/// The scopes here are transcribed from
/// `compat/upstream/inventories/gateway-protocol.json`; `tests/frozen_catalog.rs`
/// independently proves the registry agrees with that file.
const SUBJECTS: [(&str, Class); 9] = [
    ("health", Class::HealthBypass),
    (
        "diagnostics.stability",
        Class::Operator(OperatorScope::Read),
    ),
    (
        "doctor.memory.resetDreamDiary",
        Class::Operator(OperatorScope::Write),
    ),
    ("config.set", Class::Operator(OperatorScope::Admin)),
    (
        "exec.approval.list",
        Class::Operator(OperatorScope::Approvals),
    ),
    ("node.pair.list", Class::Operator(OperatorScope::Pairing)),
    ("skills.bins", Class::Node),
    ("sessions.create", Class::Dynamic(OperatorScope::Write)),
    ("sessions.delete", Class::Dynamic(OperatorScope::Admin)),
];

/// Independent restatement of the authorization rules.
fn expected(role: Role, granted: &[OperatorScope], class: Class) -> Verdict {
    if role == Role::Worker {
        return Verdict::WorkerNotAdmitted;
    }
    if matches!(class, Class::HealthBypass) {
        return Verdict::Allowed;
    }
    let required = match class {
        Class::HealthBypass => unreachable!("handled above"),
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
fn every_role_and_scope_combination_matches_the_written_rules() {
    let registry = methods::registry().expect("every handler installs");
    let params = json!({});
    let mut allowed = 0_usize;
    let mut denied = 0_usize;

    for role in [Role::Operator, Role::Node, Role::Worker] {
        for bits in 0_u8..64 {
            let granted = subset(bits);
            for (method, class) in SUBJECTS {
                let actual = verdict_of(registry.authorize_call(role, &granted, method, &params));
                let expected = expected(role, &granted, class);
                assert_eq!(
                    actual,
                    expected,
                    "role={} scopes={:?} method={method}",
                    role.as_str(),
                    names(&granted)
                );
                if actual == Verdict::Allowed {
                    allowed += 1;
                } else {
                    denied += 1;
                }
            }
        }
    }

    // 3 roles x 64 subsets x 9 methods.
    assert_eq!(allowed + denied, 1728);
    // The matrix must actually exercise denials, not just accept everything.
    assert!(denied > allowed, "expected the matrix to be denial-heavy");
}

#[test]
fn a_worker_is_refused_every_representative_method_including_health() {
    let registry = methods::registry().expect("every handler installs");
    let params = json!({});
    for (method, _) in SUBJECTS {
        let error = registry
            .authorize_call(Role::Worker, &ALL_SCOPES, method, &params)
            .expect_err("workers are never admitted to ordinary Gateway RPC");
        assert_eq!(
            error,
            DispatchError::Unauthorized(AuthorizationError::WorkerNotAdmitted)
        );
        assert_eq!(error.wire_code(), "UNAUTHORIZED");
    }
}

#[test]
fn write_implies_read_but_read_never_implies_write() {
    let registry = methods::registry().expect("every handler installs");
    let params = json!({});

    registry
        .authorize_call(
            Role::Operator,
            &[OperatorScope::Write],
            "diagnostics.stability",
            &params,
        )
        .expect("operator.write satisfies an operator.read method");

    let error = registry
        .authorize_call(
            Role::Operator,
            &[OperatorScope::Read],
            "doctor.memory.resetDreamDiary",
            &params,
        )
        .expect_err("operator.read must not satisfy an operator.write method");
    assert_eq!(
        error,
        DispatchError::Unauthorized(AuthorizationError::MissingScope {
            method: "doctor.memory.resetDreamDiary".to_owned(),
            required: OperatorScope::Write,
        })
    );
}

#[test]
fn admin_alone_satisfies_every_operator_classification() {
    let registry = methods::registry().expect("every handler installs");
    let params = json!({});
    for (method, class) in SUBJECTS {
        let result =
            registry.authorize_call(Role::Operator, &[OperatorScope::Admin], method, &params);
        match class {
            Class::Node => assert_eq!(
                verdict_of(result),
                Verdict::RoleMismatch(Role::Node),
                "`{method}` is node-classified and must stay closed to operators"
            ),
            Class::HealthBypass | Class::Operator(_) | Class::Dynamic(_) => {
                result.unwrap_or_else(|error| panic!("`{method}` must admit admin: {error}"));
            }
        }
    }
}

#[test]
fn an_unknown_method_identity_fails_closed() {
    let registry = methods::registry().expect("every handler installs");
    let error = registry
        .authorize_call(
            Role::Operator,
            &[OperatorScope::Admin],
            "sessions.createEverything",
            &json!({}),
        )
        .expect_err("identities outside the frozen catalog are refused");
    assert_eq!(
        error,
        DispatchError::UnknownMethod("sessions.createEverything".to_owned())
    );
    assert_eq!(error.wire_code(), "METHOD_NOT_FOUND");
}

#[test]
fn event_visibility_is_enforced_for_every_role_and_scope_combination() {
    let cases: [(&str, EventVisibility); 6] = [
        ("connect.challenge", EventVisibility::Handshake),
        ("tick", EventVisibility::AllAuthenticated),
        ("node.invoke.request", EventVisibility::Node),
        (
            "exec.approval.requested",
            EventVisibility::Operator(OperatorScope::Approvals),
        ),
        (
            "device.pair.requested",
            EventVisibility::Operator(OperatorScope::Pairing),
        ),
        (
            "terminal.data",
            EventVisibility::Operator(OperatorScope::Admin),
        ),
    ];

    for (event, visibility) in cases {
        assert_eq!(event_visibility(event), Some(visibility));
        for role in [Role::Operator, Role::Node, Role::Worker] {
            for bits in 0_u8..64 {
                let granted = subset(bits);
                let expected = match visibility {
                    EventVisibility::Handshake => false,
                    EventVisibility::AllAuthenticated => role != Role::Worker,
                    EventVisibility::Node => role == Role::Node,
                    EventVisibility::Operator(required) => {
                        role == Role::Operator
                            && (granted.contains(&OperatorScope::Admin)
                                || granted.contains(&required)
                                || (required == OperatorScope::Read
                                    && granted.contains(&OperatorScope::Write)))
                    }
                };
                assert_eq!(
                    visibility.admits(role, &granted),
                    expected,
                    "event={event} role={} scopes={:?}",
                    role.as_str(),
                    names(&granted)
                );
            }
        }
    }
}

#[test]
fn a_node_connection_never_observes_operator_scoped_events() {
    for (name, visibility) in claw_gateway::events::event_catalog() {
        if let EventVisibility::Operator(_) = visibility {
            assert!(
                !visibility.admits(Role::Node, &ALL_SCOPES),
                "`{name}` leaked to a node connection"
            );
        }
    }
}
