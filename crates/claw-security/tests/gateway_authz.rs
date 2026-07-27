//! The gateway authorization matrix, evaluated exhaustively against the frozen
//! `compat/upstream` contract.
//!
//! The matrix is total, not sampled. Every cell of
//! `role x granted-scope-set x method` is evaluated and compared against an
//! oracle written from the contract text — a hand-written 6x6 scope-satisfier
//! table plus the ordered role/scope gates — rather than from
//! `claw_security::gateway_authz`. Every refusal is compared as a whole value,
//! so a denial that names the wrong gate, the wrong role or the wrong scope
//! fails just as loudly as an accidental grant.
//!
//! The cell totals and the per-principal allow counts are pinned as literals
//! derived by hand from the frozen classification histogram. A rule that
//! quietly widened — dropping the worker gate, making every scope satisfy every
//! method, or letting an unresolved dynamic method through — changes those
//! totals and fails here even if the oracle had been written to agree with it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use claw_security::authorization::{RegistryError, Role, RoleScopeError, Scope, ScopeSet};
use claw_security::gateway_authz::{
    DUAL_PLANE_METHOD, MethodDenial, MethodGrant, MethodRequirement, Principal,
    authorize_inventory_method, authorize_method, method_requirement, parse_granted_scopes,
    parse_principal, satisfying_scope, validate_principal,
};
use serde_json::Value;

/// `manifest.json#canonical_counts.gateway_methods`.
const FROZEN_METHOD_COUNT: usize = 278;
/// `manifest.json#canonical_counts.gateway_roles`.
const FROZEN_ROLE_COUNT: usize = 3;
/// `manifest.json#canonical_counts.gateway_scopes`.
const FROZEN_SCOPE_COUNT: usize = 6;

/// Frozen `scope` classification histogram of the 278 method rows.
const FROZEN_CLASSIFICATION_HISTOGRAM: [(&str, usize); 7] = [
    ("dynamic", 4),
    ("node", 9),
    ("operator.admin", 86),
    ("operator.approvals", 11),
    ("operator.pairing", 12),
    ("operator.read", 97),
    ("operator.write", 59),
];

/// Every cell of the static plane matrix: 278 methods x 24 principals.
const STATIC_MATRIX_CELLS: usize = FROZEN_METHOD_COUNT * 24;
/// Grants in the static plane matrix; see `EXPECTED_ALLOWED_PER_PRINCIPAL`.
const STATIC_MATRIX_GRANTS: usize = 890;

/// Every cell of the dynamic matrix: 4 methods x 24 principals x 8 resolutions.
const DYNAMIC_MATRIX_CELLS: usize = 4 * 24 * 8;
/// Grants in the dynamic matrix: 4 methods x 18 satisfied (principal, scope) pairs.
const DYNAMIC_MATRIX_GRANTS: usize = 72;

/// Hand-derived allow count for each of the 24 principals of the static matrix.
///
/// Derived from `FROZEN_CLASSIFICATION_HISTOGRAM` with `health` lifted out of
/// `operator.read` onto the dual plane, so the operator-plane rows are
/// `read 96`, `write 59`, `admin 86`, `approvals 11`, `pairing 12` — 264 in
/// total — beside `node 9` and `dynamic 4`:
///
/// - `worker` reaches nothing at all.
/// - `node` reaches `health` and the nine node-plane methods, whatever it holds.
/// - `operator` always reaches `health`, never the node plane, and never an
///   unresolved dynamic method; `operator.write` adds the 96 read methods to
///   its own 59, `operator.admin` covers all 264, and `operator.talk.secrets`
///   is carried by no method at this baseline and therefore adds nothing.
const EXPECTED_ALLOWED_PER_PRINCIPAL: [(&str, &str, usize); 24] = [
    ("operator", "{}", 1),
    ("operator", "{operator.admin}", 265),
    ("operator", "{operator.read}", 97),
    ("operator", "{operator.write}", 156),
    ("operator", "{operator.approvals}", 12),
    ("operator", "{operator.pairing}", 13),
    ("operator", "{operator.talk.secrets}", 1),
    ("operator", "{all}", 265),
    ("node", "{}", 10),
    ("node", "{operator.admin}", 10),
    ("node", "{operator.read}", 10),
    ("node", "{operator.write}", 10),
    ("node", "{operator.approvals}", 10),
    ("node", "{operator.pairing}", 10),
    ("node", "{operator.talk.secrets}", 10),
    ("node", "{all}", 10),
    ("worker", "{}", 0),
    ("worker", "{operator.admin}", 0),
    ("worker", "{operator.read}", 0),
    ("worker", "{operator.write}", 0),
    ("worker", "{operator.approvals}", 0),
    ("worker", "{operator.pairing}", 0),
    ("worker", "{operator.talk.secrets}", 0),
    ("worker", "{all}", 0),
];

/// Hand-derived denial histogram of the static plane matrix.
///
/// `worker` refuses all 8 x 278 = 2224 cells; `node` is refused the 264
/// operator-plane and 4 dynamic methods, 8 x 268 = 2144, and `operator` the 9
/// node-plane methods, 8 x 9 = 72; the 4 dynamic methods are unresolved for
/// every operator principal, 8 x 4 = 32; the remaining 1310 are scope refusals.
const EXPECTED_STATIC_DENIALS: [(&str, usize); 4] = [
    ("role-mismatch", 2216),
    ("scope-not-granted", 1310),
    ("unresolved-dynamic-scope", 32),
    ("worker-not-admitted", 2224),
];

/// Hand-derived denial histogram of the dynamic matrix.
///
/// `worker` and `node` each refuse 8 scope sets x 8 resolutions x 4 methods;
/// each operator principal meets one absent and one empty resolution per
/// method, and 192 - 72 = 120 of the resolved cells name an unheld scope.
const EXPECTED_DYNAMIC_DENIALS: [(&str, usize); 5] = [
    ("empty-dynamic-scope", 32),
    ("role-mismatch", 256),
    ("scope-not-granted", 120),
    ("unresolved-dynamic-scope", 32),
    ("worker-not-admitted", 256),
];

/// Which granted singleton scope satisfies which required scope.
///
/// Rows are the single granted scope, columns the required scope, both in the
/// frozen ordinal order `[admin, read, write, approvals, pairing,
/// talk.secrets]`. Written out by hand from the closed scope set rather than
/// derived from the crate: `operator.admin` stands in for every scope,
/// `operator.write` stands in for `operator.read`, and nothing else implies
/// anything.
const SINGLETON_SATISFIER: [[Option<Scope>; 6]; 6] = [
    [
        Some(Scope::OperatorAdmin),
        Some(Scope::OperatorAdmin),
        Some(Scope::OperatorAdmin),
        Some(Scope::OperatorAdmin),
        Some(Scope::OperatorAdmin),
        Some(Scope::OperatorAdmin),
    ],
    [None, Some(Scope::OperatorRead), None, None, None, None],
    [
        None,
        Some(Scope::OperatorWrite),
        Some(Scope::OperatorWrite),
        None,
        None,
        None,
    ],
    [None, None, None, Some(Scope::OperatorApprovals), None, None],
    [None, None, None, None, Some(Scope::OperatorPairing), None],
    [
        None,
        None,
        None,
        None,
        None,
        Some(Scope::OperatorTalkSecrets),
    ],
];

/// One method row of the frozen gateway protocol inventory.
struct MethodRow {
    id: String,
    classification: String,
}

fn repository_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(relative)
}

fn read_json(relative: &str) -> Value {
    let bytes = fs::read(repository_file(relative)).expect("read frozen contract");
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    serde_json::from_slice(bytes).expect("parse frozen contract")
}

fn frozen_methods() -> Vec<MethodRow> {
    let inventory = read_json("compat/upstream/inventories/gateway-protocol.json");
    let rows = inventory["items"]
        .as_array()
        .expect("inventory items")
        .iter()
        .filter(|item| item["kind"] == "method")
        .map(|item| MethodRow {
            id: item["id"].as_str().expect("method id").to_owned(),
            classification: item["scope"].as_str().expect("method scope").to_owned(),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows.len(),
        FROZEN_METHOD_COUNT,
        "the frozen inventory must carry exactly the pinned method count"
    );
    assert_eq!(
        rows.iter()
            .map(|row| row.id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        FROZEN_METHOD_COUNT,
        "method identities must be unique"
    );
    let mut histogram = BTreeMap::new();
    for row in &rows {
        *histogram
            .entry(row.classification.as_str())
            .or_insert(0_usize) += 1;
    }
    assert_eq!(
        histogram,
        FROZEN_CLASSIFICATION_HISTOGRAM
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        "the matrix totals below are derived from this histogram"
    );
    rows
}

/// The 8 granted scope sets each role is evaluated against.
fn matrix_scope_sets() -> Vec<(&'static str, Vec<Scope>)> {
    let mut sets = vec![("{}", Vec::new())];
    for scope in Scope::ALL {
        sets.push((
            match scope {
                Scope::OperatorAdmin => "{operator.admin}",
                Scope::OperatorRead => "{operator.read}",
                Scope::OperatorWrite => "{operator.write}",
                Scope::OperatorApprovals => "{operator.approvals}",
                Scope::OperatorPairing => "{operator.pairing}",
                Scope::OperatorTalkSecrets => "{operator.talk.secrets}",
            },
            vec![scope],
        ));
    }
    sets.push(("{all}", Scope::ALL.to_vec()));
    assert_eq!(sets.len(), FROZEN_SCOPE_COUNT + 2);
    sets
}

/// The oracle's scope lookup, written out rather than delegated to the crate.
fn oracle_scope(classification: &str) -> Scope {
    match classification {
        "operator.admin" => Scope::OperatorAdmin,
        "operator.read" => Scope::OperatorRead,
        "operator.write" => Scope::OperatorWrite,
        "operator.approvals" => Scope::OperatorApprovals,
        "operator.pairing" => Scope::OperatorPairing,
        "operator.talk.secrets" => Scope::OperatorTalkSecrets,
        other => panic!("frozen inventory carries an unknown classification `{other}`"),
    }
}

/// Table-driven satisfaction: a set satisfies whatever any of its members does.
fn oracle_satisfier(granted: &[Scope], required: Scope) -> Option<Scope> {
    let candidates = granted
        .iter()
        .filter_map(|held| {
            SINGLETON_SATISFIER[usize::from(held.ordinal())][usize::from(required.ordinal())]
        })
        .collect::<Vec<_>>();
    if candidates.contains(&required) {
        Some(required)
    } else if candidates.contains(&Scope::OperatorWrite) {
        Some(Scope::OperatorWrite)
    } else if candidates.contains(&Scope::OperatorAdmin) {
        Some(Scope::OperatorAdmin)
    } else {
        candidates.first().copied()
    }
}

/// The frozen rules restated: worker, then dual plane, then role, then scope.
fn oracle(
    role: Role,
    granted: &[Scope],
    method: &str,
    classification: &str,
    resolution: Option<&[Scope]>,
) -> Result<MethodGrant, MethodDenial> {
    if role == Role::Worker {
        return Err(MethodDenial::WorkerNotAdmitted);
    }
    if method == "health" {
        return Ok(MethodGrant::DualPlane);
    }
    if classification == "node" {
        return if role == Role::Node {
            Ok(MethodGrant::NodePlane)
        } else {
            Err(MethodDenial::RoleMismatch {
                required: Role::Node,
                actual: role,
            })
        };
    }
    if role != Role::Operator {
        return Err(MethodDenial::RoleMismatch {
            required: Role::Operator,
            actual: role,
        });
    }
    if classification == "dynamic" {
        let Some(resolved) = resolution else {
            return Err(MethodDenial::UnresolvedDynamicScope);
        };
        if resolved.is_empty() {
            return Err(MethodDenial::EmptyDynamicScope);
        }
        let mut required = resolved.to_vec();
        required.sort_by_key(|scope| scope.ordinal());
        required.dedup();
        for scope in required {
            if oracle_satisfier(granted, scope).is_none() {
                return Err(MethodDenial::ScopeNotGranted { required: scope });
            }
        }
        return Ok(MethodGrant::DynamicOperatorScopes);
    }
    let required = oracle_scope(classification);
    oracle_satisfier(granted, required)
        .map(|satisfied_by| MethodGrant::OperatorScope {
            required,
            satisfied_by,
        })
        .ok_or(MethodDenial::ScopeNotGranted { required })
}

const fn denial_label(denial: MethodDenial) -> &'static str {
    match denial {
        MethodDenial::WorkerNotAdmitted => "worker-not-admitted",
        MethodDenial::RoleMismatch { .. } => "role-mismatch",
        MethodDenial::ScopeNotGranted { .. } => "scope-not-granted",
        MethodDenial::UnresolvedDynamicScope => "unresolved-dynamic-scope",
        MethodDenial::EmptyDynamicScope => "empty-dynamic-scope",
    }
}

#[test]
fn authorization_matrix_covers_every_role_scope_and_method() {
    let methods = frozen_methods();
    let scope_sets = matrix_scope_sets();
    assert_eq!(Role::ALL.len(), FROZEN_ROLE_COUNT);
    assert_eq!(Scope::ALL.len(), FROZEN_SCOPE_COUNT);

    let mut cells = 0_usize;
    let mut grants = 0_usize;
    let mut denials: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut per_principal: Vec<(&str, &str, usize)> = Vec::new();

    for role in Role::ALL {
        for (label, granted) in &scope_sets {
            let principal = Principal::new(role, ScopeSet::from_scopes(granted.iter().copied()));
            let mut principal_grants = 0_usize;
            for method in &methods {
                let actual =
                    authorize_inventory_method(principal, &method.id, &method.classification, None)
                        .expect("every frozen classification resolves");
                let expected = oracle(role, granted, &method.id, &method.classification, None);
                assert_eq!(
                    actual, expected,
                    "role={role} scopes={label} method={} ({})",
                    method.id, method.classification
                );
                cells += 1;
                match actual {
                    Ok(_) => {
                        grants += 1;
                        principal_grants += 1;
                    }
                    Err(denial) => *denials.entry(denial_label(denial)).or_default() += 1,
                }
            }
            per_principal.push((role.as_str(), *label, principal_grants));
        }
    }

    assert_eq!(cells, STATIC_MATRIX_CELLS, "the matrix must be total");
    assert_eq!(grants, STATIC_MATRIX_GRANTS);
    assert_eq!(
        denials.values().sum::<usize>(),
        STATIC_MATRIX_CELLS - STATIC_MATRIX_GRANTS
    );
    assert_eq!(
        per_principal,
        EXPECTED_ALLOWED_PER_PRINCIPAL.to_vec(),
        "per-principal reach must equal the hand-derived table"
    );
    assert_eq!(
        denials,
        EXPECTED_STATIC_DENIALS
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        "every refusal must land on the gate the contract names"
    );
}

#[test]
fn every_denial_names_the_gate_that_refused_it() {
    let methods = frozen_methods();
    let classification = |name: &str| {
        methods
            .iter()
            .find(|row| row.id == name)
            .unwrap_or_else(|| panic!("frozen inventory carries `{name}`"))
            .classification
            .clone()
    };
    // These identities and classifications are hard-coded, so a bug that made
    // the matrix above read the inventory wrongly cannot also silence this.
    assert_eq!(classification("health"), "operator.read");
    assert_eq!(classification("status"), "operator.read");
    assert_eq!(classification("send"), "operator.write");
    assert_eq!(classification("config.set"), "operator.admin");
    assert_eq!(classification("approval.get"), "operator.approvals");
    assert_eq!(classification("node.pair.list"), "operator.pairing");
    assert_eq!(classification("node.event"), "node");
    assert_eq!(classification("plugins.sessionAction"), "dynamic");

    let authorize = |role: Role, granted: &[Scope], method: &str| {
        authorize_inventory_method(
            Principal::new(role, ScopeSet::from_scopes(granted.iter().copied())),
            method,
            &classification(method),
            None,
        )
        .expect("frozen classification")
    };

    // A worker holding every operator scope still reaches nothing, including
    // the one method both ordinary gateway roles reach.
    for method in ["health", "status", "node.event", "plugins.sessionAction"] {
        assert_eq!(
            authorize(Role::Worker, &Scope::ALL, method),
            Err(MethodDenial::WorkerNotAdmitted),
            "worker must not reach {method}"
        );
    }

    // The role gate runs before the scope gate, in both directions.
    assert_eq!(
        authorize(Role::Node, &[Scope::OperatorAdmin], "config.set"),
        Err(MethodDenial::RoleMismatch {
            required: Role::Operator,
            actual: Role::Node,
        })
    );
    assert_eq!(
        authorize(Role::Operator, &[Scope::OperatorAdmin], "node.event"),
        Err(MethodDenial::RoleMismatch {
            required: Role::Node,
            actual: Role::Operator,
        })
    );

    // A refusal names the scope the method wanted, not merely that one was missing.
    for (method, required) in [
        ("status", Scope::OperatorRead),
        ("send", Scope::OperatorWrite),
        ("config.set", Scope::OperatorAdmin),
        ("approval.get", Scope::OperatorApprovals),
        ("node.pair.list", Scope::OperatorPairing),
    ] {
        assert_eq!(
            authorize(Role::Operator, &[Scope::OperatorTalkSecrets], method),
            Err(MethodDenial::ScopeNotGranted { required }),
            "{method} must name the scope it requires"
        );
        assert_eq!(
            authorize(Role::Operator, &[required], method),
            Ok(MethodGrant::OperatorScope {
                required,
                satisfied_by: required,
            })
        );
    }

    // Exactly the two implications the closed set carries, and no third.
    assert_eq!(
        authorize(Role::Operator, &[Scope::OperatorWrite], "status"),
        Ok(MethodGrant::OperatorScope {
            required: Scope::OperatorRead,
            satisfied_by: Scope::OperatorWrite,
        })
    );
    assert_eq!(
        authorize(Role::Operator, &[Scope::OperatorRead], "send"),
        Err(MethodDenial::ScopeNotGranted {
            required: Scope::OperatorWrite,
        })
    );
    assert_eq!(
        authorize(
            Role::Operator,
            &[Scope::OperatorApprovals],
            "node.pair.list"
        ),
        Err(MethodDenial::ScopeNotGranted {
            required: Scope::OperatorPairing,
        })
    );
    assert_eq!(
        authorize(Role::Operator, &[Scope::OperatorAdmin], "approval.get"),
        Ok(MethodGrant::OperatorScope {
            required: Scope::OperatorApprovals,
            satisfied_by: Scope::OperatorAdmin,
        })
    );

    // `health` is the documented dual-plane exception, and the only one.
    assert_eq!(
        authorize(Role::Node, &[], DUAL_PLANE_METHOD),
        Ok(MethodGrant::DualPlane)
    );
    assert_eq!(
        authorize(Role::Operator, &[], DUAL_PLANE_METHOD),
        Ok(MethodGrant::DualPlane)
    );
    assert_eq!(
        methods
            .iter()
            .filter(|row| method_requirement(&row.id, &row.classification)
                == Ok(MethodRequirement::DualPlane))
            .count(),
        1
    );

    // Denial messages carry the same facts as the variants.
    assert_eq!(
        MethodDenial::WorkerNotAdmitted.to_string(),
        "worker role is not admitted to ordinary gateway RPC"
    );
    assert_eq!(
        MethodDenial::RoleMismatch {
            required: Role::Node,
            actual: Role::Operator,
        }
        .to_string(),
        "method requires role=node; authenticated as role=operator"
    );
    assert_eq!(
        MethodDenial::ScopeNotGranted {
            required: Scope::OperatorPairing,
        }
        .to_string(),
        "method requires scope operator.pairing"
    );
}

#[test]
fn dynamic_scope_resolution_fails_closed_across_the_matrix() {
    let methods = frozen_methods();
    let dynamic = methods
        .iter()
        .filter(|row| row.classification == "dynamic")
        .collect::<Vec<_>>();
    assert_eq!(dynamic.len(), 4);

    let mut resolutions: Vec<(&str, Option<Vec<Scope>>)> =
        vec![("absent", None), ("empty", Some(Vec::new()))];
    for scope in Scope::ALL {
        resolutions.push((scope.as_str(), Some(vec![scope])));
    }
    assert_eq!(resolutions.len(), FROZEN_SCOPE_COUNT + 2);

    let mut cells = 0_usize;
    let mut grants = 0_usize;
    let mut denials: BTreeMap<&'static str, usize> = BTreeMap::new();

    for role in Role::ALL {
        for (label, granted) in &matrix_scope_sets() {
            let principal = Principal::new(role, ScopeSet::from_scopes(granted.iter().copied()));
            for method in &dynamic {
                for (resolution_label, resolution) in &resolutions {
                    let actual = authorize_inventory_method(
                        principal,
                        &method.id,
                        &method.classification,
                        resolution
                            .as_ref()
                            .map(|scopes| ScopeSet::from_scopes(scopes.iter().copied())),
                    )
                    .expect("dynamic classification resolves");
                    let expected = oracle(
                        role,
                        granted,
                        &method.id,
                        &method.classification,
                        resolution.as_deref(),
                    );
                    assert_eq!(
                        actual, expected,
                        "role={role} scopes={label} method={} resolution={resolution_label}",
                        method.id
                    );
                    cells += 1;
                    match actual {
                        Ok(_) => grants += 1,
                        Err(denial) => *denials.entry(denial_label(denial)).or_default() += 1,
                    }
                }
            }
        }
    }

    assert_eq!(cells, DYNAMIC_MATRIX_CELLS);
    assert_eq!(grants, DYNAMIC_MATRIX_GRANTS);
    assert_eq!(
        denials.values().sum::<usize>(),
        DYNAMIC_MATRIX_CELLS - DYNAMIC_MATRIX_GRANTS
    );
    assert_eq!(
        denials,
        EXPECTED_DYNAMIC_DENIALS
            .into_iter()
            .collect::<BTreeMap<_, _>>()
    );

    // A multi-scope resolution needs every member, and names the first unheld
    // one in frozen ordinal order rather than the first one written.
    let writer = Principal::new(
        Role::Operator,
        ScopeSet::from_scopes([Scope::OperatorWrite]),
    );
    assert_eq!(
        authorize_method(
            writer,
            MethodRequirement::DynamicOperatorScope,
            Some(ScopeSet::from_scopes([
                Scope::OperatorRead,
                Scope::OperatorWrite
            ]))
        ),
        Ok(MethodGrant::DynamicOperatorScopes)
    );
    assert_eq!(
        authorize_method(
            writer,
            MethodRequirement::DynamicOperatorScope,
            Some(ScopeSet::from_scopes([
                Scope::OperatorPairing,
                Scope::OperatorApprovals,
            ]))
        ),
        Err(MethodDenial::ScopeNotGranted {
            required: Scope::OperatorApprovals,
        })
    );
    assert_eq!(
        authorize_method(writer, MethodRequirement::DynamicOperatorScope, None),
        Err(MethodDenial::UnresolvedDynamicScope)
    );
    assert_eq!(
        authorize_method(
            writer,
            MethodRequirement::DynamicOperatorScope,
            Some(ScopeSet::EMPTY)
        ),
        Err(MethodDenial::EmptyDynamicScope)
    );
    // An admin resolution is still refused to a caller who is not an operator.
    assert_eq!(
        authorize_method(
            Principal::new(Role::Node, ScopeSet::from_scopes(Scope::ALL)),
            MethodRequirement::DynamicOperatorScope,
            Some(ScopeSet::from_scopes([Scope::OperatorRead]))
        ),
        Err(MethodDenial::RoleMismatch {
            required: Role::Operator,
            actual: Role::Node,
        })
    );
}

#[test]
fn scope_satisfaction_lattice_is_exhaustive() {
    let mut cells = 0_usize;
    let mut satisfied = 0_usize;
    for bits in 0_u8..64 {
        let held = Scope::ALL
            .into_iter()
            .filter(|scope| bits & (1 << scope.ordinal()) != 0)
            .collect::<Vec<_>>();
        let granted = ScopeSet::from_scopes(held.iter().copied());
        assert_eq!(
            granted.bits(),
            bits,
            "scope sets must round-trip their bits"
        );
        assert_eq!(granted.iter().collect::<Vec<_>>(), held);
        for required in Scope::ALL {
            let actual = satisfying_scope(granted, required);
            assert_eq!(
                actual,
                oracle_satisfier(&held, required),
                "granted={held:?} required={required}"
            );
            cells += 1;
            if actual.is_some() {
                satisfied += 1;
            }
        }
    }
    assert_eq!(cells, 64 * FROZEN_SCOPE_COUNT);
    // The 32 sets holding `operator.admin` satisfy all six requirements, 192
    // cells. Of the other 32, `operator.read` is satisfied by the 24 that hold
    // read or write, and each of the four remaining non-admin scopes by the 16
    // that hold it: 192 + 24 + 64 = 280. Pinned so that a widened implication
    // cannot pass unnoticed.
    assert_eq!(satisfied, 280);
    assert_eq!(
        satisfying_scope(ScopeSet::EMPTY, Scope::OperatorRead),
        None,
        "an empty grant satisfies nothing"
    );
    assert_eq!(
        satisfying_scope(
            ScopeSet::from_scopes([Scope::OperatorRead]),
            Scope::OperatorWrite
        ),
        None,
        "read must not imply write"
    );
    assert_eq!(
        satisfying_scope(
            ScopeSet::from_scopes([Scope::OperatorAdmin, Scope::OperatorRead]),
            Scope::OperatorRead
        ),
        Some(Scope::OperatorRead),
        "an exact grant is reported ahead of an administrative override"
    );
}

#[test]
fn operator_scopes_are_closed_to_the_operator_role() {
    let mut accepted = 0_usize;
    let mut rejected = 0_usize;
    for role in Role::ALL {
        for (label, granted) in &matrix_scope_sets() {
            let principal = Principal::new(role, ScopeSet::from_scopes(granted.iter().copied()));
            let actual = validate_principal(principal);
            let expected = if role == Role::Operator || granted.is_empty() {
                Ok(())
            } else {
                Err(RoleScopeError::OperatorScopesRequireOperatorRole)
            };
            assert_eq!(actual, expected, "role={role} scopes={label}");
            if actual.is_ok() {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
    }
    assert_eq!(
        accepted, 10,
        "operator with any set, plus node and worker with none"
    );
    assert_eq!(
        rejected, 14,
        "node and worker with each of the seven non-empty sets"
    );
    assert_eq!(
        RoleScopeError::OperatorScopesRequireOperatorRole.to_string(),
        "operator scopes require role=operator"
    );
}

#[test]
fn closed_registries_reject_unknown_identities() {
    let inventory = read_json("compat/upstream/inventories/gateway-protocol.json");
    let items = inventory["items"].as_array().expect("inventory items");
    let frozen = |kind: &str| {
        items
            .iter()
            .filter(|item| item["kind"] == kind)
            .map(|item| item["id"].as_str().expect("id").to_owned())
            .collect::<BTreeSet<_>>()
    };
    let roles = frozen("role");
    let scopes = frozen("scope");
    assert_eq!(roles.len(), FROZEN_ROLE_COUNT);
    assert_eq!(scopes.len(), FROZEN_SCOPE_COUNT);
    assert_eq!(
        roles,
        Role::ALL
            .into_iter()
            .map(|role| role.as_str().to_owned())
            .collect()
    );
    assert_eq!(
        scopes,
        Scope::ALL
            .into_iter()
            .map(|scope| scope.as_str().to_owned())
            .collect()
    );

    for role in &roles {
        let principal = parse_principal(role, scopes.iter().map(String::as_str))
            .expect("frozen identities parse");
        assert_eq!(principal.role.as_str(), role.as_str());
        assert_eq!(principal.granted_scopes, ScopeSet::from_scopes(Scope::ALL));
    }

    // An unknown member rejects the whole list; it is never dropped so that the
    // recognised members quietly take effect.
    for unknown in [
        "operator.superuser",
        "operator.Read",
        "operator.read ",
        "",
        "node",
        "dynamic",
    ] {
        assert_eq!(
            parse_granted_scopes(["operator.read", unknown]),
            Err(RegistryError::UnknownScope),
            "`{unknown}` must reject the whole scope list"
        );
        assert_eq!(
            parse_principal("operator", ["operator.read", unknown]),
            Err(RegistryError::UnknownScope)
        );
    }
    for unknown in ["Operator", "operators", "admin", "", " node"] {
        assert_eq!(
            parse_principal(unknown, ["operator.read"]),
            Err(RegistryError::UnknownRole),
            "`{unknown}` must not resolve to a role"
        );
    }

    // A method classification outside the closed set is a resolution failure,
    // not a denial a caller could mistake for a scope problem.
    assert_eq!(
        authorize_inventory_method(
            Principal::new(Role::Operator, ScopeSet::from_scopes(Scope::ALL)),
            "status",
            "operator.superuser",
            None,
        ),
        Err(RegistryError::UnknownScope)
    );
    assert_eq!(
        RegistryError::UnknownScope.to_string(),
        "unknown gateway scope"
    );
    assert_eq!(
        RegistryError::UnknownRole.to_string(),
        "unknown gateway role"
    );
}
