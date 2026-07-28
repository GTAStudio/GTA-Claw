//! The tool catalog is pinned against the frozen upstream gateway contract.
//!
//! Every tool declares the gateway scope that fronts it over the wire. Those
//! scope names are not free-form: they must be scopes that actually exist in
//! `compat/upstream/inventories/gateway-protocol.json`, and the read/write/
//! approval split must match how upstream fronts the equivalent methods.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use claw_tools::exec::{ExecPolicy, ProcessExecTool};
use claw_tools::fs::{FsGlobTool, FsListTool, FsPatchTool, FsReadTool, FsSearchTool, FsWriteTool};
use claw_tools::net::{
    DenyAllSearchProvider, DenyAllTransport, NetFetchTool, UrlPolicy, WebSearchTool,
};
use claw_tools::permission::{Capability, RiskLevel};
use claw_tools::registry::ToolRegistry;
use serde_json::Value;

/// Builds the complete shipped tool surface.
fn full_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    for tool in [
        Box::new(FsReadTool) as Box<dyn claw_tools::tool::Tool>,
        Box::new(FsWriteTool),
        Box::new(FsListTool),
        Box::new(FsGlobTool),
        Box::new(FsSearchTool),
        Box::new(FsPatchTool),
        Box::new(ProcessExecTool::new(ExecPolicy::deny_all())),
        Box::new(NetFetchTool::new(
            UrlPolicy::public_internet(),
            DenyAllTransport,
        )),
        Box::new(WebSearchTool::new(
            UrlPolicy::public_internet(),
            DenyAllSearchProvider,
        )),
    ] {
        registry.register(tool).expect("each tool name is unique");
    }
    registry
}

/// Reads the frozen inventory without modifying it.
fn frozen_inventory() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("compat")
        .join("upstream")
        .join("inventories")
        .join("gateway-protocol.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "the frozen inventory must be readable at {}: {error}",
            path.display()
        )
    });
    let body = bytes
        .strip_prefix(&[0xef, 0xbb, 0xbf][..])
        .unwrap_or(&bytes);
    serde_json::from_slice(body).expect("the frozen inventory is valid JSON")
}

/// Maps frozen method identity to its declared scope.
fn frozen_method_scopes() -> BTreeMap<String, String> {
    let inventory = frozen_inventory();
    let items = inventory["items"]
        .as_array()
        .expect("the inventory carries an item array");
    let mut scopes = BTreeMap::new();
    for item in items {
        if item["kind"] != "method" {
            continue;
        }
        let (Some(id), Some(scope)) = (item["id"].as_str(), item["scope"].as_str()) else {
            continue;
        };
        scopes.insert(id.to_owned(), scope.to_owned());
    }
    assert!(
        scopes.len() > 100,
        "the frozen inventory looks truncated: {} methods",
        scopes.len()
    );
    scopes
}

#[test]
fn the_shipped_tool_surface_is_exactly_these_nine_tools() {
    let registry = full_registry();
    assert_eq!(
        registry.names(),
        vec![
            "fs_glob",
            "fs_list",
            "fs_patch",
            "fs_read",
            "fs_search",
            "fs_write",
            "net_fetch",
            "process_exec",
            "web_search",
        ]
    );
}

#[test]
fn every_tool_declares_the_capability_risk_and_approval_it_actually_needs() {
    let registry = full_registry();
    let actual: BTreeMap<&str, (Capability, RiskLevel, bool)> = registry
        .descriptors()
        .into_iter()
        .map(|descriptor| {
            (
                descriptor.name,
                (
                    descriptor.permission.capability,
                    descriptor.permission.risk,
                    descriptor.permission.requires_approval,
                ),
            )
        })
        .collect();
    let expected: BTreeMap<&str, (Capability, RiskLevel, bool)> = BTreeMap::from([
        (
            "fs_glob",
            (Capability::FilesystemRead, RiskLevel::Low, false),
        ),
        (
            "fs_list",
            (Capability::FilesystemRead, RiskLevel::Low, false),
        ),
        (
            "fs_patch",
            (Capability::FilesystemWrite, RiskLevel::Medium, true),
        ),
        (
            "fs_read",
            (Capability::FilesystemRead, RiskLevel::Low, false),
        ),
        (
            "fs_search",
            (Capability::FilesystemRead, RiskLevel::Low, false),
        ),
        (
            "fs_write",
            (Capability::FilesystemWrite, RiskLevel::Medium, true),
        ),
        (
            "net_fetch",
            (Capability::NetworkFetch, RiskLevel::High, true),
        ),
        (
            "process_exec",
            (Capability::ProcessExecute, RiskLevel::High, true),
        ),
        (
            "web_search",
            (Capability::NetworkSearch, RiskLevel::Medium, true),
        ),
    ]);
    assert_eq!(actual, expected);
}

#[test]
fn every_mutating_or_escaping_tool_requires_explicit_approval() {
    for descriptor in full_registry().descriptors() {
        let mutating = descriptor.permission.capability != Capability::FilesystemRead;
        assert_eq!(
            descriptor.permission.requires_approval, mutating,
            "{} has the wrong approval requirement",
            descriptor.name
        );
        if descriptor.permission.risk == RiskLevel::High {
            assert!(
                descriptor.permission.requires_approval,
                "{} is high risk but does not require approval",
                descriptor.name
            );
        }
    }
}

#[test]
fn declared_gateway_scopes_exist_in_the_frozen_inventory() {
    let frozen = frozen_method_scopes();
    let known: BTreeSet<&str> = frozen.values().map(String::as_str).collect();
    for descriptor in full_registry().descriptors() {
        assert!(
            known.contains(descriptor.permission.gateway_scope),
            "{} declares scope {:?}, which upstream never uses",
            descriptor.name,
            descriptor.permission.gateway_scope
        );
    }
}

#[test]
fn tool_scopes_track_the_frozen_methods_that_front_them() {
    let frozen = frozen_method_scopes();
    // These are the upstream methods our surface is reachable through.
    assert_eq!(
        frozen.get("tools.catalog").map(String::as_str),
        Some("operator.read")
    );
    assert_eq!(
        frozen.get("tools.effective").map(String::as_str),
        Some("operator.read")
    );
    assert_eq!(
        frozen.get("tools.invoke").map(String::as_str),
        Some("operator.write")
    );
    assert_eq!(
        frozen.get("exec.approval.request").map(String::as_str),
        Some("operator.approvals")
    );

    let scopes: BTreeMap<&str, &str> = full_registry()
        .descriptors()
        .into_iter()
        .map(|descriptor| (descriptor.name, descriptor.permission.gateway_scope))
        .collect();
    let read_scope = frozen["tools.catalog"].as_str();
    let write_scope = frozen["tools.invoke"].as_str();
    let approvals_scope = frozen["exec.approval.request"].as_str();

    for name in ["fs_read", "fs_list", "fs_glob", "fs_search", "web_search"] {
        assert_eq!(
            *scopes.get(name).expect("the tool is registered"),
            read_scope,
            "{name} is not fronted as a read"
        );
    }
    for name in ["fs_write", "fs_patch", "net_fetch"] {
        assert_eq!(
            *scopes.get(name).expect("the tool is registered"),
            write_scope,
            "{name} is not fronted as a write"
        );
    }
    assert_eq!(
        *scopes.get("process_exec").expect("the tool is registered"),
        approvals_scope
    );
}

#[test]
fn the_operator_catalog_carries_the_whole_permission_model() {
    let registry = full_registry();
    let catalog = registry.catalog();
    let entries = catalog["tools"]
        .as_array()
        .expect("the catalog carries an array");
    assert_eq!(entries.len(), 9);

    let exec = entries
        .iter()
        .find(|entry| entry["name"] == "process_exec")
        .expect("process_exec is catalogued");
    assert_eq!(
        exec["permission"],
        serde_json::json!({
            "capability": "process.execute",
            "risk": "high",
            "requires_approval": true,
            "gateway_scope": "operator.approvals",
        })
    );
    assert_eq!(exec["title"], "Run a program");
    assert_eq!(exec["parameters"]["type"], "object");
    assert_eq!(exec["parameters"]["additionalProperties"], false);
    assert_eq!(
        exec["parameters"]["required"],
        serde_json::json!(["program"])
    );

    // No entry may omit any part of the model.
    for entry in entries {
        for key in ["name", "title", "description", "parameters", "permission"] {
            assert!(
                entry.get(key).is_some(),
                "catalog entry {:?} is missing {key}",
                entry["name"]
            );
        }
        for key in ["capability", "risk", "requires_approval", "gateway_scope"] {
            assert!(
                entry["permission"].get(key).is_some(),
                "catalog entry {:?} is missing permission.{key}",
                entry["name"]
            );
        }
    }
}

#[test]
fn the_provider_catalog_never_leaks_the_permission_model_to_the_model() {
    let registry = full_registry();
    let catalog = registry.provider_catalog();
    let entries = catalog.as_array().expect("an array of declarations");
    assert_eq!(entries.len(), 9);
    for entry in entries {
        assert_eq!(entry["type"], "function");
        let function = &entry["function"];
        assert!(function.get("name").is_some());
        assert!(function.get("description").is_some());
        assert_eq!(function["parameters"]["type"], "object");
        assert_eq!(function["parameters"]["additionalProperties"], false);
        // Permission metadata is operator-facing only; a model must not be
        // able to read the approval policy out of its own tool declarations.
        assert!(
            function.get("permission").is_none() && entry.get("permission").is_none(),
            "the provider declaration leaked the permission model"
        );
    }
}

#[test]
fn every_tool_schema_is_closed_and_documented() {
    for descriptor in full_registry().descriptors() {
        let schema = descriptor.schema.to_json_schema();
        assert_eq!(schema["type"], "object", "{}", descriptor.name);
        assert_eq!(
            schema["additionalProperties"], false,
            "{} accepts unknown properties",
            descriptor.name
        );
        let properties = schema["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{} has no properties", descriptor.name));
        assert!(
            !properties.is_empty(),
            "{} takes no arguments",
            descriptor.name
        );
        for (name, property) in properties {
            let description = property["description"]
                .as_str()
                .unwrap_or_else(|| panic!("{}.{name} has no description", descriptor.name));
            assert!(
                description.len() > 10,
                "{}.{name} has a useless description",
                descriptor.name
            );
        }
        assert!(
            descriptor.description.len() > 40,
            "{} has a uselessly short description",
            descriptor.name
        );
    }
}
