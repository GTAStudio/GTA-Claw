//! Real behavior for the method families this server implements.
//!
//! # Payload shapes are this crate's own
//!
//! `compat/upstream/inventories/gateway-protocol.json` freezes method
//! *identities*, their authorization classification, and whether they are
//! advertised. It records no request or response schema. The shapes below are
//! therefore this crate's design and are **not** claimed to be byte-compatible
//! with upstream `OpenClaw` payloads. They are strict: unknown fields are
//! rejected and every identity is length-bounded.

mod nodes;
mod sessions;
mod system;

use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;

use crate::dispatch::{MethodRegistry, StaticDynamicScopes};
use crate::error::DispatchError;

/// Maximum accepted length of any caller-supplied identity.
pub const MAX_IDENTITY_BYTES: usize = 128;
/// Maximum accepted length of a caller-supplied free-text field.
pub const MAX_TEXT_BYTES: usize = 4096;
/// Maximum accepted length of a node invocation payload.
pub const MAX_INVOCATION_PAYLOAD_BYTES: usize = 64 * 1024;

/// Installs every implemented handler into a registry.
///
/// # Errors
///
/// Returns [`DispatchError::UnknownMethod`] if an identity drifts out of the
/// frozen catalog, which makes catalog drift a hard failure at startup.
pub fn install(registry: &mut MethodRegistry) -> Result<(), DispatchError> {
    system::install(registry)?;
    sessions::install(registry)?;
    nodes::install(registry)?;
    Ok(())
}

/// Builds a registry with the frozen catalog and every implemented handler.
///
/// # Errors
///
/// Propagates any failure from [`install`].
pub fn registry() -> Result<MethodRegistry, DispatchError> {
    let mut registry = MethodRegistry::with_dynamic_resolver(Arc::new(StaticDynamicScopes));
    install(&mut registry)?;
    Ok(registry)
}

/// Decodes strict parameters for one method.
pub(crate) fn params_of<T>(method: &str, params: Value) -> Result<T, DispatchError>
where
    T: for<'de> Deserialize<'de>,
{
    let params = if params.is_null() {
        Value::Object(serde_json::Map::new())
    } else {
        params
    };
    serde_json::from_value(params).map_err(|error| DispatchError::InvalidParams {
        method: method.to_owned(),
        detail: error.to_string(),
    })
}

/// Validates a caller-supplied identity.
pub(crate) fn identity(method: &str, field: &str, value: &str) -> Result<(), DispatchError> {
    if value.is_empty() {
        return Err(DispatchError::InvalidParams {
            method: method.to_owned(),
            detail: format!("`{field}` must not be empty"),
        });
    }
    if value.len() > MAX_IDENTITY_BYTES {
        return Err(DispatchError::InvalidParams {
            method: method.to_owned(),
            detail: format!(
                "`{field}` is {} bytes, above the {MAX_IDENTITY_BYTES} byte limit",
                value.len()
            ),
        });
    }
    if value
        .chars()
        .any(|character| character.is_control() || character == '\u{7f}')
    {
        return Err(DispatchError::InvalidParams {
            method: method.to_owned(),
            detail: format!("`{field}` must not contain control characters"),
        });
    }
    Ok(())
}

/// Validates a caller-supplied free-text field.
pub(crate) fn bounded_text(
    method: &str,
    field: &str,
    value: &str,
    limit: usize,
) -> Result<(), DispatchError> {
    if value.len() > limit {
        return Err(DispatchError::InvalidParams {
            method: method.to_owned(),
            detail: format!(
                "`{field}` is {} bytes, above the {limit} byte limit",
                value.len()
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use claw_protocol::gateway::core_methods;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct Sample {
        id: String,
        #[serde(default)]
        title: Option<String>,
    }

    #[test]
    fn every_installed_handler_names_a_catalogued_method() {
        let registry = registry().expect("handlers install");
        let catalog: Vec<&'static str> =
            core_methods().iter().map(|method| method.name()).collect();
        let implemented = registry.implemented_names();
        assert!(!implemented.is_empty());
        for name in &implemented {
            assert!(catalog.contains(name), "`{name}` is not catalogued");
        }
    }

    #[test]
    fn the_implemented_set_is_exactly_the_documented_list() {
        let registry = registry().expect("handlers install");
        assert_eq!(
            registry.implemented_names(),
            vec![
                "gateway.identity.get",
                "health",
                "last-heartbeat",
                "node.describe",
                "node.event",
                "node.list",
                "node.pending.ack",
                "node.pending.drain",
                "node.pending.enqueue",
                "node.pending.pull",
                "sessions.create",
                "sessions.delete",
                "sessions.describe",
                "sessions.get",
                "sessions.list",
                "sessions.messages.subscribe",
                "sessions.messages.unsubscribe",
                "sessions.patch",
                "sessions.subscribe",
                "sessions.unsubscribe",
                "set-heartbeats",
                "system-presence",
                "system.info",
            ]
        );
    }

    #[test]
    fn absent_params_decode_as_an_empty_object() {
        #[derive(Debug, Deserialize, Eq, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct Empty {}
        assert_eq!(
            params_of::<Empty>("health", Value::Null).expect("empty params"),
            Empty {}
        );
    }

    #[test]
    fn unknown_params_fields_are_rejected_with_the_method_identity() {
        let error = params_of::<Sample>(
            "sessions.create",
            serde_json::json!({ "id": "s1", "extra": 1 }),
        )
        .expect_err("unknown field");
        match error {
            DispatchError::InvalidParams { method, detail } => {
                assert_eq!(method, "sessions.create");
                assert!(detail.contains("extra"), "unexpected detail: {detail}");
            }
            other => panic!("expected invalid params: {other:?}"),
        }
    }

    #[test]
    fn identity_validation_rejects_empty_control_and_oversized_values() {
        assert!(identity("m", "id", "session-1").is_ok());
        assert!(matches!(
            identity("m", "id", ""),
            Err(DispatchError::InvalidParams { .. })
        ));
        assert!(matches!(
            identity("m", "id", "bad\nid"),
            Err(DispatchError::InvalidParams { .. })
        ));
        assert!(matches!(
            identity("m", "id", "\u{7f}"),
            Err(DispatchError::InvalidParams { .. })
        ));
        let long = "a".repeat(MAX_IDENTITY_BYTES + 1);
        assert!(matches!(
            identity("m", "id", &long),
            Err(DispatchError::InvalidParams { .. })
        ));
        let exact = "a".repeat(MAX_IDENTITY_BYTES);
        assert!(identity("m", "id", &exact).is_ok());
    }

    #[test]
    fn bounded_text_accepts_the_exact_limit_and_refuses_one_more() {
        let exact = "x".repeat(16);
        assert!(bounded_text("m", "title", &exact, 16).is_ok());
        let over = "x".repeat(17);
        assert!(matches!(
            bounded_text("m", "title", &over, 16),
            Err(DispatchError::InvalidParams { .. })
        ));
    }
}
