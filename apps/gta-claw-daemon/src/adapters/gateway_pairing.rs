//! Durable Gateway device grants administered through authenticated HTTP RPC.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use claw_gateway::{DeviceDirectory, Grant};
use claw_http_api::{PortError, PortErrorKind};
use claw_protocol::gateway::{OperatorScope, Role};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::http_api::GatewayPairingAdmin;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StoredPairing {
    device_id: String,
    role: Role,
    scopes: Vec<OperatorScope>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingDocument {
    pairings: Vec<StoredPairing>,
}

/// One durable pairing file and the live Gateway grant directory it feeds.
#[derive(Debug)]
pub struct GatewayPairingStore {
    path: PathBuf,
    pairings: Mutex<BTreeMap<String, StoredPairing>>,
    devices: DeviceDirectory,
}

impl GatewayPairingStore {
    /// Opens and validates the durable pairing file.
    ///
    /// # Errors
    ///
    /// Returns a safe error when the file cannot be read, contains malformed or
    /// duplicate grants, or cannot be initialized durably.
    pub fn open(path: PathBuf) -> Result<Arc<Self>, String> {
        let mut pairings = BTreeMap::new();
        if path.exists() {
            let bytes = std::fs::read(&path).map_err(|error| safe_io("read", &error))?;
            let document: PairingDocument = serde_json::from_slice(&bytes)
                .map_err(|_| "gateway pairing file is invalid".to_owned())?;
            for pairing in document.pairings {
                validate_pairing(&pairing)?;
                if pairings
                    .insert(pairing.device_id.clone(), pairing)
                    .is_some()
                {
                    return Err("gateway pairing file contains a duplicate device".to_owned());
                }
            }
        } else {
            persist_pairings(&path, &pairings)?;
        }
        let devices = DeviceDirectory::new();
        for pairing in pairings.values() {
            devices.pair(
                pairing.device_id.clone(),
                Grant::new(pairing.role, pairing.scopes.iter().copied()),
            );
        }
        Ok(Arc::new(Self {
            path,
            pairings: Mutex::new(pairings),
            devices,
        }))
    }

    /// Returns the live directory shared by handshake and connection policy.
    #[must_use]
    pub fn devices(&self) -> DeviceDirectory {
        self.devices.clone()
    }

    /// Returns the number of durable grants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pairings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Reports whether no durable device grant exists.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn list(&self) -> Value {
        let pairings = self.pairings.lock().unwrap_or_else(PoisonError::into_inner);
        json!({
            "pairings": pairings
                .values()
                .map(|pairing| json!({
                    "deviceId": pairing.device_id,
                    "role": pairing.role.as_str(),
                    "scopes": pairing
                        .scopes
                        .iter()
                        .map(|scope| scope.as_str())
                        .collect::<Vec<_>>(),
                }))
                .collect::<Vec<_>>()
        })
    }

    fn approve(&self, method: &str, params: Option<&Value>) -> Result<Value, PortError> {
        let params = params.and_then(Value::as_object).ok_or_else(|| {
            PortError::new(
                PortErrorKind::InvalidRequest,
                "pair approval requires an object",
            )
        })?;
        let device_id = params
            .get("deviceId")
            .and_then(Value::as_str)
            .filter(|device_id| valid_device_id(device_id))
            .ok_or_else(|| {
                PortError::new(
                    PortErrorKind::InvalidRequest,
                    "pair approval requires a canonical deviceId",
                )
            })?;
        let default_role = if method.starts_with("node.") {
            Role::Node
        } else {
            Role::Operator
        };
        let role = params
            .get("role")
            .and_then(Value::as_str)
            .map_or(Some(default_role), Role::from_identity)
            .filter(|role| !matches!(role, Role::Worker))
            .ok_or_else(|| {
                PortError::new(
                    PortErrorKind::InvalidRequest,
                    "pair approval role must be operator or node",
                )
            })?;
        let scopes = parse_scopes(params.get("scopes"), role)?;
        let pairing = StoredPairing {
            device_id: device_id.to_owned(),
            role,
            scopes,
        };
        let mut held = self.pairings.lock().map_err(|_| {
            PortError::new(PortErrorKind::Internal, "gateway pairing state unavailable")
        })?;
        let mut candidate = held.clone();
        candidate.insert(device_id.to_owned(), pairing.clone());
        persist_pairings(&self.path, &candidate)
            .map_err(|error| PortError::new(PortErrorKind::Unavailable, error))?;
        *held = candidate;
        drop(held);
        let generation = self.devices.pair(
            pairing.device_id.clone(),
            Grant::new(pairing.role, pairing.scopes.iter().copied()),
        );
        Ok(json!({
            "approved": true,
            "deviceId": pairing.device_id,
            "role": pairing.role.as_str(),
            "scopes": pairing
                .scopes
                .iter()
                .map(|scope| scope.as_str())
                .collect::<Vec<_>>(),
            "generation": generation,
        }))
    }

    fn remove(&self, params: Option<&Value>) -> Result<Value, PortError> {
        let device_id = params
            .and_then(|params| params.get("deviceId"))
            .and_then(Value::as_str)
            .filter(|device_id| valid_device_id(device_id))
            .ok_or_else(|| {
                PortError::new(
                    PortErrorKind::InvalidRequest,
                    "pair removal requires a canonical deviceId",
                )
            })?;
        let mut held = self.pairings.lock().map_err(|_| {
            PortError::new(PortErrorKind::Internal, "gateway pairing state unavailable")
        })?;
        let mut candidate = held.clone();
        let existed = candidate.remove(device_id).is_some();
        persist_pairings(&self.path, &candidate)
            .map_err(|error| PortError::new(PortErrorKind::Unavailable, error))?;
        *held = candidate;
        drop(held);
        let revoked = self.devices.revoke(device_id);
        Ok(json!({
            "removed": existed || revoked,
            "deviceId": device_id,
        }))
    }
}

impl GatewayPairingAdmin for GatewayPairingStore {
    fn dispatch(&self, method: &str, params: Option<&Value>) -> Result<Option<Value>, PortError> {
        let payload = match method {
            "device.pair.list" | "node.pair.list" => self.list(),
            "device.pair.approve" | "node.pair.approve" => self.approve(method, params)?,
            "device.pair.reject" | "device.pair.remove" | "node.pair.reject"
            | "node.pair.remove" => self.remove(params)?,
            _ => return Ok(None),
        };
        Ok(Some(payload))
    }
}

fn parse_scopes(value: Option<&Value>, role: Role) -> Result<Vec<OperatorScope>, PortError> {
    if role == Role::Node {
        return Ok(Vec::new());
    }
    let Some(values) = value.and_then(Value::as_array) else {
        return Ok(vec![OperatorScope::Read]);
    };
    let mut scopes = Vec::with_capacity(values.len());
    for value in values {
        let scope = value
            .as_str()
            .and_then(OperatorScope::from_identity)
            .ok_or_else(|| {
                PortError::new(
                    PortErrorKind::InvalidRequest,
                    "pair approval contains an unknown scope",
                )
            })?;
        scopes.push(scope);
    }
    scopes.sort_unstable();
    scopes.dedup();
    Ok(scopes)
}

fn validate_pairing(pairing: &StoredPairing) -> Result<(), String> {
    if !valid_device_id(&pairing.device_id) || pairing.role == Role::Worker {
        return Err("gateway pairing file contains an invalid grant".to_owned());
    }
    if pairing.role == Role::Node && !pairing.scopes.is_empty() {
        return Err("gateway node pairing carries operator scopes".to_owned());
    }
    Ok(())
}

fn valid_device_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn persist_pairings(path: &Path, pairings: &BTreeMap<String, StoredPairing>) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "gateway pairing path has no parent".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|error| safe_io("create directory", &error))?;
    let temporary = path.with_extension("json.tmp");
    let document = PairingDocument {
        pairings: pairings.values().cloned().collect(),
    };
    let bytes = serde_json::to_vec_pretty(&document)
        .map_err(|_| "gateway pairing file encoding failed".to_owned())?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| safe_io("open temporary file", &error))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| safe_io("write temporary file", &error))?;
    std::fs::rename(&temporary, path).map_err(|error| safe_io("publish file", &error))?;
    sync_parent(parent).map_err(|error| safe_io("sync directory", &error))
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> io::Result<()> {
    Ok(())
}

fn safe_io(operation: &str, error: &io::Error) -> String {
    format!("gateway pairing {operation} failed ({:?})", error.kind())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::json;

    use super::{GatewayPairingAdmin, GatewayPairingStore};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn approved_pairing_survives_restart_and_can_be_revoked() {
        let root = std::env::temp_dir().join(format!(
            "gta-claw-gateway-pairing-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let path = root.join("pairings.json");
        let device_id = "a".repeat(64);
        let store = GatewayPairingStore::open(path.clone()).expect("store opens");
        let approved = store
            .dispatch(
                "device.pair.approve",
                Some(&json!({
                    "deviceId":device_id,
                    "role":"operator",
                    "scopes":["operator.read"],
                })),
            )
            .expect("approval succeeds")
            .expect("method handled");
        assert_eq!(approved["approved"], true);
        assert_eq!(store.len(), 1);
        drop(store);

        let reopened = GatewayPairingStore::open(path).expect("store reopens");
        assert_eq!(reopened.len(), 1);
        let removed = reopened
            .dispatch(
                "device.pair.remove",
                Some(&json!({"deviceId":"a".repeat(64)})),
            )
            .expect("removal succeeds")
            .expect("method handled");
        assert_eq!(removed["removed"], true);
        assert_eq!(reopened.len(), 0);
        std::fs::remove_dir_all(root).expect("temporary root removed");
    }
}
