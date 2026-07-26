//! MCP registry lifecycle tests over a real child process.

use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use claw_mcp::{
    client::{DiscardEvents, RejectSampling},
    registry::{
        McpRegistry, MemoryRegistryStore, NoRegistryAuth, ServerConfig, ServerState,
        ServerTransportConfig,
    },
};

#[tokio::test]
async fn registry_manages_stdio_health_capabilities_tools_and_restart() {
    let registry = McpRegistry::load(
        Arc::new(MemoryRegistryStore::default()),
        Arc::new(NoRegistryAuth),
        Arc::new(RejectSampling),
        Arc::new(DiscardEvents),
    )
    .expect("empty registry must load");
    let mut config = ServerConfig::new(
        "fixture",
        ServerTransportConfig::Stdio {
            command: PathBuf::from(env!("CARGO_BIN_EXE_claw-mcp-fixture")),
            arguments: Vec::new(),
            environment: BTreeMap::new(),
        },
    );
    config.connect_timeout_ms = 5_000;
    config.request_timeout_ms = 1_000;
    registry.add(config).await.expect("server must be added");

    let started = registry.start("fixture").await.expect("server must start");
    assert_eq!(started.state, ServerState::Healthy);
    assert!(started.child_pid.is_some());
    assert_eq!(
        registry
            .capabilities("fixture")
            .await
            .expect("capabilities must be discoverable")
            .server_info
            .name,
        "gta-claw-mcp-fixture"
    );
    let tools = registry
        .tools("fixture")
        .await
        .expect("tool catalog must refresh");
    assert_eq!(
        tools
            .tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>(),
        vec!["echo", "hang", "sample", "notify", "cancel"]
    );

    let restarted = registry
        .restart("fixture")
        .await
        .expect("server must restart");
    assert_eq!(restarted.state, ServerState::Healthy);
    assert!(restarted.child_pid.is_some());
    let stopped = registry.stop("fixture").await.expect("server must stop");
    assert_eq!(stopped.state, ServerState::Stopped);
    assert_eq!(stopped.child_pid, None);

    let probe = registry
        .probe("fixture")
        .await
        .expect("temporary health probe must pass");
    assert_eq!(probe.state, ServerState::Healthy);
    assert_eq!(
        registry
            .status("fixture")
            .await
            .expect("status must be readable")
            .state,
        ServerState::Stopped
    );
    let reports = registry.doctor().await;
    assert_eq!(reports.len(), 1);
    assert!(reports[0].healthy);
    assert_eq!(reports[0].message, "initialize and tools/list succeeded");
}

#[tokio::test]
async fn failed_temporary_probe_still_stops_its_child() {
    let registry = McpRegistry::load(
        Arc::new(MemoryRegistryStore::default()),
        Arc::new(NoRegistryAuth),
        Arc::new(RejectSampling),
        Arc::new(DiscardEvents),
    )
    .expect("empty registry must load");
    let marker = std::env::temp_dir().join(format!(
        "gta-claw-registry-probe-cancel-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must follow epoch")
            .as_nanos()
    ));
    let mut config = ServerConfig::new(
        "hung-probe",
        ServerTransportConfig::Stdio {
            command: PathBuf::from(env!("CARGO_BIN_EXE_claw-mcp-fixture")),
            arguments: Vec::new(),
            environment: BTreeMap::from([(
                "CANCELLED_LIST_MARKER".into(),
                marker.to_string_lossy().into_owned(),
            )]),
        },
    );
    config.connect_timeout_ms = 5_000;
    config.request_timeout_ms = 100;
    registry.add(config).await.expect("server must be added");

    let error = registry
        .probe("hung-probe")
        .await
        .expect_err("hung tools/list must fail the probe");

    assert_eq!(error.to_string(), "MCP operation timed out after 100ms");
    assert_eq!(
        registry
            .status("hung-probe")
            .await
            .expect("status readable")
            .state,
        ServerState::Stopped
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while !marker.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server must observe cancellation before probe cleanup");
    std::fs::remove_file(marker).expect("probe marker removable");
}
