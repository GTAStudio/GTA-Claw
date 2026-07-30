//! Signed batch activation keeps deterministic ordering and partial success.

mod support;

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use claw_plugin_api::capability::{CapabilityGrant, LogGrant, LogLevel, ToolsGrant};
use claw_plugin_api::limits::ResourceLimits;
use claw_plugin_api::registry::DeliveryClass;
use claw_plugin_api::trust::{
    Ed25519Verifier, SignatureVerifier, TrustPolicy, VerificationError, VerificationRequest,
};
use claw_plugin_host::services::{HostServices, RecordingSink, ToolRegistration, ToolSink};
use claw_plugin_host::{
    ActivationControl, ActivationOutcome, ActivationStage, CancellationToken,
    ControlledActivationOutcome, DiscoveryRecord, DiscoveryStage, HostError, LifecycleState,
    PluginHost,
};
use ed25519_dalek::SigningKey;
use support::{
    PROBE_ID, install, install_probe_named, install_variant, manifest_for, probe_component,
    probe_component_named, probe_component_registering_tool_on_activate_and_logging_on_deactivate,
    probe_component_registering_tool_on_activate_then_spinning_on_deactivate,
    probe_component_registering_tool_then_spinning_on_activate, sign_manifest,
};

#[derive(Clone)]
struct CancellingTools {
    recorder: RecordingSink,
    cancellation: Option<CancellationToken>,
    registrations: Arc<AtomicUsize>,
}

impl CancellingTools {
    fn new(cancellation: Option<CancellationToken>) -> Self {
        Self {
            recorder: RecordingSink::new(),
            cancellation,
            registrations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn registrations(&self) -> usize {
        self.registrations.load(Ordering::Acquire)
    }

    fn tools(&self) -> Vec<ToolRegistration> {
        self.recorder.tools()
    }
}

impl ToolSink for CancellingTools {
    fn register(&self, registration: ToolRegistration) {
        let _ = self.try_register(registration);
    }

    fn try_register(
        &self,
        registration: ToolRegistration,
    ) -> Result<(), claw_plugin_host::ToolRegistrationError> {
        self.registrations.fetch_add(1, Ordering::AcqRel);
        self.recorder.try_register(registration)?;
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
        Ok(())
    }

    fn unregister(&self, plugin_id: &str, name: &str) -> bool {
        self.recorder.unregister(plugin_id, name)
    }
}

#[derive(Clone)]
struct DelayedTools {
    recorder: RecordingSink,
    delay: Duration,
}

impl ToolSink for DelayedTools {
    fn register(&self, registration: ToolRegistration) {
        let _ = self.try_register(registration);
    }

    fn try_register(
        &self,
        registration: ToolRegistration,
    ) -> Result<(), claw_plugin_host::ToolRegistrationError> {
        std::thread::sleep(self.delay);
        self.recorder.try_register(registration)
    }

    fn unregister(&self, plugin_id: &str, name: &str) -> bool {
        self.recorder.unregister(plugin_id, name)
    }
}

#[derive(Clone, Default)]
struct BlockingVerifier {
    state: Arc<(Mutex<BlockingVerifierState>, Condvar)>,
}

#[derive(Default)]
struct BlockingVerifierState {
    calls: Vec<String>,
    released: bool,
    finished: bool,
}

impl BlockingVerifier {
    fn calls(&self) -> Vec<String> {
        self.state
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .calls
            .clone()
    }

    fn release(&self) {
        let (state, wake) = &*self.state;
        let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
        state.released = true;
        wake.notify_all();
        while !state.finished {
            state = wake.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

impl SignatureVerifier for BlockingVerifier {
    fn verify(&self, request: &VerificationRequest<'_>) -> Result<(), VerificationError> {
        let (state, wake) = &*self.state;
        let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
        state.calls.push(request.manifest.id.clone());
        wake.notify_all();
        while !state.released {
            state = wake.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
        state.finished = true;
        wake.notify_all();
        Ok(())
    }
}

#[test]
fn signed_activation_reports_failures_in_order_and_keeps_later_successes() {
    let root = support::tempdir();
    let key = SigningKey::from_bytes(&[42_u8; 32]);

    let malformed = root.path().join("aaa-malformed");
    std::fs::create_dir_all(&malformed).expect("create malformed fixture");
    std::fs::write(malformed.join("plugin.json"), b"{not-json").expect("write malformed manifest");

    let good_component = probe_component();
    let good_manifest = sign_manifest(&manifest_for(&good_component), &key, "release");
    install(root.path(), "bbb-good", &good_component, &good_manifest);

    let other_id = "gta-claw-fixture-other";
    let other_component = probe_component_named(other_id);
    let mut other_manifest = manifest_for(&other_component);
    other_manifest.id = other_id.to_owned();
    let mut tampered = sign_manifest(&other_manifest, &key, "release");
    tampered.description.push_str(" after signing");
    install(root.path(), "ccc-tampered", &other_component, &tampered);

    let policy = TrustPolicy::deny_all()
        .with_root(root.path().to_path_buf())
        .require_signature(true)
        .require_identity_binding(false)
        .with_trusted_key_id("release")
        .allow_delivery_class(DeliveryClass::Core);
    let mut host = PluginHost::builder()
        .trust_policy(policy)
        .verifier(Arc::new(
            Ed25519Verifier::new().with_key("release", key.verifying_key().to_bytes()),
        ))
        .build()
        .expect("host");

    let report = host.activate_discovered();
    assert_eq!(report.activated_count(), 1);
    assert_eq!(report.failure_count(), 2);
    assert_eq!(report.outcomes().len(), 3);

    let paths: Vec<&str> = report
        .outcomes()
        .iter()
        .map(|outcome| {
            let path = match outcome {
                ActivationOutcome::Activated(plugin) => &plugin.directory,
                ActivationOutcome::Failed(failure) => &failure.path,
            };
            path.file_name()
                .and_then(|name| name.to_str())
                .expect("fixture directory name")
        })
        .collect();
    assert_eq!(paths, ["aaa-malformed", "bbb-good", "ccc-tampered"]);

    let ActivationOutcome::Failed(malformed) = &report.outcomes()[0] else {
        panic!("the malformed manifest should fail");
    };
    assert_eq!(malformed.stage, ActivationStage::Manifest);
    assert!(malformed.plugin_id.is_none());
    assert!(malformed.error.to_string().contains("manifest JSON"));

    let ActivationOutcome::Activated(good) = &report.outcomes()[1] else {
        panic!("the signed fixture should activate");
    };
    assert_eq!(good.id, PROBE_ID);
    assert_eq!(good.signing_key_id.as_deref(), Some("release"));
    assert_eq!(host.state(PROBE_ID), Some(LifecycleState::Active));
    assert_eq!(host.signing_key_id(PROBE_ID), Some("release"));

    let ActivationOutcome::Failed(tampered) = &report.outcomes()[2] else {
        panic!("the tampered signature should fail");
    };
    assert_eq!(tampered.plugin_id.as_deref(), Some(other_id));
    assert_eq!(tampered.stage, ActivationStage::Load);
    assert!(matches!(
        tampered.error,
        HostError::Verification(VerificationError::BadSignature { .. })
    ));
    assert!(tampered.cleanup_error.is_none());
    assert_eq!(host.loaded_ids(), [PROBE_ID]);
}

#[test]
fn detailed_discovery_surfaces_an_unreadable_root() {
    let base = support::tempdir();
    let missing = base.path().join("missing");
    let host = PluginHost::builder()
        .trust_policy(TrustPolicy::deny_all().with_root(missing.clone()))
        .build()
        .expect("host");

    let records = host.discover_detailed();
    assert_eq!(records.len(), 1);
    let DiscoveryRecord::Failed { path, stage, error } = &records[0] else {
        panic!("a missing root must be a diagnostic");
    };
    assert_eq!(path, &missing);
    assert_eq!(*stage, DiscoveryStage::Root);
    assert!(error.to_string().contains("i/o error"));
}

#[cfg(unix)]
#[test]
fn detailed_discovery_surfaces_child_metadata_failures() {
    use std::os::unix::fs::symlink;

    let root = support::tempdir();
    let broken = root.path().join("broken-plugin");
    symlink(root.path().join("missing-target"), &broken).expect("create broken child symlink");
    let host = PluginHost::builder()
        .trust_policy(TrustPolicy::deny_all().with_root(root.path().to_path_buf()))
        .build()
        .expect("host");

    let records = host.discover_detailed();
    assert_eq!(records.len(), 1);
    let DiscoveryRecord::Failed { path, stage, .. } = &records[0] else {
        panic!("broken child metadata must be a diagnostic");
    };
    assert_eq!(path, &broken);
    assert_eq!(*stage, DiscoveryStage::Manifest);
}

#[cfg(unix)]
#[test]
fn detailed_discovery_surfaces_a_dangling_manifest_symlink() {
    use std::os::unix::fs::symlink;

    let root = support::tempdir();
    let plugin = root.path().join("broken-plugin");
    std::fs::create_dir_all(&plugin).expect("create plugin directory");
    symlink(plugin.join("missing-manifest"), plugin.join("plugin.json"))
        .expect("create dangling manifest symlink");
    let host = PluginHost::builder()
        .trust_policy(TrustPolicy::deny_all().with_root(root.path().to_path_buf()))
        .build()
        .expect("host");

    let records = host.discover_detailed();
    assert_eq!(records.len(), 1);
    let DiscoveryRecord::Failed { path, stage, .. } = &records[0] else {
        panic!("dangling manifest symlink must be a diagnostic");
    };
    assert_eq!(path, &plugin);
    assert_eq!(*stage, DiscoveryStage::Manifest);
}

#[test]
fn controlled_activation_reports_preexisting_cancellation_and_deadline() {
    let root = support::tempdir();
    support::install_probe(root.path(), "probe", Vec::new());
    let mut host = PluginHost::builder()
        .trust_policy(support::unsigned_core_policy(root.path()))
        .build()
        .expect("host");
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled = ActivationControl::new(
        NonZeroUsize::new(1).expect("one is non-zero"),
        Instant::now() + Duration::from_secs(1),
        cancellation,
    )
    .expect("bounded control");
    let report = host.activate_discovered_with_control(&cancelled);
    assert!(matches!(
        report.outcomes(),
        [ControlledActivationOutcome::Cancelled]
    ));
    assert!(host.loaded_ids().is_empty());

    let expired = ActivationControl::new(
        NonZeroUsize::new(1).expect("one is non-zero"),
        Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("the process has run for at least a millisecond"),
        CancellationToken::new(),
    )
    .expect("bounded control");
    let report = host.activate_discovered_with_control(&expired);
    assert!(matches!(
        report.outcomes(),
        [ControlledActivationOutcome::DeadlineExceeded]
    ));
    assert!(host.loaded_ids().is_empty());
}

#[test]
fn controlled_activation_rejects_an_unbounded_candidate_capacity() {
    let error = ActivationControl::new(
        NonZeroUsize::new(usize::MAX).expect("usize::MAX is non-zero"),
        Instant::now() + Duration::from_secs(1),
        CancellationToken::new(),
    )
    .expect_err("the candidate heap has a hard ceiling");
    assert_eq!(error.requested(), usize::MAX);
}

#[test]
fn controlled_activation_stops_at_the_hard_candidate_limit_in_lexical_order() {
    let root = support::tempdir();
    let first_id = "gta-claw-fixture-alpha";
    let second_id = "gta-claw-fixture-bravo";
    let first = install_probe_named(root.path(), "aaa-first", first_id, Vec::new());
    let second = install_probe_named(root.path(), "bbb-second", second_id, Vec::new());
    let mut host = PluginHost::builder()
        .trust_policy(support::unsigned_core_policy(root.path()))
        .operator_policy(support::ceiling_from_all(&[&first, &second]))
        .build()
        .expect("host");
    let control = ActivationControl::new(
        NonZeroUsize::new(1).expect("one is non-zero"),
        Instant::now() + Duration::from_secs(5),
        CancellationToken::new(),
    )
    .expect("bounded control");

    let report = host.activate_discovered_with_control(&control);
    assert_eq!(report.activated_count(), 1);
    assert_eq!(report.outcomes().len(), 2);
    assert!(matches!(
        report.outcomes()[0].candidate(),
        Some(ActivationOutcome::Activated(plugin)) if plugin.id == first_id
    ));
    assert!(matches!(
        report.outcomes()[1],
        ControlledActivationOutcome::CandidateLimitReached { limit }
            if limit.get() == 1
    ));
    assert_eq!(host.loaded_ids(), [first_id]);
    assert_eq!(host.state(second_id), None);
}

#[test]
fn cancellation_during_guest_activation_removes_the_instance_and_its_tools() {
    let root = support::tempdir();
    let component = probe_component_registering_tool_then_spinning_on_activate();
    let grants = vec![CapabilityGrant::Tools(ToolsGrant {
        max_tools: 1,
        max_schema_bytes: 1024,
    })];
    let directory = install_variant(root.path(), "probe", &component, grants.clone());
    let cancellation = CancellationToken::new();
    let tools = CancellingTools::new(Some(cancellation.clone()));
    let mut host = PluginHost::builder()
        .trust_policy(support::unsigned_core_policy(root.path()))
        .operator_policy(support::probe_ceiling(grants))
        .services(HostServices::deny_all().with_tools(Arc::new(tools.clone())))
        .build()
        .expect("host");
    let control = ActivationControl::new(
        NonZeroUsize::new(1).expect("one is non-zero"),
        Instant::now() + Duration::from_secs(5),
        cancellation,
    )
    .expect("bounded control");

    let report = host.activate_discovered_with_control(&control);
    assert!(matches!(
        report.outcomes(),
        [ControlledActivationOutcome::Cancelled]
    ));
    assert_eq!(
        tools.registrations(),
        1,
        "the guest registered before cancel"
    );
    assert!(
        tools.tools().is_empty(),
        "cancellation must purge stale tools"
    );
    assert!(host.loaded_ids().is_empty());
    assert_eq!(host.state(PROBE_ID), None);
    assert_eq!(
        directory.file_name().and_then(|name| name.to_str()),
        Some("probe")
    );
}

#[test]
fn cancellation_after_successful_activation_runs_deactivate_before_discard() {
    let root = support::tempdir();
    let component = probe_component_registering_tool_on_activate_and_logging_on_deactivate();
    let grants = vec![
        CapabilityGrant::Tools(ToolsGrant {
            max_tools: 1,
            max_schema_bytes: 1024,
        }),
        CapabilityGrant::Log(LogGrant {
            min_level: LogLevel::Trace,
            max_message_bytes: 1024,
        }),
    ];
    install_variant(root.path(), "probe", &component, grants.clone());
    let cancellation = CancellationToken::new();
    let tools = CancellingTools::new(Some(cancellation.clone()));
    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(support::unsigned_core_policy(root.path()))
        .operator_policy(support::probe_ceiling(grants))
        .services(
            HostServices::deny_all()
                .with_tools(Arc::new(tools.clone()))
                .with_logs(Arc::new(recorder.clone())),
        )
        .build()
        .expect("host");
    let control = ActivationControl::new(
        NonZeroUsize::new(1).expect("one is non-zero"),
        Instant::now() + Duration::from_secs(5),
        cancellation,
    )
    .expect("bounded control");

    let report = host.activate_discovered_with_control(&control);

    assert!(matches!(
        report.outcomes(),
        [ControlledActivationOutcome::Cancelled]
    ));
    assert_eq!(
        recorder.logs().len(),
        1,
        "successful activation must be deactivated before cancellation discards it"
    );
    assert!(tools.tools().is_empty());
    assert!(host.loaded_ids().is_empty());
}

#[test]
fn deadline_after_successful_activation_runs_deactivate_before_discard() {
    let root = support::tempdir();
    let component = probe_component_registering_tool_on_activate_and_logging_on_deactivate();
    let grants = vec![
        CapabilityGrant::Tools(ToolsGrant {
            max_tools: 1,
            max_schema_bytes: 1024,
        }),
        CapabilityGrant::Log(LogGrant {
            min_level: LogLevel::Trace,
            max_message_bytes: 1024,
        }),
    ];
    install_variant(root.path(), "probe", &component, grants.clone());
    let tools = DelayedTools {
        recorder: RecordingSink::new(),
        delay: Duration::from_millis(75),
    };
    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(support::unsigned_core_policy(root.path()))
        .operator_policy(support::probe_ceiling(grants))
        .services(
            HostServices::deny_all()
                .with_tools(Arc::new(tools.clone()))
                .with_logs(Arc::new(recorder.clone())),
        )
        .build()
        .expect("host");
    let control = ActivationControl::new(
        NonZeroUsize::new(1).expect("one is non-zero"),
        Instant::now() + Duration::from_millis(20),
        CancellationToken::new(),
    )
    .expect("bounded control");

    let report = host.activate_discovered_with_control(&control);

    assert!(matches!(
        report.outcomes(),
        [ControlledActivationOutcome::DeadlineExceeded]
    ));
    assert_eq!(
        recorder.logs().len(),
        1,
        "successful activation must be deactivated before deadline cleanup discards it"
    );
    assert!(tools.recorder.tools().is_empty());
    assert!(host.loaded_ids().is_empty());
}

#[test]
fn successful_activation_cannot_bypass_its_plugin_deadline() {
    let root = support::tempdir();
    let component = probe_component_registering_tool_on_activate_and_logging_on_deactivate();
    let grants = vec![CapabilityGrant::Tools(ToolsGrant {
        max_tools: 1,
        max_schema_bytes: 1024,
    })];
    let mut manifest = manifest_for(&component);
    manifest.capabilities.clone_from(&grants);
    manifest.limits = ResourceLimits {
        fuel: u64::MAX,
        wall_clock_timeout_ms: 20,
        ..ResourceLimits::default()
    };
    install(root.path(), "probe", &component, &manifest);
    let tools = DelayedTools {
        recorder: RecordingSink::new(),
        delay: Duration::from_millis(75),
    };
    let mut host = PluginHost::builder()
        .trust_policy(support::unsigned_core_policy(root.path()))
        .operator_policy(support::probe_ceiling(grants))
        .services(HostServices::deny_all().with_tools(Arc::new(tools.clone())))
        .build()
        .expect("host");
    let control = ActivationControl::new(
        NonZeroUsize::new(1).expect("one is non-zero"),
        Instant::now() + Duration::from_secs(5),
        CancellationToken::new(),
    )
    .expect("bounded control");

    let report = host.activate_discovered_with_control(&control);

    let [ControlledActivationOutcome::Candidate(outcome)] = report.outcomes() else {
        panic!("the plugin deadline should be a candidate failure");
    };
    let ActivationOutcome::Failed(failure) = outcome.as_ref() else {
        panic!("a late successful return must not activate the plugin");
    };
    assert_eq!(failure.stage, ActivationStage::Activate);
    assert_eq!(
        failure.error.termination(),
        Some(claw_plugin_host::TerminationCause::Timeout)
    );
    assert!(tools.recorder.tools().is_empty());
    assert!(host.loaded_ids().is_empty());
}

#[test]
fn post_activation_cancellation_uses_a_short_rollback_deadline() {
    let root = support::tempdir();
    let component = probe_component_registering_tool_on_activate_then_spinning_on_deactivate();
    let grants = vec![CapabilityGrant::Tools(ToolsGrant {
        max_tools: 1,
        max_schema_bytes: 1024,
    })];
    let mut manifest = manifest_for(&component);
    manifest.capabilities.clone_from(&grants);
    manifest.limits = ResourceLimits {
        fuel: u64::MAX,
        wall_clock_timeout_ms: 10 * 60 * 1000,
        ..ResourceLimits::default()
    };
    install(root.path(), "probe", &component, &manifest);
    let cancellation = CancellationToken::new();
    let tools = CancellingTools::new(Some(cancellation.clone()));
    let mut host = PluginHost::builder()
        .trust_policy(support::unsigned_core_policy(root.path()))
        .operator_policy(support::probe_ceiling(grants))
        .services(HostServices::deny_all().with_tools(Arc::new(tools.clone())))
        .build()
        .expect("host");
    let control = ActivationControl::new(
        NonZeroUsize::new(1).expect("one is non-zero"),
        Instant::now() + Duration::from_secs(5),
        cancellation,
    )
    .expect("bounded control");

    let started = Instant::now();
    let report = host.activate_discovered_with_control(&control);
    let elapsed = started.elapsed();

    assert!(matches!(
        report.outcomes(),
        [ControlledActivationOutcome::Cancelled]
    ));
    assert!(
        elapsed < Duration::from_secs(2),
        "activation rollback exceeded its short cleanup budget: {elapsed:?}"
    );
    assert!(tools.tools().is_empty());
    assert!(host.loaded_ids().is_empty());
}

#[test]
fn admission_deadline_abandons_blocked_verification_and_stops_later_plugins() {
    let root = support::tempdir();
    let first_id = "gta-claw-fixture-alpha";
    let second_id = "gta-claw-fixture-bravo";
    let first = install_probe_named(root.path(), "aaa-first", first_id, Vec::new());
    let second = install_probe_named(root.path(), "bbb-second", second_id, Vec::new());
    let verifier = BlockingVerifier::default();
    let mut host = PluginHost::builder()
        .trust_policy(support::unsigned_core_policy(root.path()))
        .operator_policy(support::ceiling_from_all(&[&first, &second]))
        .verifier(Arc::new(verifier.clone()))
        .build()
        .expect("host");
    let control = ActivationControl::new(
        NonZeroUsize::new(2).expect("two is non-zero"),
        Instant::now() + Duration::from_millis(50),
        CancellationToken::new(),
    )
    .expect("bounded control");

    let started = Instant::now();
    let report = host.activate_discovered_with_control(&control);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(500),
        "blocked verifier escaped the admission deadline: {elapsed:?}"
    );
    assert!(matches!(
        report.outcomes(),
        [ControlledActivationOutcome::DeadlineExceeded]
    ));
    assert_eq!(
        verifier.calls(),
        vec![first_id],
        "the deadline must stop admission before the later plugin"
    );
    assert!(host.loaded_ids().is_empty());

    let retry_control = ActivationControl::new(
        NonZeroUsize::new(2).expect("two is non-zero"),
        Instant::now() + Duration::from_secs(5),
        CancellationToken::new(),
    )
    .expect("bounded retry");
    let retry_started = Instant::now();
    let retry = host.activate_discovered_with_control(&retry_control);
    assert!(
        retry_started.elapsed() < Duration::from_millis(500),
        "a retained admission worker must reject, not queue, a retry"
    );
    assert_eq!(
        verifier.calls(),
        vec![first_id],
        "the retry must not create another blocked verifier worker"
    );
    assert_eq!(retry.outcomes().len(), 2);
    for outcome in retry.outcomes() {
        let ControlledActivationOutcome::Candidate(outcome) = outcome else {
            panic!("a busy admission worker is a candidate failure");
        };
        let ActivationOutcome::Failed(failure) = outcome.as_ref() else {
            panic!("a retry must not activate while the old worker is retained");
        };
        assert_eq!(failure.stage, ActivationStage::Manifest);
        assert!(
            failure
                .error
                .to_string()
                .contains("previous controlled admission worker is still running")
        );
    }
    verifier.release();
}

#[test]
fn short_deadline_stops_discovered_activation_without_stale_tools() {
    let root = support::tempdir();
    let component = probe_component_registering_tool_then_spinning_on_activate();
    let grants = vec![CapabilityGrant::Tools(ToolsGrant {
        max_tools: 1,
        max_schema_bytes: 1024,
    })];
    install_variant(root.path(), "probe", &component, grants.clone());
    let tools = CancellingTools::new(None);
    let mut host = PluginHost::builder()
        .trust_policy(support::unsigned_core_policy(root.path()))
        .operator_policy(support::probe_ceiling(grants))
        .services(HostServices::deny_all().with_tools(Arc::new(tools.clone())))
        .build()
        .expect("host");
    let control = ActivationControl::new(
        NonZeroUsize::new(1).expect("one is non-zero"),
        Instant::now() + Duration::from_millis(30),
        CancellationToken::new(),
    )
    .expect("bounded control");

    let report = host.activate_discovered_with_control(&control);
    assert!(matches!(
        report.outcomes(),
        [ControlledActivationOutcome::DeadlineExceeded]
    ));
    assert!(tools.tools().is_empty(), "deadline must purge stale tools");
    assert!(host.loaded_ids().is_empty());
}
