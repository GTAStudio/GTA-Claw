//! Acceptance coverage for `interop.clients.native`.
//!
//! Upstream sources at
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`: `apps`, `ui`,
//! `src/tui` and `src/cli`.
//!
//! The suite drives every one of the ten inventoried surfaces through the
//! pinned protocol-v4 negotiation reducer (or its fail-closed local attachment
//! contract) plus its platform smoke steps. It does **not** build or execute
//! the shipped client applications, which is why the row this file supports is
//! `partial` rather than `implemented`; the gap is enumerated surface by
//! surface in [`claw_clients::conformance::COVERAGE`] and asserted below.

use claw_clients::conformance::{
    AttachmentError, AttachmentEvidence, AttachmentOutcome, COVERAGE, ClientIntegration,
    LocalProcessAttachment, RelayAttachment, SmokeStep, coverage, negotiate_profile, run_all,
    run_smoke,
};
use claw_clients::{
    ClientCapability, ConnectionContract, GatewayProfile, SessionEventKind, SurfaceId, surface,
};
use claw_protocol::gateway::{
    ClientId, ClientMode, CompatibilityMode, ConnectErrorDetailCode, DeviceProofDecision,
    NegotiationState, OperatorScope, Role,
};

fn gateway_profiles(surface_id: SurfaceId) -> &'static [GatewayProfile] {
    let ConnectionContract::GatewayV4(profiles) = surface(surface_id).connection else {
        panic!("{surface_id:?} does not use the Gateway transport");
    };
    profiles
}

#[test]
fn every_inventoried_surface_completes_its_connection_and_platform_smoke_suite() {
    let reports = run_all().expect("every frozen surface completes its smoke suite");
    assert_eq!(reports.len(), 10);
    assert_eq!(
        reports
            .iter()
            .map(|report| report.surface)
            .collect::<Vec<_>>(),
        SurfaceId::ALL.to_vec()
    );

    for report in &reports {
        let contract = surface(report.surface);
        let expected = coverage(report.surface);
        assert_eq!(
            report.steps, expected.host_steps,
            "{:?} ran different steps than it claims",
            report.surface
        );

        match contract.connection {
            ConnectionContract::GatewayV4(profiles) => {
                assert_eq!(report.connections.len(), profiles.len());
                assert_eq!(report.attachment, None);
                for (outcome, profile) in report.connections.iter().zip(profiles) {
                    assert_eq!(outcome.profile, *profile);
                    assert_eq!(outcome.protocol, 4, "{:?}", report.surface);
                    assert_eq!(outcome.compatibility, CompatibilityMode::Current);
                    assert_eq!(outcome.state, NegotiationState::Ready);
                    assert_eq!(outcome.role, profile.role);
                    assert_eq!(outcome.scopes, profile.scopes.to_vec());
                }
            }
            ConnectionContract::AuthenticatedLocalProcess => {
                assert!(report.connections.is_empty());
                assert_eq!(report.attachment, Some(AttachmentOutcome::LocalProcess));
            }
            ConnectionContract::ChromeExtensionRelay => {
                assert!(report.connections.is_empty());
                assert_eq!(report.attachment, Some(AttachmentOutcome::ChromeRelay));
            }
        }

        assert_eq!(report.granted, contract.capabilities.to_vec());
        assert_eq!(report.delivered.len(), contract.events.len());
        for (index, event) in report.delivered.iter().enumerate() {
            let expected_sequence = u64::try_from(index).expect("small index") + 1;
            assert_eq!(event.sequence, expected_sequence);
            assert_eq!(event.kind, contract.events[index]);
        }
    }
}

#[test]
fn coverage_enumerates_the_frozen_inventory_and_names_every_unfinished_client() {
    assert_eq!(COVERAGE.len(), SurfaceId::ALL.len());
    for (record, surface_id) in COVERAGE.iter().zip(SurfaceId::ALL) {
        assert_eq!(record.surface, surface_id);
        assert_eq!(coverage(surface_id), record);
    }

    // Pinned so the honest `partial` status cannot drift into an unstated
    // `implemented` claim: no surface is exercised through its shipped client.
    let expected: [(SurfaceId, ClientIntegration); 10] = [
        (
            SurfaceId::Cli,
            ClientIntegration::PendingInRepositoryClient("apps/gta-claw-cli"),
        ),
        (
            SurfaceId::Tui,
            ClientIntegration::PendingInRepositoryClient("apps/gta-claw-tui"),
        ),
        (
            SurfaceId::ControlUi,
            ClientIntegration::UpstreamClientNotShipped,
        ),
        (
            SurfaceId::Android,
            ClientIntegration::PendingInRepositoryClient("apps/gta-claw-android"),
        ),
        (
            SurfaceId::Ios,
            ClientIntegration::PendingInRepositoryClient("apps/gta-claw-ios"),
        ),
        (
            SurfaceId::MacOs,
            ClientIntegration::PendingInRepositoryClient("desktop/apps/gta-claw-desktop"),
        ),
        (
            SurfaceId::MacOsMlxTts,
            ClientIntegration::UpstreamClientNotShipped,
        ),
        (
            SurfaceId::Swabble,
            ClientIntegration::UpstreamClientNotShipped,
        ),
        (
            SurfaceId::ChromeExtension,
            ClientIntegration::UpstreamClientNotShipped,
        ),
        (
            SurfaceId::NodeHost,
            ClientIntegration::PendingInRepositoryClient("apps/gta-claw-daemon"),
        ),
    ];
    for (surface_id, client) in expected {
        assert_eq!(coverage(surface_id).client, client, "{surface_id:?}");
    }

    // Every surface either negotiates protocol v4 or attaches locally, never
    // neither and never both.
    for record in &COVERAGE {
        let negotiates = record
            .host_steps
            .contains(&SmokeStep::ProtocolV4Negotiation);
        let attaches = record.host_steps.contains(&SmokeStep::LocalAttachment);
        assert!(negotiates ^ attaches, "{:?}", record.surface);
        assert!(
            record
                .host_steps
                .contains(&SmokeStep::CapabilityNegotiation)
        );
        assert!(record.host_steps.contains(&SmokeStep::SessionProjection));
        assert!(record.host_steps.contains(&SmokeStep::EventDelivery));
    }
}

#[test]
fn negotiation_is_fail_closed_on_protocol_range_and_device_proof() {
    let cli = gateway_profiles(SurfaceId::Cli)[0];

    let downgraded = negotiate_profile(SurfaceId::Cli, &cli, 3, 3, DeviceProofDecision::Verified)
        .expect_err("a v3-only client must be refused");
    assert_eq!(downgraded.step, SmokeStep::ProtocolV4Negotiation);
    assert_eq!(
        downgraded.rejection,
        Some(ConnectErrorDetailCode::ProtocolMismatch)
    );
    assert!(
        downgraded.detail.contains("unsupported protocol range"),
        "{}",
        downgraded.detail
    );

    let unverified =
        negotiate_profile(SurfaceId::Cli, &cli, 4, 4, DeviceProofDecision::NotRequired)
            .expect_err("an unverified device proof must be refused");
    assert_eq!(
        unverified.rejection,
        Some(ConnectErrorDetailCode::DeviceAuthInvalid)
    );
    assert!(
        unverified.detail.contains("device proof"),
        "{}",
        unverified.detail
    );

    assert!(
        negotiate_profile(SurfaceId::Cli, &cli, 4, 4, DeviceProofDecision::Verified).is_ok(),
        "the frozen CLI profile must still connect"
    );
}

#[test]
fn negotiation_refuses_profiles_the_frozen_contract_does_not_admit() {
    let forged = GatewayProfile {
        client_id: ClientId::Cli,
        mode: ClientMode::Cli,
        role: Role::Operator,
        scopes: &[OperatorScope::Read],
        requires_device_identity: true,
    };
    let cross_surface = negotiate_profile(
        SurfaceId::Android,
        &forged,
        4,
        4,
        DeviceProofDecision::Verified,
    )
    .expect_err("a CLI identity must not connect as the Android surface");
    assert_eq!(cross_surface.surface, SurfaceId::Android);
    assert_eq!(cross_surface.rejection, None);
    assert_eq!(
        cross_surface.detail,
        "client connection profile is not allowed"
    );

    let overgrant = GatewayProfile {
        scopes: &[OperatorScope::Admin, OperatorScope::TalkSecrets],
        ..gateway_profiles(SurfaceId::Tui)[0]
    };
    let denied = negotiate_profile(
        SurfaceId::Tui,
        &overgrant,
        4,
        4,
        DeviceProofDecision::Verified,
    )
    .expect_err("a scope outside the frozen ceiling must be refused");
    assert_eq!(
        denied.detail, "client connection profile is not allowed",
        "the ceiling check must run before any frame is decoded"
    );

    let wrong_transport = negotiate_profile(
        SurfaceId::ChromeExtension,
        &forged,
        4,
        4,
        DeviceProofDecision::Verified,
    )
    .expect_err("the relay surface has no Gateway profile");
    assert_eq!(
        wrong_transport.detail,
        "client surface does not use the Gateway transport"
    );
}

#[test]
fn node_profiles_negotiate_protocol_v4_with_no_operator_scopes() {
    for surface_id in [
        SurfaceId::Android,
        SurfaceId::Ios,
        SurfaceId::MacOs,
        SurfaceId::NodeHost,
    ] {
        let node = gateway_profiles(surface_id)
            .iter()
            .find(|profile| profile.role == Role::Node)
            .copied()
            .unwrap_or_else(|| panic!("{surface_id:?} must declare a node profile"));
        let outcome = negotiate_profile(surface_id, &node, 4, 4, DeviceProofDecision::Verified)
            .unwrap_or_else(|error| panic!("{surface_id:?} node profile: {error}"));
        assert_eq!(outcome.role, Role::Node);
        assert!(outcome.scopes.is_empty());
        assert_eq!(outcome.protocol, 4);
        assert_eq!(outcome.state, NegotiationState::Ready);
    }
}

#[test]
fn local_attachment_is_fail_closed_on_identity_secret_loopback_and_transport() {
    assert_eq!(
        attach_local(SurfaceId::MacOsMlxTts, false, true),
        Err(AttachmentError::ExecutableIdentityUnverified)
    );
    assert_eq!(
        attach_local(SurfaceId::Swabble, true, false),
        Err(AttachmentError::AttachmentSecretUnverified)
    );
    assert_eq!(
        attach_local(SurfaceId::Swabble, true, true),
        Ok(AttachmentOutcome::LocalProcess)
    );

    assert_eq!(
        claw_clients::conformance::attach(
            SurfaceId::ChromeExtension,
            AttachmentEvidence::Relay(RelayAttachment {
                loopback_only: false,
                ..RelayAttachment::VERIFIED
            }),
        ),
        Err(AttachmentError::LoopbackRequired)
    );
    assert_eq!(
        claw_clients::conformance::attach(
            SurfaceId::ChromeExtension,
            AttachmentEvidence::Relay(RelayAttachment {
                extension_identity_verified: false,
                ..RelayAttachment::VERIFIED
            }),
        ),
        Err(AttachmentError::ExtensionIdentityUnverified)
    );

    // A sidecar may not present relay evidence, and a Gateway surface may not
    // attach locally at all.
    assert_eq!(
        claw_clients::conformance::attach(
            SurfaceId::Swabble,
            AttachmentEvidence::Relay(RelayAttachment::VERIFIED),
        ),
        Err(AttachmentError::TransportMismatch)
    );
    assert_eq!(
        claw_clients::conformance::attach(
            SurfaceId::ChromeExtension,
            AttachmentEvidence::LocalProcess(LocalProcessAttachment::VERIFIED),
        ),
        Err(AttachmentError::TransportMismatch)
    );
    assert_eq!(
        claw_clients::conformance::attach(
            SurfaceId::Cli,
            AttachmentEvidence::LocalProcess(LocalProcessAttachment::VERIFIED),
        ),
        Err(AttachmentError::GatewaySurface)
    );
}

fn attach_local(
    surface_id: SurfaceId,
    identity: bool,
    secret: bool,
) -> Result<AttachmentOutcome, AttachmentError> {
    claw_clients::conformance::attach(
        surface_id,
        AttachmentEvidence::LocalProcess(LocalProcessAttachment {
            executable_identity_verified: identity,
            attachment_secret_verified: secret,
        }),
    )
}

#[test]
fn platform_smoke_denies_capabilities_and_events_outside_each_surface() {
    for surface_id in SurfaceId::ALL {
        let report = run_smoke(surface_id).unwrap_or_else(|error| panic!("{error}"));
        let contract = surface(surface_id);
        if let Some(denied) = report.denied_capability {
            assert!(
                !contract.capabilities.contains(&denied),
                "{surface_id:?} reported a granted capability as denied"
            );
        }
        if let Some(rejected) = report.rejected_event {
            assert!(
                !contract.events.contains(&rejected),
                "{surface_id:?} reported a permitted event as rejected"
            );
        }
    }

    let control_ui = run_smoke(SurfaceId::ControlUi).expect("control ui smoke suite");
    assert_eq!(
        control_ui.denied_capability,
        Some(ClientCapability::NodeCommands)
    );
    assert_eq!(control_ui.rejected_event, None);
    assert_eq!(
        control_ui.projection.messages,
        Some(vec!["first".to_owned(), "second".to_owned()])
    );
    assert!(control_ui.projection.writable);

    let extension = run_smoke(SurfaceId::ChromeExtension).expect("chrome extension smoke suite");
    assert_eq!(extension.granted, vec![ClientCapability::ChromeDevtools]);
    assert!(extension.delivered.is_empty());
    assert_eq!(
        extension.rejected_event,
        Some(SessionEventKind::SessionChanged)
    );
    assert_eq!(extension.projection.messages, None);
    assert_eq!(extension.projection.active, None);
    assert_eq!(extension.projection.pending_approvals, None);
    assert!(!extension.projection.writable);

    let sidecar = run_smoke(SurfaceId::MacOsMlxTts).expect("tts sidecar smoke suite");
    assert_eq!(sidecar.granted, vec![ClientCapability::SpeechSynthesis]);
    assert_eq!(sidecar.delivered.len(), 1);
    assert_eq!(sidecar.delivered[0].kind, SessionEventKind::Talk);
    assert_eq!(
        sidecar.denied_capability,
        Some(ClientCapability::SessionRead)
    );
}
