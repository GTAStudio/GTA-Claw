//! Regressions for the two defects the audits kept finding.
//!
//! Every test here would pass against a composition that made a security
//! decision once and reused it, or that carried a name across a boundary and
//! re-resolved it — except that each one is written to fail in exactly that
//! case. They are the reason the composition is shaped the way it is.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use claw_application::composition::{
    Action, ActionRequest, AuthorityPort, Capability, CapabilitySet, Clock, CredentialName,
    CredentialRequest, DnsPort, EgressDenial, EgressGuard, EgressPolicy, GrantIssuer, HostPattern,
    Lifecycle, LifecyclePhase, Principal, ProviderReply, ResolvedEndpoint, SecretStorePort,
    SubsystemErrorKind, ToolName, TurnEvent, TurnEventSink, well_known,
};
use claw_domain::SessionId;
use gta_claw_daemon::adapters::model::request_tool;
use gta_claw_daemon::adapters::state::MemorySecrets;
use gta_claw_daemon::adapters::support::{LivePolicy, PolicyStance, SteppedClock, TableDns};
use gta_claw_daemon::compose::Daemon;

/// Discards events; these tests assert on outcomes, not on the stream.
#[derive(Debug)]
struct Ignore;

impl TurnEventSink for Ignore {
    fn emit(&self, _event: TurnEvent) {}
}

fn operator() -> Principal {
    Principal::new("operator", CapabilitySet::all())
}

fn session(name: &str) -> SessionId {
    SessionId::new(name).expect("the literal is a usable session id")
}

fn read_tool() -> ToolName {
    ToolName::new("workspace.read").expect("the literal satisfies the grammar")
}

fn address(literal: &str) -> IpAddr {
    literal.parse().expect("the literal is an address")
}

async fn started(clock: Arc<SteppedClock>) -> Daemon {
    let mut daemon = Daemon::builder()
        .clock(clock as Arc<dyn Clock>)
        .build()
        .expect("the composition is orderable");

    daemon.start().await.expect("every subsystem comes up");
    daemon
}

/// Walks a lifecycle to `Running` the way the host does, which is what opens
/// the epoch gate a grant is minted against.
fn running_lifecycle() -> Lifecycle {
    let mut lifecycle = Lifecycle::new();

    for phase in [
        LifecyclePhase::Initializing,
        LifecyclePhase::Initialized,
        LifecyclePhase::Starting,
        LifecyclePhase::Running,
    ] {
        lifecycle
            .transition_to(phase)
            .expect("the run comes up legally");
    }

    lifecycle
}

// ---------------------------------------------------------------------------
// Rule 1: a decision authorizing a new action is taken at that moment.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn withdrawing_a_permission_mid_turn_stops_the_very_next_action() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;

    // The decisions in a tool-using turn are, in order: open-session,
    // submit-turn, read-credential, call-provider, invoke-tool. Withdrawing
    // after the fourth places the change exactly between the provider call and
    // the tool call, with no race.
    daemon.transport().push_reply(ProviderReply::new(
        "let me look".to_owned(),
        vec![request_tool(&read_tool(), "{}")],
    ));
    daemon
        .policy()
        .change_stance_after(4, PolicyStance::RefuseTools);

    let error = daemon
        .run_turn(&operator(), &session("withdrawn"), "look", &Ignore)
        .await
        .expect_err("the tool decision is taken after the policy changed");

    assert_eq!(error.kind(), SubsystemErrorKind::Denied);
    assert_eq!(error.subsystem().as_str(), "tools");
    assert_eq!(
        error.detail(),
        "policy refused invoke-tool workspace.read: the operator withdrew this permission"
    );
    assert_eq!(
        daemon.tools().invocations().len(),
        0,
        "the tool never ran once the permission was withdrawn"
    );

    // The provider call that was already authorized went through, which is the
    // point: the composition does not retroactively undo it, it refuses the
    // next one.
    assert_eq!(daemon.transport().calls().len(), 1);
    assert_eq!(daemon.policy().decisions(), 5);

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

#[tokio::test]
async fn a_capability_expires_against_the_clock_at_the_moment_it_is_redeemed() {
    let clock = Arc::new(SteppedClock::new());
    let policy = Arc::new(LivePolicy::new(Duration::from_millis(10)));
    let gate = running_lifecycle();
    let issuer = GrantIssuer::new(
        Arc::clone(&policy) as Arc<dyn AuthorityPort>,
        Arc::clone(&clock) as Arc<dyn Clock>,
        gate.epoch_gate(),
        Duration::from_secs(60),
    );

    let request = ActionRequest::new(well_known::engine(), operator(), Action::SubmitTurn)
        .in_session(session("expiring"));

    let fresh = issuer
        .issue(&request, "payload")
        .await
        .expect("the policy permits it");
    assert_eq!(
        fresh.redeem().expect("nine milliseconds have not passed"),
        "payload"
    );

    let stale = issuer
        .issue(&request, "payload")
        .await
        .expect("the policy permits it");
    clock.advance(11);

    let denial = stale
        .redeem()
        .expect_err("the capability outlived its ten milliseconds");

    assert_eq!(
        denial.to_string(),
        "grant 2 expired: redeemed 11ms after it was minted, 1ms past its lifetime"
    );
}

#[tokio::test]
async fn a_capability_dies_when_the_run_it_was_issued_in_drains() {
    let clock = Arc::new(SteppedClock::new());
    let policy = Arc::new(LivePolicy::new(Duration::from_secs(60)));
    let mut lifecycle = running_lifecycle();
    let issuer = GrantIssuer::new(
        Arc::clone(&policy) as Arc<dyn AuthorityPort>,
        Arc::clone(&clock) as Arc<dyn Clock>,
        lifecycle.epoch_gate(),
        Duration::from_secs(60),
    );

    let request = ActionRequest::new(well_known::engine(), operator(), Action::SubmitTurn)
        .in_session(session("draining"));
    let grant = issuer
        .issue(&request, "payload")
        .await
        .expect("the policy permits it");

    lifecycle
        .transition_to(LifecyclePhase::Draining)
        .expect("running may drain");

    let denial = grant
        .redeem()
        .expect_err("the run that authorized this is over");

    assert_eq!(
        denial.to_string(),
        "the daemon left the run epoch the grant was minted in"
    );
    assert_eq!(policy.decisions(), 1);
}

#[tokio::test]
async fn a_turn_started_before_shutdown_cannot_take_a_new_decision_after_it() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;

    daemon
        .run_turn(&operator(), &session("before"), "hi", &Ignore)
        .await
        .expect("the turn completes while running");

    daemon.stop().await.expect("the daemon stops");

    let error = daemon
        .run_turn(&operator(), &session("after"), "hi", &Ignore)
        .await
        .expect_err("nothing may be authorized once the run has ended");

    assert_eq!(error.kind(), SubsystemErrorKind::Denied);
    assert_eq!(
        error.detail(),
        "the daemon is not running, so nothing can be authorized"
    );
}

#[tokio::test]
async fn refusing_everything_stops_a_turn_at_the_first_decision() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;

    daemon.policy().set_stance(PolicyStance::RefuseEverything);

    let error = daemon
        .run_turn(&operator(), &session("refused"), "hi", &Ignore)
        .await
        .expect_err("the first decision is refused");

    assert_eq!(error.kind(), SubsystemErrorKind::Denied);
    assert_eq!(
        error.detail(),
        "policy refused open-session: the operator withdrew this permission"
    );
    assert_eq!(daemon.transport().calls().len(), 0);
    assert_eq!(daemon.persistence().commits(), 0);

    daemon.policy().set_stance(PolicyStance::Permit);

    daemon
        .run_turn(&operator(), &session("refused"), "hi", &Ignore)
        .await
        .expect("restoring the permission takes effect on the next decision");

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

// ---------------------------------------------------------------------------
// Rule 2: validated objects cross boundaries, never re-resolvable names.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_destination_that_moves_between_resolutions_does_not_move_an_endpoint_already_checked() {
    let clock = Arc::new(SteppedClock::new()) as Arc<dyn Clock>;
    let dns = Arc::new(TableDns::new([(
        "api.example.test".to_owned(),
        vec![address("203.0.113.7")],
    )]));
    let guard = EgressGuard::new(
        EgressPolicy::deny_all().allow_host(HostPattern::parse("api.example.test")),
        Arc::clone(&dns) as Arc<dyn DnsPort>,
        clock,
    );

    let first = guard
        .resolve_url("https://api.example.test/v1")
        .await
        .expect("the host is allowed and public");
    assert_eq!(first.addresses(), [address("203.0.113.7")]);

    // Classic rebinding: the name now points at the loopback interface.
    dns.set("api.example.test", vec![address("127.0.0.1")]);

    let denial = guard
        .resolve_url("https://api.example.test/v1")
        .await
        .expect_err("the new answer is a private address");
    assert_eq!(
        denial,
        EgressDenial::BlockedAddress {
            host: "api.example.test".to_owned(),
            address: address("127.0.0.1"),
            classification: "loopback",
        }
    );

    // The endpoint checked before the move still carries the address that was
    // checked. A transport holding it connects there and nowhere else.
    assert_eq!(first.addresses(), [address("203.0.113.7")]);
    assert_eq!(first.authority(), "api.example.test:443");
}

#[tokio::test]
async fn a_host_is_refused_when_any_of_its_addresses_is_blocked() {
    let clock = Arc::new(SteppedClock::new()) as Arc<dyn Clock>;
    let dns = Arc::new(TableDns::new([(
        "split.example.test".to_owned(),
        vec![address("203.0.113.9"), address("10.0.0.5")],
    )]));
    let guard = EgressGuard::new(
        EgressPolicy::deny_all().allow_host(HostPattern::parse("split.example.test")),
        dns as Arc<dyn DnsPort>,
        clock,
    );

    let denial = guard
        .resolve_url("https://split.example.test/")
        .await
        .expect_err("one bad address poisons the whole answer");

    assert_eq!(
        denial,
        EgressDenial::BlockedAddress {
            host: "split.example.test".to_owned(),
            address: address("10.0.0.5"),
            classification: "private",
        }
    );
}

#[tokio::test]
async fn a_credential_filed_for_one_origin_is_refused_for_another() {
    let clock = Arc::new(SteppedClock::new()) as Arc<dyn Clock>;
    let dns = Arc::new(TableDns::new([
        ("one.example.test".to_owned(), vec![address("203.0.113.1")]),
        ("two.example.test".to_owned(), vec![address("203.0.113.2")]),
    ]));
    let guard = EgressGuard::new(
        EgressPolicy::deny_all().allow_host(HostPattern::parse("*.example.test")),
        dns as Arc<dyn DnsPort>,
        Arc::clone(&clock),
    );

    let one: ResolvedEndpoint = guard
        .resolve_url("https://one.example.test/")
        .await
        .expect("the first host is allowed");
    let two: ResolvedEndpoint = guard
        .resolve_url("https://two.example.test/")
        .await
        .expect("the second host is allowed");

    let name = CredentialName::new("shared").expect("the literal satisfies the grammar");
    let secrets = MemorySecrets::new();
    secrets.preload(&name, one.clone(), "super-secret");

    let policy = Arc::new(LivePolicy::new(Duration::from_secs(60)));
    let lifecycle = running_lifecycle();
    let issuer = GrantIssuer::new(
        Arc::clone(&policy) as Arc<dyn AuthorityPort>,
        Arc::clone(&clock),
        lifecycle.epoch_gate(),
        Duration::from_secs(60),
    );

    let request = ActionRequest::new(
        well_known::secrets(),
        operator(),
        Action::ReadCredential {
            credential: name.clone(),
        },
    );

    let allowed = issuer
        .issue(&request, CredentialRequest::new(name.clone(), one.clone()))
        .await
        .expect("the policy permits it");
    let lease = secrets
        .lease(allowed)
        .await
        .expect("the credential matches its origin");
    assert!(lease.is_bound_to(&one));
    assert!(!lease.is_bound_to(&two));
    assert_eq!(lease.expose(), "super-secret");

    let misdirected = issuer
        .issue(&request, CredentialRequest::new(name, two))
        .await
        .expect("the policy permits it");
    let error = secrets
        .lease(misdirected)
        .await
        .expect_err("the credential belongs to the other origin");

    assert_eq!(error.kind(), SubsystemErrorKind::Invalid);
    assert_eq!(
        error.detail(),
        "shared is filed against one.example.test:443 and cannot be presented to two.example.test:443"
    );
    assert_eq!(secrets.releases(), 1);
}

#[tokio::test]
async fn a_tool_name_the_model_invented_never_reaches_the_tool_surface() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;
    let invented = ToolName::new("workspace.delete").expect("the literal satisfies the grammar");

    daemon.transport().push_reply(ProviderReply::new(
        "deleting".to_owned(),
        vec![request_tool(&invented, "{}")],
    ));

    let error = daemon
        .run_turn(&operator(), &session("invented"), "delete", &Ignore)
        .await
        .expect_err("the name is resolved against the turn's catalogue");

    assert_eq!(error.kind(), SubsystemErrorKind::NotFound);
    assert_eq!(
        error.detail(),
        "workspace.delete is not available to this turn"
    );
    assert_eq!(daemon.tools().invocations().len(), 0);

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

#[tokio::test]
async fn the_transport_is_given_addresses_rather_than_a_name_to_resolve() {
    let clock = Arc::new(SteppedClock::new());
    let mut daemon = started(Arc::clone(&clock)).await;

    daemon
        .run_turn(&operator(), &session("addresses"), "hi", &Ignore)
        .await
        .expect("the turn completes");

    // Moving the provider's name to a private address after the fact must not
    // change where the call that already happened went.
    daemon
        .dns()
        .set("models.example.test", vec![address("127.0.0.1")]);

    let calls = daemon.transport().calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].addresses, vec![address("203.0.113.10")]);

    let error = daemon
        .run_turn(&operator(), &session("addresses"), "again", &Ignore)
        .await
        .expect_err("the next turn re-resolves and is refused");

    assert_eq!(error.kind(), SubsystemErrorKind::Invalid);
    assert_eq!(
        error.detail(),
        "models.example.test resolved to 127.0.0.1, which is a loopback address"
    );
    assert_eq!(daemon.transport().calls().len(), 1);

    assert!(daemon.stop().await.expect("the daemon stops").is_clean());
}

#[tokio::test]
async fn a_plugin_instance_holds_only_the_capabilities_decided_for_it() {
    use claw_application::composition::{PluginActivation, PluginHostPort};

    let clock = Arc::new(SteppedClock::new()) as Arc<dyn Clock>;
    let policy = Arc::new(LivePolicy::new(Duration::from_secs(60)));
    let lifecycle = running_lifecycle();
    let issuer = GrantIssuer::new(
        Arc::clone(&policy) as Arc<dyn AuthorityPort>,
        clock,
        lifecycle.epoch_gate(),
        Duration::from_secs(60),
    );

    let host = gta_claw_daemon::adapters::plugins::PerActivationPluginHost::new();

    let narrow = CapabilitySet::from_capabilities([Capability::ReadWorkspace]);
    let wide = CapabilitySet::from_capabilities([
        Capability::ReadWorkspace,
        Capability::WriteWorkspace,
        Capability::Network,
    ]);

    let request = ActionRequest::new(well_known::plugin_host(), operator(), Action::SubmitTurn);

    let first = host
        .activate(
            issuer
                .issue(
                    &request,
                    PluginActivation::new("formatter".to_owned(), narrow.clone()),
                )
                .await
                .expect("the policy permits it"),
        )
        .await
        .expect("the component instantiates");
    let second = host
        .activate(
            issuer
                .issue(
                    &request,
                    PluginActivation::new("indexer".to_owned(), wide.clone()),
                )
                .await
                .expect("the policy permits it"),
        )
        .await
        .expect("the component instantiates");

    assert_eq!(host.capabilities_of(&first), Some(narrow));
    assert_eq!(host.capabilities_of(&second), Some(wide));
    assert_eq!(host.live_instances(), 2);

    host.teardown(first.clone())
        .await
        .expect("the instance is live");

    assert_eq!(host.capabilities_of(&first), None);
    assert_eq!(host.live_instances(), 1);

    let error = host
        .teardown(first)
        .await
        .expect_err("an instance cannot be torn down twice");
    assert_eq!(error.kind(), SubsystemErrorKind::NotFound);
    assert_eq!(host.activations(), 2);
}
