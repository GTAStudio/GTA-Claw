//! Runaway guests must be stopped without taking the host with them.
//!
//! Each test drives the real probe component into a specific kind of runaway
//! behaviour — an infinite loop, an unbounded `memory.grow` loop and unbounded
//! recursion — and checks both that the host regains control with the right
//! [`TerminationCause`] and that the host is still usable afterwards.

mod support;

use claw_plugin_api::capability::{CapabilityGrant, ClockGrant};
use claw_plugin_api::limits::ResourceLimits;
use claw_plugin_host::{HostError, LifecycleState, PluginHost, TerminationCause};
use support::{PROBE_ID, install_probe_named, install_probe_with, unsigned_core_policy};

fn host_for(root: &std::path::Path) -> PluginHost {
    PluginHost::builder()
        .trust_policy(unsigned_core_policy(root))
        .build()
        .expect("host")
}

/// A host whose operator ceiling matches the manifests in `directories`.
fn host_for_all(root: &std::path::Path, directories: &[&std::path::Path]) -> PluginHost {
    PluginHost::builder()
        .trust_policy(unsigned_core_policy(root))
        .operator_policy(support::ceiling_from_all(directories))
        .build()
        .expect("host")
}

#[test]
fn an_infinite_loop_runs_out_of_fuel() {
    let root = support::tempdir();
    let limits = ResourceLimits {
        fuel: 2_000_000,
        // Long enough that the epoch deadline cannot be what stops the guest.
        wall_clock_timeout_ms: 60_000,
        ..ResourceLimits::default()
    };
    let dir = install_probe_with(root.path(), "probe", Vec::new(), limits);
    let mut host = host_for(root.path());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    let error = host
        .invoke_tool(&id, "s", "{}")
        .expect_err("an infinite loop must not return");
    assert_eq!(error.termination(), Some(TerminationCause::FuelExhausted));

    assert_eq!(
        host.state(&id),
        Some(LifecycleState::Faulted(TerminationCause::FuelExhausted)),
        "a terminated guest is quarantined"
    );
}

#[test]
fn an_infinite_loop_runs_out_of_wall_clock_time() {
    let root = support::tempdir();
    let limits = ResourceLimits {
        // Far more fuel than 150ms of spinning can burn, so only the epoch
        // deadline can stop this guest.
        fuel: u64::MAX,
        wall_clock_timeout_ms: 150,
        ..ResourceLimits::default()
    };
    let dir = install_probe_with(root.path(), "probe", Vec::new(), limits);
    let mut host = host_for(root.path());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    let started = std::time::Instant::now();
    let error = host
        .invoke_tool(&id, "s", "{}")
        .expect_err("an infinite loop must not return");
    let elapsed = started.elapsed();

    assert_eq!(error.termination(), Some(TerminationCause::Timeout));
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "the guest must be interrupted promptly, took {elapsed:?}"
    );
    assert_eq!(
        host.state(&id),
        Some(LifecycleState::Faulted(TerminationCause::Timeout))
    );
}

#[test]
fn a_memory_bomb_is_refused_by_the_limiter() {
    let root = support::tempdir();
    let limits = ResourceLimits {
        // Two megabytes: the probe grows in 16 page (1 MiB) steps, so it hits
        // the ceiling after a couple of iterations.
        max_memory_bytes: 2 * 1024 * 1024,
        max_payload_bytes: 64 * 1024,
        fuel: 1_000_000_000,
        wall_clock_timeout_ms: 30_000,
        ..ResourceLimits::default()
    };
    let dir = install_probe_with(root.path(), "probe", Vec::new(), limits);
    let mut host = host_for(root.path());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    let error = host
        .invoke_tool(&id, "m", "{}")
        .expect_err("the memory bomb must not return a value");
    assert_eq!(
        error.termination(),
        Some(TerminationCause::ResourceLimit),
        "growth past the cap must be reported as a resource limit"
    );

    let usage = host.resource_usage(&id).expect("usage");
    assert!(
        usage.hit_memory_ceiling,
        "the limiter must have refused at least one growth request"
    );
    assert!(
        usage.peak_memory_bytes <= 2 * 1024 * 1024,
        "the guest never got more than its cap, peaked at {}",
        usage.peak_memory_bytes
    );
    assert_eq!(
        host.state(&id),
        Some(LifecycleState::Faulted(TerminationCause::ResourceLimit))
    );
}

#[test]
fn unbounded_recursion_hits_the_stack_guard() {
    let root = support::tempdir();
    let limits = ResourceLimits {
        fuel: u64::MAX,
        wall_clock_timeout_ms: 30_000,
        ..ResourceLimits::default()
    };
    let dir = install_probe_with(root.path(), "probe", Vec::new(), limits);
    let mut host = host_for(root.path());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    let error = host
        .invoke_tool(&id, "r", "{}")
        .expect_err("unbounded recursion must not return");
    assert_eq!(
        error.termination(),
        Some(TerminationCause::StackOverflow),
        "the guest stack guard, not the host stack, must catch this"
    );
    assert_eq!(
        host.state(&id),
        Some(LifecycleState::Faulted(TerminationCause::StackOverflow))
    );
}

#[test]
fn a_faulted_plugin_refuses_further_calls_until_it_is_reloaded() {
    let root = support::tempdir();
    let dir = install_probe_with(root.path(), "probe", Vec::new(), ResourceLimits::default());
    let mut host = host_for(root.path());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    assert_eq!(
        host.invoke_tool(&id, "x", "{}").expect("healthy call"),
        "ok"
    );

    let error = host
        .invoke_tool(&id, "t", "{}")
        .expect_err("the trap probe must trap");
    assert_eq!(error.termination(), Some(TerminationCause::Trap));

    let error = host
        .invoke_tool(&id, "x", "{}")
        .expect_err("a faulted plugin must not run again");
    match error {
        HostError::Faulted { id: faulted, cause } => {
            assert_eq!(faulted, PROBE_ID);
            assert_eq!(cause, TerminationCause::Trap);
        }
        other => panic!("expected a faulted plugin, got {other}"),
    }

    let reloaded = host.reload(&id).expect("reload");
    assert_eq!(reloaded, PROBE_ID);
    assert_eq!(host.state(&id), Some(LifecycleState::Loaded));
    host.activate(&id).expect("reactivate");
    assert_eq!(
        host.invoke_tool(&id, "x", "{}").expect("healthy again"),
        "ok",
        "a reload must give the plugin a clean instance"
    );
}

#[test]
fn a_bystander_keeps_working_while_its_neighbour_keeps_running_away() {
    let root = support::tempdir();
    let limits = ResourceLimits {
        fuel: 2_000_000,
        wall_clock_timeout_ms: 30_000,
        max_memory_bytes: 2 * 1024 * 1024,
        max_payload_bytes: 64 * 1024,
        ..ResourceLimits::default()
    };
    let victim = install_probe_with(root.path(), "victim", Vec::new(), limits);
    let bystander = install_probe_named(
        root.path(),
        "bystander",
        "gta-claw-fixture-other",
        vec![CapabilityGrant::Clock(ClockGrant { resolution_ms: 1 })],
    );

    let mut host = host_for_all(root.path(), &[&victim, &bystander]);
    let victim_id = host.load(&victim).expect("load victim");
    let bystander_id = host.load(&bystander).expect("load bystander");
    host.activate(&victim_id).expect("activate victim");
    host.activate(&bystander_id).expect("activate bystander");

    let runaways = [
        ("s", TerminationCause::FuelExhausted),
        ("m", TerminationCause::ResourceLimit),
        ("r", TerminationCause::StackOverflow),
        ("t", TerminationCause::Trap),
    ];
    for (probe, expected) in runaways {
        let error = host
            .invoke_tool(&victim_id, probe, "{}")
            .expect_err("a runaway must never return a value");
        assert_eq!(
            error.termination(),
            Some(expected),
            "probe {probe} ended the wrong way"
        );
        assert_eq!(
            host.state(&victim_id),
            Some(LifecycleState::Faulted(expected))
        );

        // The neighbour is untouched: same instance, still active, still able
        // to use the capability it was granted.
        assert_eq!(host.state(&bystander_id), Some(LifecycleState::Active));
        assert_eq!(
            host.invoke_tool(&bystander_id, "x", "{}")
                .expect("the bystander must still run"),
            "ok"
        );
        assert_eq!(
            host.invoke_tool(&bystander_id, "a", "{}")
                .expect("the bystander must still reach its clock"),
            "o0"
        );

        // Give the victim a fresh instance for the next runaway.
        host.reload(&victim_id).expect("reload victim");
        host.activate(&victim_id).expect("reactivate victim");
    }

    assert!(
        host.denials(&bystander_id).is_empty(),
        "the bystander was never refused anything"
    );
}
