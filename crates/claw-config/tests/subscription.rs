//! Tear-free publication, subscription, and file detection tests.

mod common;

use std::sync::Arc;
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use claw_config::{ConfigDomain, ConfigFileWatcher, ConfigHub, ConfigHubError, parse_json5};

const VALID: &str = r#"
{
  schema_version: 1,
  core: {
    auth: { github: { pat: "env:GITHUB_TOKEN", device: { enabled: false } } },
    role: { source_url: "https://roles.example.test/default.json" },
    channels: { teams: { enabled: false } },
    server: { port: 3978, public_domain: "localhost" },
    logging: {},
    sessions: {},
    copilot: {},
    legacy: {},
    updates: {},
    admin: {},
    network: {},
  },
}
"#;

#[test]
fn subscribers_receive_complete_typed_changes() {
    let initial = parse_json5(VALID, "initial.json5").expect("initial");
    let hub = ConfigHub::new(initial.clone());
    let subscription = hub.subscribe().expect("subscribe");
    let changed = VALID
        .replace("port: 3978", "port: 8080")
        .replace("logging: {}", "logging: { level: \"debug\" }");

    let published = hub.reload_json5(&changed, "changed.json5").expect("reload");
    let delivered = subscription.recv().expect("delivered change");

    assert_eq!(
        published.changed_domains,
        vec![ConfigDomain::Server, ConfigDomain::Logging]
    );
    assert_eq!(
        published.restart_required_domains,
        vec![ConfigDomain::Server]
    );
    assert_eq!(delivered, published);
    assert_eq!(*published.previous, initial);
    assert_eq!(published.current.core().server().port(), 8080);
}

#[test]
fn concurrent_readers_never_observe_torn_nested_state() {
    let initial = parse_json5(VALID, "initial.json5").expect("initial");
    let hub = ConfigHub::new(initial);
    let running = Arc::new(AtomicBool::new(true));
    let mut readers = Vec::new();
    for _ in 0..8 {
        let reader_hub = hub.clone();
        let reader_running = Arc::clone(&running);
        readers.push(thread::spawn(move || {
            while reader_running.load(Ordering::Acquire) {
                let snapshot = reader_hub.snapshot().expect("reader snapshot");
                let pair = (
                    snapshot.core().server().port(),
                    snapshot.core().server().public_domain(),
                );
                assert!(
                    pair == (3_978, "localhost") || pair == (8_080, "new.example.test"),
                    "torn pair: {pair:?}"
                );
            }
        }));
    }

    let changed = VALID.replace("port: 3978", "port: 8080").replace(
        "public_domain: \"localhost\"",
        "public_domain: \"new.example.test\"",
    );
    for iteration in 0..100 {
        let source = if iteration % 2 == 0 { &changed } else { VALID };
        hub.reload_json5(source, "race.json5").expect("publish");
    }
    running.store(false, Ordering::Release);
    for reader in readers {
        reader.join().expect("reader completed");
    }
}

#[test]
fn concurrent_publishers_deliver_notifications_in_committed_order() {
    let initial = parse_json5(VALID, "initial.json5").expect("initial");
    let hub = ConfigHub::new(initial.clone());
    let subscription = hub.subscribe().expect("subscribe");
    let barrier = Arc::new(Barrier::new(3));
    let sources = [
        VALID.replace("port: 3978", "port: 8001"),
        VALID.replace("port: 3978", "port: 8002"),
    ];
    let publishers = sources
        .into_iter()
        .map(|source| {
            let publisher = hub.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                publisher
                    .reload_json5(&source, "concurrent.json5")
                    .expect("publish")
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    for publisher in publishers {
        publisher.join().expect("publisher completed");
    }

    let first = subscription.recv().expect("first notification");
    let second = subscription.recv().expect("second notification");
    assert_eq!(*first.previous, initial);
    assert_eq!(second.previous, first.current);
    assert_eq!(hub.snapshot().expect("final snapshot"), second.current);
}

#[test]
fn file_watcher_detects_real_byte_changes_and_keeps_last_good_on_corruption() {
    let directory = common::TestDirectory::create();
    let path = directory.path().join("config.json5");
    std::fs::write(&path, VALID).expect("write initial");
    let mut watcher = ConfigFileWatcher::from_file(&path).expect("watch");
    let hub = watcher.hub();
    let subscription = hub.subscribe().expect("subscribe");

    assert_eq!(watcher.poll().expect("unchanged poll"), None);
    let changed = VALID.replace("port: 3978", "port: 8080");
    std::fs::write(&path, changed).expect("write changed");
    let change = watcher
        .poll()
        .expect("changed poll")
        .expect("detected change");
    assert_eq!(change.current.core().server().port(), 8080);
    assert_eq!(
        subscription.recv().expect("notification").changed_domains,
        vec![ConfigDomain::Server]
    );

    std::fs::write(&path, b"{ core:").expect("write genuine truncated bytes");
    let error = watcher.poll().expect_err("truncated candidate must fail");
    match error {
        ConfigHubError::Config(claw_config::ConfigError::Syntax {
            source_name,
            message,
        }) => {
            assert_eq!(source_name, path.display().to_string());
            assert!(!message.is_empty());
        }
        other => panic!("expected syntax error, got {other}"),
    }
    assert_eq!(
        hub.snapshot().expect("last good").core().server().port(),
        8080
    );
}
