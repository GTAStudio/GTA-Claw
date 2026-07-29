//! Restart acceptance: a goal that was acknowledged is still there after the process is gone.
//!
//! Every test in this file destroys the objects that wrote the goal before it reads one back, and
//! the first test destroys the whole *process*. That distinction is the point of the file: a store
//! that merely holds no cache passes a same-process check while still depending on state a crash
//! would take with it. Only bytes that reached the filesystem can satisfy these.

use std::process::Command;

use claw_application::model::goal::GoalStatus;
use claw_goals::invoke_goal_tool;
use claw_goals::testing::{TempRoot, block_on, open_durable, session_id};

/// Runs the goal writer in a separate OS process and returns what it printed.
fn write_in_another_process(root: &TempRoot, session: &str, clock: u64, action: &str, value: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_claw-goal-writer"))
        .arg(root.path())
        .arg(session)
        .arg(clock.to_string())
        .arg(action)
        .arg(value)
        .output()
        .expect("the goal writer runs");

    assert!(
        output.status.success(),
        "the goal writer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_goal_written_by_another_process_is_recovered_after_that_process_exits() {
    let root = TempRoot::new("restart-process");
    let session = "cross-process";

    write_in_another_process(&root, session, 1_000, "set", "ship the durable store");
    write_in_another_process(&root, session, 5_000, "progress", "wrote the adapter");
    write_in_another_process(&root, session, 9_000, "progress", "wrote the tests");

    // Nothing of the writers survives: they were separate processes that have already exited.
    let durable = open_durable(root.path(), 20_000);
    let recovered = block_on(durable.service.active(&session_id(session)))
        .expect("the store answers")
        .expect("the goal outlived the process that set it");

    assert_eq!(recovered.objective, "ship the durable store");
    assert_eq!(recovered.status, GoalStatus::Active);
    assert_eq!(recovered.revision, 3);
    assert_eq!(
        recovered
            .progress
            .iter()
            .map(|entry| entry.note.as_str())
            .collect::<Vec<_>>(),
        vec!["wrote the adapter", "wrote the tests"]
    );
    assert!(durable.store.recovery().is_clean());
}

#[test]
fn a_goal_closed_by_another_process_stays_closed() {
    let root = TempRoot::new("restart-close");
    let session = "cross-process-close";

    write_in_another_process(&root, session, 1_000, "set", "finish the ledger row");
    write_in_another_process(&root, session, 5_000, "close", "achieved");

    let durable = open_durable(root.path(), 20_000);
    let session_id = session_id(session);
    assert!(
        block_on(durable.service.active(&session_id))
            .expect("the store answers")
            .is_none(),
        "a closed goal must not come back as the active one"
    );

    let history = block_on(durable.service.history(&session_id)).expect("the store answers");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].status, GoalStatus::Achieved);
    assert!(history[0].closed_at.is_some());
}

#[test]
fn the_whole_history_survives_a_restart_in_creation_order() {
    let root = TempRoot::new("restart-history");
    let session = session_id("history");

    {
        let durable = open_durable(root.path(), 1_000);
        let first = block_on(durable.service.start(&session, "first objective")).expect("set");
        block_on(durable.service.record_progress(&first.goal_id, "a step")).expect("progress");
        block_on(durable.service.close(&first.goal_id, GoalStatus::Achieved)).expect("close");
        block_on(durable.service.start(&session, "second objective")).expect("set");
    }

    let durable = open_durable(root.path(), 100_000);
    let history = block_on(durable.service.history(&session)).expect("the store answers");

    assert_eq!(
        history
            .iter()
            .map(|record| (record.objective.as_str(), record.status))
            .collect::<Vec<_>>(),
        vec![
            ("first objective", GoalStatus::Achieved),
            ("second objective", GoalStatus::Active),
        ]
    );
    assert_eq!(history[0].progress.len(), 1);
    assert_eq!(history[0].progress[0].note, "a step");
    // set, progress, close: three persisted mutations, so revision three.
    assert_eq!(history[0].revision, 3);
    assert_eq!(history[1].revision, 1);
}

#[test]
fn the_next_goal_identifier_is_read_from_disk_rather_than_from_memory() {
    let root = TempRoot::new("restart-ids");
    let session = session_id("ids");

    {
        let durable = open_durable(root.path(), 1_000);
        block_on(durable.service.start(&session, "first")).expect("set");
        block_on(durable.service.start(&session, "second")).expect("set");
    }

    let durable = open_durable(root.path(), 100_000);
    let third = block_on(durable.service.start(&session, "third")).expect("set");

    assert_eq!(third.goal_id.as_str(), "ids:goal-3");
}

#[test]
fn a_reader_sees_the_bytes_on_disk_and_not_a_remembered_value() {
    let root = TempRoot::new("restart-bytes");
    let session = session_id("bytes");

    let goal_id = {
        let durable = open_durable(root.path(), 1_000);
        block_on(durable.service.start(&session, "the written objective"))
            .expect("set")
            .goal_id
    };

    // Editing the file behind the store's back is the only way to tell "read from disk" from
    // "returned what this process last wrote".
    let goal_file = std::fs::read_dir(root.path().join("goals"))
        .expect("the goals directory exists")
        .map(|entry| entry.expect("readable").path())
        .find(|path| path.extension().is_some_and(|value| value == "json"))
        .expect("one goal file exists");
    let text = std::fs::read_to_string(&goal_file).expect("readable");
    std::fs::write(
        &goal_file,
        text.replace("the written objective", "the edited objective"),
    )
    .expect("writable");

    let durable = open_durable(root.path(), 100_000);
    let recovered = block_on(durable.service.active(&session))
        .expect("the store answers")
        .expect("present");

    assert_eq!(recovered.goal_id, goal_id);
    assert_eq!(recovered.objective, "the edited objective");
}

#[test]
fn a_record_written_without_its_index_entry_is_adopted_on_the_next_start() {
    let root = TempRoot::new("restart-orphan");
    let session = session_id("orphan");

    {
        let durable = open_durable(root.path(), 1_000);
        block_on(durable.service.start(&session, "an orphaned objective")).expect("set");
    }

    // A crash between the record write and the index write leaves exactly this on disk.
    let sessions = root.path().join("sessions");
    for entry in std::fs::read_dir(&sessions).expect("the sessions directory exists") {
        std::fs::remove_file(entry.expect("readable").path()).expect("removable");
    }

    let durable = open_durable(root.path(), 100_000);

    assert_eq!(durable.store.recovery().adopted_orphans, 1);
    assert_eq!(durable.store.recovery().pruned_dangling, 0);
    let recovered = block_on(durable.service.active(&session))
        .expect("the store answers")
        .expect("the orphan was adopted rather than lost");
    assert_eq!(recovered.objective, "an orphaned objective");
}

#[test]
fn a_partial_write_left_behind_by_a_crash_is_discarded_on_the_next_start() {
    let root = TempRoot::new("restart-partial");
    let session = session_id("partial");

    {
        let durable = open_durable(root.path(), 1_000);
        block_on(durable.service.start(&session, "a complete objective")).expect("set");
    }

    let stray = root.path().join("goals").join("pending-1234-0");
    std::fs::write(&stray, "{\"schema\":1,\"goal_id\":\"trunc").expect("writable");

    let durable = open_durable(root.path(), 100_000);

    assert_eq!(durable.store.recovery().discarded_partial_writes, 1);
    assert!(!stray.exists(), "a half-written file must not survive");
    assert_eq!(
        block_on(durable.service.active(&session))
            .expect("the store answers")
            .expect("present")
            .objective,
        "a complete objective"
    );
}

#[test]
fn an_index_naming_a_vanished_record_is_pruned_instead_of_failing_every_read() {
    let root = TempRoot::new("restart-dangling");
    let session = session_id("dangling");

    let doomed = {
        let durable = open_durable(root.path(), 1_000);
        let first = block_on(durable.service.start(&session, "first")).expect("set");
        block_on(durable.service.start(&session, "second")).expect("set");
        assert_eq!(
            block_on(durable.service.history(&session))
                .expect("the store answers")
                .len(),
            2
        );
        first.goal_id
    };

    // Losing a single record file must not make the session unreadable.
    let goals = root.path().join("goals");
    let victim = std::fs::read_dir(&goals)
        .expect("the goals directory exists")
        .map(|entry| entry.expect("readable").path())
        .find(|path| {
            std::fs::read_to_string(path)
                .expect("readable")
                .contains(doomed.as_str())
        })
        .expect("the first goal has a file");
    std::fs::remove_file(&victim).expect("removable");

    let durable = open_durable(root.path(), 100_000);

    assert_eq!(durable.store.recovery().pruned_dangling, 1);
    let history = block_on(durable.service.history(&session)).expect("the store answers");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].objective, "second");
    let third = block_on(durable.service.start(&session, "third")).expect("set");
    assert_eq!(
        third.goal_id.as_str(),
        "dangling:goal-3",
        "pruning a lost record must not rewind the durable high-water mark"
    );
}

#[test]
fn a_legacy_index_migrates_its_high_water_before_record_loss_and_restart() {
    let root = TempRoot::new("restart-high-water-migration");
    let session = session_id("migrate");
    {
        let durable = open_durable(root.path(), 1_000);
        block_on(durable.service.start(&session, "first")).expect("set");
        block_on(durable.service.start(&session, "second")).expect("set");
    }

    let index_path = std::fs::read_dir(root.path().join("sessions"))
        .expect("sessions directory")
        .map(|entry| entry.expect("readable").path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .expect("session index");
    let mut index: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&index_path).expect("index reads"))
            .expect("index JSON");
    index
        .as_object_mut()
        .expect("index object")
        .remove("goal_id_high_water");
    std::fs::write(
        &index_path,
        serde_json::to_string_pretty(&index).expect("index encodes"),
    )
    .expect("legacy fixture writes");

    {
        let migrated = open_durable(root.path(), 50_000);
        assert!(migrated.store.recovery().is_clean());
    }

    let second_record = std::fs::read_dir(root.path().join("goals"))
        .expect("goals directory")
        .map(|entry| entry.expect("readable").path())
        .find(|path| {
            std::fs::read_to_string(path)
                .expect("record reads")
                .contains("migrate:goal-2")
        })
        .expect("second record");
    std::fs::remove_file(second_record).expect("record loss injected");

    let reopened = open_durable(root.path(), 100_000);
    assert_eq!(reopened.store.recovery().pruned_dangling, 1);
    let third = block_on(reopened.service.start(&session, "third")).expect("set");
    assert_eq!(third.goal_id.as_str(), "migrate:goal-3");
}

#[test]
fn a_model_tool_goal_and_an_operator_goal_share_one_durable_history_across_a_restart() {
    let root = TempRoot::new("restart-mixed");
    let session = session_id("mixed");

    {
        let durable = open_durable(root.path(), 1_000);
        block_on(durable.service.start(&session, "the operator objective")).expect("set");
        block_on(invoke_goal_tool(
            &durable.service,
            &session,
            "{\"action\":\"set\",\"objective\":\"the model objective\"}",
        ))
        .expect("the model sets a goal");
    }

    let durable = open_durable(root.path(), 100_000);
    let history = block_on(durable.service.history(&session)).expect("the store answers");

    assert_eq!(
        history
            .iter()
            .map(|record| (record.objective.as_str(), record.status))
            .collect::<Vec<_>>(),
        vec![
            ("the operator objective", GoalStatus::Superseded),
            ("the model objective", GoalStatus::Active),
        ]
    );
}

/// Returns the single goal record file under `root`.
#[cfg(unix)]
fn only_goal_file(root: &std::path::Path) -> std::path::PathBuf {
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(root.join("goals"))
        .expect("the goals directory exists")
        .map(|entry| entry.expect("readable").path())
        .filter(|path| path.extension().is_some_and(|value| value == "json"))
        .collect();
    assert_eq!(files.len(), 1, "the test writes exactly one goal");
    files.pop().expect("one goal file exists")
}

#[cfg(unix)]
#[test]
fn every_publication_is_a_rename_into_a_directory_that_was_then_synchronized() {
    use std::os::unix::fs::MetadataExt;

    let root = TempRoot::new("restart-fsync");
    let session = session_id("fsync");
    let durable = open_durable(root.path(), 1_000);

    let goal = block_on(durable.service.start(&session, "the published objective")).expect("set");
    // Setting a goal publishes the record and, because the goal is new to the session, the index.
    assert_eq!(durable.store.synced_publications(), 2);
    assert_eq!(durable.store.unsynced_publications(), 0);

    let record_path = only_goal_file(root.path());
    let published = std::fs::read(&record_path).expect("read the record");
    let published_inode = std::fs::metadata(&record_path).expect("metadata").ino();

    // A second name for the same inode. An in-place rewrite would change what this link sees; a
    // temporary-file-then-rename can only ever leave it holding the exact previous bytes.
    let witness = root.path().join("witness.json");
    std::fs::hard_link(&record_path, &witness).expect("hard link the published record");

    block_on(durable.service.record_progress(&goal.goal_id, "a step")).expect("progress");

    assert_eq!(
        std::fs::read(&witness).expect("read witness"),
        published,
        "the previous record bytes must survive intact, so the write was never in place"
    );
    assert_ne!(
        std::fs::metadata(&record_path).expect("metadata").ino(),
        published_inode,
        "a published record must be a renamed replacement, not a rewritten original"
    );
    assert_eq!(
        durable.store.synced_publications(),
        3,
        "the directory entry of every published file must be flushed, or the rename can be lost"
    );
    assert_eq!(
        durable.store.unsynced_publications(),
        0,
        "a healthy store must report no unresolved durability caveat"
    );

    // The directory sync is a durability step, not a visibility one: the goal still reads back
    // from a freshly opened store.
    let reopened = open_durable(root.path(), 100_000);
    assert_eq!(
        block_on(reopened.service.active(&session))
            .expect("the store answers")
            .expect("the goal survived")
            .progress
            .len(),
        1
    );
    assert_eq!(
        reopened.store.synced_publications(),
        0,
        "a store that has published nothing has synchronized nothing"
    );
}
