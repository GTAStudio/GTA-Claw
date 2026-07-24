//! Public API compatibility checks.

use std::sync::{Arc, atomic::AtomicBool};

use claw_sqlite_file_control::{BackupExecutionContext, BeginOwnedConnection, ManualTransaction};

fn terminal_abort_commit_method_is_public<Connection: BeginOwnedConnection>(
    transaction: ManualTransaction<Connection>,
) {
    let _future = transaction.commit_with_deadline_terminal_on_abort(
        std::time::Instant::now(),
        std::time::Instant::now(),
        Arc::new(AtomicBool::new(false)),
        std::time::Duration::ZERO,
        None,
    );
}

#[test]
fn native_wal_and_vfs_controls_are_public() {
    let _enable = claw_sqlite_file_control::enable_persistent_wal;
    let _disable_close_checkpoint = claw_sqlite_file_control::disable_wal_checkpoint_on_close;
    let _vfs_name = claw_sqlite_file_control::main_database_vfs_name;
}

#[test]
fn native_process_signal_counter_is_public() {
    let _install = claw_sqlite_file_control::ProcessSignalCounter::install;
    let _take_next = claw_sqlite_file_control::ProcessSignalCounter::take_next;
    let _mark_ready = claw_sqlite_file_control::ProcessSignalCounter::mark_ready;
    let _commit_clean_exit = claw_sqlite_file_control::ProcessSignalCounter::commit_clean_exit;
    let _wait_next = claw_sqlite_file_control::ProcessSignalCounter::wait_next;
}

#[test]
fn terminal_abort_commit_control_is_public() {
    let _api = terminal_abort_commit_method_is_public::<sqlx::pool::PoolConnection<sqlx::Sqlite>>;
}

#[test]
fn backup_execution_context_preserves_exhaustive_literal_api() {
    let _context = BackupExecutionContext {
        deadline: std::time::Instant::now(),
        cancelled: Arc::new(AtomicBool::new(false)),
        max_pages: 1,
        source_busy_timeout: std::time::Duration::ZERO,
        destination_busy_timeout: std::time::Duration::ZERO,
    };
}
