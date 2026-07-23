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
    let _vfs_name = claw_sqlite_file_control::main_database_vfs_name;
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
