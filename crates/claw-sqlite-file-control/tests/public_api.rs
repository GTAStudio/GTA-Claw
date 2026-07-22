//! Public API compatibility checks.

use std::sync::{Arc, atomic::AtomicBool};

use claw_sqlite_file_control::BackupExecutionContext;

#[test]
fn native_wal_and_vfs_controls_are_public() {
    let _enable = claw_sqlite_file_control::enable_persistent_wal;
    let _vfs_name = claw_sqlite_file_control::main_database_vfs_name;
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
