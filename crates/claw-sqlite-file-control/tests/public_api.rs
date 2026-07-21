//! Public API compatibility checks.

use std::sync::{Arc, atomic::AtomicBool};

use claw_sqlite_file_control::BackupExecutionContext;

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
