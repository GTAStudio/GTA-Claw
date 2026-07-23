#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub(crate) const DATABASE_NAME: &str = "state.sqlite";
pub(crate) const WAL_NAME: &str = "state.sqlite-wal";
pub(crate) const WRITER_LOCK_NAME: &str = "state.writer.lock";
pub(crate) const SNAPSHOT_DATA_NAMES: [&str; 2] = ["snapshot-0.sqlite", "snapshot-1.sqlite"];
pub(crate) const SNAPSHOT_METADATA_NAMES: [&str; 2] = ["snapshot-0.meta", "snapshot-1.meta"];
pub(crate) const SELECTOR_NAME: &str = "snapshot.selector";
pub(crate) const ENTRY_NAMES: [&str; 8] = [
    DATABASE_NAME,
    WAL_NAME,
    WRITER_LOCK_NAME,
    SNAPSHOT_DATA_NAMES[0],
    SNAPSHOT_METADATA_NAMES[0],
    SNAPSHOT_DATA_NAMES[1],
    SNAPSHOT_METADATA_NAMES[1],
    SELECTOR_NAME,
];
