//! Bounded portable snapshots of the state database, excluding external goal or asset stores.

use std::io::{BufRead, Write};

use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    MAX_KEY_BYTES, MAX_RECORD_BYTES, RECORDS, SCHEMA_VERSION, StateDatabase, StateError,
    checked_key, storage,
};

const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
const MAX_SNAPSHOT_RECORDS: usize = 262_144;
const MAX_LINE_BYTES: usize = MAX_RECORD_BYTES + MAX_KEY_BYTES * 6 + 256;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Entry {
    Header {
        format: String,
        schema: u64,
    },
    Record {
        key: String,
        value: Box<serde_json::value::RawValue>,
    },
    Complete {
        records: usize,
        sha256: String,
    },
}

/// Counts and integrity digest for one completely written or restored snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotReceipt {
    /// Exact number of state records.
    pub records: usize,
    /// Complete encoded bytes including the integrity footer.
    pub bytes: usize,
    /// Digest of the header and ordered record lines, excluding the footer.
    pub sha256: String,
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
        .map(char::from)
        .collect()
}

fn encoded(entry: &Entry) -> Result<Vec<u8>, StateError> {
    let mut line = serde_json::to_vec(entry).map_err(|_| StateError::InvalidRecord)?;
    line.push(b'\n');
    if line.len() > MAX_LINE_BYTES {
        return Err(StateError::InvalidRecord);
    }
    Ok(line)
}

fn write_entry(
    output: &mut impl Write,
    entry: &Entry,
    bytes: &mut usize,
    digest: Option<&mut Sha256>,
) -> Result<(), StateError> {
    let line = encoded(entry)?;
    *bytes = bytes
        .checked_add(line.len())
        .filter(|count| *count <= MAX_SNAPSHOT_BYTES)
        .ok_or(StateError::InvalidRecord)?;
    output.write_all(&line).map_err(storage)?;
    if let Some(digest) = digest {
        digest.update(&line);
    }
    Ok(())
}

fn read_entry(
    input: &mut impl BufRead,
    bytes: &mut usize,
) -> Result<Option<(Entry, Vec<u8>)>, StateError> {
    let mut line = Vec::new();
    let limit = MAX_LINE_BYTES.min(MAX_SNAPSHOT_BYTES.saturating_sub(*bytes));
    if limit == 0 {
        return Err(StateError::InvalidRecord);
    }
    let count = std::io::Read::take(
        &mut *input,
        u64::try_from(limit).map_err(|_| StateError::InvalidRecord)? + 1,
    )
    .read_until(b'\n', &mut line)
    .map_err(storage)?;
    if count == 0 {
        return Ok(None);
    }
    if count > limit || line.last() != Some(&b'\n') {
        return Err(StateError::InvalidRecord);
    }
    *bytes += count;
    let entry = serde_json::from_slice(&line).map_err(|_| StateError::InvalidRecord)?;
    Ok(Some((entry, line)))
}

impl StateDatabase {
    /// Writes one coherent snapshot from a single read transaction to a caller-owned sink.
    ///
    /// Snapshots contain private state in plaintext. The caller owns encryption, file permissions,
    /// publication, flushing and any external-store snapshot coordination.
    ///
    /// # Errors
    /// Refuses a recovery-fenced source, oversized/corrupt records, output failure or fixed bounds.
    /// A partial stream has no valid footer and must never be published as a completed backup.
    pub fn export_snapshot(&self, output: &mut impl Write) -> Result<SnapshotReceipt, StateError> {
        if self.recovery_required() {
            return Err(StateError::CommitUnknown(
                "reconcile state before publishing a backup".to_owned(),
            ));
        }
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(RECORDS).map_err(storage)?;
        let mut bytes = 0;
        let mut records = 0;
        let mut digest = Sha256::new();
        write_entry(
            output,
            &Entry::Header {
                format: "gta-claw-state".to_owned(),
                schema: SCHEMA_VERSION,
            },
            &mut bytes,
            Some(&mut digest),
        )?;
        for entry in table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let key = checked_key(key.value().to_owned())?;
            if value.value().len() > MAX_RECORD_BYTES || records == MAX_SNAPSHOT_RECORDS {
                return Err(StateError::InvalidRecord);
            }
            let value: Box<serde_json::value::RawValue> =
                serde_json::from_slice(value.value()).map_err(|_| StateError::InvalidRecord)?;
            write_entry(
                output,
                &Entry::Record { key, value },
                &mut bytes,
                Some(&mut digest),
            )?;
            records += 1;
        }
        if self.recovery_required() {
            return Err(StateError::CommitUnknown(
                "state became uncertain during export; snapshot was not finalized".to_owned(),
            ));
        }
        let sha256 = hex(&digest.finalize());
        write_entry(
            output,
            &Entry::Complete {
                records,
                sha256: sha256.clone(),
            },
            &mut bytes,
            None,
        )?;
        Ok(SnapshotReceipt {
            records,
            bytes,
            sha256,
        })
    }

    /// Restores an intact snapshot atomically into an empty state database.
    ///
    /// Existing records are never overwritten. The caller must restore into an independent target
    /// and validate domain/runtime compatibility before any use; this does not resume work.
    ///
    /// # Errors
    /// Refuses nonempty/fenced targets, wrong schema, malformed/truncated/tampered/trailing input,
    /// unordered keys and resource-limit failures. No record is published before all checks pass.
    pub fn restore_snapshot(
        &self,
        input: &mut impl BufRead,
    ) -> Result<SnapshotReceipt, StateError> {
        let mut recovery = self
            .recovery_required
            .lock()
            .map_err(|_| StateError::CommitUnknown("state write gate failed".to_owned()))?;
        if *recovery {
            return Err(StateError::CommitUnknown(
                "target requires recovery".to_owned(),
            ));
        }
        let write = self.database.begin_write().map_err(storage)?;
        let mut table = write.open_table(RECORDS).map_err(storage)?;
        if !table.is_empty().map_err(storage)? {
            return Err(StateError::Conflict);
        }
        let mut bytes = 0;
        let Some((Entry::Header { format, schema }, header)) = read_entry(input, &mut bytes)?
        else {
            return Err(StateError::Schema);
        };
        if format != "gta-claw-state" || schema != SCHEMA_VERSION {
            return Err(StateError::Schema);
        }
        let mut digest = Sha256::new();
        digest.update(header);
        let mut records = 0;
        let mut previous: Option<String> = None;
        let receipt = loop {
            let Some((entry, line)) = read_entry(input, &mut bytes)? else {
                return Err(StateError::InvalidRecord);
            };
            match entry {
                Entry::Record { key, value } => {
                    checked_key(key.clone())?;
                    if records == MAX_SNAPSHOT_RECORDS
                        || value.get().len() > MAX_RECORD_BYTES
                        || previous.as_ref().is_some_and(|previous| previous >= &key)
                    {
                        return Err(StateError::InvalidRecord);
                    }
                    table
                        .insert(key.as_str(), value.get().as_bytes())
                        .map_err(storage)?;
                    digest.update(line);
                    previous = Some(key);
                    records += 1;
                }
                Entry::Complete {
                    records: expected,
                    sha256,
                } => {
                    if expected != records
                        || sha256 != hex(&digest.finalize())
                        || !input.fill_buf().map_err(storage)?.is_empty()
                    {
                        return Err(StateError::InvalidRecord);
                    }
                    break SnapshotReceipt {
                        records,
                        bytes,
                        sha256,
                    };
                }
                Entry::Header { .. } => return Err(StateError::Schema),
            }
        };
        drop(table);
        let committed = write
            .commit()
            .map_err(|error| StateError::CommitUnknown(error.to_string()));
        if committed.is_err() {
            *recovery = true;
        }
        drop(recovery);
        committed?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Mutation, tests::Fixture};
    use std::io::Cursor;

    #[test]
    fn snapshot_database_open_modes_never_create_sources_or_replace_targets() {
        let source = Fixture::new();
        assert!(StateDatabase::open_existing(source.path()).is_err());
        assert!(!source.path().exists());
        let database = StateDatabase::create_new(source.path()).expect("new target");
        database
            .commit(vec![Mutation::put("preserved", &true).expect("record")])
            .expect("initial state");
        assert!(StateDatabase::create_new(source.path()).is_err());
        drop(database);
        let existing = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(source.path())
            .expect("existing target handle");
        assert!(matches!(
            StateDatabase::from_new_file(existing),
            Err(StateError::Conflict)
        ));
        let reopened = StateDatabase::open_existing(source.path()).expect("existing source");
        assert!(
            reopened
                .get("preserved")
                .expect("retained record")
                .expect("value")
                .decode::<bool>()
                .expect("typed value")
        );
    }

    #[test]
    fn snapshot_roundtrip_preserves_exact_records_and_never_overwrites_existing_state() {
        let source = Fixture::new();
        let target = Fixture::new();
        let source = StateDatabase::open(source.path()).expect("source");
        source
            .commit(vec![
                Mutation::put(
                    "one",
                    &serde_json::json!({"private":"value","number":9_007_199_254_740_993_u64}),
                )
                .expect("record"),
                Mutation::put("two", &vec![1, 2, 3]).expect("record"),
            ])
            .expect("source commit");
        let mut bytes = Vec::new();
        let receipt = source
            .export_snapshot(&mut bytes)
            .expect("coherent snapshot");
        let target = StateDatabase::open(target.path()).expect("independent target");
        assert_eq!(
            target
                .restore_snapshot(&mut Cursor::new(&bytes))
                .expect("restore"),
            receipt
        );
        assert_eq!(receipt.records, 2);
        assert!(source.get("one").expect("source") == target.get("one").expect("target"));
        assert!(matches!(
            target.restore_snapshot(&mut Cursor::new(&bytes)),
            Err(StateError::Conflict)
        ));
    }

    #[test]
    fn malformed_snapshot_never_publishes_partial_records() {
        let source = Fixture::new();
        let source = StateDatabase::open(source.path()).expect("source");
        source
            .commit(vec![Mutation::put("one", &true).expect("record")])
            .expect("source commit");
        let mut original = Vec::new();
        source.export_snapshot(&mut original).expect("snapshot");
        let mut tampered = original.clone();
        let offset = tampered
            .windows(4)
            .position(|bytes| bytes == b"true")
            .expect("fixture content");
        tampered[offset..offset + 4].copy_from_slice(b"null");
        let mut trailing = original.clone();
        trailing.extend_from_slice(b"{}\n");
        for bytes in [
            original[..original.len() - 10].to_vec(),
            tampered,
            trailing,
            b"{\"header\":{\"format\":\"gta-claw-state\",\"schema\":99}}\n".to_vec(),
        ] {
            let root = Fixture::new();
            let target = StateDatabase::open(root.path()).expect("empty target");
            assert!(target.restore_snapshot(&mut Cursor::new(bytes)).is_err());
            assert!(target.get("one").expect("no partial publication").is_none());
            assert!(!target.recovery_required());
        }
    }

    #[test]
    fn snapshot_limits_duplicate_keys_and_late_source_failure_cannot_publish_complete_backups() {
        struct FaultOnOutput<'a> {
            database: &'a StateDatabase,
            bytes: Vec<u8>,
        }
        impl Write for FaultOnOutput<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.database.require_recovery();
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let root = Fixture::new();
        let database = StateDatabase::open(root.path()).expect("target");
        let header = encoded(&Entry::Header {
            format: "gta-claw-state".to_owned(),
            schema: SCHEMA_VERSION,
        })
        .expect("header");
        let record = encoded(&Entry::Record {
            key: "duplicate".to_owned(),
            value: serde_json::from_str("true").expect("raw value"),
        })
        .expect("record");
        let mut repeated = header.clone();
        repeated.extend_from_slice(&record);
        repeated.extend_from_slice(&record);
        let digest = hex(&Sha256::digest(&repeated));
        repeated.extend_from_slice(
            &encoded(&Entry::Complete {
                records: 2,
                sha256: digest,
            })
            .expect("valid digest footer"),
        );
        assert!(matches!(
            database.restore_snapshot(&mut Cursor::new(repeated)),
            Err(StateError::InvalidRecord)
        ));
        assert!(
            database
                .get("duplicate")
                .expect("no overwritten duplicate")
                .is_none()
        );
        let mut oversized = header;
        oversized.extend(std::iter::repeat_n(b' ', MAX_LINE_BYTES + 1));
        assert!(matches!(
            database.restore_snapshot(&mut Cursor::new(oversized)),
            Err(StateError::InvalidRecord)
        ));

        let mut output = FaultOnOutput {
            database: &database,
            bytes: Vec::new(),
        };
        assert!(matches!(
            database.export_snapshot(&mut output),
            Err(StateError::CommitUnknown(_))
        ));
        assert!(!String::from_utf8_lossy(&output.bytes).contains("complete"));
        assert!(matches!(
            database.export_snapshot(&mut Vec::new()),
            Err(StateError::CommitUnknown(_))
        ));
    }

    #[test]
    fn snapshot_reads_one_transaction_even_when_the_source_changes_during_output() {
        struct ConcurrentWriter<'a> {
            source: &'a StateDatabase,
            bytes: Vec<u8>,
            changed: bool,
        }
        impl Write for ConcurrentWriter<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if !self.changed {
                    self.changed = true;
                    self.source
                        .commit(vec![Mutation::put("value", &"new").expect("record")])
                        .expect("concurrent write");
                }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let root = Fixture::new();
        let source = StateDatabase::open(root.path()).expect("source");
        source
            .commit(vec![Mutation::put("value", &"old").expect("record")])
            .expect("initial record");
        let mut writer = ConcurrentWriter {
            source: &source,
            bytes: Vec::new(),
            changed: false,
        };
        source
            .export_snapshot(&mut writer)
            .expect("consistent read snapshot");
        let restored_root = Fixture::new();
        let restored = StateDatabase::open(restored_root.path()).expect("target");
        restored
            .restore_snapshot(&mut Cursor::new(writer.bytes))
            .expect("restore");
        assert_eq!(
            restored
                .get("value")
                .expect("record")
                .expect("value")
                .decode::<String>()
                .expect("string"),
            "old"
        );
        assert_eq!(
            source
                .get("value")
                .expect("record")
                .expect("value")
                .decode::<String>()
                .expect("string"),
            "new"
        );
    }
}
