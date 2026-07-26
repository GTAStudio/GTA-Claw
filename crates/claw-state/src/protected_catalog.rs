use sha2::{Digest as _, Sha256};

pub(crate) const MAX_SNAPSHOT_BYTES: u64 = 67_108_864;
pub(crate) const METADATA_LEN: usize = 160;
pub(crate) const SELECTOR_CELL_LEN: usize = 128;
pub(crate) const SELECTOR_LEN: usize = SELECTOR_CELL_LEN * 2;

const METADATA_MAGIC: &[u8; 8] = b"GTCLPM01";
const SELECTOR_MAGIC: &[u8; 8] = b"GTCLPS01";
const FORMAT_VERSION: u16 = 1;
const METADATA_CHECKSUM_OFFSET: usize = 104;
const METADATA_CHECKSUM_END: usize = 136;
const SELECTOR_CHECKSUM_OFFSET: usize = 64;
const SELECTOR_CHECKSUM_END: usize = 96;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CatalogIdentity {
    pub(crate) database_device: u64,
    pub(crate) database_inode: u64,
    pub(crate) writer_device: u64,
    pub(crate) writer_inode: u64,
    pub(crate) writer_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SnapshotMetadata {
    pub(crate) slot: u8,
    pub(crate) generation: u64,
    pub(crate) identity: CatalogIdentity,
    pub(crate) byte_length: u64,
    pub(crate) digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SelectorCell {
    pub(crate) cell: u8,
    pub(crate) slot: u8,
    pub(crate) generation: u64,
    pub(crate) metadata_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SlotObservation {
    pub(crate) byte_length: u64,
    pub(crate) digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveredSnapshot {
    pub(crate) cell: u8,
    pub(crate) metadata: SnapshotMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct PublicationPlan {
    pub(crate) generation: u64,
    pub(crate) slot: u8,
    pub(crate) selector_cell: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CatalogFormatError {
    reason: &'static str,
}

impl CatalogFormatError {
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl std::fmt::Display for CatalogFormatError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl std::error::Error for CatalogFormatError {}

pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn encode_metadata(metadata: SnapshotMetadata) -> [u8; METADATA_LEN] {
    assert!(metadata.slot < 2);
    assert!(metadata.generation > 0);
    assert!(metadata.identity.writer_generation > 0);
    assert!((1..=MAX_SNAPSHOT_BYTES).contains(&metadata.byte_length));

    let mut encoded = [0_u8; METADATA_LEN];
    encoded[..8].copy_from_slice(METADATA_MAGIC);
    encoded[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    encoded[10] = metadata.slot;
    encoded[12..16].copy_from_slice(&(METADATA_LEN as u32).to_be_bytes());
    encoded[16..24].copy_from_slice(&metadata.generation.to_be_bytes());
    encoded[24..32].copy_from_slice(&metadata.identity.writer_generation.to_be_bytes());
    encoded[32..40].copy_from_slice(&metadata.identity.database_device.to_be_bytes());
    encoded[40..48].copy_from_slice(&metadata.identity.database_inode.to_be_bytes());
    encoded[48..56].copy_from_slice(&metadata.identity.writer_device.to_be_bytes());
    encoded[56..64].copy_from_slice(&metadata.identity.writer_inode.to_be_bytes());
    encoded[64..72].copy_from_slice(&metadata.byte_length.to_be_bytes());
    encoded[72..104].copy_from_slice(&metadata.digest);
    let checksum = digest(&encoded[..METADATA_CHECKSUM_OFFSET]);
    encoded[METADATA_CHECKSUM_OFFSET..METADATA_CHECKSUM_END].copy_from_slice(&checksum);
    encoded
}

pub(crate) fn decode_metadata(
    encoded: &[u8],
) -> Result<Option<SnapshotMetadata>, CatalogFormatError> {
    if encoded.is_empty() {
        return Ok(None);
    }
    if encoded.len() != METADATA_LEN {
        return Err(CatalogFormatError::new(
            "snapshot metadata has a malformed fixed length",
        ));
    }
    if &encoded[..8] != METADATA_MAGIC {
        return Err(CatalogFormatError::new(
            "snapshot metadata magic is invalid",
        ));
    }
    if read_u16(encoded, 8) != FORMAT_VERSION {
        return Err(CatalogFormatError::new(
            "snapshot metadata version is unsupported",
        ));
    }
    if encoded[10] >= 2 {
        return Err(CatalogFormatError::new("snapshot metadata slot is invalid"));
    }
    if encoded[11] != 0
        || read_u32(encoded, 12) as usize != METADATA_LEN
        || encoded[METADATA_CHECKSUM_END..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(CatalogFormatError::new(
            "snapshot metadata reserved fields are invalid",
        ));
    }
    let expected_checksum = digest(&encoded[..METADATA_CHECKSUM_OFFSET]);
    if encoded[METADATA_CHECKSUM_OFFSET..METADATA_CHECKSUM_END] != expected_checksum {
        return Err(CatalogFormatError::new(
            "snapshot metadata checksum is invalid",
        ));
    }
    let generation = read_u64(encoded, 16);
    let writer_generation = read_u64(encoded, 24);
    let byte_length = read_u64(encoded, 64);
    if generation == 0 {
        return Err(CatalogFormatError::new(
            "snapshot metadata generation is zero",
        ));
    }
    if writer_generation == 0 {
        return Err(CatalogFormatError::new(
            "snapshot writer generation is zero",
        ));
    }
    if !(1..=MAX_SNAPSHOT_BYTES).contains(&byte_length) {
        return Err(CatalogFormatError::new(
            "snapshot metadata byte length is out of bounds",
        ));
    }
    let mut snapshot_digest = [0_u8; 32];
    snapshot_digest.copy_from_slice(&encoded[72..104]);
    Ok(Some(SnapshotMetadata {
        slot: encoded[10],
        generation,
        identity: CatalogIdentity {
            writer_generation,
            database_device: read_u64(encoded, 32),
            database_inode: read_u64(encoded, 40),
            writer_device: read_u64(encoded, 48),
            writer_inode: read_u64(encoded, 56),
        },
        byte_length,
        digest: snapshot_digest,
    }))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn encode_selector_cell(cell: SelectorCell) -> [u8; SELECTOR_CELL_LEN] {
    assert!(cell.cell < 2);
    assert!(cell.slot < 2);
    assert!(cell.generation > 0);

    let mut encoded = [0_u8; SELECTOR_CELL_LEN];
    encoded[..8].copy_from_slice(SELECTOR_MAGIC);
    encoded[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    encoded[10] = cell.cell;
    encoded[11] = cell.slot;
    encoded[12..16].copy_from_slice(&(SELECTOR_CELL_LEN as u32).to_be_bytes());
    encoded[16..24].copy_from_slice(&cell.generation.to_be_bytes());
    encoded[24..28].copy_from_slice(&(METADATA_LEN as u32).to_be_bytes());
    encoded[32..64].copy_from_slice(&cell.metadata_digest);
    let checksum = digest(&encoded[..SELECTOR_CHECKSUM_OFFSET]);
    encoded[SELECTOR_CHECKSUM_OFFSET..SELECTOR_CHECKSUM_END].copy_from_slice(&checksum);
    encoded
}

pub(crate) fn decode_selector_cell(
    encoded: &[u8],
    expected_cell: u8,
) -> Result<Option<SelectorCell>, CatalogFormatError> {
    if encoded.len() != SELECTOR_CELL_LEN {
        return Err(CatalogFormatError::new(
            "snapshot selector cell has a malformed fixed length",
        ));
    }
    if encoded.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    if &encoded[..8] != SELECTOR_MAGIC {
        return Err(CatalogFormatError::new(
            "snapshot selector magic is invalid",
        ));
    }
    if read_u16(encoded, 8) != FORMAT_VERSION {
        return Err(CatalogFormatError::new(
            "snapshot selector version is unsupported",
        ));
    }
    if encoded[10] != expected_cell || encoded[11] >= 2 {
        return Err(CatalogFormatError::new(
            "snapshot selector cell or slot is invalid",
        ));
    }
    if read_u32(encoded, 12) as usize != SELECTOR_CELL_LEN
        || read_u32(encoded, 24) as usize != METADATA_LEN
        || encoded[28..32].iter().any(|byte| *byte != 0)
        || encoded[SELECTOR_CHECKSUM_END..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(CatalogFormatError::new(
            "snapshot selector reserved fields are invalid",
        ));
    }
    let expected_checksum = digest(&encoded[..SELECTOR_CHECKSUM_OFFSET]);
    if encoded[SELECTOR_CHECKSUM_OFFSET..SELECTOR_CHECKSUM_END] != expected_checksum {
        return Err(CatalogFormatError::new(
            "snapshot selector checksum is invalid",
        ));
    }
    let generation = read_u64(encoded, 16);
    if generation == 0 {
        return Err(CatalogFormatError::new(
            "snapshot selector generation is zero",
        ));
    }
    let mut metadata_digest = [0_u8; 32];
    metadata_digest.copy_from_slice(&encoded[32..64]);
    Ok(Some(SelectorCell {
        cell: encoded[10],
        slot: encoded[11],
        generation,
        metadata_digest,
    }))
}

pub(crate) fn recover(
    selector: &[u8],
    metadata: [&[u8]; 2],
    slots: [SlotObservation; 2],
    expected_identity: CatalogIdentity,
) -> Result<Option<RecoveredSnapshot>, CatalogFormatError> {
    if selector.len() != SELECTOR_LEN {
        return Err(CatalogFormatError::new(
            "snapshot selector has a malformed fixed length",
        ));
    }

    let mut decoded = [None, None];
    let mut malformed = [false, false];
    for cell_index in 0..2 {
        let start = cell_index * SELECTOR_CELL_LEN;
        match decode_selector_cell(
            &selector[start..start + SELECTOR_CELL_LEN],
            cell_index as u8,
        ) {
            Ok(cell) => decoded[cell_index] = cell,
            Err(_) => malformed[cell_index] = true,
        }
    }

    let mut validated = [None, None];
    let mut committed_corrupt = [false, false];
    for cell_index in 0..2 {
        let Some(cell) = decoded[cell_index] else {
            continue;
        };
        let slot = usize::from(cell.slot);
        let valid = (|| {
            let generation_index = generation_index(cell.generation);
            if cell.cell != generation_index || cell.slot != generation_index {
                return Err(CatalogFormatError::new(
                    "snapshot selector cell or slot contradicts its generation",
                ));
            }
            if digest(metadata[slot]) != cell.metadata_digest {
                return Err(CatalogFormatError::new(
                    "selector metadata digest does not match the selected metadata",
                ));
            }
            let parsed = decode_metadata(metadata[slot])?.ok_or_else(|| {
                CatalogFormatError::new("selector references empty snapshot metadata")
            })?;
            if parsed.slot != cell.slot || parsed.generation != cell.generation {
                return Err(CatalogFormatError::new(
                    "selector and metadata generation binding contradict",
                ));
            }
            if parsed.identity != expected_identity {
                return Err(CatalogFormatError::new(
                    "snapshot metadata database or writer identity contradicts the live store",
                ));
            }
            if slots[slot].byte_length != parsed.byte_length || slots[slot].digest != parsed.digest
            {
                return Err(CatalogFormatError::new(
                    "snapshot metadata does not match the held slot bytes",
                ));
            }
            Ok(RecoveredSnapshot {
                cell: cell.cell,
                metadata: parsed,
            })
        })();
        match valid {
            Ok(recovered) => validated[cell_index] = Some(recovered),
            Err(_) => committed_corrupt[cell_index] = true,
        }
    }

    let valid_generations = validated
        .iter()
        .flatten()
        .map(|recovered| recovered.metadata.generation)
        .collect::<Vec<_>>();
    if valid_generations.is_empty() {
        let empty_digest = digest(&[]);
        if decoded.iter().all(Option::is_none)
            && !malformed.into_iter().any(|value| value)
            && metadata.iter().all(|bytes| bytes.is_empty())
            && slots
                .iter()
                .all(|slot| slot.byte_length == 0 && slot.digest == empty_digest)
        {
            return Ok(None);
        }
        return Err(CatalogFormatError::new(
            "snapshot catalog has no valid committed selector",
        ));
    }

    let highest_valid_generation = *valid_generations
        .iter()
        .max()
        .expect("one valid generation exists");
    for cell_index in 0..2 {
        if let Some(cell) = decoded[cell_index]
            && committed_corrupt[cell_index]
        {
            if cell.generation >= highest_valid_generation {
                return Err(CatalogFormatError::new(
                    "newest checksum-valid selector references corrupt committed state",
                ));
            }
            if cell.generation.checked_add(1) != Some(highest_valid_generation) {
                return Err(CatalogFormatError::new(
                    "checksum-valid stale selector contradicts monotonic generation order",
                ));
            }
        }
    }

    if let (Some(left), Some(right)) = (decoded[0], decoded[1])
        && left.generation == right.generation
    {
        return Err(CatalogFormatError::new("snapshot selector generations tie"));
    }
    if let (Some(left), Some(right)) = (validated[0], validated[1]) {
        let (older, newer) = if left.metadata.generation < right.metadata.generation {
            (left, right)
        } else {
            (right, left)
        };
        if newer
            .metadata
            .generation
            .checked_sub(older.metadata.generation)
            != Some(1)
            || newer.metadata.slot == older.metadata.slot
        {
            return Err(CatalogFormatError::new(
                "snapshot selector generations contradict monotonic slot alternation",
            ));
        }
    }

    Ok(validated
        .into_iter()
        .flatten()
        .max_by_key(|recovered| recovered.metadata.generation))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn publication_plan(
    current: Option<RecoveredSnapshot>,
) -> Result<PublicationPlan, CatalogFormatError> {
    match current {
        Some(current) => {
            Ok(PublicationPlan {
                generation: current.metadata.generation.checked_add(1).ok_or_else(|| {
                    CatalogFormatError::new("snapshot generation space is exhausted")
                })?,
                slot: 1 - current.metadata.slot,
                selector_cell: 1 - current.cell,
            })
        }
        None => Ok(PublicationPlan {
            generation: 1,
            slot: 0,
            selector_cell: 0,
        }),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed field is in bounds"),
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed field is in bounds"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed field is in bounds"),
    )
}

fn generation_index(generation: u64) -> u8 {
    u8::try_from((generation - 1) & 1).expect("generation parity fits u8")
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: CatalogIdentity = CatalogIdentity {
        database_device: 11,
        database_inode: 12,
        writer_device: 13,
        writer_inode: 14,
        writer_generation: 1,
    };

    fn committed(
        selector: &mut [u8; SELECTOR_LEN],
        metadata_files: &mut [Vec<u8>; 2],
        slots: &mut [SlotObservation; 2],
        cell: u8,
        slot: u8,
        generation: u64,
        bytes: &[u8],
    ) {
        let observation = SlotObservation {
            byte_length: bytes.len() as u64,
            digest: digest(bytes),
        };
        slots[usize::from(slot)] = observation;
        let encoded_metadata = encode_metadata(SnapshotMetadata {
            slot,
            generation,
            identity: IDENTITY,
            byte_length: observation.byte_length,
            digest: observation.digest,
        });
        metadata_files[usize::from(slot)] = encoded_metadata.to_vec();
        let encoded_cell = encode_selector_cell(SelectorCell {
            cell,
            slot,
            generation,
            metadata_digest: digest(&encoded_metadata),
        });
        let start = usize::from(cell) * SELECTOR_CELL_LEN;
        selector[start..start + SELECTOR_CELL_LEN].copy_from_slice(&encoded_cell);
    }

    #[test]
    fn formats_round_trip_and_bind_every_identity_field() {
        let metadata = SnapshotMetadata {
            slot: 1,
            generation: 42,
            identity: IDENTITY,
            byte_length: 9,
            digest: digest(b"snapshot"),
        };
        let encoded = encode_metadata(metadata);
        assert_eq!(decode_metadata(&encoded), Ok(Some(metadata)));
        let cell = SelectorCell {
            cell: 1,
            slot: 1,
            generation: 42,
            metadata_digest: digest(&encoded),
        };
        assert_eq!(
            decode_selector_cell(&encode_selector_cell(cell), 1),
            Ok(Some(cell))
        );
    }

    #[test]
    fn malformed_lengths_versions_and_checksums_are_rejected() {
        assert!(decode_metadata(&[0; METADATA_LEN - 1]).is_err());
        let metadata = SnapshotMetadata {
            slot: 0,
            generation: 1,
            identity: IDENTITY,
            byte_length: 1,
            digest: digest(b"x"),
        };
        let mut encoded = encode_metadata(metadata);
        encoded[8] = 9;
        assert!(decode_metadata(&encoded).is_err());
        let mut encoded = encode_metadata(metadata);
        encoded[72] ^= 1;
        assert!(decode_metadata(&encoded).is_err());

        let mut cell = encode_selector_cell(SelectorCell {
            cell: 0,
            slot: 0,
            generation: 1,
            metadata_digest: digest(&encode_metadata(metadata)),
        });
        cell[32] ^= 1;
        assert!(decode_selector_cell(&cell, 0).is_err());
    }

    #[test]
    fn recovery_selects_the_highest_alternating_generation() {
        let mut selector = [0; SELECTOR_LEN];
        let mut metadata = [Vec::new(), Vec::new()];
        let mut slots = [
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
        ];
        committed(&mut selector, &mut metadata, &mut slots, 0, 0, 7, b"seven");
        committed(&mut selector, &mut metadata, &mut slots, 1, 1, 8, b"eight");
        let recovered = recover(&selector, [&metadata[0], &metadata[1]], slots, IDENTITY)
            .expect("recover catalog")
            .expect("committed snapshot");
        assert_eq!(recovered.metadata.generation, 8);
        assert_eq!(publication_plan(Some(recovered)).unwrap().generation, 9);
        assert_eq!(publication_plan(Some(recovered)).unwrap().slot, 0);
        assert_eq!(publication_plan(Some(recovered)).unwrap().selector_cell, 0);
    }

    #[test]
    fn torn_new_cell_falls_back_but_checksum_valid_corruption_fails_closed() {
        let mut selector = [0; SELECTOR_LEN];
        let mut metadata = [Vec::new(), Vec::new()];
        let mut slots = [
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
        ];
        committed(
            &mut selector,
            &mut metadata,
            &mut slots,
            0,
            0,
            1,
            b"previous",
        );
        selector[SELECTOR_CELL_LEN..SELECTOR_CELL_LEN + 8].copy_from_slice(SELECTOR_MAGIC);
        assert_eq!(
            recover(&selector, [&metadata[0], &metadata[1]], slots, IDENTITY)
                .unwrap()
                .unwrap()
                .metadata
                .generation,
            1
        );

        committed(&mut selector, &mut metadata, &mut slots, 1, 1, 2, b"new");
        metadata[1][72] ^= 1;
        assert!(recover(&selector, [&metadata[0], &metadata[1]], slots, IDENTITY).is_err());
    }

    #[test]
    fn scrubbed_stale_slot_and_unselected_new_metadata_preserve_current_commit() {
        let mut selector = [0; SELECTOR_LEN];
        let mut metadata = [Vec::new(), Vec::new()];
        let mut slots = [
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
        ];
        committed(&mut selector, &mut metadata, &mut slots, 0, 0, 9, b"older");
        committed(
            &mut selector,
            &mut metadata,
            &mut slots,
            1,
            1,
            10,
            b"current",
        );

        metadata[0].clear();
        slots[0] = SlotObservation {
            byte_length: 0,
            digest: digest(&[]),
        };
        let recovered = recover(&selector, [&metadata[0], &metadata[1]], slots, IDENTITY)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.metadata.generation, 10);

        let torn_metadata = encode_metadata(SnapshotMetadata {
            slot: 0,
            generation: 11,
            identity: IDENTITY,
            byte_length: 4,
            digest: digest(b"torn"),
        });
        metadata[0] = torn_metadata.to_vec();
        slots[0] = SlotObservation {
            byte_length: 4,
            digest: digest(b"torn"),
        };
        assert_eq!(
            recover(&selector, [&metadata[0], &metadata[1]], slots, IDENTITY)
                .unwrap()
                .unwrap()
                .metadata
                .generation,
            10
        );
    }

    #[test]
    fn ties_gaps_identity_changes_and_exhaustion_fail_closed() {
        let mut selector = [0; SELECTOR_LEN];
        let mut metadata = [Vec::new(), Vec::new()];
        let mut slots = [
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
        ];
        committed(&mut selector, &mut metadata, &mut slots, 0, 0, 4, b"left");
        committed(&mut selector, &mut metadata, &mut slots, 1, 1, 4, b"right");
        assert!(recover(&selector, [&metadata[0], &metadata[1]], slots, IDENTITY).is_err());

        committed(&mut selector, &mut metadata, &mut slots, 1, 1, 9, b"right");
        assert!(recover(&selector, [&metadata[0], &metadata[1]], slots, IDENTITY).is_err());

        let mut valid_selector = [0; SELECTOR_LEN];
        let mut valid_metadata = [Vec::new(), Vec::new()];
        let mut valid_slots = [
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
        ];
        committed(
            &mut valid_selector,
            &mut valid_metadata,
            &mut valid_slots,
            0,
            0,
            1,
            b"identity",
        );
        assert!(
            recover(
                &valid_selector,
                [&valid_metadata[0], &valid_metadata[1]],
                valid_slots,
                IDENTITY,
            )
            .is_ok()
        );
        for changed_identity in [
            CatalogIdentity {
                database_device: 99,
                ..IDENTITY
            },
            CatalogIdentity {
                database_inode: 99,
                ..IDENTITY
            },
            CatalogIdentity {
                writer_device: 99,
                ..IDENTITY
            },
            CatalogIdentity {
                writer_inode: 99,
                ..IDENTITY
            },
            CatalogIdentity {
                writer_generation: 99,
                ..IDENTITY
            },
        ] {
            assert!(
                recover(
                    &valid_selector,
                    [&valid_metadata[0], &valid_metadata[1]],
                    valid_slots,
                    changed_identity,
                )
                .is_err()
            );
        }

        let exhausted = RecoveredSnapshot {
            cell: 1,
            metadata: SnapshotMetadata {
                slot: 1,
                generation: u64::MAX,
                identity: IDENTITY,
                byte_length: 1,
                digest: digest(b"x"),
            },
        };
        assert!(publication_plan(Some(exhausted)).is_err());
    }

    #[test]
    fn empty_selector_has_no_committed_snapshot() {
        let empty_slot = SlotObservation {
            byte_length: 0,
            digest: digest(&[]),
        };
        assert_eq!(
            recover(
                &[0; SELECTOR_LEN],
                [&[], &[]],
                [empty_slot, empty_slot],
                IDENTITY
            ),
            Ok(None)
        );
        assert_eq!(
            publication_plan(None),
            Ok(PublicationPlan {
                generation: 1,
                slot: 0,
                selector_cell: 0,
            })
        );
    }

    #[test]
    fn empty_selector_rejects_nonempty_uncommitted_artifacts() {
        let empty_slot = SlotObservation {
            byte_length: 0,
            digest: digest(&[]),
        };
        let nonempty_slot = SlotObservation {
            byte_length: 1,
            digest: digest(b"x"),
        };
        assert!(
            recover(
                &[0; SELECTOR_LEN],
                [&[1_u8][..], &[]],
                [empty_slot, empty_slot],
                IDENTITY,
            )
            .is_err()
        );
        assert!(
            recover(
                &[0; SELECTOR_LEN],
                [&[], &[]],
                [nonempty_slot, empty_slot],
                IDENTITY,
            )
            .is_err()
        );
    }

    #[test]
    fn generation_parity_and_stale_generation_gaps_fail_closed() {
        let invalid_metadata = SnapshotMetadata {
            slot: 1,
            generation: 1,
            identity: IDENTITY,
            byte_length: 1,
            digest: digest(b"x"),
        };
        let invalid_selector = SelectorCell {
            cell: 1,
            slot: 1,
            generation: 1,
            metadata_digest: digest(&encode_metadata(invalid_metadata)),
        };
        let mut invalid_catalog = [0; SELECTOR_LEN];
        invalid_catalog[SELECTOR_CELL_LEN..]
            .copy_from_slice(&encode_selector_cell(invalid_selector));
        assert!(
            recover(
                &invalid_catalog,
                [&[], &encode_metadata(invalid_metadata)],
                [
                    SlotObservation {
                        byte_length: 0,
                        digest: digest(&[]),
                    },
                    SlotObservation {
                        byte_length: 1,
                        digest: digest(b"x"),
                    },
                ],
                IDENTITY,
            )
            .is_err()
        );

        let mut selector = [0; SELECTOR_LEN];
        let mut metadata = [Vec::new(), Vec::new()];
        let mut slots = [
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
        ];
        committed(&mut selector, &mut metadata, &mut slots, 0, 0, 1, b"old");
        committed(
            &mut selector,
            &mut metadata,
            &mut slots,
            1,
            1,
            4,
            b"current",
        );
        metadata[0].clear();
        slots[0] = SlotObservation {
            byte_length: 0,
            digest: digest(&[]),
        };
        assert!(recover(&selector, [&metadata[0], &metadata[1]], slots, IDENTITY).is_err());
    }

    #[test]
    fn every_torn_new_selector_prefix_falls_back_to_the_previous_generation() {
        let mut base_selector = [0; SELECTOR_LEN];
        let mut base_metadata = [Vec::new(), Vec::new()];
        let mut base_slots = [
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
        ];
        committed(
            &mut base_selector,
            &mut base_metadata,
            &mut base_slots,
            0,
            0,
            1,
            b"previous",
        );

        let next_bytes = b"next";
        let next_observation = SlotObservation {
            byte_length: next_bytes.len() as u64,
            digest: digest(next_bytes),
        };
        let next_metadata = encode_metadata(SnapshotMetadata {
            slot: 1,
            generation: 2,
            identity: IDENTITY,
            byte_length: next_observation.byte_length,
            digest: next_observation.digest,
        });
        let next_cell = encode_selector_cell(SelectorCell {
            cell: 1,
            slot: 1,
            generation: 2,
            metadata_digest: digest(&next_metadata),
        });

        for prefix in 0..SELECTOR_CELL_LEN {
            let mut selector = base_selector;
            let start = SELECTOR_CELL_LEN;
            selector[start..start + prefix].copy_from_slice(&next_cell[..prefix]);
            let metadata = [base_metadata[0].as_slice(), next_metadata.as_slice()];
            let recovered = recover(
                &selector,
                metadata,
                [base_slots[0], next_observation],
                IDENTITY,
            )
            .expect("torn selector remains recoverable")
            .expect("previous selector remains committed");
            let expected = if prefix < SELECTOR_CHECKSUM_END { 1 } else { 2 };
            assert_eq!(recovered.metadata.generation, expected, "prefix={prefix}");
        }
    }

    #[test]
    fn every_torn_inactive_metadata_and_data_prefix_preserves_current_generation() {
        let mut selector = [0; SELECTOR_LEN];
        let mut metadata = [Vec::new(), Vec::new()];
        let mut slots = [
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
            SlotObservation {
                byte_length: 0,
                digest: digest(&[]),
            },
        ];
        committed(&mut selector, &mut metadata, &mut slots, 0, 0, 1, b"one");
        committed(&mut selector, &mut metadata, &mut slots, 1, 1, 2, b"two");

        let next_bytes = b"replacement-three";
        let next_observation = SlotObservation {
            byte_length: next_bytes.len() as u64,
            digest: digest(next_bytes),
        };
        let next_metadata = encode_metadata(SnapshotMetadata {
            slot: 0,
            generation: 3,
            identity: IDENTITY,
            byte_length: next_observation.byte_length,
            digest: next_observation.digest,
        });

        for prefix in 0..=METADATA_LEN {
            let recovered = recover(
                &selector,
                [&next_metadata[..prefix], &metadata[1]],
                [next_observation, slots[1]],
                IDENTITY,
            )
            .expect("torn inactive metadata preserves current selector")
            .expect("current selector remains committed");
            assert_eq!(recovered.metadata.generation, 2, "metadata prefix={prefix}");
        }

        for prefix in 0..=next_bytes.len() {
            let torn_slot = SlotObservation {
                byte_length: prefix as u64,
                digest: digest(&next_bytes[..prefix]),
            };
            let recovered = recover(
                &selector,
                [&metadata[0], &metadata[1]],
                [torn_slot, slots[1]],
                IDENTITY,
            )
            .expect("torn inactive data preserves current selector")
            .expect("current selector remains committed");
            assert_eq!(recovered.metadata.generation, 2, "data prefix={prefix}");
        }

        let committed_selector = encode_selector_cell(SelectorCell {
            cell: 0,
            slot: 0,
            generation: 3,
            metadata_digest: digest(&next_metadata),
        });
        selector[..SELECTOR_CELL_LEN].copy_from_slice(&committed_selector);
        assert!(
            recover(
                &selector,
                [&next_metadata, &metadata[1]],
                [
                    SlotObservation {
                        byte_length: 1,
                        digest: digest(b"x"),
                    },
                    slots[1],
                ],
                IDENTITY,
            )
            .is_err()
        );
    }
}
