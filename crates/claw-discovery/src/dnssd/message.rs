//! DNS message encoding and decoding, including RFC 1035 name compression.
//!
//! The decoder is the security-relevant half. It refuses a compression pointer
//! that does not point strictly backwards, which is what makes the pointer walk
//! provably terminating, and it enforces the 255-byte name ceiling across the
//! whole expansion rather than per fragment.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::DnsSdError;
use super::name::{MAX_NAME_BYTES, Name};
use super::txt::TxtRecord;

/// The `IN` class value.
pub const CLASS_IN: u16 = 1;
/// The mDNS cache-flush bit, carried in the top bit of the class field.
pub const CACHE_FLUSH: u16 = 0x8000;
/// The mDNS unicast-response bit, carried in the top bit of a question class.
pub const UNICAST_RESPONSE: u16 = 0x8000;
/// The `QR` response flag.
pub const FLAG_RESPONSE: u16 = 0x8000;
/// The `AA` authoritative-answer flag, always set by an mDNS responder.
pub const FLAG_AUTHORITATIVE: u16 = 0x0400;
/// The `TC` truncation flag.
pub const FLAG_TRUNCATED: u16 = 0x0200;

/// `A` record type.
pub const TYPE_A: u16 = 1;
/// `PTR` record type.
pub const TYPE_PTR: u16 = 12;
/// `TXT` record type.
pub const TYPE_TXT: u16 = 16;
/// `AAAA` record type.
pub const TYPE_AAAA: u16 = 28;
/// `SRV` record type.
pub const TYPE_SRV: u16 = 33;
/// `ANY` query type.
pub const TYPE_ANY: u16 = 255;

const POINTER_MASK: u8 = 0xc0;
const MAX_POINTER_OFFSET: usize = 0x3fff;

/// The record payloads this codec understands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordData {
    /// An IPv4 host address.
    A(Ipv4Addr),
    /// An IPv6 host address.
    Aaaa(Ipv6Addr),
    /// A pointer to another name.
    Ptr(Name),
    /// A service location.
    Srv {
        /// Selection priority, lowest first.
        priority: u16,
        /// Relative weight within one priority.
        weight: u16,
        /// TCP or UDP port.
        port: u16,
        /// Host name serving the instance.
        target: Name,
    },
    /// A DNS-SD key/value set.
    Txt(TxtRecord),
    /// A record type this codec does not model, preserved verbatim.
    Other {
        /// The numeric record type.
        record_type: u16,
        /// The uninterpreted rdata bytes.
        rdata: Vec<u8>,
    },
}

impl RecordData {
    /// Returns the numeric record type of this payload.
    #[must_use]
    pub fn record_type(&self) -> u16 {
        match self {
            Self::A(_) => TYPE_A,
            Self::Aaaa(_) => TYPE_AAAA,
            Self::Ptr(_) => TYPE_PTR,
            Self::Srv { .. } => TYPE_SRV,
            Self::Txt(_) => TYPE_TXT,
            Self::Other { record_type, .. } => *record_type,
        }
    }
}

/// One resource record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRecord {
    /// Owner name.
    pub name: Name,
    /// Record class, cache-flush bit excluded.
    pub class: u16,
    /// Whether the mDNS cache-flush bit is set.
    pub cache_flush: bool,
    /// Time to live in seconds. Zero is a goodbye announcement.
    pub ttl: u32,
    /// Record payload.
    pub data: RecordData,
}

impl ResourceRecord {
    /// Returns the numeric record type.
    #[must_use]
    pub fn record_type(&self) -> u16 {
        self.data.record_type()
    }
}

/// One question.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    /// Queried name.
    pub name: Name,
    /// Queried record type.
    pub query_type: u16,
    /// Queried class, unicast-response bit excluded.
    pub query_class: u16,
    /// Whether the mDNS unicast-response bit is set.
    pub unicast_response: bool,
}

/// A complete DNS message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Message {
    /// Transaction identifier. mDNS uses zero.
    pub id: u16,
    /// Header flags, excluding the counts.
    pub flags: u16,
    /// Question section.
    pub questions: Vec<Question>,
    /// Answer section.
    pub answers: Vec<ResourceRecord>,
    /// Authority section.
    pub authorities: Vec<ResourceRecord>,
    /// Additional section.
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    /// Returns `true` when the `QR` bit is set.
    #[must_use]
    pub fn is_response(&self) -> bool {
        self.flags & FLAG_RESPONSE != 0
    }

    /// Returns `true` when the `TC` bit is set.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.flags & FLAG_TRUNCATED != 0
    }

    /// Returns every record in answer, authority and additional order.
    #[must_use]
    pub fn records(&self) -> Vec<&ResourceRecord> {
        self.answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.additionals.iter())
            .collect()
    }

    /// Encodes the message, compressing every name suffix seen before.
    ///
    /// # Errors
    ///
    /// Returns [`DnsSdError::SectionTooLarge`] when a section holds more than
    /// 65535 entries or a single rdata exceeds 65535 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, DnsSdError> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&section_count(self.questions.len())?.to_be_bytes());
        out.extend_from_slice(&section_count(self.answers.len())?.to_be_bytes());
        out.extend_from_slice(&section_count(self.authorities.len())?.to_be_bytes());
        out.extend_from_slice(&section_count(self.additionals.len())?.to_be_bytes());

        let mut offsets: BTreeMap<Vec<u8>, u16> = BTreeMap::new();
        for question in &self.questions {
            encode_name(&mut out, &question.name, &mut offsets);
            out.extend_from_slice(&question.query_type.to_be_bytes());
            let class = question.query_class
                | if question.unicast_response {
                    UNICAST_RESPONSE
                } else {
                    0
                };
            out.extend_from_slice(&class.to_be_bytes());
        }
        for record in self
            .answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.additionals.iter())
        {
            encode_record(&mut out, record, &mut offsets)?;
        }
        Ok(out)
    }

    /// Decodes a message from the wire.
    ///
    /// # Errors
    ///
    /// Returns [`DnsSdError::Truncated`] for a short buffer,
    /// [`DnsSdError::BadPointer`] for a compression pointer that does not point
    /// strictly backwards, [`DnsSdError::NameTooLong`] when an expansion runs
    /// past 255 bytes and [`DnsSdError::TrailingBytes`] when bytes remain after
    /// the declared sections.
    pub fn decode(bytes: &[u8]) -> Result<Self, DnsSdError> {
        if bytes.len() < 12 {
            return Err(DnsSdError::Truncated);
        }
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let counts = [
            usize::from(u16::from_be_bytes([bytes[4], bytes[5]])),
            usize::from(u16::from_be_bytes([bytes[6], bytes[7]])),
            usize::from(u16::from_be_bytes([bytes[8], bytes[9]])),
            usize::from(u16::from_be_bytes([bytes[10], bytes[11]])),
        ];
        let mut cursor = 12usize;
        let mut questions = Vec::with_capacity(counts[0].min(64));
        for _ in 0..counts[0] {
            let name = decode_name(bytes, &mut cursor)?;
            let query_type = read_u16(bytes, &mut cursor)?;
            let raw_class = read_u16(bytes, &mut cursor)?;
            questions.push(Question {
                name,
                query_type,
                query_class: raw_class & !UNICAST_RESPONSE,
                unicast_response: raw_class & UNICAST_RESPONSE != 0,
            });
        }
        let answers = decode_records(bytes, &mut cursor, counts[1])?;
        let authorities = decode_records(bytes, &mut cursor, counts[2])?;
        let additionals = decode_records(bytes, &mut cursor, counts[3])?;
        if cursor != bytes.len() {
            return Err(DnsSdError::TrailingBytes);
        }
        Ok(Self {
            id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

fn section_count(value: usize) -> Result<u16, DnsSdError> {
    u16::try_from(value).map_err(|_| DnsSdError::SectionTooLarge(value))
}

fn encode_name(out: &mut Vec<u8>, name: &Name, offsets: &mut BTreeMap<Vec<u8>, u16>) {
    let labels = name.labels();
    for index in 0..labels.len() {
        let suffix = suffix_key(&labels[index..]);
        if let Some(&offset) = offsets.get(&suffix) {
            out.extend_from_slice(&(offset | 0xc000).to_be_bytes());
            return;
        }
        if out.len() <= MAX_POINTER_OFFSET {
            // Only an offset that fits in 14 bits can ever be pointed at.
            let offset = u16::try_from(out.len()).unwrap_or(u16::MAX);
            offsets.insert(suffix, offset);
        }
        // Label length is bounded by Name::validate.
        let length = u8::try_from(labels[index].len()).unwrap_or(u8::MAX);
        out.push(length);
        out.extend_from_slice(&labels[index]);
    }
    out.push(0);
}

fn suffix_key(labels: &[Vec<u8>]) -> Vec<u8> {
    let mut key = Vec::new();
    for label in labels {
        key.extend(label.iter().map(u8::to_ascii_lowercase));
        key.push(b'.');
    }
    key
}

fn encode_record(
    out: &mut Vec<u8>,
    record: &ResourceRecord,
    offsets: &mut BTreeMap<Vec<u8>, u16>,
) -> Result<(), DnsSdError> {
    encode_name(out, &record.name, offsets);
    out.extend_from_slice(&record.record_type().to_be_bytes());
    let class = record.class | if record.cache_flush { CACHE_FLUSH } else { 0 };
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&record.ttl.to_be_bytes());

    let length_position = out.len();
    out.extend_from_slice(&[0, 0]);
    match &record.data {
        RecordData::A(address) => out.extend_from_slice(&address.octets()),
        RecordData::Aaaa(address) => out.extend_from_slice(&address.octets()),
        RecordData::Ptr(target) => encode_name(out, target, offsets),
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            // RFC 2782 forbids compressing an SRV target, so no offsets are
            // consulted or recorded for it.
            let mut untracked = BTreeMap::new();
            encode_name(out, target, &mut untracked);
        }
        RecordData::Txt(txt) => out.extend_from_slice(&txt.encode()),
        RecordData::Other { rdata, .. } => out.extend_from_slice(rdata),
    }
    let rdata_len = out.len() - length_position - 2;
    let rdata_len = u16::try_from(rdata_len).map_err(|_| DnsSdError::SectionTooLarge(rdata_len))?;
    out[length_position..length_position + 2].copy_from_slice(&rdata_len.to_be_bytes());
    Ok(())
}

fn decode_records(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<ResourceRecord>, DnsSdError> {
    let mut records = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        let name = decode_name(bytes, cursor)?;
        let record_type = read_u16(bytes, cursor)?;
        let raw_class = read_u16(bytes, cursor)?;
        let ttl = read_u32(bytes, cursor)?;
        let rdata_len = usize::from(read_u16(bytes, cursor)?);
        let rdata_end = cursor.checked_add(rdata_len).ok_or(DnsSdError::Truncated)?;
        if rdata_end > bytes.len() {
            return Err(DnsSdError::Truncated);
        }
        let rdata = &bytes[*cursor..rdata_end];
        let data = decode_rdata(bytes, record_type, rdata, *cursor)?;
        *cursor = rdata_end;
        records.push(ResourceRecord {
            name,
            class: raw_class & !CACHE_FLUSH,
            cache_flush: raw_class & CACHE_FLUSH != 0,
            ttl,
            data,
        });
    }
    Ok(records)
}

fn decode_rdata(
    message: &[u8],
    record_type: u16,
    rdata: &[u8],
    rdata_start: usize,
) -> Result<RecordData, DnsSdError> {
    match record_type {
        TYPE_A => {
            let octets: [u8; 4] = rdata.try_into().map_err(|_| DnsSdError::BadRdata(TYPE_A))?;
            Ok(RecordData::A(Ipv4Addr::from(octets)))
        }
        TYPE_AAAA => {
            let octets: [u8; 16] = rdata
                .try_into()
                .map_err(|_| DnsSdError::BadRdata(TYPE_AAAA))?;
            Ok(RecordData::Aaaa(Ipv6Addr::from(octets)))
        }
        TYPE_PTR => {
            let mut inner = rdata_start;
            let target = decode_name(message, &mut inner)?;
            if inner != rdata_start + rdata.len() {
                return Err(DnsSdError::BadRdata(TYPE_PTR));
            }
            Ok(RecordData::Ptr(target))
        }
        TYPE_SRV => {
            if rdata.len() < 7 {
                return Err(DnsSdError::BadRdata(TYPE_SRV));
            }
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let mut inner = rdata_start + 6;
            let target = decode_name(message, &mut inner)?;
            if inner != rdata_start + rdata.len() {
                return Err(DnsSdError::BadRdata(TYPE_SRV));
            }
            Ok(RecordData::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        TYPE_TXT => Ok(RecordData::Txt(TxtRecord::decode(rdata)?)),
        other => Ok(RecordData::Other {
            record_type: other,
            rdata: rdata.to_vec(),
        }),
    }
}

fn decode_name(bytes: &[u8], cursor: &mut usize) -> Result<Name, DnsSdError> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut position = *cursor;
    let mut followed_pointer = false;
    let mut budget = MAX_NAME_BYTES;

    loop {
        let length_byte = *bytes.get(position).ok_or(DnsSdError::Truncated)?;
        if length_byte & POINTER_MASK == POINTER_MASK {
            let second = *bytes.get(position + 1).ok_or(DnsSdError::Truncated)?;
            let target = usize::from(u16::from_be_bytes([length_byte & !POINTER_MASK, second]));
            // A pointer must move strictly backwards. Combined with the 255-byte
            // budget every label consumes, that makes the walk provably
            // terminating: pointer-only chains strictly decrease, and any cycle
            // that runs through a label exhausts the budget instead of spinning.
            if target >= position {
                return Err(DnsSdError::BadPointer);
            }
            if !followed_pointer {
                *cursor = position + 2;
                followed_pointer = true;
            }
            position = target;
            continue;
        }
        if length_byte & POINTER_MASK != 0 {
            return Err(DnsSdError::BadPointer);
        }
        let length = usize::from(length_byte);
        if length == 0 {
            if !followed_pointer {
                *cursor = position + 1;
            }
            break;
        }
        budget = budget
            .checked_sub(length + 1)
            .ok_or(DnsSdError::NameTooLong(MAX_NAME_BYTES + 1))?;
        let start = position + 1;
        let end = start.checked_add(length).ok_or(DnsSdError::Truncated)?;
        if end > bytes.len() {
            return Err(DnsSdError::Truncated);
        }
        labels.push(bytes[start..end].to_vec());
        position = end;
    }
    Name::from_labels(labels)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, DnsSdError> {
    let end = cursor.checked_add(2).ok_or(DnsSdError::Truncated)?;
    if end > bytes.len() {
        return Err(DnsSdError::Truncated);
    }
    let value = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]);
    *cursor = end;
    Ok(value)
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, DnsSdError> {
    let end = cursor.checked_add(4).ok_or(DnsSdError::Truncated)?;
    if end > bytes.len() {
        return Err(DnsSdError::Truncated);
    }
    let value = u32::from_be_bytes([
        bytes[*cursor],
        bytes[*cursor + 1],
        bytes[*cursor + 2],
        bytes[*cursor + 3],
    ]);
    *cursor = end;
    Ok(value)
}
