//! DNS-SD and multicast DNS wire contracts.
//!
//! The modules here implement the byte-level side of RFC 1035, RFC 6762 and
//! RFC 6763 with no I/O at all, so an advertisement, a browse query, a poisoned
//! response and a wide-area resolution chain can all be asserted against exact
//! pinned bytes on any runner.

pub mod message;
pub mod name;
pub mod service;
pub mod txt;

use core::fmt;
use std::error::Error;

pub use message::{Message, Question, RecordData, ResourceRecord};
pub use name::Name;
pub use service::{ResolvedService, ServiceAdvertisement};
pub use txt::{TxtRecord, TxtValue};

/// Every way a DNS-SD encode, decode or resolution can fail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsSdError {
    /// A label had zero length outside the root position.
    EmptyLabel,
    /// A label exceeded 63 bytes.
    LabelTooLong(usize),
    /// An encoded name exceeded 255 bytes.
    NameTooLong(usize),
    /// A presentation-form escape was truncated or not three decimal digits.
    BadEscape,
    /// A TXT character string exceeded 255 bytes.
    CharacterStringTooLong(usize),
    /// A TXT key was empty or held a byte outside printable US-ASCII minus `=`.
    InvalidTxtKey(String),
    /// A TXT record carried zero rdata bytes, which RFC 6763 forbids.
    EmptyTxtRdata,
    /// The buffer ended in the middle of a field.
    Truncated,
    /// Bytes remained after every declared section had been decoded.
    TrailingBytes,
    /// A raw DNS message exceeded the 16-bit transport length ceiling.
    MessageTooLarge {
        /// Bytes presented or produced.
        actual: usize,
        /// Maximum raw DNS message bytes.
        limit: usize,
    },
    /// Header section counts cannot fit in the bytes that follow the header.
    ImpossibleSectionCounts {
        /// Declared question count.
        questions: usize,
        /// Declared answer, authority and additional record count.
        records: usize,
        /// Bytes available after the header.
        available: usize,
    },
    /// A compression pointer did not point strictly backwards, or a label
    /// length byte used a reserved high-bit pattern.
    BadPointer,
    /// One encoded name exceeded the compression-pointer hop ceiling.
    CompressionPointerLimit {
        /// Maximum pointer hops accepted for one expanded name.
        limit: usize,
    },
    /// Expanding compressed names exhausted the message-wide decode-work budget.
    DecodeWorkLimit {
        /// Maximum units of name-decode work allowed for this message.
        limit: usize,
    },
    /// The rdata of the named record type had the wrong shape.
    BadRdata(u16),
    /// A section held more entries, or an rdata more bytes, than the wire
    /// format can express.
    SectionTooLarge(usize),
    /// Resolution was attempted on a message without the QR bit set.
    NotAResponse,
    /// A record was outside the zone the answer was solicited from.
    OutOfBailiwick(String),
    /// A required record of the named type was missing for the named owner.
    MissingRecord(String, u16),
    /// Two records of the named type disagreed for the named owner.
    ConflictingRecords(String, u16),
    /// No conflict-free instance name existed below the search limit.
    NoFreeInstanceName(String),
}

impl fmt::Display for DnsSdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLabel => formatter.write_str("DNS label is empty"),
            Self::LabelTooLong(length) => {
                write!(formatter, "DNS label is {length} bytes, limit is 63")
            }
            Self::NameTooLong(length) => {
                write!(formatter, "DNS name is {length} bytes, limit is 255")
            }
            Self::BadEscape => formatter.write_str("malformed presentation-form escape"),
            Self::CharacterStringTooLong(length) => write!(
                formatter,
                "TXT character string is {length} bytes, limit is 255"
            ),
            Self::InvalidTxtKey(key) => write!(formatter, "invalid TXT key {key:?}"),
            Self::EmptyTxtRdata => formatter.write_str("TXT record carried zero rdata bytes"),
            Self::Truncated => formatter.write_str("DNS message ended mid-field"),
            Self::TrailingBytes => {
                formatter.write_str("DNS message had bytes after the declared sections")
            }
            Self::MessageTooLarge { actual, limit } => {
                write!(formatter, "DNS message is {actual} bytes, limit is {limit}")
            }
            Self::ImpossibleSectionCounts {
                questions,
                records,
                available,
            } => write!(
                formatter,
                "DNS header declares {questions} questions and {records} records, which cannot fit \
                 in the {available} bytes after the header"
            ),
            Self::BadPointer => {
                formatter.write_str("DNS name compression pointer did not point strictly backwards")
            }
            Self::CompressionPointerLimit { limit } => {
                write!(
                    formatter,
                    "DNS name compression exceeded the {limit}-pointer hop limit"
                )
            }
            Self::DecodeWorkLimit { limit } => {
                write!(
                    formatter,
                    "DNS name expansion exceeded the {limit}-unit message decode budget"
                )
            }
            Self::BadRdata(record_type) => {
                write!(formatter, "malformed rdata for record type {record_type}")
            }
            Self::SectionTooLarge(length) => {
                write!(
                    formatter,
                    "DNS section or rdata of {length} does not fit the wire format"
                )
            }
            Self::NotAResponse => formatter.write_str("DNS message is not a response"),
            Self::OutOfBailiwick(name) => {
                write!(formatter, "record owner {name} is outside the queried zone")
            }
            Self::MissingRecord(owner, record_type) => write!(
                formatter,
                "no record of type {record_type} for owner {owner}"
            ),
            Self::ConflictingRecords(owner, record_type) => write!(
                formatter,
                "conflicting records of type {record_type} for owner {owner}"
            ),
            Self::NoFreeInstanceName(desired) => {
                write!(formatter, "no conflict-free instance name for {desired:?}")
            }
        }
    }
}

impl Error for DnsSdError {}
