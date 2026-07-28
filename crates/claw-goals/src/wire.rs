//! The on-disk encoding of a durable goal.
//!
//! [`GoalRecord`] lives in `claw-application`, which deliberately carries no serialisation
//! dependency, so the persisted shape is owned here instead. Keeping it here also means the file
//! format is a decision of the adapter rather than an accident of a struct definition: fields are
//! named explicitly, statuses are written as their frozen labels, and the envelope carries a
//! schema number so a future format change is a decode error rather than a silent misread.
//!
//! Decoding re-validates every invariant the writer is supposed to have upheld. A goal file is
//! the only surviving evidence of a session's intent, so a corrupted one must be reported, never
//! interpreted.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_application::model::goal::{GoalProgress, GoalRecord, GoalStatus};
use claw_application::model::ids::GoalId;
use claw_application::model::time::Timestamp;
use claw_domain::SessionId;
use serde::{Deserialize, Serialize};

/// The schema number written into every goal file this crate produces.
pub const SCHEMA_VERSION: u32 = 1;

/// The persisted form of one progress entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProgressEnvelope {
    index: u64,
    note: String,
    recorded_at_millis: i64,
    compacted: bool,
}

/// The write-side mirror of [`ProgressEnvelope`], borrowing the note.
///
/// The field set, the names and the declaration order are the same, so the
/// bytes are the same.
#[derive(Serialize)]
struct ProgressEnvelopeRef<'a> {
    index: u64,
    note: &'a str,
    recorded_at_millis: i64,
    compacted: bool,
}

/// The persisted form of one goal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GoalEnvelope {
    schema: u32,
    goal_id: String,
    session_id: String,
    objective: String,
    status: String,
    created_at_millis: i64,
    updated_at_millis: i64,
    closed_at_millis: Option<i64>,
    compacted_entries: u64,
    revision: u64,
    progress: Vec<ProgressEnvelope>,
}

/// The write-side mirror of [`GoalEnvelope`], borrowing every string.
///
/// [`encode`] used to build an owned [`GoalEnvelope`] purely to hand it to
/// `serde_json`, which copied the objective, both identifiers, the status label
/// and every progress note — up to a quarter of a megabyte of copying whose
/// only consumer was the serializer that immediately copied it again into the
/// output buffer. The field set, the names and the declaration order are
/// identical, and the workspace builds `serde_json` with `preserve_order`, so
/// the bytes this produces are the bytes the owned envelope produced.
#[derive(Serialize)]
struct GoalEnvelopeRef<'a> {
    schema: u32,
    goal_id: &'a str,
    session_id: &'a str,
    objective: &'a str,
    status: &'a str,
    created_at_millis: i64,
    updated_at_millis: i64,
    closed_at_millis: Option<i64>,
    compacted_entries: u64,
    revision: u64,
    progress: ProgressSeq<'a>,
}

/// Serializes a record's progress history straight out of the record.
///
/// A `Vec` of borrowing envelopes would still allocate one vector per encode;
/// this streams the same JSON array from the slice the record already holds.
struct ProgressSeq<'a>(&'a [GoalProgress]);

impl Serialize for ProgressSeq<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|entry| ProgressEnvelopeRef {
            index: entry.index,
            note: &entry.note,
            recorded_at_millis: entry.recorded_at.as_millis(),
            compacted: entry.compacted,
        }))
    }
}

/// A goal file that could not be turned back into a [`GoalRecord`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    /// The bytes were not the JSON object this crate writes.
    Malformed(String),
    /// The envelope carries a schema this build does not understand.
    UnsupportedSchema {
        /// The schema this build writes and reads.
        expected: u32,
        /// The schema the file carries.
        found: u32,
    },
    /// A field was present but violated a goal invariant.
    Invalid {
        /// The offending field.
        field: &'static str,
        /// Why it was rejected.
        reason: String,
    },
}

impl Display for WireError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(detail) => write!(formatter, "malformed goal record: {detail}"),
            Self::UnsupportedSchema { expected, found } => write!(
                formatter,
                "goal record schema {found} is not the supported schema {expected}"
            ),
            Self::Invalid { field, reason } => {
                write!(formatter, "goal record field {field} is invalid: {reason}")
            }
        }
    }
}

impl Error for WireError {}

fn invalid(field: &'static str, reason: impl Into<String>) -> WireError {
    WireError::Invalid {
        field,
        reason: reason.into(),
    }
}

fn status_from_label(label: &str) -> Option<GoalStatus> {
    GoalStatus::ALL
        .into_iter()
        .find(|status| status.label() == label)
}

/// Encodes one goal as the bytes written to disk.
///
/// The output is pretty-printed with a trailing newline: a goal file is the artefact an operator
/// reaches for when a session went wrong, and an unreadable one is a worse trade than a few
/// hundred extra bytes.
///
/// # Errors
///
/// Returns [`WireError::Malformed`] only if `serde_json` cannot serialise the envelope, which
/// requires a serializer failure rather than any property of the record.
pub fn encode(record: &GoalRecord) -> Result<String, WireError> {
    let envelope = GoalEnvelopeRef {
        schema: SCHEMA_VERSION,
        goal_id: record.goal_id.as_str(),
        session_id: record.session_id.as_str(),
        objective: &record.objective,
        status: record.status.label(),
        created_at_millis: record.created_at.as_millis(),
        updated_at_millis: record.updated_at.as_millis(),
        closed_at_millis: record.closed_at.map(Timestamp::as_millis),
        compacted_entries: record.compacted_entries,
        revision: record.revision,
        progress: ProgressSeq(&record.progress),
    };

    let mut text = serde_json::to_string_pretty(&envelope)
        .map_err(|error| WireError::Malformed(error.to_string()))?;
    text.push('\n');
    Ok(text)
}

/// Decodes one goal file, re-validating every invariant the writer should have upheld.
///
/// # Errors
///
/// Returns [`WireError::Malformed`] when the text is not the expected JSON object,
/// [`WireError::UnsupportedSchema`] when it was written by a different format version, and
/// [`WireError::Invalid`] when a field breaks a goal invariant: an unusable identifier, a blank
/// objective, a revision of zero, an unknown status label, a closed status without a closing
/// timestamp (or an active status with one), or progress indices that do not strictly increase.
pub fn decode(text: &str) -> Result<GoalRecord, WireError> {
    let envelope: GoalEnvelope =
        serde_json::from_str(text).map_err(|error| WireError::Malformed(error.to_string()))?;

    if envelope.schema != SCHEMA_VERSION {
        return Err(WireError::UnsupportedSchema {
            expected: SCHEMA_VERSION,
            found: envelope.schema,
        });
    }

    let goal_id =
        GoalId::new(&envelope.goal_id).map_err(|error| invalid("goal_id", error.to_string()))?;
    let session_id = SessionId::new(envelope.session_id.clone())
        .map_err(|error| invalid("session_id", error.to_string()))?;

    if envelope.objective.trim().is_empty() {
        return Err(invalid("objective", "must not be blank"));
    }
    if envelope.revision == 0 {
        return Err(invalid("revision", "must be at least 1"));
    }

    let status = status_from_label(&envelope.status)
        .ok_or_else(|| invalid("status", format!("unknown status {}", envelope.status)))?;

    let closed_at = envelope.closed_at_millis.map(Timestamp::from_millis);
    match (status.is_closed(), closed_at.is_some()) {
        (true, false) => return Err(invalid("closed_at_millis", "a closed goal must carry one")),
        (false, true) => {
            return Err(invalid(
                "closed_at_millis",
                "an active goal must not carry one",
            ));
        }
        _ => {}
    }

    let mut progress = Vec::with_capacity(envelope.progress.len());
    let mut previous: Option<u64> = None;
    for entry in envelope.progress {
        if let Some(previous) = previous
            && entry.index <= previous
        {
            return Err(invalid("progress", "indices must strictly increase"));
        }
        if entry.note.trim().is_empty() {
            return Err(invalid("progress", "a note must not be blank"));
        }
        previous = Some(entry.index);
        progress.push(GoalProgress {
            index: entry.index,
            note: entry.note,
            recorded_at: Timestamp::from_millis(entry.recorded_at_millis),
            compacted: entry.compacted,
        });
    }

    Ok(GoalRecord {
        goal_id,
        session_id,
        objective: envelope.objective,
        status,
        progress,
        created_at: Timestamp::from_millis(envelope.created_at_millis),
        updated_at: Timestamp::from_millis(envelope.updated_at_millis),
        closed_at,
        compacted_entries: envelope.compacted_entries,
        revision: envelope.revision,
    })
}

#[cfg(test)]
mod tests {
    use super::{SCHEMA_VERSION, WireError, decode, encode};
    use claw_application::model::goal::{GoalProgress, GoalRecord, GoalStatus};
    use claw_application::model::ids::GoalId;
    use claw_application::model::time::Timestamp;
    use claw_domain::SessionId;

    fn record() -> GoalRecord {
        GoalRecord {
            goal_id: GoalId::new("s:goal-1").expect("valid goal id"),
            session_id: SessionId::new("s").expect("valid session id"),
            objective: "ship the adapter".to_owned(),
            status: GoalStatus::Active,
            progress: vec![
                GoalProgress {
                    index: 0,
                    note: "wrote the store".to_owned(),
                    recorded_at: Timestamp::from_millis(10),
                    compacted: false,
                },
                GoalProgress {
                    index: 1,
                    note: "wrote the tests".to_owned(),
                    recorded_at: Timestamp::from_millis(20),
                    compacted: false,
                },
            ],
            created_at: Timestamp::from_millis(1),
            updated_at: Timestamp::from_millis(20),
            closed_at: None,
            compacted_entries: 0,
            revision: 3,
        }
    }

    #[test]
    fn a_record_round_trips_through_the_encoding() {
        let original = record();
        let encoded = encode(&original).expect("record encodes");

        assert_eq!(decode(&encoded).expect("record decodes"), original);
    }

    #[test]
    fn a_closed_record_round_trips_with_its_closing_timestamp() {
        let mut original = record();
        original.status = GoalStatus::Achieved;
        original.closed_at = Some(Timestamp::from_millis(99));
        let encoded = encode(&original).expect("record encodes");

        assert_eq!(decode(&encoded).expect("record decodes"), original);
    }

    #[test]
    fn the_encoding_names_every_field_and_writes_status_labels() {
        let encoded = encode(&record()).expect("record encodes");
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("valid json");

        assert_eq!(value["schema"], SCHEMA_VERSION);
        assert_eq!(value["goal_id"], "s:goal-1");
        assert_eq!(value["session_id"], "s");
        assert_eq!(value["status"], "active");
        assert_eq!(value["closed_at_millis"], serde_json::Value::Null);
        assert_eq!(value["revision"], 3);
        assert_eq!(value["progress"][1]["note"], "wrote the tests");
        assert!(encoded.ends_with('\n'));
    }

    #[test]
    fn a_foreign_schema_is_refused_rather_than_guessed_at() {
        let encoded = encode(&record()).expect("record encodes");
        let bumped = encoded.replace("\"schema\": 1", "\"schema\": 2");

        assert_eq!(
            decode(&bumped),
            Err(WireError::UnsupportedSchema {
                expected: 1,
                found: 2,
            })
        );
    }

    #[test]
    fn an_unknown_status_label_is_refused() {
        let encoded = encode(&record()).expect("record encodes");
        let tampered = encoded.replace("\"active\"", "\"paused\"");

        assert_eq!(
            decode(&tampered),
            Err(WireError::Invalid {
                field: "status",
                reason: "unknown status paused".to_owned(),
            })
        );
    }

    #[test]
    fn a_closed_goal_without_a_closing_timestamp_is_refused() {
        let encoded = encode(&record()).expect("record encodes");
        let tampered = encoded.replace("\"active\"", "\"achieved\"");

        assert_eq!(
            decode(&tampered),
            Err(WireError::Invalid {
                field: "closed_at_millis",
                reason: "a closed goal must carry one".to_owned(),
            })
        );
    }

    #[test]
    fn an_active_goal_carrying_a_closing_timestamp_is_refused() {
        let encoded = encode(&record()).expect("record encodes");
        let tampered = encoded.replace("\"closed_at_millis\": null", "\"closed_at_millis\": 5");

        assert_eq!(
            decode(&tampered),
            Err(WireError::Invalid {
                field: "closed_at_millis",
                reason: "an active goal must not carry one".to_owned(),
            })
        );
    }

    #[test]
    fn out_of_order_progress_indices_are_refused() {
        let mut original = record();
        original.progress[1].index = 0;
        let encoded = encode(&original).expect("record encodes");

        assert_eq!(
            decode(&encoded),
            Err(WireError::Invalid {
                field: "progress",
                reason: "indices must strictly increase".to_owned(),
            })
        );
    }

    #[test]
    fn a_blank_objective_and_a_zero_revision_are_refused() {
        let mut blank = record();
        blank.objective = "   ".to_owned();
        assert_eq!(
            decode(&encode(&blank).expect("encodes")),
            Err(WireError::Invalid {
                field: "objective",
                reason: "must not be blank".to_owned(),
            })
        );

        let mut unversioned = record();
        unversioned.revision = 0;
        assert_eq!(
            decode(&encode(&unversioned).expect("encodes")),
            Err(WireError::Invalid {
                field: "revision",
                reason: "must be at least 1".to_owned(),
            })
        );
    }

    #[test]
    fn truncated_bytes_are_reported_rather_than_interpreted() {
        let encoded = encode(&record()).expect("record encodes");
        let truncated = &encoded[..encoded.len() / 2];

        assert!(matches!(decode(truncated), Err(WireError::Malformed(_))));
    }

    #[test]
    fn a_blank_identifier_is_refused() {
        let encoded = encode(&record()).expect("record encodes");
        let tampered = encoded.replace("\"goal_id\": \"s:goal-1\"", "\"goal_id\": \"\"");

        assert!(matches!(
            decode(&tampered),
            Err(WireError::Invalid {
                field: "goal_id",
                ..
            })
        ));
    }
}
