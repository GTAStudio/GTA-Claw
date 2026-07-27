//! Pinned Gateway core event catalog projections and fail-closed envelopes.
//!
//! The catalog itself is generated at build time from the validator-owned
//! inventory `compat/upstream/inventories/gateway-protocol.json`, which pins
//! `src/gateway/server-methods-list.ts` and `src/gateway/events.ts` at
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`.
//!
//! Two things live here. [`core_event_envelope`] is the fail-closed constructor
//! for the `{"type":"event", ...}` envelope: it refuses any identity that is not
//! in the pinned catalog, so an emitter cannot invent a core event name, while
//! the decoder still accepts schema-permitted extension events. The pinned
//! inventory records event identities only, so nothing here claims a per-event
//! payload shape; the envelope fields are the contract this catalog covers.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::gateway::{
    EventFrame, EventName, EventSequence, OpaqueField, StateVersion, core_events,
    resolve_core_event,
};

/// Returns every generated core event identity in canonical inventory order.
pub fn event_names() -> impl Iterator<Item = &'static str> {
    core_events().iter().map(|event| event.name())
}

/// Returns the number of generated core events.
#[must_use]
pub fn event_count() -> usize {
    core_events().len()
}

/// Reports whether this exact identity is a pinned core event.
#[must_use]
pub fn is_core_event(name: &str) -> bool {
    resolve_core_event(name).is_some()
}

/// Classifies an exact identity as a pinned core event name.
///
/// Returns `None` for anything outside the catalog rather than falling back to
/// [`EventName::Extension`], so a caller that means "core event" cannot silently
/// emit an extension.
#[must_use]
pub fn core_event_name(name: &str) -> Option<EventName> {
    resolve_core_event(name).map(EventName::Core)
}

/// Builds an event envelope for a pinned core event.
///
/// # Errors
///
/// Returns [`EventCatalogError::UnknownEvent`] when the identity is not in the
/// pinned catalog.
pub fn core_event_envelope(
    name: &str,
    payload: OpaqueField,
    sequence: Option<EventSequence>,
    state_version: Option<StateVersion>,
) -> Result<EventFrame, EventCatalogError> {
    let event = core_event_name(name).ok_or_else(|| EventCatalogError::UnknownEvent {
        name: name.to_owned(),
    })?;
    Ok(EventFrame::new(event, payload, sequence, state_version))
}

/// A refusal to build an envelope for an identity outside the pinned catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventCatalogError {
    /// The identity is not a pinned core event.
    UnknownEvent {
        /// The rejected identity.
        name: String,
    },
}

impl Display for EventCatalogError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownEvent { name } => {
                write!(formatter, "`{name}` is not a pinned core gateway event")
            }
        }
    }
}

impl Error for EventCatalogError {}

/// The first exact difference between the generated catalog and pinned rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventCatalogDrift {
    /// The catalog and the pinned rows have different lengths.
    Count {
        /// Number of generated events.
        generated: usize,
        /// Number of pinned rows.
        pinned: usize,
    },
    /// A pinned row repeated an identity already supplied.
    DuplicateName {
        /// The repeated identity.
        name: String,
    },
    /// Canonical order or membership diverged at this position.
    Name {
        /// Zero-based canonical position.
        position: usize,
        /// Generated identity at that position.
        generated: &'static str,
        /// Pinned identity at that position.
        pinned: String,
    },
    /// A generated event could not be resolved back by its own identity.
    Unresolvable {
        /// The unresolvable identity.
        name: &'static str,
    },
}

impl Display for EventCatalogDrift {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count { generated, pinned } => write!(
                formatter,
                "catalog holds {generated} events; pinned inventory holds {pinned}"
            ),
            Self::DuplicateName { name } => {
                write!(formatter, "pinned event `{name}` is supplied twice")
            }
            Self::Name {
                position,
                generated,
                pinned,
            } => write!(
                formatter,
                "event {position} is `{generated}` in the catalog and `{pinned}` in the pinned inventory"
            ),
            Self::Unresolvable { name } => {
                write!(
                    formatter,
                    "catalog event `{name}` does not resolve by identity"
                )
            }
        }
    }
}

impl Error for EventCatalogDrift {}

/// Compares the generated event catalog against pinned identities, in order.
///
/// # Errors
///
/// Returns the first [`EventCatalogDrift`] observed.
pub fn verify_pinned_events<'a, I>(pinned: I) -> Result<(), EventCatalogDrift>
where
    I: IntoIterator<Item = &'a str>,
{
    let generated = core_events();
    let pinned = pinned.into_iter().collect::<Vec<_>>();
    if pinned.len() != generated.len() {
        return Err(EventCatalogDrift::Count {
            generated: generated.len(),
            pinned: pinned.len(),
        });
    }

    let mut seen = BTreeSet::new();
    for (position, name) in pinned.iter().copied().enumerate() {
        let entry = generated[position];
        if !seen.insert(name) {
            return Err(EventCatalogDrift::DuplicateName {
                name: name.to_owned(),
            });
        }
        if entry.name() != name {
            return Err(EventCatalogDrift::Name {
                position,
                generated: entry.name(),
                pinned: name.to_owned(),
            });
        }
        if resolve_core_event(entry.name()).map(|event| event.name()) != Some(entry.name()) {
            return Err(EventCatalogDrift::Unresolvable { name: entry.name() });
        }
    }
    Ok(())
}
