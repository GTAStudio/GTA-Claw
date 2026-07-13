use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::rc::Rc;

use serde::Deserializer;
use serde::de::{DeserializeOwned, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};

use super::frame::{
    ConnectChallenge, ConnectParams, EventSequence, EventWire, FrameValidationError, HelloOk,
    KindProbe, OpaqueField, RequestWire, ResponseWire, ShutdownEvent, TickEvent, Validate,
    classify_method,
};
use super::{
    DynamicPluginRegistry, EventFrame, Frame, FrameKind, RequestFrame, RequestId, ResponseFrame,
    TransportPhase, ValidationPolicy,
};

/// Transport-independent strict JSON codec for Gateway frames and handshake DTOs.
#[derive(Clone, Debug)]
pub struct Codec {
    phase: TransportPhase,
    policy: ValidationPolicy,
    dynamic_methods: BTreeMap<String, ()>,
}

impl Codec {
    /// Creates a codec for a phase and explicit validation policy.
    pub fn new(phase: TransportPhase, policy: ValidationPolicy) -> Result<Self, CodecError> {
        policy.validate().map_err(CodecError::InvalidPolicy)?;
        Ok(Self {
            phase,
            policy,
            dynamic_methods: BTreeMap::new(),
        })
    }

    /// Creates a pre-authentication codec using mechanically derived defaults.
    #[must_use]
    pub fn preauthentication() -> Self {
        Self::new(
            TransportPhase::PreAuthentication,
            ValidationPolicy::for_phase(TransportPhase::PreAuthentication),
        )
        .expect("mechanically derived policy is valid")
    }

    /// Creates an authenticated codec using mechanically derived defaults.
    #[must_use]
    pub fn authenticated() -> Self {
        Self::new(
            TransportPhase::Authenticated,
            ValidationPolicy::for_phase(TransportPhase::Authenticated),
        )
        .expect("mechanically derived policy is valid")
    }

    /// Explicitly opts this codec into the supplied, already-validated plugin registry.
    pub fn allow_dynamic_plugins(
        mut self,
        registry: &DynamicPluginRegistry,
    ) -> Result<Self, CodecError> {
        let count = registry.len();
        if count > self.policy.max_collection_items {
            return Err(CodecError::PolicyLimit {
                path: "$dynamicMethods".to_owned(),
                actual: count,
                limit: self.policy.max_collection_items,
            });
        }
        self.dynamic_methods
            .extend(registry.names().map(|name| (name.to_owned(), ())));
        Ok(self)
    }

    /// Returns the transport phase.
    #[must_use]
    pub const fn phase(&self) -> TransportPhase {
        self.phase
    }

    /// Returns the active explicit validation policy.
    #[must_use]
    pub const fn policy(&self) -> &ValidationPolicy {
        &self.policy
    }

    /// Strictly decodes one complete frame.
    pub fn decode(&self, bytes: &[u8]) -> Result<Frame, CodecError> {
        self.check_size(bytes.len())?;
        preflight_json(bytes, &self.policy)?;
        let probe: KindProbe = decode_typed(bytes)?;
        if let Some(field) = probe.contradictory_field() {
            return Err(CodecError::ContradictoryEnvelopeField {
                kind: probe.kind.clone(),
                field: field.to_owned(),
            });
        }
        let frame = match probe.kind.as_str() {
            "req" => {
                let wire: RequestWire = decode_typed(bytes)?;
                let (id, method, params) = wire.into_parts();
                let method = classify_method(method, &self.dynamic_methods)
                    .map_err(|name| CodecError::UnknownMethod(name.as_str().to_owned()))?;
                Frame::Request(RequestFrame::new(id, method, params))
            }
            "res" => {
                let wire: ResponseWire = decode_typed(bytes)?;
                Frame::Response(wire.into_frame())
            }
            "event" => {
                let wire: EventWire = decode_typed(bytes)?;
                Frame::Event(wire.into_frame())
            }
            unknown => return Err(CodecError::UnknownFrameKind(unknown.to_owned())),
        };
        frame
            .validate(&self.policy)
            .map_err(CodecError::from_validation)?;
        Ok(frame)
    }

    /// Decodes a response and verifies its exact correlation identifier.
    pub fn decode_response(
        &self,
        bytes: &[u8],
        expected_id: &RequestId,
    ) -> Result<ResponseFrame, CodecError> {
        match self.decode(bytes)? {
            Frame::Response(response) if response.id() == expected_id => Ok(response),
            Frame::Response(response) => Err(CodecError::ResponseIdMismatch {
                expected: expected_id.as_str().to_owned(),
                received: response.id().as_str().to_owned(),
            }),
            other => Err(CodecError::UnexpectedFrame {
                expected: FrameKind::Res,
                received: other.kind(),
            }),
        }
    }

    /// Encodes one frame and enforces the active phase cap before returning bytes.
    pub fn encode(&self, frame: &Frame) -> Result<Vec<u8>, CodecError> {
        frame
            .validate(&self.policy)
            .map_err(CodecError::from_validation)?;
        let encoded = serde_json::to_vec(frame).map_err(CodecError::Encode)?;
        self.check_size(encoded.len())?;
        preflight_json(&encoded, &self.policy)?;
        Ok(encoded)
    }

    /// Decodes connect parameters from a strict `connect` request.
    pub fn decode_connect(&self, request: &RequestFrame) -> Result<ConnectParams, CodecError> {
        if request.method().as_str() != "connect" {
            return Err(CodecError::ExpectedConnectMethod(
                request.method().as_str().to_owned(),
            ));
        }
        let params: ConnectParams = self.decode_required_opaque(request.params(), "$.params")?;
        params
            .validate(&self.policy)
            .map_err(CodecError::from_validation)?;
        Ok(params)
    }

    /// Decodes a successful hello payload from a response.
    pub fn decode_hello(&self, response: &ResponseFrame) -> Result<HelloOk, CodecError> {
        if !response.ok() {
            return Err(CodecError::UnsuccessfulResponse {
                id: response.id().as_str().to_owned(),
            });
        }
        let hello: HelloOk = self.decode_required_opaque(response.payload(), "$.payload")?;
        hello
            .validate(&self.policy)
            .map_err(CodecError::from_validation)?;
        Ok(hello)
    }

    /// Decodes a `connect.challenge` event payload.
    pub fn decode_challenge(&self, event: &EventFrame) -> Result<ConnectChallenge, CodecError> {
        if event.event().as_str() != "connect.challenge" {
            return Err(CodecError::ExpectedChallengeEvent(
                event.event().as_str().to_owned(),
            ));
        }
        let challenge: ConnectChallenge =
            self.decode_required_opaque(event.payload(), "$.payload")?;
        challenge
            .validate(&self.policy)
            .map_err(CodecError::from_validation)?;
        Ok(challenge)
    }

    /// Decodes a strict `tick` control event payload.
    pub fn decode_tick(&self, event: &EventFrame) -> Result<TickEvent, CodecError> {
        if event.event().as_str() != "tick" {
            return Err(CodecError::ExpectedControlEvent {
                expected: "tick",
                received: event.event().as_str().to_owned(),
            });
        }
        self.decode_required_opaque(event.payload(), "$.payload")
    }

    /// Decodes and validates a strict `shutdown` control event payload.
    pub fn decode_shutdown(&self, event: &EventFrame) -> Result<ShutdownEvent, CodecError> {
        if event.event().as_str() != "shutdown" {
            return Err(CodecError::ExpectedControlEvent {
                expected: "shutdown",
                received: event.event().as_str().to_owned(),
            });
        }
        let shutdown: ShutdownEvent = self.decode_required_opaque(event.payload(), "$.payload")?;
        shutdown
            .validate(&self.policy)
            .map_err(CodecError::from_validation)?;
        Ok(shutdown)
    }

    /// Decodes a deliberately opaque value through duplicate and path-aware checks.
    pub fn decode_opaque<T: DeserializeOwned>(
        &self,
        value: &super::OpaqueJson,
    ) -> Result<T, CodecError> {
        let bytes = value.as_json().as_bytes();
        self.check_size(bytes.len())?;
        preflight_json(bytes, &self.policy)?;
        decode_typed(bytes)
    }

    fn decode_required_opaque<T: DeserializeOwned>(
        &self,
        field: &OpaqueField,
        path: &'static str,
    ) -> Result<T, CodecError> {
        match field {
            OpaqueField::Value(value) => self.decode_opaque(value),
            OpaqueField::Omitted => Err(CodecError::MissingOpaqueField(path)),
            OpaqueField::Null => Err(CodecError::NullOpaqueField(path)),
        }
    }

    fn check_size(&self, actual: usize) -> Result<(), CodecError> {
        let limit = self.phase.max_frame_bytes();
        if actual > limit {
            Err(CodecError::FrameTooLarge {
                phase: self.phase,
                actual,
                limit,
            })
        } else {
            Ok(())
        }
    }
}

fn decode_typed<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        let path = error.path().to_string();
        let error = error.into_inner();
        CodecError::TypedDecode {
            path,
            message: error.to_string(),
            line: error.line(),
            column: error.column(),
        }
    })?;
    deserializer.end().map_err(CodecError::from_json)?;
    Ok(value)
}

#[derive(Clone, Debug)]
enum PreflightFailure {
    Duplicate {
        path: String,
        key: String,
    },
    Collection {
        path: String,
        actual: usize,
        limit: usize,
    },
    Nesting {
        path: String,
        depth: usize,
        limit: usize,
    },
    NonFinite {
        path: String,
    },
}

#[derive(Clone)]
struct PreflightSeed {
    path: String,
    depth: usize,
    policy: ValidationPolicy,
    failure: Rc<RefCell<Option<PreflightFailure>>>,
}

impl<'de> DeserializeSeed<'de> for PreflightSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PreflightVisitor(self))
    }
}

struct PreflightVisitor(PreflightSeed);

impl<'de> Visitor<'de> for PreflightVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("valid bounded JSON")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.is_finite() {
            Ok(())
        } else {
            *self.0.failure.borrow_mut() = Some(PreflightFailure::NonFinite { path: self.0.path });
            Err(E::custom("non-finite JSON number"))
        }
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.0.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.check_depth::<A::Error>()?;
        let mut count = 0;
        while sequence
            .next_element_seed(self.0.child(format!("{}[{count}]", self.0.path)))?
            .is_some()
        {
            count += 1;
            self.check_collection::<A::Error>(count)?;
        }
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        self.check_depth::<A::Error>()?;
        let mut keys = BTreeSet::new();
        let mut count = 0;
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                *self.0.failure.borrow_mut() = Some(PreflightFailure::Duplicate {
                    path: self.0.path.clone(),
                    key,
                });
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            count += 1;
            self.check_collection::<A::Error>(count)?;
            let child_path = format!("{}[{}]", self.0.path, quoted_key(&key));
            map.next_value_seed(self.0.child(child_path))?;
        }
        Ok(())
    }
}

impl PreflightVisitor {
    fn check_depth<E: serde::de::Error>(&self) -> Result<(), E> {
        if self.0.depth > self.0.policy.max_nesting_depth {
            *self.0.failure.borrow_mut() = Some(PreflightFailure::Nesting {
                path: self.0.path.clone(),
                depth: self.0.depth,
                limit: self.0.policy.max_nesting_depth,
            });
            Err(E::custom("JSON nesting policy exceeded"))
        } else {
            Ok(())
        }
    }

    fn check_collection<E: serde::de::Error>(&self, actual: usize) -> Result<(), E> {
        if actual > self.0.policy.max_collection_items {
            *self.0.failure.borrow_mut() = Some(PreflightFailure::Collection {
                path: self.0.path.clone(),
                actual,
                limit: self.0.policy.max_collection_items,
            });
            Err(E::custom("JSON collection policy exceeded"))
        } else {
            Ok(())
        }
    }
}

impl PreflightSeed {
    fn child(&self, path: String) -> Self {
        Self {
            path,
            depth: self.depth + 1,
            policy: self.policy.clone(),
            failure: Rc::clone(&self.failure),
        }
    }
}

fn quoted_key(key: &str) -> String {
    serde_json::to_string(key).expect("serializing a string cannot fail")
}

fn preflight_json(bytes: &[u8], policy: &ValidationPolicy) -> Result<(), CodecError> {
    let failure = Rc::new(RefCell::new(None));
    let seed = PreflightSeed {
        path: "$".to_owned(),
        depth: 1,
        policy: policy.clone(),
        failure: Rc::clone(&failure),
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    if let Err(error) = seed.deserialize(&mut deserializer) {
        return Err(match failure.borrow_mut().take() {
            Some(PreflightFailure::Duplicate { path, key }) => {
                CodecError::DuplicateKey { path, key }
            }
            Some(PreflightFailure::Collection {
                path,
                actual,
                limit,
            }) => CodecError::CollectionLimit {
                path,
                actual,
                limit,
            },
            Some(PreflightFailure::Nesting { path, depth, limit }) => {
                CodecError::NestingLimit { path, depth, limit }
            }
            Some(PreflightFailure::NonFinite { path }) => CodecError::NonFiniteNumber { path },
            None => CodecError::from_json(error),
        });
    }
    deserializer.end().map_err(CodecError::from_json)
}

/// Stateful checker for per-connection broadcast event sequences.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventSequenceTracker {
    last: Option<EventSequence>,
}

impl EventSequenceTracker {
    /// Creates an empty tracker expecting the first sequenced broadcast to be one.
    #[must_use]
    pub const fn new() -> Self {
        Self { last: None }
    }

    /// Observes an optional sequence.
    ///
    /// Targeted events with no sequence do not alter state. Forward gaps update
    /// the tracker to the received value before returning the typed gap.
    pub fn observe(&mut self, sequence: Option<EventSequence>) -> Result<(), EventSequenceError> {
        let Some(received) = sequence else {
            return Ok(());
        };
        let expected = match self.last {
            None => 1,
            Some(last) => last
                .get()
                .checked_add(1)
                .ok_or(EventSequenceError::Overflow { last: last.get() })?,
        };
        if received.get() > expected {
            self.last = Some(received);
            return Err(EventSequenceError::Gap {
                expected,
                received: received.get(),
            });
        }
        if received.get() < expected {
            return Err(EventSequenceError::NonMonotonic {
                last: self.last.map_or(0, EventSequence::get),
                received: received.get(),
            });
        }
        self.last = Some(received);
        Ok(())
    }

    /// Returns the last sequenced broadcast observed.
    #[must_use]
    pub const fn last(&self) -> Option<EventSequence> {
        self.last
    }
}

/// A sequence continuity failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventSequenceError {
    /// One or more broadcasts were skipped.
    Gap {
        /// Next expected sequence.
        expected: u64,
        /// Received sequence.
        received: u64,
    },
    /// A repeated or backwards sequence was observed.
    NonMonotonic {
        /// Last accepted sequence, or zero before the first event.
        last: u64,
        /// Received sequence.
        received: u64,
    },
    /// Incrementing the last sequence would overflow.
    Overflow {
        /// Last accepted sequence.
        last: u64,
    },
}

impl Display for EventSequenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gap { expected, received } => {
                write!(
                    formatter,
                    "event sequence gap: expected {expected}, received {received}"
                )
            }
            Self::NonMonotonic { last, received } => write!(
                formatter,
                "event sequence is not monotonic: last {last}, received {received}"
            ),
            Self::Overflow { last } => write!(formatter, "event sequence overflow after {last}"),
        }
    }
}

impl Error for EventSequenceError {}

/// A strict frame encoding or decoding failure.
#[derive(Debug)]
pub enum CodecError {
    /// The caller supplied an invalid validation policy.
    InvalidPolicy(super::LimitError),
    /// The frame exceeds the proven phase cap.
    FrameTooLarge {
        /// Active phase.
        phase: TransportPhase,
        /// Actual byte count.
        actual: usize,
        /// Proven byte cap.
        limit: usize,
    },
    /// JSON was malformed, trailing, or contained an out-of-range number.
    MalformedJson {
        /// Parser message.
        message: String,
        /// One-based line.
        line: usize,
        /// One-based column.
        column: usize,
    },
    /// A duplicate key occurred anywhere in the JSON tree.
    DuplicateKey {
        /// Path of the containing object.
        path: String,
        /// Repeated exact key.
        key: String,
    },
    /// A JSON collection exceeded explicit policy.
    CollectionLimit {
        /// Collection path.
        path: String,
        /// Actual observed entries.
        actual: usize,
        /// Allowed entries.
        limit: usize,
    },
    /// JSON nesting exceeded explicit policy.
    NestingLimit {
        /// Nested path.
        path: String,
        /// Actual depth.
        depth: usize,
        /// Allowed depth.
        limit: usize,
    },
    /// A non-finite numeric representation was rejected.
    NonFiniteNumber {
        /// Numeric path.
        path: String,
    },
    /// Typed decoding failed with its Serde path.
    TypedDecode {
        /// Serde field/index path.
        path: String,
        /// Decoder message.
        message: String,
        /// One-based line.
        line: usize,
        /// One-based column.
        column: usize,
    },
    /// The top-level discriminator was not recognized.
    UnknownFrameKind(String),
    /// A field belonging to another envelope kind contradicted the discriminator.
    ContradictoryEnvelopeField {
        /// Declared frame kind.
        kind: String,
        /// Contradictory field.
        field: String,
    },
    /// A request did not name a frozen or explicitly opted-in method.
    UnknownMethod(String),
    /// A policy limit was exceeded by a typed field.
    PolicyLimit {
        /// Field path.
        path: String,
        /// Actual size.
        actual: usize,
        /// Allowed size.
        limit: usize,
    },
    /// Serialization failed.
    Encode(serde_json::Error),
    /// A response ID did not exactly echo the expected request ID.
    ResponseIdMismatch {
        /// Expected ID.
        expected: String,
        /// Received ID.
        received: String,
    },
    /// A typed success payload was requested from an unsuccessful response.
    UnsuccessfulResponse {
        /// Response correlation ID.
        id: String,
    },
    /// A frame variant differed from the API's expected variant.
    UnexpectedFrame {
        /// Expected variant.
        expected: FrameKind,
        /// Received variant.
        received: FrameKind,
    },
    /// A connect decoder received another method.
    ExpectedConnectMethod(String),
    /// A challenge decoder received another event.
    ExpectedChallengeEvent(String),
    /// A control payload decoder received another event.
    ExpectedControlEvent {
        /// Expected event.
        expected: &'static str,
        /// Received event.
        received: String,
    },
    /// A required opaque field was omitted.
    MissingOpaqueField(&'static str),
    /// A required typed payload was explicitly null.
    NullOpaqueField(&'static str),
}

impl CodecError {
    fn from_json(error: serde_json::Error) -> Self {
        Self::MalformedJson {
            message: error.to_string(),
            line: error.line(),
            column: error.column(),
        }
    }

    fn from_validation(error: FrameValidationError) -> Self {
        match error {
            FrameValidationError::Limit {
                path,
                actual,
                limit,
            } => Self::PolicyLimit {
                path,
                actual,
                limit,
            },
        }
    }
}

impl Display for CodecError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(error) => Display::fmt(error, formatter),
            Self::FrameTooLarge {
                phase,
                actual,
                limit,
            } => write!(
                formatter,
                "{phase:?} frame is {actual} bytes; cap is {limit}"
            ),
            Self::MalformedJson {
                message,
                line,
                column,
            } => write!(formatter, "malformed JSON at {line}:{column}: {message}"),
            Self::DuplicateKey { path, key } => {
                write!(formatter, "duplicate JSON key `{key}` in {path}")
            }
            Self::CollectionLimit {
                path,
                actual,
                limit,
            }
            | Self::PolicyLimit {
                path,
                actual,
                limit,
            } => write!(formatter, "{path} has size {actual}; limit is {limit}"),
            Self::NestingLimit { path, depth, limit } => {
                write!(
                    formatter,
                    "{path} has nesting depth {depth}; limit is {limit}"
                )
            }
            Self::NonFiniteNumber { path } => write!(formatter, "non-finite number at {path}"),
            Self::TypedDecode {
                path,
                message,
                line,
                column,
            } => write!(
                formatter,
                "typed JSON decode failed at {path} ({line}:{column}): {message}"
            ),
            Self::UnknownFrameKind(kind) => write!(formatter, "unknown frame kind `{kind}`"),
            Self::ContradictoryEnvelopeField { kind, field } => {
                write!(
                    formatter,
                    "`{field}` contradicts `{kind}` frame discriminator"
                )
            }
            Self::UnknownMethod(method) => write!(formatter, "unknown Gateway method `{method}`"),
            Self::Encode(error) => write!(formatter, "frame encoding failed: {error}"),
            Self::ResponseIdMismatch { expected, received } => write!(
                formatter,
                "response id mismatch: expected `{expected}`, received `{received}`"
            ),
            Self::UnsuccessfulResponse { id } => {
                write!(formatter, "response `{id}` is unsuccessful")
            }
            Self::UnexpectedFrame { expected, received } => {
                write!(
                    formatter,
                    "expected {expected:?} frame, received {received:?}"
                )
            }
            Self::ExpectedConnectMethod(method) => {
                write!(formatter, "expected connect request, received `{method}`")
            }
            Self::ExpectedChallengeEvent(event) => {
                write!(
                    formatter,
                    "expected connect.challenge event, received `{event}`"
                )
            }
            Self::ExpectedControlEvent { expected, received } => {
                write!(
                    formatter,
                    "expected {expected} event, received `{received}`"
                )
            }
            Self::MissingOpaqueField(path) => write!(formatter, "required field {path} is omitted"),
            Self::NullOpaqueField(path) => write!(formatter, "required field {path} is null"),
        }
    }
}

impl Error for CodecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPolicy(error) => Some(error),
            Self::Encode(error) => Some(error),
            _ => None,
        }
    }
}
