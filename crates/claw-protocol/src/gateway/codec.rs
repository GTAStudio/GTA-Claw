use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Write};

use serde::de::{DeserializeOwned, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::frame::{
    ConnectChallenge, ConnectParams, EventSequence, EventWire, FrameValidationError, HelloOk,
    KindProbe, OpaqueField, RequestWire, ResponseWire, ShutdownEvent, TickEvent, Validate,
    classify_method,
};
use super::{
    DynamicPluginRegistry, EventFrame, Frame, FrameKind, RequestFrame, RequestId, ResponseFrame,
    TransportPhase, ValidationPolicy,
};

#[derive(Serialize)]
struct SerializableRequest<'a, T: ?Sized> {
    #[serde(rename = "type")]
    kind: &'static str,
    id: &'a RequestId,
    method: &'a super::GatewayMethodName,
    params: &'a T,
}

/// Transport-independent strict JSON codec for Gateway frames and handshake DTOs.
#[derive(Clone, Debug)]
pub struct Codec {
    phase: TransportPhase,
    policy: ValidationPolicy,
    dynamic_methods: BTreeSet<String>,
}

impl Codec {
    /// Creates a codec for a phase and explicit validation policy.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::InvalidPolicy`] when any limit in `policy` is
    /// zero, because a zero limit would reject every frame instead of bounding
    /// one dimension of it.
    pub fn new(phase: TransportPhase, policy: ValidationPolicy) -> Result<Self, CodecError> {
        policy.validate().map_err(CodecError::InvalidPolicy)?;
        Ok(Self {
            phase,
            policy,
            dynamic_methods: BTreeSet::new(),
        })
    }

    /// Creates a pre-authentication codec using mechanically derived defaults.
    #[must_use]
    pub const fn preauthentication() -> Self {
        Self::derived(TransportPhase::PreAuthentication)
    }

    /// Creates an authenticated codec using mechanically derived defaults.
    #[must_use]
    pub const fn authenticated() -> Self {
        Self::derived(TransportPhase::Authenticated)
    }

    /// Builds a codec from a mechanically derived policy.
    ///
    /// This deliberately bypasses [`ValidationPolicy::validate`] instead of
    /// asserting it: every limit produced by [`ValidationPolicy::for_phase`] is
    /// either the phase's non-zero transport cap or the non-zero default
    /// nesting depth, so there is no zero limit for validation to reject and no
    /// panic path to document.
    const fn derived(phase: TransportPhase) -> Self {
        Self {
            phase,
            policy: ValidationPolicy::for_phase(phase),
            dynamic_methods: BTreeSet::new(),
        }
    }

    /// Explicitly opts this codec into the supplied, already-validated plugin registry.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::PolicyLimit`] at `$dynamicMethods` when the
    /// registry holds more methods than `max_collection_items` allows, so an
    /// oversized plugin surface cannot be smuggled past the active policy.
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
            .extend(registry.names().map(str::to_owned));
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
    ///
    /// # Errors
    ///
    /// The checks run in this order, and the first failure is returned:
    ///
    /// - [`CodecError::FrameTooLarge`] — `bytes` is longer than the phase cap
    ///   (64 KiB pre-authentication, 25 MiB authenticated). The length is
    ///   rejected before any parsing, so an oversized frame is never buffered.
    /// - [`CodecError::MalformedJson`] — the bytes are not one syntactically
    ///   valid JSON document, or bytes trail the top-level value.
    /// - [`CodecError::DuplicateKey`], [`CodecError::CollectionLimit`],
    ///   [`CodecError::NestingLimit`], [`CodecError::NonFiniteNumber`] — a
    ///   preflight policy rejection anywhere in the JSON tree, reported with
    ///   the offending path.
    /// - [`CodecError::TypedDecode`] — the envelope did not match the strict
    ///   schema: a missing or misspelled field, an unknown field under
    ///   `deny_unknown_fields`, a wrong JSON type, an empty string where the
    ///   schema requires a non-empty one, or a non-positive `seq`.
    /// - [`CodecError::UnknownFrameKind`] — `type` is not `req`, `res` or
    ///   `event`.
    /// - [`CodecError::ContradictoryEnvelopeField`] — a field belonging to a
    ///   different envelope kind appeared alongside the declared `type`, such
    ///   as `payload` on a `req`.
    /// - [`CodecError::UnknownMethod`] — a request named a method that is
    ///   neither in the frozen core registry nor in a registry this codec was
    ///   explicitly opted into through [`Codec::allow_dynamic_plugins`].
    /// - [`CodecError::PolicyLimit`] — a decoded field exceeded a typed policy
    ///   bound, such as `$.id` or `$.error.message`.
    pub fn decode(&self, bytes: &[u8]) -> Result<Frame, CodecError> {
        // Three passes over the bytes, and measured to be worth keeping as
        // three. A bare `serde_json` scan of these frames costs 104 ns (95 B)
        // and 1798 ns (2.6 KiB), so folding the envelope probe into the
        // preflight walk would save roughly 16 % and 25 % of a decode. It is
        // not safe to do: `CodecError::TypedDecode` carries the path, message,
        // line and column that `serde_path_to_error` and `serde_json` produce,
        // and the documented rejection order — policy, then envelope kind, then
        // schema — would have to be reproduced by hand from the preflight
        // visitor, where none of that position information exists.
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
    ///
    /// # Errors
    ///
    /// Returns every rejection listed for [`Codec::decode`], plus
    /// [`CodecError::UnexpectedFrame`] when the frame decoded to a request or
    /// an event, and [`CodecError::ResponseIdMismatch`] when it is a response
    /// whose `id` is not byte-for-byte `expected_id`.
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
    ///
    /// # Errors
    ///
    /// - [`CodecError::PolicyLimit`] — a field of `frame` exceeds a typed
    ///   policy bound, named by its JSON path.
    /// - [`CodecError::FrameTooLarge`] — serialization reached the phase cap.
    ///   The writer stops at the cap, so an oversized frame is never fully
    ///   materialized.
    /// - [`CodecError::Encode`] — `serde_json` refused the value.
    /// - [`CodecError::CollectionLimit`], [`CodecError::NestingLimit`],
    ///   [`CodecError::NonFiniteNumber`], [`CodecError::DuplicateKey`] — the
    ///   post-encode preflight rejected the produced bytes, which is how an
    ///   opaque payload that was accepted under a wider policy is stopped from
    ///   leaving under a narrower one.
    pub fn encode(&self, frame: &Frame) -> Result<Vec<u8>, CodecError> {
        frame
            .validate(&self.policy)
            .map_err(CodecError::from_validation)?;
        self.encode_bounded(frame)
    }

    /// Encodes a typed request with caller-supplied serializable parameters.
    ///
    /// Serialization writes directly into the phase-bounded writer, so a
    /// parameter source that would exceed the transport cap cannot force a full
    /// oversized intermediate allocation.
    ///
    /// # Errors
    ///
    /// - [`CodecError::PolicyLimit`] — `id` is longer than
    ///   `max_request_id_bytes`, or a dynamic plugin `method` is longer than
    ///   `max_name_bytes`.
    /// - [`CodecError::FrameTooLarge`] — `params` pushed the serialized request
    ///   past the phase cap; encoding stops at the cap rather than completing.
    /// - [`CodecError::Encode`] — the caller's `Serialize` implementation
    ///   failed, for example on a non-string map key or a non-finite float.
    /// - [`CodecError::CollectionLimit`], [`CodecError::NestingLimit`],
    ///   [`CodecError::NonFiniteNumber`], [`CodecError::DuplicateKey`] — the
    ///   post-encode preflight rejected the serialized parameters.
    pub fn encode_request<T>(
        &self,
        id: &RequestId,
        method: &super::GatewayMethodName,
        params: &T,
    ) -> Result<Vec<u8>, CodecError>
    where
        T: Serialize + ?Sized,
    {
        RequestFrame::new(id.clone(), method.clone(), OpaqueField::Omitted)
            .validate(&self.policy)
            .map_err(CodecError::from_validation)?;
        self.encode_bounded(&SerializableRequest {
            kind: "req",
            id,
            method,
            params,
        })
    }

    fn encode_bounded<T>(&self, value: &T) -> Result<Vec<u8>, CodecError>
    where
        T: Serialize + ?Sized,
    {
        let limit = self.phase.max_frame_bytes();
        let mut writer = BoundedWriter::new(limit);
        let serialization = serde_json::to_writer(&mut writer, value);
        if let Some(actual) = writer.exceeded_at {
            return Err(CodecError::FrameTooLarge {
                phase: self.phase,
                actual,
                limit,
            });
        }
        serialization.map_err(CodecError::Encode)?;
        let encoded = writer.into_bytes();
        preflight_json(&encoded, &self.policy)?;
        Ok(encoded)
    }

    /// Decodes connect parameters from a strict `connect` request.
    ///
    /// # Errors
    ///
    /// - [`CodecError::ExpectedConnectMethod`] — `request` names a method other
    ///   than `connect`.
    /// - [`CodecError::MissingOpaqueField`] or [`CodecError::NullOpaqueField`]
    ///   at `$.params` — `connect` requires parameters, so neither an omitted
    ///   nor an explicitly null `params` is accepted.
    /// - [`CodecError::TypedDecode`] — the parameters did not match the strict
    ///   connect schema: an unknown field, a missing `minProtocol`,
    ///   `maxProtocol`, `client.id`, `client.version`, `client.platform` or
    ///   `client.mode`, a client id or mode outside the closed sets, or a
    ///   protocol version that is not a positive integer.
    /// - [`CodecError::DuplicateKey`], [`CodecError::CollectionLimit`],
    ///   [`CodecError::NestingLimit`], [`CodecError::NonFiniteNumber`] — a
    ///   preflight policy rejection inside the parameters.
    /// - [`CodecError::PolicyLimit`] — a name, capability list, command list,
    ///   scope list, permission map or device proof field exceeded its bound.
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
    ///
    /// # Errors
    ///
    /// - [`CodecError::UnsuccessfulResponse`] — `response.ok()` is false, so
    ///   there is no success payload to read; inspect `response.error()`
    ///   instead.
    /// - [`CodecError::MissingOpaqueField`] or [`CodecError::NullOpaqueField`]
    ///   at `$.payload` — a successful response carried no hello payload.
    /// - [`CodecError::TypedDecode`] — the payload did not match the strict
    ///   `hello-ok` schema: a `type` other than `hello-ok`, an unknown field, or
    ///   a missing `protocol`, `server`, `features`, `snapshot`, `auth` or
    ///   `policy`.
    /// - [`CodecError::DuplicateKey`], [`CodecError::CollectionLimit`],
    ///   [`CodecError::NestingLimit`], [`CodecError::NonFiniteNumber`] — a
    ///   preflight policy rejection inside the payload.
    /// - [`CodecError::PolicyLimit`] — a hello name, feature list, presence
    ///   entry, Control UI tab, plugin surface URL or device token exceeded its
    ///   bound.
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
    ///
    /// # Errors
    ///
    /// - [`CodecError::ExpectedChallengeEvent`] — `event` names an event other
    ///   than `connect.challenge`.
    /// - [`CodecError::MissingOpaqueField`] or [`CodecError::NullOpaqueField`]
    ///   at `$.payload` — the challenge event carried no payload.
    /// - [`CodecError::TypedDecode`] — the payload is not exactly
    ///   `{"nonce": <non-empty string>, "ts": <non-negative integer>}`; unknown
    ///   fields are rejected.
    /// - [`CodecError::PolicyLimit`] at `$.payload.nonce` — the nonce exceeds
    ///   `max_name_bytes`.
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
    ///
    /// # Errors
    ///
    /// - [`CodecError::ExpectedControlEvent`] — `event` names an event other
    ///   than `tick`.
    /// - [`CodecError::MissingOpaqueField`] or [`CodecError::NullOpaqueField`]
    ///   at `$.payload` — the tick carried no payload.
    /// - [`CodecError::TypedDecode`] — the payload is not exactly
    ///   `{"ts": <non-negative integer>}`; unknown fields are rejected.
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
    ///
    /// # Errors
    ///
    /// - [`CodecError::ExpectedControlEvent`] — `event` names an event other
    ///   than `shutdown`.
    /// - [`CodecError::MissingOpaqueField`] or [`CodecError::NullOpaqueField`]
    ///   at `$.payload` — the shutdown notice carried no payload.
    /// - [`CodecError::TypedDecode`] — `reason` is absent or empty, or an
    ///   unknown field was present.
    /// - [`CodecError::PolicyLimit`] at `$.payload.reason` — the reason exceeds
    ///   `max_name_bytes`.
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
    ///
    /// # Errors
    ///
    /// - [`CodecError::FrameTooLarge`] — the retained JSON text is longer than
    ///   the phase cap.
    /// - [`CodecError::DuplicateKey`], [`CodecError::CollectionLimit`],
    ///   [`CodecError::NestingLimit`], [`CodecError::NonFiniteNumber`] — a
    ///   preflight policy rejection, reported with the offending path.
    /// - [`CodecError::TypedDecode`] — the value did not match `T`.
    /// - [`CodecError::MalformedJson`] — bytes trail the top-level value.
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

    const fn check_size(&self, actual: usize) -> Result<(), CodecError> {
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

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded_at: Option<usize>,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        // Measured: shrinking this to 1 KiB, so a small frame reserves less,
        // changed nothing on a 95-byte frame (251 ns against 252 ns) and cost
        // about 4 % on a 2.6 KiB frame (3370 ns against 3250 ns) because that
        // frame then grows the buffer twice. The allocator hands the same 8 KiB
        // block back on every encode, so the reservation is not the cost.
        Self {
            bytes: Vec::with_capacity(limit.min(8 * 1024)),
            limit,
            exceeded_at: None,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        if buffer.len() > remaining {
            self.bytes.extend_from_slice(&buffer[..remaining]);
            self.exceeded_at = Some(self.limit.saturating_add(1));
            return Err(io::Error::other("serialized frame exceeds byte cap"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
    deserializer
        .end()
        .map_err(|error| CodecError::from_json(&error))?;
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

/// One `$["key"]` or `$[0]` step, borrowed from the frame being walked.
///
/// The walk is the highest-volume code in this crate, so the JSON path is kept
/// as this parent-linked stack of borrowed segments and is rendered into a
/// `String` only by [`PathNode::render`], on the failure paths. Formatting it
/// eagerly cost one allocation per array element and two per object entry.
enum PathSegment<'a> {
    Index(usize),
    Key(&'a str),
}

struct PathNode<'a> {
    parent: Option<&'a Self>,
    segment: PathSegment<'a>,
}

impl PathNode<'_> {
    fn render(node: Option<&Self>) -> String {
        let mut reversed = Vec::new();
        let mut current = node;
        while let Some(entry) = current {
            reversed.push(&entry.segment);
            current = entry.parent;
        }
        let mut path = String::from("$");
        for segment in reversed.iter().rev() {
            path.push('[');
            match segment {
                PathSegment::Index(index) => path.push_str(&index.to_string()),
                PathSegment::Key(key) => path.push_str(&quoted_key(key)),
            }
            path.push(']');
        }
        path
    }
}

#[derive(Clone, Copy)]
struct PreflightSeed<'a> {
    path: Option<&'a PathNode<'a>>,
    depth: usize,
    policy: &'a ValidationPolicy,
    failure: &'a RefCell<Option<PreflightFailure>>,
}

impl<'de> DeserializeSeed<'de> for PreflightSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PreflightVisitor(self))
    }
}

/// An object key borrowed straight out of the frame when it needs no unescaping.
struct MapKey<'de>(Cow<'de, str>);

impl<'de> Deserialize<'de> for MapKey<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(MapKeyVisitor)
    }
}

struct MapKeyVisitor;

impl<'de> Visitor<'de> for MapKeyVisitor {
    type Value = MapKey<'de>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(MapKey(Cow::Borrowed(value)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(MapKey(Cow::Owned(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(MapKey(Cow::Owned(value)))
    }
}

struct PreflightVisitor<'a>(PreflightSeed<'a>);

impl<'de> Visitor<'de> for PreflightVisitor<'_> {
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
            *self.0.failure.borrow_mut() = Some(PreflightFailure::NonFinite {
                path: PathNode::render(self.0.path),
            });
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
        loop {
            let node = PathNode {
                parent: self.0.path,
                segment: PathSegment::Index(count),
            };
            if sequence.next_element_seed(self.0.child(&node))?.is_none() {
                break;
            }
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
        let mut keys = SeenKeys::new();
        let mut count = 0;
        while let Some(MapKey(key)) = map.next_key::<MapKey<'de>>()? {
            if keys.contains(&key) {
                *self.0.failure.borrow_mut() = Some(PreflightFailure::Duplicate {
                    path: PathNode::render(self.0.path),
                    key: key.into_owned(),
                });
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            count += 1;
            self.check_collection::<A::Error>(count)?;
            let node = PathNode {
                parent: self.0.path,
                segment: PathSegment::Key(&key),
            };
            map.next_value_seed(self.0.child(&node))?;
            keys.insert(key);
        }
        Ok(())
    }
}

/// Keys already seen in the object currently being walked.
///
/// Frames are shallow and narrow — the widest wire struct has nine fields — so
/// the first keys are held in a stack array and compared linearly, which keeps
/// the common object allocation-free. The set is built only for an object that
/// outgrows the array, so a hostile object with thousands of keys still gets
/// logarithmic lookups instead of degrading to a quadratic scan.
///
/// Measured on the medium request frame (2.6 KiB, 60 objects): the previous
/// unconditional `BTreeSet` cost one node allocation per object.
struct SeenKeys<'de> {
    inline: [Option<Cow<'de, str>>; INLINE_KEY_CAPACITY],
    len: usize,
    overflow: Option<BTreeSet<Cow<'de, str>>>,
}

/// Keys held on the stack before an object falls back to the set.
const INLINE_KEY_CAPACITY: usize = 12;

impl<'de> SeenKeys<'de> {
    const fn new() -> Self {
        Self {
            inline: [const { None }; INLINE_KEY_CAPACITY],
            len: 0,
            overflow: None,
        }
    }

    fn contains(&self, key: &str) -> bool {
        self.overflow.as_ref().map_or_else(
            || {
                self.inline[..self.len]
                    .iter()
                    .any(|seen| seen.as_deref() == Some(key))
            },
            |overflow| overflow.contains(key),
        )
    }

    fn insert(&mut self, key: Cow<'de, str>) {
        if let Some(overflow) = &mut self.overflow {
            overflow.insert(key);
            return;
        }
        if let Some(slot) = self.inline.get_mut(self.len) {
            *slot = Some(key);
            self.len += 1;
            return;
        }
        let mut overflow: BTreeSet<Cow<'de, str>> =
            self.inline.iter_mut().filter_map(Option::take).collect();
        overflow.insert(key);
        self.overflow = Some(overflow);
    }
}

impl PreflightVisitor<'_> {
    fn check_depth<E: serde::de::Error>(&self) -> Result<(), E> {
        if self.0.depth > self.0.policy.max_nesting_depth {
            *self.0.failure.borrow_mut() = Some(PreflightFailure::Nesting {
                path: PathNode::render(self.0.path),
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
                path: PathNode::render(self.0.path),
                actual,
                limit: self.0.policy.max_collection_items,
            });
            Err(E::custom("JSON collection policy exceeded"))
        } else {
            Ok(())
        }
    }
}

impl<'a> PreflightSeed<'a> {
    const fn child<'node>(&self, node: &'node PathNode<'node>) -> PreflightSeed<'node>
    where
        'a: 'node,
    {
        PreflightSeed {
            path: Some(node),
            depth: self.depth + 1,
            policy: self.policy,
            failure: self.failure,
        }
    }
}

fn quoted_key(key: &str) -> String {
    serde_json::to_string(key).expect("serializing a string cannot fail")
}

fn preflight_json(bytes: &[u8], policy: &ValidationPolicy) -> Result<(), CodecError> {
    let failure = RefCell::new(None);
    let seed = PreflightSeed {
        path: None,
        depth: 1,
        policy,
        failure: &failure,
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
            None => CodecError::from_json(&error),
        });
    }
    deserializer
        .end()
        .map_err(|error| CodecError::from_json(&error))
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
    ///
    /// # Errors
    ///
    /// - [`EventSequenceError::Gap`] — the sequence is ahead of the next
    ///   expected value, so at least one broadcast was missed. The tracker
    ///   adopts the received value so the caller resynchronizes after
    ///   refetching state.
    /// - [`EventSequenceError::NonMonotonic`] — the sequence repeats or moves
    ///   backwards, which means a replayed or reordered broadcast. The tracker
    ///   keeps its previous value.
    /// - [`EventSequenceError::Overflow`] — the last accepted sequence is
    ///   `u64::MAX`, so no successor exists.
    pub fn observe(&mut self, sequence: Option<EventSequence>) -> Result<(), EventSequenceError> {
        let Some(received) = sequence else {
            return Ok(());
        };
        let expected = match self.last {
            None => 1,
            Some(last) => last
                .get()
                .checked_add(1)
                .ok_or_else(|| EventSequenceError::Overflow { last: last.get() })?,
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
    fn from_json(error: &serde_json::Error) -> Self {
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

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::BoundedWriter;

    #[test]
    fn bounded_writer_never_buffers_past_limit() {
        let mut writer = BoundedWriter::new(64);
        let error = writer
            .write_all(&vec![b'x'; 1024 * 1024])
            .expect_err("oversized write must stop");

        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(writer.bytes.len(), 64);
        assert_eq!(writer.exceeded_at, Some(65));
    }
}
