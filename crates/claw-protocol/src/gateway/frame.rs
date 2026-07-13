use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;

use super::registry::{CoreEvent, CoreMethod, DynamicPluginMethod, resolve_core_event};
use super::{ValidationPolicy, resolve_core_method};

fn deserialize_optional_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

macro_rules! string_newtype {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates a non-empty value under an explicit UTF-8 byte limit.
            pub fn new(
                value: impl Into<String>,
                max_bytes: usize,
            ) -> Result<Self, StringValidationError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(StringValidationError::Empty($label));
                }
                if value.len() > max_bytes {
                    return Err(StringValidationError::TooLong {
                        field: $label,
                        actual: value.len(),
                        limit: max_bytes,
                    });
                }
                Ok(Self(value))
            }

            /// Returns the exact wire string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub(crate) fn validate_len(
                &self,
                max_bytes: usize,
                path: &str,
            ) -> Result<(), FrameValidationError> {
                if self.0.len() > max_bytes {
                    return Err(FrameValidationError::Limit {
                        path: path.to_owned(),
                        actual: self.0.len(),
                        limit: max_bytes,
                    });
                }
                Ok(())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                if value.is_empty() {
                    return Err(D::Error::custom(concat!($label, " must not be empty")));
                }
                Ok(Self(value))
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

string_newtype!(
    /// A non-empty protocol name whose byte maximum is caller policy.
    Name,
    "name"
);
string_newtype!(
    /// A non-empty request/response correlation identifier.
    RequestId,
    "request id"
);
string_newtype!(
    /// An extensible non-empty Gateway error code.
    ErrorCode,
    "error code"
);
string_newtype!(
    /// A non-empty Gateway error message.
    ErrorMessage,
    "error message"
);
string_newtype!(
    /// The exact challenge nonce bytes represented by their wire string.
    ChallengeNonce,
    "challenge nonce"
);
string_newtype!(
    /// Encoded Ed25519 public-key bytes carried by the device proof.
    DevicePublicKey,
    "device public key"
);
string_newtype!(
    /// Encoded signature bytes carried by the device proof.
    DeviceSignature,
    "device signature"
);

/// Canonical built-in top-level Gateway error codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreErrorCode {
    /// Client has not completed linking.
    NotLinked,
    /// Device still needs pairing approval.
    NotPaired,
    /// Agent operation exceeded its wait window.
    AgentTimeout,
    /// Request validation or preconditions failed.
    InvalidRequest,
    /// Approval was missing or expired.
    ApprovalNotFound,
    /// Service or backend is temporarily unavailable.
    Unavailable,
}

impl CoreErrorCode {
    /// All six pinned built-in codes in source order.
    pub const ALL: [Self; 6] = [
        Self::NotLinked,
        Self::NotPaired,
        Self::AgentTimeout,
        Self::InvalidRequest,
        Self::ApprovalNotFound,
        Self::Unavailable,
    ];

    /// Returns the exact wire identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotLinked => "NOT_LINKED",
            Self::NotPaired => "NOT_PAIRED",
            Self::AgentTimeout => "AGENT_TIMEOUT",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::ApprovalNotFound => "APPROVAL_NOT_FOUND",
            Self::Unavailable => "UNAVAILABLE",
        }
    }

    /// Parses an exact built-in identity.
    #[must_use]
    pub fn from_identity(identity: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|code| code.as_str() == identity)
    }
}

impl ErrorCode {
    /// Constructs the extensible wire code from a pinned built-in code.
    #[must_use]
    pub fn from_core(code: CoreErrorCode) -> Self {
        Self(code.as_str().to_owned())
    }

    /// Classifies this extensible code when it is one of the pinned built-ins.
    #[must_use]
    pub fn core(&self) -> Option<CoreErrorCode> {
        CoreErrorCode::from_identity(self.as_str())
    }
}

/// A failure constructing a policy-bounded string newtype.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StringValidationError {
    /// The schema requires a non-empty string.
    Empty(&'static str),
    /// The value exceeded the explicit caller policy.
    TooLong {
        /// Field category.
        field: &'static str,
        /// Actual UTF-8 byte length.
        actual: usize,
        /// Allowed UTF-8 byte length.
        limit: usize,
    },
}

impl Display for StringValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(field) => write!(formatter, "{field} must not be empty"),
            Self::TooLong {
                field,
                actual,
                limit,
            } => write!(formatter, "{field} is {actual} bytes; limit is {limit}"),
        }
    }
}

impl Error for StringValidationError {}

macro_rules! integer_newtype {
    ($(#[$meta:meta])* $name:ident, $minimum:literal, $message:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            /// Creates a validated integer.
            pub fn new(value: u64) -> Result<Self, IntegerValidationError> {
                if value < $minimum {
                    return Err(IntegerValidationError($message));
                }
                Ok(Self(value))
            }

            /// Returns the wire integer.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = deserialize_nonnegative_integer(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }
    };
}

fn deserialize_nonnegative_integer<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct IntegerVisitor;

    impl Visitor<'_> for IntegerVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            formatter.write_str("a finite, non-negative integer within u64 range")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u64::try_from(value).map_err(E::custom)
        }

        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            const U64_UPPER_EXCLUSIVE: f64 = 18_446_744_073_709_551_616.0;
            if value.is_finite()
                && (0.0..U64_UPPER_EXCLUSIVE).contains(&value)
                && value.fract() == 0.0
            {
                Ok(value as u64)
            } else {
                Err(E::custom("number is not a finite non-negative u64 integer"))
            }
        }
    }

    deserializer.deserialize_any(IntegerVisitor)
}

integer_newtype!(
    /// A positive Gateway protocol version.
    ProtocolVersion,
    1,
    "protocol version must be positive"
);
integer_newtype!(
    /// A schema integer constrained to one or greater.
    PositiveInteger,
    1,
    "integer must be positive"
);
integer_newtype!(
    /// A broadcast event sequence; zero is rejected because broadcasts begin at one.
    EventSequence,
    1,
    "event sequence must be positive"
);

impl ProtocolVersion {
    pub(crate) const fn new_const(value: u64) -> Self {
        Self(value)
    }
}

/// A schema integer constrained to zero or greater.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NonNegativeInteger(u64);

impl NonNegativeInteger {
    /// Creates a non-negative integer. The `u64` representation proves the invariant.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the wire integer.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for NonNegativeInteger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_nonnegative_integer(deserializer).map(Self)
    }
}

/// A failure constructing a bounded integer newtype.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegerValidationError(&'static str);

impl Display for IntegerValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for IntegerValidationError {}

/// A finite JSON number used by Control UI tab ordering.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FiniteNumber(f64);

impl FiniteNumber {
    /// Creates a finite number.
    pub fn new(value: f64) -> Result<Self, IntegerValidationError> {
        if value.is_finite() {
            Ok(Self(value))
        } else {
            Err(IntegerValidationError("number must be finite"))
        }
    }

    /// Returns the finite value.
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for FiniteNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(f64::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Opaque, syntactically valid JSON retained without exposing `serde_json::Value`.
pub struct OpaqueJson(Box<RawValue>);

impl OpaqueJson {
    /// Returns the retained JSON text.
    #[must_use]
    pub fn as_json(&self) -> &str {
        self.0.get()
    }

    /// Returns the retained encoded byte length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.0.get().len()
    }
}

impl Clone for OpaqueJson {
    fn clone(&self) -> Self {
        Self(
            RawValue::from_string(self.0.get().to_owned())
                .expect("an existing RawValue always contains valid JSON"),
        )
    }
}

impl fmt::Debug for OpaqueJson {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OpaqueJson")
            .field(&self.0.get())
            .finish()
    }
}

impl PartialEq for OpaqueJson {
    fn eq(&self, other: &Self) -> bool {
        self.0.get() == other.0.get()
    }
}

impl Eq for OpaqueJson {}

impl Serialize for OpaqueJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OpaqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Box::<RawValue>::deserialize(deserializer).map(Self)
    }
}

/// Presence state for an optional opaque field, preserving omitted versus explicit `null`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum OpaqueField {
    /// The field was omitted.
    #[default]
    Omitted,
    /// The field was explicitly JSON `null`.
    Null,
    /// The field contained a non-null opaque JSON value.
    Value(OpaqueJson),
}

impl OpaqueField {
    /// Reports whether the field is omitted.
    #[must_use]
    pub const fn is_omitted(&self) -> bool {
        matches!(self, Self::Omitted)
    }

    /// Returns the non-null opaque value, if present.
    #[must_use]
    pub const fn value(&self) -> Option<&OpaqueJson> {
        match self {
            Self::Value(value) => Some(value),
            Self::Omitted | Self::Null => None,
        }
    }
}

impl Serialize for OpaqueField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Omitted => serializer.serialize_unit(),
            Self::Null => serializer.serialize_none(),
            Self::Value(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for OpaqueField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        if raw.get().trim() == "null" {
            Ok(Self::Null)
        } else {
            Ok(Self::Value(OpaqueJson(raw)))
        }
    }
}

/// Closed client product identifier from `client-info.ts`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ClientId {
    /// Browser chat UI.
    #[serde(rename = "webchat-ui")]
    WebchatUi,
    /// OpenClaw control UI.
    #[serde(rename = "openclaw-control-ui")]
    ControlUi,
    /// OpenClaw terminal UI.
    #[serde(rename = "openclaw-tui")]
    Tui,
    /// Legacy webchat client.
    #[serde(rename = "webchat")]
    Webchat,
    /// Command-line client.
    #[serde(rename = "cli")]
    Cli,
    /// Trusted same-process backend.
    #[serde(rename = "gateway-client")]
    GatewayClient,
    /// macOS app.
    #[serde(rename = "openclaw-macos")]
    MacOs,
    /// iOS app.
    #[serde(rename = "openclaw-ios")]
    Ios,
    /// watchOS app.
    #[serde(rename = "openclaw-watchos")]
    WatchOs,
    /// Android app.
    #[serde(rename = "openclaw-android")]
    Android,
    /// Headless node host.
    #[serde(rename = "node-host")]
    NodeHost,
    /// Closed worker client.
    #[serde(rename = "openclaw-worker")]
    Worker,
    /// Test client.
    #[serde(rename = "test")]
    Test,
    /// Fingerprint client.
    #[serde(rename = "fingerprint")]
    Fingerprint,
    /// Lightweight probe.
    #[serde(rename = "openclaw-probe")]
    Probe,
}

impl ClientId {
    /// Returns the exact closed wire identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WebchatUi => "webchat-ui",
            Self::ControlUi => "openclaw-control-ui",
            Self::Tui => "openclaw-tui",
            Self::Webchat => "webchat",
            Self::Cli => "cli",
            Self::GatewayClient => "gateway-client",
            Self::MacOs => "openclaw-macos",
            Self::Ios => "openclaw-ios",
            Self::WatchOs => "openclaw-watchos",
            Self::Android => "openclaw-android",
            Self::NodeHost => "node-host",
            Self::Worker => "openclaw-worker",
            Self::Test => "test",
            Self::Fingerprint => "fingerprint",
            Self::Probe => "openclaw-probe",
        }
    }
}

/// Closed coarse client mode from `client-info.ts`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientMode {
    /// Browser chat.
    Webchat,
    /// CLI.
    Cli,
    /// Control UI.
    Ui,
    /// Trusted backend.
    Backend,
    /// Node host.
    Node,
    /// Closed worker.
    Worker,
    /// Probe.
    Probe,
    /// Test.
    Test,
}

impl ClientMode {
    /// Returns the exact closed wire identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Webchat => "webchat",
            Self::Cli => "cli",
            Self::Ui => "ui",
            Self::Backend => "backend",
            Self::Node => "node",
            Self::Worker => "worker",
            Self::Probe => "probe",
            Self::Test => "test",
        }
    }
}

/// Closed configured authentication mode in a snapshot.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMode {
    /// No configured shared authentication.
    None,
    /// Shared token.
    Token,
    /// Shared password.
    Password,
    /// Trusted reverse proxy.
    TrustedProxy,
}

/// Client metadata in a connect request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientInfo {
    /// Closed product identifier.
    pub id: ClientId,
    /// Optional non-empty display name.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub display_name: Option<Name>,
    /// Non-empty app/package version.
    pub version: Name,
    /// Non-empty runtime platform.
    pub platform: Name,
    /// Optional non-empty device family.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub device_family: Option<Name>,
    /// Optional non-empty model identifier.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub model_identifier: Option<Name>,
    /// Closed coarse client mode.
    pub mode: ClientMode,
    /// Optional non-empty per-installation/process identifier.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub instance_id: Option<Name>,
}

/// Typed device proof fields; verification is delegated to an authentication port.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeviceProof {
    /// Device fingerprint identity.
    pub id: Name,
    /// Encoded Ed25519 public key.
    pub public_key: DevicePublicKey,
    /// Encoded signature.
    pub signature: DeviceSignature,
    /// Signature timestamp in epoch milliseconds.
    pub signed_at: NonNegativeInteger,
    /// Exact challenge nonce covered by the signature.
    pub nonce: ChallengeNonce,
}

/// Optional credentials accepted by the connect schema.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthCredentials {
    /// Shared or fallback token; an empty string is schema-valid.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub token: Option<String>,
    /// Bootstrap token.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub bootstrap_token: Option<String>,
    /// Explicit device token.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub device_token: Option<String>,
    /// Shared password.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub password: Option<String>,
    /// Internal approval runtime credential.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub approval_runtime_token: Option<String>,
    /// Internal agent runtime identity credential.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub agent_runtime_identity_token: Option<String>,
}

/// Exact connect parameters from `schema/frames.ts`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConnectParams {
    /// Lowest protocol accepted by the client.
    pub min_protocol: ProtocolVersion,
    /// Highest protocol accepted by the client.
    pub max_protocol: ProtocolVersion,
    /// Closed client metadata.
    pub client: ClientInfo,
    /// Optional capability names.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub caps: Option<Vec<Name>>,
    /// Optional node command claims.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub commands: Option<Vec<Name>>,
    /// Optional node permission claims.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub permissions: Option<BTreeMap<Name, bool>>,
    /// Optional path environment; empty is schema-valid.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub path_env: Option<String>,
    /// Optional non-empty role claim.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub role: Option<Name>,
    /// Optional non-empty scope claims.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub scopes: Option<Vec<Name>>,
    /// Optional device identity proof.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub device: Option<DeviceProof>,
    /// Optional authentication credentials.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth: Option<AuthCredentials>,
    /// Optional locale; empty is schema-valid.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub locale: Option<String>,
    /// Optional user agent; empty is schema-valid.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_agent: Option<String>,
}

/// One gateway-visible presence record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PresenceEntry {
    /// Optional host name.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub host: Option<Name>,
    /// Optional IP text.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub ip: Option<Name>,
    /// Optional version.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub version: Option<Name>,
    /// Optional platform.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub platform: Option<Name>,
    /// Optional device family.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub device_family: Option<Name>,
    /// Optional model identifier.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub model_identifier: Option<Name>,
    /// Optional mode.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub mode: Option<Name>,
    /// Optional idle seconds.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_input_seconds: Option<NonNegativeInteger>,
    /// Optional reason.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub reason: Option<Name>,
    /// Optional tags.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub tags: Option<Vec<Name>>,
    /// Optional free text; empty is schema-valid.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub text: Option<String>,
    /// Observation timestamp.
    pub ts: NonNegativeInteger,
    /// Optional device identity.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub device_id: Option<Name>,
    /// Optional role identities.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub roles: Option<Vec<Name>>,
    /// Optional scope identities.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub scopes: Option<Vec<Name>>,
    /// Optional instance identity.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub instance_id: Option<Name>,
}

/// Default routing keys included in a snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SessionDefaults {
    /// Default agent identity.
    pub default_agent_id: Name,
    /// Main routing key.
    pub main_key: Name,
    /// Main session routing key.
    pub main_session_key: Name,
    /// Optional routing scope.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub scope: Option<Name>,
}

/// Monotonic snapshot subtree versions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateVersion {
    /// Presence subtree version.
    pub presence: NonNegativeInteger,
    /// Health subtree version.
    pub health: NonNegativeInteger,
}

/// Available update metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAvailable {
    /// Current version.
    pub current_version: Name,
    /// Latest version.
    pub latest_version: Name,
    /// Update channel.
    pub channel: Name,
    /// Additive fields allowed by the pinned nested TypeBox object.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, OpaqueJson>,
}

impl<'de> Deserialize<'de> for UpdateAvailable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UpdateAvailableVisitor;

        impl<'de> Visitor<'de> for UpdateAvailableVisitor {
            type Value = UpdateAvailable;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("update metadata with required version and channel fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut current_version = None;
                let mut latest_version = None;
                let mut channel = None;
                let mut extensions = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "currentVersion" => current_version = Some(map.next_value()?),
                        "latestVersion" => latest_version = Some(map.next_value()?),
                        "channel" => channel = Some(map.next_value()?),
                        _ => {
                            extensions.insert(key, map.next_value()?);
                        }
                    }
                }
                Ok(UpdateAvailable {
                    current_version: current_version
                        .ok_or_else(|| A::Error::missing_field("currentVersion"))?,
                    latest_version: latest_version
                        .ok_or_else(|| A::Error::missing_field("latestVersion"))?,
                    channel: channel.ok_or_else(|| A::Error::missing_field("channel"))?,
                    extensions,
                })
            }
        }

        deserializer.deserialize_map(UpdateAvailableVisitor)
    }
}

/// Initial Gateway state snapshot; provider health remains deliberately opaque.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Snapshot {
    /// Presence entries.
    pub presence: Vec<PresenceEntry>,
    /// Provider-contributed health JSON.
    pub health: OpaqueJson,
    /// Snapshot subtree versions.
    pub state_version: StateVersion,
    /// Gateway uptime in milliseconds.
    pub uptime_ms: NonNegativeInteger,
    /// Optional configuration path.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub config_path: Option<Name>,
    /// Optional state directory.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub state_dir: Option<Name>,
    /// Optional session routing defaults.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub session_defaults: Option<SessionDefaults>,
    /// Optional configured authentication mode.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_mode: Option<AuthMode>,
    /// Optional update metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub update_available: Option<UpdateAvailable>,
}

/// Successful hello server identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HelloServer {
    /// Server version.
    pub version: Name,
    /// Connection identifier.
    pub conn_id: Name,
}

/// Successful hello feature discovery lists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HelloFeatures {
    /// Advertised method names.
    pub methods: Vec<Name>,
    /// Advertised event names.
    pub events: Vec<Name>,
    /// Optional server capability names.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub capabilities: Option<Vec<Name>>,
}

/// Control UI tab grouping.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlUiTabGroup {
    /// Gateway-wide controls.
    Control,
    /// Agent-focused controls.
    Agent,
}

/// Plugin-declared Control UI tab descriptor.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ControlUiTab {
    /// Plugin identity.
    pub plugin_id: Name,
    /// Tab identity.
    pub id: Name,
    /// Display label.
    pub label: Name,
    /// Optional description.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// Optional icon.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub icon: Option<String>,
    /// Optional route path.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub path: Option<String>,
    /// Optional tab group.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub group: Option<ControlUiTabGroup>,
    /// Optional finite sort order.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub order: Option<FiniteNumber>,
}

/// Exact plugin surface-name to scoped-URL mapping.
pub type PluginSurfaceUrls = BTreeMap<Name, Name>;

/// One additional device token issued by bootstrap authentication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HelloDeviceToken {
    /// Issued device token.
    pub device_token: Name,
    /// Role bound to the token.
    pub role: Name,
    /// Scopes bound to the token.
    pub scopes: Vec<Name>,
    /// Issuance time in epoch milliseconds.
    pub issued_at_ms: NonNegativeInteger,
}

/// Negotiated authentication information in a successful hello.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HelloAuth {
    /// Optional primary device token.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub device_token: Option<Name>,
    /// Negotiated role identity.
    pub role: Name,
    /// Negotiated operator scopes.
    pub scopes: Vec<Name>,
    /// Optional primary token issuance time.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub issued_at_ms: Option<NonNegativeInteger>,
    /// Optional bounded bootstrap handoff tokens.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub device_tokens: Option<Vec<HelloDeviceToken>>,
}

/// Transport policy announced by a successful hello.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HelloPolicy {
    /// Maximum payload bytes.
    pub max_payload: PositiveInteger,
    /// Maximum buffered outbound bytes.
    pub max_buffered_bytes: PositiveInteger,
    /// Tick interval in milliseconds.
    pub tick_interval_ms: PositiveInteger,
}

/// Exact successful Gateway hello payload.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HelloOk {
    /// Literal payload discriminator.
    #[serde(rename = "type")]
    pub kind: HelloOkKind,
    /// Negotiated protocol; successful legacy clients still receive version four.
    pub protocol: ProtocolVersion,
    /// Server identity.
    pub server: HelloServer,
    /// Feature discovery.
    pub features: HelloFeatures,
    /// Initial state.
    pub snapshot: Snapshot,
    /// Optional plugin Control UI tabs.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub control_ui_tabs: Option<Vec<ControlUiTab>>,
    /// Optional scoped plugin surface URLs.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub plugin_surface_urls: Option<PluginSurfaceUrls>,
    /// Negotiated authentication information.
    pub auth: HelloAuth,
    /// Transport policy.
    pub policy: HelloPolicy,
}

/// Literal `hello-ok` payload discriminator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum HelloOkKind {
    /// Successful hello.
    #[serde(rename = "hello-ok")]
    HelloOk,
}

/// Structured response error shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ErrorShape {
    /// Extensible non-empty error code.
    pub code: ErrorCode,
    /// Non-empty human-readable message.
    pub message: ErrorMessage,
    /// Optional opaque details, preserving explicit null.
    #[serde(default, skip_serializing_if = "OpaqueField::is_omitted")]
    pub details: OpaqueField,
    /// Optional retryability flag.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub retryable: Option<bool>,
    /// Optional non-negative retry delay.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub retry_after_ms: Option<NonNegativeInteger>,
}

/// Top-level frame discriminator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameKind {
    /// Request frame.
    Req,
    /// Response frame.
    Res,
    /// Event frame.
    Event,
}

/// A method name retaining frozen-core versus opted-in plugin provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicGatewayMethodName(Name);

impl DynamicGatewayMethodName {
    /// Creates an outbound dynamic name from an explicitly registered plugin method.
    #[must_use]
    pub fn from_registered(method: &DynamicPluginMethod) -> Self {
        Self(Name(method.name().to_owned()))
    }

    /// Returns the exact registered identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A method name retaining frozen-core versus opted-in plugin provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayMethodName {
    /// Frozen core method.
    Core(&'static CoreMethod),
    /// Explicitly registered runtime plugin method.
    DynamicPlugin(DynamicGatewayMethodName),
}

impl GatewayMethodName {
    /// Returns the exact method identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Core(method) => method.name(),
            Self::DynamicPlugin(name) => name.as_str(),
        }
    }
}

impl Serialize for GatewayMethodName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// A core or explicit extension event name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventName {
    /// Frozen core event.
    Core(&'static CoreEvent),
    /// Schema-permitted event extension.
    Extension(Name),
}

impl EventName {
    /// Returns the exact event identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Core(event) => event.name(),
            Self::Extension(name) => name.as_str(),
        }
    }
}

impl Serialize for EventName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EventName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = Name::deserialize(deserializer)?;
        Ok(match resolve_core_event(name.as_str()) {
            Some(event) => Self::Core(event),
            None => Self::Extension(name),
        })
    }
}

/// Strict request envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestFrame {
    id: RequestId,
    method: GatewayMethodName,
    params: OpaqueField,
}

impl RequestFrame {
    /// Creates a request envelope.
    #[must_use]
    pub const fn new(id: RequestId, method: GatewayMethodName, params: OpaqueField) -> Self {
        Self { id, method, params }
    }

    /// Returns the request ID.
    #[must_use]
    pub const fn id(&self) -> &RequestId {
        &self.id
    }

    /// Returns the classified method name.
    #[must_use]
    pub const fn method(&self) -> &GatewayMethodName {
        &self.method
    }

    /// Returns the omission-aware parameters.
    #[must_use]
    pub const fn params(&self) -> &OpaqueField {
        &self.params
    }
}

impl Serialize for RequestFrame {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RequestWireRef {
            kind: RequestTag::Req,
            id: &self.id,
            method: &self.method,
            params: &self.params,
        }
        .serialize(serializer)
    }
}

/// Strict response envelope; `ok` does not constrain `payload`/`error` combinations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseFrame {
    id: RequestId,
    ok: bool,
    payload: OpaqueField,
    error: Option<ErrorShape>,
}

impl ResponseFrame {
    /// Creates any schema-valid response combination.
    #[must_use]
    pub const fn new(
        id: RequestId,
        ok: bool,
        payload: OpaqueField,
        error: Option<ErrorShape>,
    ) -> Self {
        Self {
            id,
            ok,
            payload,
            error,
        }
    }

    /// Returns the echoed request ID.
    #[must_use]
    pub const fn id(&self) -> &RequestId {
        &self.id
    }

    /// Returns the upstream semantic success discriminator.
    #[must_use]
    pub const fn ok(&self) -> bool {
        self.ok
    }

    /// Returns the omission-aware payload.
    #[must_use]
    pub const fn payload(&self) -> &OpaqueField {
        &self.payload
    }

    /// Returns the optional structured error.
    #[must_use]
    pub const fn error(&self) -> Option<&ErrorShape> {
        self.error.as_ref()
    }
}

impl Serialize for ResponseFrame {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ResponseWireRef {
            kind: ResponseTag::Res,
            id: &self.id,
            ok: self.ok,
            payload: &self.payload,
            error: self.error.as_ref(),
        }
        .serialize(serializer)
    }
}

/// Strict event envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventFrame {
    event: EventName,
    payload: OpaqueField,
    sequence: Option<EventSequence>,
    state_version: Option<StateVersion>,
}

impl EventFrame {
    /// Creates an event envelope.
    #[must_use]
    pub const fn new(
        event: EventName,
        payload: OpaqueField,
        sequence: Option<EventSequence>,
        state_version: Option<StateVersion>,
    ) -> Self {
        Self {
            event,
            payload,
            sequence,
            state_version,
        }
    }

    /// Returns the classified event name.
    #[must_use]
    pub const fn event(&self) -> &EventName {
        &self.event
    }

    /// Returns the omission-aware payload.
    #[must_use]
    pub const fn payload(&self) -> &OpaqueField {
        &self.payload
    }

    /// Returns the optional positive broadcast sequence.
    #[must_use]
    pub const fn sequence(&self) -> Option<EventSequence> {
        self.sequence
    }

    /// Returns optional snapshot version counters.
    #[must_use]
    pub const fn state_version(&self) -> Option<StateVersion> {
        self.state_version
    }
}

impl Serialize for EventFrame {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        EventWireRef {
            kind: EventTag::Event,
            event: &self.event,
            payload: &self.payload,
            sequence: self.sequence,
            state_version: self.state_version,
        }
        .serialize(serializer)
    }
}

/// A classified Gateway frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame {
    /// Request.
    Request(RequestFrame),
    /// Response.
    Response(ResponseFrame),
    /// Event.
    Event(EventFrame),
}

impl Frame {
    /// Returns the top-level discriminator.
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        match self {
            Self::Request(_) => FrameKind::Req,
            Self::Response(_) => FrameKind::Res,
            Self::Event(_) => FrameKind::Event,
        }
    }
}

impl Serialize for Frame {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Request(frame) => frame.serialize(serializer),
            Self::Response(frame) => frame.serialize(serializer),
            Self::Event(frame) => frame.serialize(serializer),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
enum RequestTag {
    #[serde(rename = "req")]
    Req,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
enum ResponseTag {
    #[serde(rename = "res")]
    Res,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
enum EventTag {
    #[serde(rename = "event")]
    Event,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestWire {
    #[serde(rename = "type")]
    kind: RequestTag,
    id: RequestId,
    method: Name,
    #[serde(default)]
    params: OpaqueField,
}

impl RequestWire {
    pub(crate) fn into_parts(self) -> (RequestId, Name, OpaqueField) {
        let Self {
            kind: RequestTag::Req,
            id,
            method,
            params,
        } = self;
        (id, method, params)
    }
}

#[derive(Serialize)]
struct RequestWireRef<'a> {
    #[serde(rename = "type")]
    kind: RequestTag,
    id: &'a RequestId,
    method: &'a GatewayMethodName,
    #[serde(skip_serializing_if = "OpaqueField::is_omitted")]
    params: &'a OpaqueField,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponseWire {
    #[serde(rename = "type")]
    kind: ResponseTag,
    id: RequestId,
    ok: bool,
    #[serde(default)]
    payload: OpaqueField,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    error: Option<ErrorShape>,
}

impl ResponseWire {
    pub(crate) fn into_frame(self) -> ResponseFrame {
        let Self {
            kind: ResponseTag::Res,
            id,
            ok,
            payload,
            error,
        } = self;
        ResponseFrame::new(id, ok, payload, error)
    }
}

#[derive(Serialize)]
struct ResponseWireRef<'a> {
    #[serde(rename = "type")]
    kind: ResponseTag,
    id: &'a RequestId,
    ok: bool,
    #[serde(skip_serializing_if = "OpaqueField::is_omitted")]
    payload: &'a OpaqueField,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a ErrorShape>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct EventWire {
    #[serde(rename = "type")]
    kind: EventTag,
    event: EventName,
    #[serde(default)]
    payload: OpaqueField,
    #[serde(
        default,
        rename = "seq",
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    sequence: Option<EventSequence>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    state_version: Option<StateVersion>,
}

impl EventWire {
    pub(crate) fn into_frame(self) -> EventFrame {
        let Self {
            kind: EventTag::Event,
            event,
            payload,
            sequence,
            state_version,
        } = self;
        EventFrame::new(event, payload, sequence, state_version)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EventWireRef<'a> {
    #[serde(rename = "type")]
    kind: EventTag,
    event: &'a EventName,
    #[serde(skip_serializing_if = "OpaqueField::is_omitted")]
    payload: &'a OpaqueField,
    #[serde(rename = "seq", skip_serializing_if = "Option::is_none")]
    sequence: Option<EventSequence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_version: Option<StateVersion>,
}

/// Exact `connect.challenge` event payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectChallenge {
    /// Non-empty nonce.
    pub nonce: ChallengeNonce,
    /// Challenge timestamp in epoch milliseconds.
    pub ts: NonNegativeInteger,
}

/// Periodic server heartbeat payload from `frames.ts`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TickEvent {
    /// Server timestamp in epoch milliseconds.
    pub ts: NonNegativeInteger,
}

/// Server shutdown notice payload from `frames.ts`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShutdownEvent {
    /// Non-empty shutdown reason.
    pub reason: Name,
    /// Optional non-negative expected restart delay.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub restart_expected_ms: Option<NonNegativeInteger>,
}

#[derive(Deserialize)]
pub(crate) struct KindProbe {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    #[serde(flatten)]
    remaining: BTreeMap<String, serde::de::IgnoredAny>,
}

impl KindProbe {
    pub(crate) fn contradictory_field(&self) -> Option<&str> {
        let fields: &[&str] = match self.kind.as_str() {
            "req" => &["ok", "payload", "error", "event", "seq", "stateVersion"],
            "res" => &["method", "params", "event", "seq", "stateVersion"],
            "event" => &["id", "method", "params", "ok", "error"],
            _ => &[],
        };
        fields
            .iter()
            .copied()
            .find(|field| self.remaining.contains_key(*field))
    }
}

pub(crate) trait Validate {
    fn validate(&self, policy: &ValidationPolicy) -> Result<(), FrameValidationError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FrameValidationError {
    Limit {
        path: String,
        actual: usize,
        limit: usize,
    },
}

fn validate_collection(
    actual: usize,
    policy: &ValidationPolicy,
    path: &str,
) -> Result<(), FrameValidationError> {
    if actual > policy.max_collection_items {
        return Err(FrameValidationError::Limit {
            path: path.to_owned(),
            actual,
            limit: policy.max_collection_items,
        });
    }
    Ok(())
}

fn validate_names<'a>(
    values: impl IntoIterator<Item = &'a Name>,
    policy: &ValidationPolicy,
    path: &str,
) -> Result<(), FrameValidationError> {
    for (index, value) in values.into_iter().enumerate() {
        value.validate_len(policy.max_name_bytes, &format!("{path}[{index}]"))?;
    }
    Ok(())
}

impl Validate for RequestFrame {
    fn validate(&self, policy: &ValidationPolicy) -> Result<(), FrameValidationError> {
        self.id.validate_len(policy.max_request_id_bytes, "$.id")?;
        match &self.method {
            GatewayMethodName::Core(_) => Ok(()),
            GatewayMethodName::DynamicPlugin(name) => {
                if name.as_str().len() > policy.max_name_bytes {
                    Err(FrameValidationError::Limit {
                        path: "$.method".to_owned(),
                        actual: name.as_str().len(),
                        limit: policy.max_name_bytes,
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl Validate for ResponseFrame {
    fn validate(&self, policy: &ValidationPolicy) -> Result<(), FrameValidationError> {
        self.id.validate_len(policy.max_request_id_bytes, "$.id")?;
        if let Some(error) = &self.error {
            error
                .code
                .validate_len(policy.max_name_bytes, "$.error.code")?;
            error
                .message
                .validate_len(policy.max_error_message_bytes, "$.error.message")?;
            if let Some(details) = error.details.value()
                && details.encoded_len() > policy.max_error_details_bytes
            {
                return Err(FrameValidationError::Limit {
                    path: "$.error.details".to_owned(),
                    actual: details.encoded_len(),
                    limit: policy.max_error_details_bytes,
                });
            }
        }
        Ok(())
    }
}

impl Validate for EventFrame {
    fn validate(&self, policy: &ValidationPolicy) -> Result<(), FrameValidationError> {
        if let EventName::Extension(name) = &self.event {
            name.validate_len(policy.max_name_bytes, "$.event")?;
        }
        Ok(())
    }
}

impl Validate for Frame {
    fn validate(&self, policy: &ValidationPolicy) -> Result<(), FrameValidationError> {
        match self {
            Self::Request(frame) => frame.validate(policy),
            Self::Response(frame) => frame.validate(policy),
            Self::Event(frame) => frame.validate(policy),
        }
    }
}

impl Validate for ConnectParams {
    fn validate(&self, policy: &ValidationPolicy) -> Result<(), FrameValidationError> {
        for (path, value) in [
            ("$.client.version", &self.client.version),
            ("$.client.platform", &self.client.platform),
        ] {
            value.validate_len(policy.max_name_bytes, path)?;
        }
        for (path, value) in [
            ("$.client.displayName", self.client.display_name.as_ref()),
            ("$.client.deviceFamily", self.client.device_family.as_ref()),
            (
                "$.client.modelIdentifier",
                self.client.model_identifier.as_ref(),
            ),
            ("$.client.instanceId", self.client.instance_id.as_ref()),
            ("$.role", self.role.as_ref()),
        ] {
            if let Some(value) = value {
                value.validate_len(policy.max_name_bytes, path)?;
            }
        }
        for (path, values) in [
            ("$.caps", self.caps.as_ref()),
            ("$.commands", self.commands.as_ref()),
            ("$.scopes", self.scopes.as_ref()),
        ] {
            if let Some(values) = values {
                validate_collection(values.len(), policy, path)?;
                validate_names(values, policy, path)?;
            }
        }
        if let Some(permissions) = &self.permissions {
            validate_collection(permissions.len(), policy, "$.permissions")?;
            validate_names(permissions.keys(), policy, "$.permissions")?;
        }
        if let Some(device) = &self.device {
            device
                .id
                .validate_len(policy.max_name_bytes, "$.device.id")?;
            device
                .public_key
                .validate_len(policy.max_name_bytes, "$.device.publicKey")?;
            device
                .signature
                .validate_len(policy.max_name_bytes, "$.device.signature")?;
            device
                .nonce
                .validate_len(policy.max_name_bytes, "$.device.nonce")?;
        }
        Ok(())
    }
}

impl Validate for HelloOk {
    fn validate(&self, policy: &ValidationPolicy) -> Result<(), FrameValidationError> {
        self.server
            .version
            .validate_len(policy.max_name_bytes, "$.server.version")?;
        self.server
            .conn_id
            .validate_len(policy.max_name_bytes, "$.server.connId")?;
        for (path, values) in [
            ("$.features.methods", Some(&self.features.methods)),
            ("$.features.events", Some(&self.features.events)),
            (
                "$.features.capabilities",
                self.features.capabilities.as_ref(),
            ),
        ] {
            if let Some(values) = values {
                validate_collection(values.len(), policy, path)?;
                validate_names(values, policy, path)?;
            }
        }
        validate_collection(self.snapshot.presence.len(), policy, "$.snapshot.presence")?;
        for (index, entry) in self.snapshot.presence.iter().enumerate() {
            for (field, value) in [
                ("host", entry.host.as_ref()),
                ("ip", entry.ip.as_ref()),
                ("version", entry.version.as_ref()),
                ("platform", entry.platform.as_ref()),
                ("deviceFamily", entry.device_family.as_ref()),
                ("modelIdentifier", entry.model_identifier.as_ref()),
                ("mode", entry.mode.as_ref()),
                ("reason", entry.reason.as_ref()),
                ("deviceId", entry.device_id.as_ref()),
                ("instanceId", entry.instance_id.as_ref()),
            ] {
                if let Some(value) = value {
                    value.validate_len(
                        policy.max_name_bytes,
                        &format!("$.snapshot.presence[{index}].{field}"),
                    )?;
                }
            }
            for (field, values) in [
                ("tags", entry.tags.as_ref()),
                ("roles", entry.roles.as_ref()),
                ("scopes", entry.scopes.as_ref()),
            ] {
                if let Some(values) = values {
                    let path = format!("$.snapshot.presence[{index}].{field}");
                    validate_collection(values.len(), policy, &path)?;
                    validate_names(values, policy, &path)?;
                }
            }
        }
        for (path, value) in [
            ("$.snapshot.configPath", self.snapshot.config_path.as_ref()),
            ("$.snapshot.stateDir", self.snapshot.state_dir.as_ref()),
        ] {
            if let Some(value) = value {
                value.validate_len(policy.max_name_bytes, path)?;
            }
        }
        if let Some(defaults) = &self.snapshot.session_defaults {
            for (path, value) in [
                (
                    "$.snapshot.sessionDefaults.defaultAgentId",
                    Some(&defaults.default_agent_id),
                ),
                (
                    "$.snapshot.sessionDefaults.mainKey",
                    Some(&defaults.main_key),
                ),
                (
                    "$.snapshot.sessionDefaults.mainSessionKey",
                    Some(&defaults.main_session_key),
                ),
                ("$.snapshot.sessionDefaults.scope", defaults.scope.as_ref()),
            ] {
                if let Some(value) = value {
                    value.validate_len(policy.max_name_bytes, path)?;
                }
            }
        }
        if let Some(update) = &self.snapshot.update_available {
            for (path, value) in [
                (
                    "$.snapshot.updateAvailable.currentVersion",
                    &update.current_version,
                ),
                (
                    "$.snapshot.updateAvailable.latestVersion",
                    &update.latest_version,
                ),
                ("$.snapshot.updateAvailable.channel", &update.channel),
            ] {
                value.validate_len(policy.max_name_bytes, path)?;
            }
            validate_collection(
                update.extensions.len(),
                policy,
                "$.snapshot.updateAvailable.<extensions>",
            )?;
            for key in update.extensions.keys() {
                if key.len() > policy.max_name_bytes {
                    return Err(FrameValidationError::Limit {
                        path: "$.snapshot.updateAvailable.<extension-key>".to_owned(),
                        actual: key.len(),
                        limit: policy.max_name_bytes,
                    });
                }
            }
        }
        if let Some(tabs) = &self.control_ui_tabs {
            validate_collection(tabs.len(), policy, "$.controlUiTabs")?;
            for (index, tab) in tabs.iter().enumerate() {
                for (field, value) in [
                    ("pluginId", &tab.plugin_id),
                    ("id", &tab.id),
                    ("label", &tab.label),
                ] {
                    value.validate_len(
                        policy.max_name_bytes,
                        &format!("$.controlUiTabs[{index}].{field}"),
                    )?;
                }
            }
        }
        if let Some(urls) = &self.plugin_surface_urls {
            validate_collection(urls.len(), policy, "$.pluginSurfaceUrls")?;
            for (surface, url) in urls {
                surface.validate_len(policy.max_name_bytes, "$.pluginSurfaceUrls.<key>")?;
                url.validate_len(policy.max_name_bytes, "$.pluginSurfaceUrls.<value>")?;
            }
        }
        self.auth
            .role
            .validate_len(policy.max_name_bytes, "$.auth.role")?;
        validate_collection(self.auth.scopes.len(), policy, "$.auth.scopes")?;
        validate_names(&self.auth.scopes, policy, "$.auth.scopes")?;
        if let Some(token) = &self.auth.device_token {
            token.validate_len(policy.max_name_bytes, "$.auth.deviceToken")?;
        }
        if let Some(tokens) = &self.auth.device_tokens {
            validate_collection(tokens.len(), policy, "$.auth.deviceTokens")?;
            for (index, token) in tokens.iter().enumerate() {
                token.device_token.validate_len(
                    policy.max_name_bytes,
                    &format!("$.auth.deviceTokens[{index}].deviceToken"),
                )?;
                token.role.validate_len(
                    policy.max_name_bytes,
                    &format!("$.auth.deviceTokens[{index}].role"),
                )?;
                let path = format!("$.auth.deviceTokens[{index}].scopes");
                validate_collection(token.scopes.len(), policy, &path)?;
                validate_names(&token.scopes, policy, &path)?;
            }
        }
        Ok(())
    }
}

impl Validate for ConnectChallenge {
    fn validate(&self, policy: &ValidationPolicy) -> Result<(), FrameValidationError> {
        self.nonce
            .validate_len(policy.max_name_bytes, "$.payload.nonce")
    }
}

impl Validate for TickEvent {
    fn validate(&self, _policy: &ValidationPolicy) -> Result<(), FrameValidationError> {
        Ok(())
    }
}

impl Validate for ShutdownEvent {
    fn validate(&self, policy: &ValidationPolicy) -> Result<(), FrameValidationError> {
        self.reason
            .validate_len(policy.max_name_bytes, "$.payload.reason")
    }
}

pub(crate) fn classify_method(
    method: Name,
    dynamic_methods: &BTreeMap<String, ()>,
) -> Result<GatewayMethodName, Name> {
    if let Some(core) = resolve_core_method(method.as_str()) {
        Ok(GatewayMethodName::Core(core))
    } else if dynamic_methods.contains_key(method.as_str()) {
        Ok(GatewayMethodName::DynamicPlugin(DynamicGatewayMethodName(
            method,
        )))
    } else {
        Err(method)
    }
}
