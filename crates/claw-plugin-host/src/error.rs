//! Errors produced by the plugin host.

use core::fmt;
use std::path::PathBuf;

use claw_plugin_api::abi::{AbiIncompatibility, VersionParseError};
use claw_plugin_api::capability::{CapabilityDenial, CapabilitySetError};
use claw_plugin_api::limits::LimitsError;
use claw_plugin_api::manifest::ManifestError;
use claw_plugin_api::trust::{TrustError, VerificationError};

/// Why a guest call ended early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminationCause {
    /// The caller cancelled the in-flight guest call.
    Cancelled,
    /// The guest exhausted its fuel budget.
    FuelExhausted,
    /// The guest ran past its wall-clock budget and was interrupted.
    Timeout,
    /// The guest exceeded a memory, table or instance limit.
    ResourceLimit,
    /// The guest exhausted its call stack.
    StackOverflow,
    /// The guest executed a trapping instruction, including `unreachable`.
    Trap,
}

impl TerminationCause {
    /// Stable, machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::FuelExhausted => "fuel-exhausted",
            Self::Timeout => "timeout",
            Self::ResourceLimit => "resource-limit",
            Self::StackOverflow => "stack-overflow",
            Self::Trap => "trap",
        }
    }
}

impl fmt::Display for TerminationCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error reported by the guest through the ABI's `result` type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestFailure {
    /// Stable error class the guest chose.
    pub code: &'static str,
    /// Guest-supplied detail.
    pub message: String,
}

impl fmt::Display for GuestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "guest returned {}: {}", self.code, self.message)
    }
}

/// Everything that can go wrong while discovering, loading or running a plugin.
#[derive(Debug)]
#[non_exhaustive]
pub enum HostError {
    /// A filesystem operation failed.
    Io {
        /// The path the host was working on.
        path: PathBuf,
        /// Operating-system message.
        message: String,
    },
    /// The manifest was not schema-valid.
    Manifest(ManifestError),
    /// The manifest's capability list was not usable.
    CapabilitySet(CapabilitySetError),
    /// The manifest's resource limits were out of range.
    Limits(LimitsError),
    /// The component location or provenance was refused.
    Trust(TrustError),
    /// The manifest signature check failed.
    Verification(VerificationError),
    /// The component file is larger than the manifest's own limit allows.
    ComponentTooLarge {
        /// Size on disk.
        actual: u64,
        /// Limit from the manifest.
        limit: u64,
    },
    /// The component bytes did not hash to the pinned digest.
    DigestMismatch {
        /// Digest pinned by the manifest.
        expected: String,
        /// Digest of the bytes on disk.
        actual: String,
    },
    /// A value crossing the guest boundary exceeded the manifest's payload cap.
    PayloadTooLarge {
        /// Which boundary value exceeded the limit.
        field: &'static str,
        /// Encoded size in bytes.
        actual: usize,
        /// Maximum accepted size in bytes.
        limit: u32,
    },
    /// A typed JSON tool call received a non-JSON guest response.
    InvalidGuestResponse {
        /// Plugin that returned the response.
        plugin_id: String,
        /// Tool that was invoked.
        tool: String,
        /// JSON decoder diagnostic.
        message: String,
    },
    /// Typed input could not be encoded for the string-based component ABI.
    InvalidToolInput {
        /// Plugin that would have received the request.
        plugin_id: String,
        /// Tool that would have been invoked.
        tool: String,
        /// JSON encoder diagnostic.
        message: String,
    },
    /// The manifest declared an ABI version this host cannot run.
    Abi(AbiIncompatibility),
    /// A version string in the manifest was malformed.
    Version(VersionParseError),
    /// The component's `describe` disagreed with its manifest.
    IdentityMismatch {
        /// Which field disagreed.
        field: &'static str,
        /// What the manifest said.
        manifest: String,
        /// What the component said.
        component: String,
    },
    /// The component could not be compiled or instantiated.
    Instantiate(String),
    /// The component imports something this world does not provide, which for
    /// this host always means an attempt at ambient access.
    UnsatisfiedImport(String),
    /// A guest call was terminated by the sandbox.
    Terminated {
        /// Why the call ended.
        cause: TerminationCause,
        /// Wasmtime's description of the trap.
        detail: String,
    },
    /// The guest returned an error through the ABI.
    Guest(GuestFailure),
    /// Cancellation was already requested before the guest call began.
    Cancelled {
        /// Operation that was not started.
        operation: &'static str,
    },
    /// A host call was refused by capability enforcement.
    Denied(CapabilityDenial),
    /// No plugin with this id is loaded.
    UnknownPlugin(String),
    /// A plugin with this id is already loaded.
    DuplicatePlugin(String),
    /// The plugin is not in a state where this operation is allowed.
    WrongState {
        /// The plugin id.
        id: String,
        /// The state the plugin is in.
        actual: &'static str,
        /// The state the operation needs.
        expected: &'static str,
    },
    /// The plugin previously trapped and must be reloaded before further use.
    Faulted {
        /// The plugin id.
        id: String,
        /// Why it faulted.
        cause: TerminationCause,
    },
}

impl HostError {
    pub(crate) fn io(path: impl Into<PathBuf>, error: &std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            message: error.to_string(),
        }
    }

    /// The wasmtime-reported termination, when this error is a termination.
    #[must_use]
    pub const fn termination(&self) -> Option<TerminationCause> {
        match self {
            Self::Terminated { cause, .. } => Some(*cause),
            _ => None,
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(f, "i/o error at {}: {message}", path.display()),
            Self::Manifest(error) => write!(f, "invalid manifest: {error}"),
            Self::CapabilitySet(error) => write!(f, "invalid capability set: {error}"),
            Self::Limits(error) => write!(f, "invalid resource limits: {error}"),
            Self::Trust(error) => write!(f, "refused by trust policy: {error}"),
            Self::Verification(error) => write!(f, "signature check failed: {error}"),
            Self::ComponentTooLarge { actual, limit } => write!(
                f,
                "component is {actual} bytes, which exceeds the {limit} byte limit"
            ),
            Self::DigestMismatch { expected, actual } => write!(
                f,
                "component digest mismatch: manifest pins {expected}, bytes hash to {actual}"
            ),
            Self::PayloadTooLarge {
                field,
                actual,
                limit,
            } => write!(
                f,
                "plugin {field} is {actual} bytes, which exceeds the {limit} byte payload limit"
            ),
            Self::InvalidGuestResponse {
                plugin_id,
                tool,
                message,
            } => write!(
                f,
                "plugin `{plugin_id}` tool `{tool}` returned invalid JSON: {message}"
            ),
            Self::InvalidToolInput {
                plugin_id,
                tool,
                message,
            } => write!(
                f,
                "plugin `{plugin_id}` tool `{tool}` input could not be encoded as JSON: {message}"
            ),
            Self::Abi(error) => write!(f, "incompatible plugin ABI: {error}"),
            Self::Version(error) => write!(f, "malformed version: {error}"),
            Self::IdentityMismatch {
                field,
                manifest,
                component,
            } => write!(
                f,
                "component {field} `{component}` does not match manifest {field} `{manifest}`"
            ),
            Self::Instantiate(message) => {
                write!(f, "component could not be instantiated: {message}")
            }
            Self::UnsatisfiedImport(message) => {
                write!(
                    f,
                    "component requires an import this host never provides: {message}"
                )
            }
            Self::Terminated { cause, detail } => {
                write!(f, "guest call terminated ({cause}): {detail}")
            }
            Self::Guest(failure) => fmt::Display::fmt(failure, f),
            Self::Cancelled { operation } => {
                write!(f, "plugin {operation} was cancelled before it started")
            }
            Self::Denied(denial) => fmt::Display::fmt(denial, f),
            Self::UnknownPlugin(id) => write!(f, "no plugin `{id}` is loaded"),
            Self::DuplicatePlugin(id) => write!(f, "plugin `{id}` is already loaded"),
            Self::WrongState {
                id,
                actual,
                expected,
            } => write!(
                f,
                "plugin `{id}` is {actual}, but this needs it to be {expected}"
            ),
            Self::Faulted { id, cause } => {
                write!(f, "plugin `{id}` faulted ({cause}) and must be reloaded")
            }
        }
    }
}

impl core::error::Error for HostError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Manifest(error) => Some(error),
            Self::CapabilitySet(error) => Some(error),
            Self::Limits(error) => Some(error),
            Self::Trust(error) => Some(error),
            Self::Verification(error) => Some(error),
            Self::Abi(error) => Some(error),
            Self::Version(error) => Some(error),
            Self::Denied(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ManifestError> for HostError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl From<CapabilitySetError> for HostError {
    fn from(error: CapabilitySetError) -> Self {
        Self::CapabilitySet(error)
    }
}

impl From<LimitsError> for HostError {
    fn from(error: LimitsError) -> Self {
        Self::Limits(error)
    }
}

impl From<TrustError> for HostError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error)
    }
}

impl From<VerificationError> for HostError {
    fn from(error: VerificationError) -> Self {
        Self::Verification(error)
    }
}

impl From<AbiIncompatibility> for HostError {
    fn from(error: AbiIncompatibility) -> Self {
        Self::Abi(error)
    }
}

impl From<VersionParseError> for HostError {
    fn from(error: VersionParseError) -> Self {
        Self::Version(error)
    }
}
