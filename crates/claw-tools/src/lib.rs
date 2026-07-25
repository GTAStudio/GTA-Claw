//! The agent tool surface: every capability a model can invoke.
//!
//! # Threat model
//!
//! Tool arguments are attacker-controlled. A model can be steered by injected
//! content in a file it read, a page it fetched, or a message a user pasted, so
//! nothing a tool receives is trusted. The crate is built around four rules:
//!
//! 1. **Closed schemas.** [`schema::ParameterSchema`] accepts a fixed set of
//!    typed fields with explicit bounds and refuses unknown properties.
//! 2. **Deny by default.** A tool cannot run without an
//!    [`permission::Authorization`], and only [`registry::ToolRegistry`] can
//!    mint one, after a [`permission::PermissionBroker`] granted the exact
//!    capability and resource. Absent configuration means refusal. A tool that
//!    reaches a second resource mid-invocation, such as a redirect onto another
//!    host, must ask the same broker again through
//!    [`permission::Authorization::authorize`].
//! 3. **Confinement.** [`sandbox::Sandbox`] resolves every path against a
//!    workspace root and refuses traversal, symlinks, reparse points, UNC
//!    paths, alternate data streams, reserved device names and case-only
//!    collisions. [`exec`] spawns an explicit argument vector with a cleared
//!    environment. [`net`] validates every destination and every redirect hop.
//! 4. **Accountability.** Every invocation writes structured
//!    [`audit::ToolAuditRecord`] entries with secrets redacted, and the
//!    authorization record is committed before any side effect occurs.
//!
//! # Layout
//!
//! ```text
//! caller -> ToolRegistry::invoke
//!             |- ParameterSchema::validate   (closed, typed, bounded)
//!             |- Tool::resource              (pure; what will be touched)
//!             |- PermissionBroker::evaluate  (deny by default)
//!             |- audit(Authorized)           (before any side effect)
//!             |- Tool::invoke                (needs an Authorization)
//!             '- audit(Completed)
//! ```

pub mod audit;
pub mod clock;
pub mod error;
pub mod exec;
pub mod fs;
pub mod net;
pub mod permission;
pub mod registry;
pub mod sandbox;
pub mod schema;
pub mod tool;

pub use audit::{
    AuditError, AuditOutcome, AuditPhase, AuditReason, InMemoryAuditSink, ToolAuditRecord,
    ToolAuditSink, opaque_arguments, redact,
};
pub use clock::{Clock, FixedClock, MonotonicClock, SystemClock};
pub use error::ToolError;
pub use exec::{
    ArgvPolicy, CancellationToken, EnvPolicy, ExecPolicy, ExecutionError, ProcessExecTool,
    ProcessOutcome,
};
pub use fs::{
    FsGlobTool, FsListTool, FsPatchTool, FsReadTool, FsSearchTool, FsWriteTool, GlobError,
    GlobPattern, PatchError, UnifiedPatch,
};
pub use net::{
    DenyAllSearchProvider, DenyAllTransport, Destination, HttpRequest, HttpResponse, HttpTransport,
    NetFetchTool, NetworkError, PinnedHttpTransport, PrivateOriginExceptions, SearchHit,
    SearchProvider, UrlPolicy, WebSearchTool,
};
pub use permission::{
    Approval, Authorization, Capability, DenialReason, DenyAllBroker, Grant, GrantId, GrantLedger,
    GrantRequest, GrantScope, PermissionBroker, PermissionDecision, PermissionDescriptor,
    PermissionError, PermissionRequest, Resource, ResourceGate, RiskLevel,
};
pub use registry::{ToolRegistry, declared_capabilities};
pub use sandbox::{
    DirectoryEntry, EntryKind, RelativePath, ResolvedPath, Sandbox, SandboxError, SandboxLimits,
    WriteMode,
};
pub use schema::{Arguments, Field, FieldType, ParameterSchema, SchemaError};
pub use tool::{Tool, ToolContext, ToolDescriptor, ToolOutput};
