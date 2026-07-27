//! Closed worker admission protocol for the GTA Claw Gateway.
//!
//! The ordinary Gateway handshake in `claw-protocol` deliberately refuses the
//! `worker` role: [`claw_protocol::gateway::authorize`][authorize] answers
//! `AuthorizationError::WorkerNotAdmitted` for it, and the negotiation reducer
//! rejects a `worker` client identity with *"worker identity must use the
//! closed worker protocol"*. This crate is that closed protocol.
//!
//! [authorize]: https://github.com/GTAStudio/GTA-Claw
//!
//! # What "closed" means here
//!
//! A worker never joins the open operator/node RPC surface. It is admitted by
//! redeeming a single-use ticket that the Gateway minted for one worker
//! identity, for one generation, for a bounded time, carrying an explicit
//! method allowlist. Every dimension fails closed:
//!
//! | Dimension | Rule |
//! | --- | --- |
//! | admission | only a ticket this controller minted and has not yet redeemed is accepted; the secret is compared in constant time |
//! | fencing | generations are monotonic per worker identity; opening a new one immediately invalidates every older ticket **and every live session** |
//! | expiry | a ticket and the session it mints both die at a wall-clock instant read from an injectable [`Clock`] |
//! | RPC allowlist | a session may call exactly the methods named in its ticket; anything else is denied, including methods this crate itself defines |
//! | replay | a ticket may be redeemed once; a call identifier may be accepted once per session |
//! | payload limit | frame length is checked against [`PayloadLimits`] *before* any parsing |
//!
//! # Scope
//!
//! `compat/upstream/inventories/gateway-protocol.json` freezes the `worker`
//! role identity and its `closed_worker` protocol class. It does **not** freeze
//! the admission or RPC payload schemas, so the wire shapes here
//! ([`AdmissionRequest`], [`WorkerCall`]) and the method names in
//! [`WORKER_PROTOCOL_METHODS`] are this crate's own design and are not claimed
//! to be byte-compatible with the upstream package.
//!
//! # Integration
//!
//! This crate is transport-independent and holds no sockets. A Gateway embeds
//! it by keeping one [`AdmissionController`] per server, calling
//! [`AdmissionController::issue`] when it hands a worker its credentials,
//! [`AdmissionController::admit_encoded`] on the first frame of a `worker`
//! connection instead of running the ordinary handshake, and
//! [`AdmissionController::call_encoded`] for every later frame on that
//! connection.

pub mod allowlist;
pub mod clock;
pub mod controller;
pub mod error;
pub mod fencing;
pub mod identity;
pub mod limits;
pub mod secret;
pub mod ticket;

pub use allowlist::{MethodAllowlist, MethodName, MethodNameError, WORKER_PROTOCOL_METHODS};
pub use clock::{Clock, ManualClock, SystemClock};
pub use controller::{
    AdmissionController, AdmittedSession, CallAccepted, SessionId, WorkerCall, WorkerCallFrame,
};
pub use error::{AdmissionRejection, CallRejection, IssueError};
pub use fencing::{FencingError, FencingToken, GenerationLedger};
pub use identity::{CallId, IdentifierError, TicketId, WorkerId};
pub use limits::{DEFAULT_MAX_ADMISSION_BYTES, DEFAULT_MAX_CALL_BYTES, LimitError, PayloadLimits};
pub use secret::{
    ADMISSION_SECRET_BYTES, AdmissionSecret, OsSecretSource, SecretSource, SecretSourceError,
};
pub use ticket::{AdmissionRequest, AdmissionTicket, IssuedAdmission};
