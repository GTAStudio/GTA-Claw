//! The values that cross composition boundaries.
//!
//! Everything here is either a validated name or a validated *object*. The
//! distinction matters: a name is something a caller supplies and the layer
//! checks, while an object is the result of that check. Privileged operations
//! take objects, so the check cannot be skipped or repeated against a different
//! answer.

use std::fmt::{self, Display, Formatter};
use std::net::SocketAddr;
use std::time::Duration;

use claw_domain::SessionId;
use secrecy::{ExposeSecret, SecretString};

use super::authority::Principal;
use super::clock::MonotonicInstant;
use super::egress::ResolvedEndpoint;
use super::id::SubsystemId;

const MAX_NAME_BYTES: usize = 128;

/// A name that does not satisfy its grammar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidName {
    kind: &'static str,
    value: String,
    reason: &'static str,
}

impl InvalidName {
    /// Returns which kind of name was rejected.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// Returns the rejected text.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns why it was rejected.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl Display for InvalidName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {} {:?}: {}",
            self.kind, self.value, self.reason
        )
    }
}

impl std::error::Error for InvalidName {}

macro_rules! validated_name {
    ($($type_name:ident => $label:literal, $description:literal;)+) => {
        $(
            #[doc = $description]
            ///
            /// The grammar is shared by every name in the composition: between one
            /// and 128 bytes, no leading or trailing whitespace, and no control
            /// characters. It is deliberately permissive about the interior so that
            /// third-party provider and tool names are usable verbatim.
            #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
            pub struct $type_name(String);

            impl $type_name {
                #[doc = concat!("Creates a ", $label, " after checking the grammar.")]
                ///
                /// # Errors
                ///
                /// Returns [`InvalidName`] when the value is empty, longer than 128
                /// bytes, padded with whitespace, or contains a control character.
                pub fn new(value: impl Into<String>) -> Result<Self, InvalidName> {
                    let value = value.into();
                    let reject = |reason: &'static str| InvalidName {
                        kind: $label,
                        value: value.clone(),
                        reason,
                    };

                    if value.is_empty() {
                        return Err(reject("must not be empty"));
                    }
                    if value.len() > MAX_NAME_BYTES {
                        return Err(reject("must not exceed 128 bytes"));
                    }
                    if value.trim() != value {
                        return Err(reject("must not be padded with whitespace"));
                    }
                    if value.chars().any(char::is_control) {
                        return Err(reject("must not contain control characters"));
                    }

                    Ok(Self(value))
                }

                /// Returns the name as text.
                #[must_use]
                pub fn as_str(&self) -> &str {
                    &self.0
                }
            }

            impl Display for $type_name {
                fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                    formatter.write_str(&self.0)
                }
            }
        )+
    };
}

validated_name! {
    ProviderName => "provider name", "The name of a model provider, as configured.";
    ModelName => "model name", "The name of a model offered by a provider.";
    ToolName => "tool name", "The name of a tool the model may call.";
    CredentialName => "credential name", "The name a credential is filed under in the secret store.";
}

/// One thing a tool is allowed to do.
///
/// Capabilities are checked at the moment a tool is invoked, never at the moment
/// it is registered, because the set a principal is allowed can change while the
/// daemon runs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Capability {
    /// Read files inside the session workspace.
    ReadWorkspace,
    /// Modify files inside the session workspace.
    WriteWorkspace,
    /// Open outbound network connections, subject to the egress policy.
    Network,
    /// Start an operating system process.
    SpawnProcess,
    /// Read process environment variables.
    ReadEnvironment,
}

impl Capability {
    /// Every capability, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::ReadWorkspace,
        Self::WriteWorkspace,
        Self::Network,
        Self::SpawnProcess,
        Self::ReadEnvironment,
    ];

    /// Returns the stable label used in denial text.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ReadWorkspace => "read-workspace",
            Self::WriteWorkspace => "write-workspace",
            Self::Network => "network",
            Self::SpawnProcess => "spawn-process",
            Self::ReadEnvironment => "read-environment",
        }
    }
}

impl Display for Capability {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// A sorted, duplicate-free set of capabilities.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilitySet(Vec<Capability>);

impl CapabilitySet {
    /// Creates the empty set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Creates a set holding every capability.
    #[must_use]
    pub fn all() -> Self {
        Self(Capability::ALL.to_vec())
    }

    /// Creates a set from an iterator, sorting and de-duplicating it.
    #[must_use]
    pub fn from_capabilities(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        let mut held: Vec<Capability> = capabilities.into_iter().collect();
        held.sort_unstable();
        held.dedup();
        Self(held)
    }

    /// Returns whether `capability` is held.
    #[must_use]
    pub fn contains(&self, capability: Capability) -> bool {
        self.0.contains(&capability)
    }

    /// Returns whether every capability held here is also held by `other`.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0.iter().all(|held| other.contains(*held))
    }

    /// Returns the capabilities held here but not by `other`, in sorted order.
    #[must_use]
    pub fn missing_from(&self, other: &Self) -> Vec<Capability> {
        self.0
            .iter()
            .filter(|held| !other.contains(**held))
            .copied()
            .collect()
    }

    /// Returns the capabilities in sorted order.
    #[must_use]
    pub fn as_slice(&self) -> &[Capability] {
        &self.0
    }

    /// Returns whether the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<T: IntoIterator<Item = Capability>>(capabilities: T) -> Self {
        Self::from_capabilities(capabilities)
    }
}

impl Display for CapabilitySet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return formatter.write_str("none");
        }

        let rendered: Vec<&str> = self.0.iter().map(|held| held.label()).collect();
        formatter.write_str(&rendered.join(","))
    }
}

/// What the daemon was configured with.
///
/// Produced by [`ConfigPort`](super::ports::ConfigPort) and handed to every
/// subsystem through [`StartContext`](super::subsystem::StartContext).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSettings {
    listen: Vec<SocketAddr>,
    default_provider: ProviderName,
    default_model: ModelName,
    max_concurrent_turns: usize,
    turn_deadline: Duration,
    authorization_ttl: Duration,
}

impl RuntimeSettings {
    /// Creates settings.
    #[must_use]
    pub const fn new(
        listen: Vec<SocketAddr>,
        default_provider: ProviderName,
        default_model: ModelName,
        max_concurrent_turns: usize,
        turn_deadline: Duration,
        authorization_ttl: Duration,
    ) -> Self {
        Self {
            listen,
            default_provider,
            default_model,
            max_concurrent_turns,
            turn_deadline,
            authorization_ttl,
        }
    }

    /// Returns the addresses ingress subsystems should bind.
    #[must_use]
    pub fn listen(&self) -> &[SocketAddr] {
        &self.listen
    }

    /// Returns the provider used when a request does not name one.
    #[must_use]
    pub const fn default_provider(&self) -> &ProviderName {
        &self.default_provider
    }

    /// Returns the model used when a request does not name one.
    #[must_use]
    pub const fn default_model(&self) -> &ModelName {
        &self.default_model
    }

    /// Returns the cap on turns running at once.
    #[must_use]
    pub const fn max_concurrent_turns(&self) -> usize {
        self.max_concurrent_turns
    }

    /// Returns how long a single turn may run.
    #[must_use]
    pub const fn turn_deadline(&self) -> Duration {
        self.turn_deadline
    }

    /// Returns how long an authorization stays redeemable.
    ///
    /// This is an upper bound the composition enforces on top of whatever the
    /// authority returns, so a permissive policy cannot mint a long-lived
    /// capability.
    #[must_use]
    pub const fn authorization_ttl(&self) -> Duration {
        self.authorization_ttl
    }
}

/// A session that exists, addressed by a principal that was allowed to address it.
///
/// There is no public constructor: a `ResolvedSession` is what
/// [`SessionService`](super::service::SessionService) produces after consulting
/// persistence, so holding one is proof the lookup happened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSession {
    id: SessionId,
    principal: Principal,
    revision: u64,
    opened_at: MonotonicInstant,
}

impl ResolvedSession {
    pub(super) const fn new(
        id: SessionId,
        principal: Principal,
        revision: u64,
        opened_at: MonotonicInstant,
    ) -> Self {
        Self {
            id,
            principal,
            revision,
            opened_at,
        }
    }

    /// Returns the session identifier.
    #[must_use]
    pub const fn id(&self) -> &SessionId {
        &self.id
    }

    /// Returns the principal this session was resolved for.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the persisted revision the session was at when resolved.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns when the session was resolved.
    #[must_use]
    pub const fn opened_at(&self) -> MonotonicInstant {
        self.opened_at
    }
}

/// What persistence knows about a session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    id: SessionId,
    revision: u64,
    turns: u32,
}

impl SessionRecord {
    /// Creates a record.
    #[must_use]
    pub const fn new(id: SessionId, revision: u64, turns: u32) -> Self {
        Self {
            id,
            revision,
            turns,
        }
    }

    /// Returns the session identifier.
    #[must_use]
    pub const fn id(&self) -> &SessionId {
        &self.id
    }

    /// Returns the stored revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns how many turns the session has recorded.
    #[must_use]
    pub const fn turns(&self) -> u32 {
        self.turns
    }
}

/// The context a turn will be run against.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AssembledContext {
    items: Vec<String>,
    truncated: bool,
}

impl AssembledContext {
    /// Creates a context from ordered items.
    #[must_use]
    pub const fn new(items: Vec<String>, truncated: bool) -> Self {
        Self { items, truncated }
    }

    /// Returns the ordered items.
    #[must_use]
    pub fn items(&self) -> &[String] {
        &self.items
    }

    /// Returns whether older material was dropped to fit a budget.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

/// A provider that has been looked up and whose origin has been checked.
///
/// The origin is a [`ResolvedEndpoint`], so a binding is proof that the
/// provider's address passed the egress policy. Nothing downstream ever sees the
/// provider's configured URL as text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderBinding {
    name: ProviderName,
    origin: ResolvedEndpoint,
    credential: CredentialName,
    models: Vec<ModelName>,
}

impl ProviderBinding {
    /// Creates a binding.
    ///
    /// Implementations of [`ProviderRegistryPort`](super::ports::ProviderRegistryPort)
    /// build these, and must obtain `origin` from
    /// [`EgressGuard::resolve`](super::egress::EgressGuard::resolve) rather than
    /// from anywhere else.
    #[must_use]
    pub const fn new(
        name: ProviderName,
        origin: ResolvedEndpoint,
        credential: CredentialName,
        models: Vec<ModelName>,
    ) -> Self {
        Self {
            name,
            origin,
            credential,
            models,
        }
    }

    /// Returns the provider name.
    #[must_use]
    pub const fn name(&self) -> &ProviderName {
        &self.name
    }

    /// Returns the checked origin.
    #[must_use]
    pub const fn origin(&self) -> &ResolvedEndpoint {
        &self.origin
    }

    /// Returns which credential this provider authenticates with.
    #[must_use]
    pub const fn credential(&self) -> &CredentialName {
        &self.credential
    }

    /// Returns the models the provider offers.
    #[must_use]
    pub fn models(&self) -> &[ModelName] {
        &self.models
    }

    /// Returns whether the provider offers `model`.
    #[must_use]
    pub fn offers(&self, model: &ModelName) -> bool {
        self.models.contains(model)
    }
}

/// A credential, bound to the origin it was released for.
///
/// The lease is not `Clone` and does not implement `Debug` in a way that can
/// reveal the secret. Its origin is recorded so a transport can assert it is
/// sending the credential to the same place the secret store released it for.
pub struct CredentialLease {
    name: CredentialName,
    origin: ResolvedEndpoint,
    secret: SecretString,
}

impl CredentialLease {
    /// Releases `secret` for use against `origin` only.
    #[must_use]
    pub const fn new(name: CredentialName, origin: ResolvedEndpoint, secret: SecretString) -> Self {
        Self {
            name,
            origin,
            secret,
        }
    }

    /// Returns which credential this is.
    #[must_use]
    pub const fn name(&self) -> &CredentialName {
        &self.name
    }

    /// Returns the origin the credential was released for.
    #[must_use]
    pub const fn origin(&self) -> &ResolvedEndpoint {
        &self.origin
    }

    /// Returns whether this lease may be sent to `endpoint`.
    ///
    /// Two endpoints match when their scheme, host, port and checked addresses
    /// are all identical, so a credential released for one origin cannot be
    /// replayed against another that merely shares a hostname.
    #[must_use]
    pub fn is_bound_to(&self, endpoint: &ResolvedEndpoint) -> bool {
        self.origin.scheme() == endpoint.scheme()
            && self.origin.host() == endpoint.host()
            && self.origin.port() == endpoint.port()
            && self.origin.addresses() == endpoint.addresses()
    }

    /// Exposes the secret.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.secret.expose_secret()
    }
}

impl fmt::Debug for CredentialLease {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialLease")
            .field("name", &self.name)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// One authorized call to a provider.
///
/// This is the subject of a [`Grant`](super::authority::Grant): the transport
/// receives the grant, redeems it, and only then holds the call.
#[derive(Debug)]
pub struct ProviderCall {
    binding: ProviderBinding,
    credential: CredentialLease,
    model: ModelName,
    context: AssembledContext,
    prompt: String,
}

impl ProviderCall {
    /// Assembles a call.
    #[must_use]
    pub const fn new(
        binding: ProviderBinding,
        credential: CredentialLease,
        model: ModelName,
        context: AssembledContext,
        prompt: String,
    ) -> Self {
        Self {
            binding,
            credential,
            model,
            context,
            prompt,
        }
    }

    /// Returns the provider binding, including the checked origin.
    #[must_use]
    pub const fn binding(&self) -> &ProviderBinding {
        &self.binding
    }

    /// Returns the credential released for this call.
    #[must_use]
    pub const fn credential(&self) -> &CredentialLease {
        &self.credential
    }

    /// Returns the model to invoke.
    #[must_use]
    pub const fn model(&self) -> &ModelName {
        &self.model
    }

    /// Returns the assembled context.
    #[must_use]
    pub const fn context(&self) -> &AssembledContext {
        &self.context
    }

    /// Returns the prompt text.
    #[must_use]
    pub fn prompt(&self) -> &str {
        &self.prompt
    }
}

/// A tool the model asked for by name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolRequest {
    name: ToolName,
    arguments: String,
}

impl ToolRequest {
    /// Creates a request.
    #[must_use]
    pub const fn new(name: ToolName, arguments: String) -> Self {
        Self { name, arguments }
    }

    /// Returns the requested tool name.
    #[must_use]
    pub const fn name(&self) -> &ToolName {
        &self.name
    }

    /// Returns the raw arguments.
    #[must_use]
    pub fn arguments(&self) -> &str {
        &self.arguments
    }
}

/// What a provider replied.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProviderReply {
    text: String,
    requested_tools: Vec<ToolRequest>,
}

impl ProviderReply {
    /// Creates a reply.
    #[must_use]
    pub const fn new(text: String, requested_tools: Vec<ToolRequest>) -> Self {
        Self {
            text,
            requested_tools,
        }
    }

    /// Returns the assistant text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the tools the provider asked to call.
    #[must_use]
    pub fn requested_tools(&self) -> &[ToolRequest] {
        &self.requested_tools
    }
}

/// A tool that exists, with the capabilities it needs to run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolBinding {
    name: ToolName,
    description: String,
    required: CapabilitySet,
}

impl ToolBinding {
    /// Creates a binding.
    #[must_use]
    pub const fn new(name: ToolName, description: String, required: CapabilitySet) -> Self {
        Self {
            name,
            description,
            required,
        }
    }

    /// Returns the tool name.
    #[must_use]
    pub const fn name(&self) -> &ToolName {
        &self.name
    }

    /// Returns the human-readable description offered to the model.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the capabilities this tool needs.
    #[must_use]
    pub const fn required_capabilities(&self) -> &CapabilitySet {
        &self.required
    }
}

/// One authorized tool invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCall {
    binding: ToolBinding,
    session: ResolvedSession,
    arguments: String,
}

impl ToolCall {
    /// Assembles a call against an already resolved binding.
    #[must_use]
    pub const fn new(binding: ToolBinding, session: ResolvedSession, arguments: String) -> Self {
        Self {
            binding,
            session,
            arguments,
        }
    }

    /// Returns the resolved tool.
    #[must_use]
    pub const fn binding(&self) -> &ToolBinding {
        &self.binding
    }

    /// Returns the session the call belongs to.
    #[must_use]
    pub const fn session(&self) -> &ResolvedSession {
        &self.session
    }

    /// Returns the raw arguments.
    #[must_use]
    pub fn arguments(&self) -> &str {
        &self.arguments
    }
}

/// What a tool produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolOutcome {
    tool: ToolName,
    output: String,
    failed: bool,
}

impl ToolOutcome {
    /// Records a successful invocation.
    #[must_use]
    pub const fn success(tool: ToolName, output: String) -> Self {
        Self {
            tool,
            output,
            failed: false,
        }
    }

    /// Records a failed invocation.
    ///
    /// A failed tool is not a failed turn: the text is handed back to the model
    /// so it can choose what to do.
    #[must_use]
    pub const fn failure(tool: ToolName, output: String) -> Self {
        Self {
            tool,
            output,
            failed: true,
        }
    }

    /// Returns which tool ran.
    #[must_use]
    pub const fn tool(&self) -> &ToolName {
        &self.tool
    }

    /// Returns the output text.
    #[must_use]
    pub fn output(&self) -> &str {
        &self.output
    }

    /// Returns whether the tool reported failure.
    #[must_use]
    pub const fn failed(&self) -> bool {
        self.failed
    }
}

/// A turn that has been authorized and is ready to run.
#[derive(Debug)]
pub struct TurnRequest {
    session: ResolvedSession,
    prompt: String,
    binding: ProviderBinding,
    model: ModelName,
    context: AssembledContext,
    deadline: MonotonicInstant,
}

impl TurnRequest {
    pub(super) const fn new(
        session: ResolvedSession,
        prompt: String,
        binding: ProviderBinding,
        model: ModelName,
        context: AssembledContext,
        deadline: MonotonicInstant,
    ) -> Self {
        Self {
            session,
            prompt,
            binding,
            model,
            context,
            deadline,
        }
    }

    /// Returns the session.
    #[must_use]
    pub const fn session(&self) -> &ResolvedSession {
        &self.session
    }

    /// Returns the prompt text.
    #[must_use]
    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    /// Returns the provider binding chosen for the turn.
    #[must_use]
    pub const fn binding(&self) -> &ProviderBinding {
        &self.binding
    }

    /// Returns the model chosen for the turn.
    #[must_use]
    pub const fn model(&self) -> &ModelName {
        &self.model
    }

    /// Returns the assembled context.
    #[must_use]
    pub const fn context(&self) -> &AssembledContext {
        &self.context
    }

    /// Returns the instant after which the turn must stop.
    #[must_use]
    pub const fn deadline(&self) -> MonotonicInstant {
        self.deadline
    }
}

/// Something observable that happened during a turn.
///
/// Events carry a sequence number that increases by one per turn, so a consumer
/// can detect a gap rather than silently rendering a partial conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TurnEvent {
    /// The turn began.
    Started {
        /// Position in the turn's event stream.
        sequence: u64,
    },
    /// A fragment of assistant text arrived.
    AssistantDelta {
        /// Position in the turn's event stream.
        sequence: u64,
        /// The fragment.
        text: String,
    },
    /// A tool finished.
    ToolCompleted {
        /// Position in the turn's event stream.
        sequence: u64,
        /// What the tool produced.
        outcome: ToolOutcome,
    },
    /// The turn finished successfully.
    Finished {
        /// Position in the turn's event stream.
        sequence: u64,
        /// The completed turn.
        summary: TurnSummary,
    },
    /// The turn stopped without completing.
    Failed {
        /// Position in the turn's event stream.
        sequence: u64,
        /// Why it stopped.
        reason: String,
    },
}

impl TurnEvent {
    /// Returns the position of this event in its turn's stream.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        match self {
            Self::Started { sequence }
            | Self::AssistantDelta { sequence, .. }
            | Self::ToolCompleted { sequence, .. }
            | Self::Finished { sequence, .. }
            | Self::Failed { sequence, .. } => *sequence,
        }
    }

    /// Returns whether this event ends its turn.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Finished { .. } | Self::Failed { .. })
    }
}

/// A completed turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnSummary {
    response: String,
    provider: ProviderName,
    model: ModelName,
    tool_calls: u32,
}

impl TurnSummary {
    /// Creates a summary.
    #[must_use]
    pub const fn new(
        response: String,
        provider: ProviderName,
        model: ModelName,
        tool_calls: u32,
    ) -> Self {
        Self {
            response,
            provider,
            model,
            tool_calls,
        }
    }

    /// Returns the assembled assistant response.
    #[must_use]
    pub fn response(&self) -> &str {
        &self.response
    }

    /// Returns which provider served the turn.
    #[must_use]
    pub const fn provider(&self) -> &ProviderName {
        &self.provider
    }

    /// Returns which model served the turn.
    #[must_use]
    pub const fn model(&self) -> &ModelName {
        &self.model
    }

    /// Returns how many tools ran.
    #[must_use]
    pub const fn tool_calls(&self) -> u32 {
        self.tool_calls
    }
}

/// A turn as persistence stores it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnRecord {
    session: SessionId,
    ordinal: u64,
    prompt: String,
    response: String,
}

impl TurnRecord {
    /// Creates a record.
    #[must_use]
    pub const fn new(session: SessionId, ordinal: u64, prompt: String, response: String) -> Self {
        Self {
            session,
            ordinal,
            prompt,
            response,
        }
    }

    /// Returns the session the turn belongs to.
    #[must_use]
    pub const fn session(&self) -> &SessionId {
        &self.session
    }

    /// Returns the turn's position within its session, counting from one.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Returns the prompt.
    #[must_use]
    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    /// Returns the response.
    #[must_use]
    pub fn response(&self) -> &str {
        &self.response
    }
}

/// How serious an observed event is.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    /// Detail useful only when diagnosing.
    Debug,
    /// Normal operation.
    Info,
    /// Something unexpected that did not stop the daemon.
    Warn,
    /// Something that failed.
    Error,
}

impl Severity {
    /// Returns the stable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

impl Display for Severity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// One telemetry record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedEvent {
    subsystem: SubsystemId,
    severity: Severity,
    message: String,
    at: MonotonicInstant,
}

impl ObservedEvent {
    /// Creates an event.
    #[must_use]
    pub const fn new(
        subsystem: SubsystemId,
        severity: Severity,
        message: String,
        at: MonotonicInstant,
    ) -> Self {
        Self {
            subsystem,
            severity,
            message,
            at,
        }
    }

    /// Returns which subsystem emitted it.
    #[must_use]
    pub const fn subsystem(&self) -> &SubsystemId {
        &self.subsystem
    }

    /// Returns the severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Returns the message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns when it happened.
    #[must_use]
    pub const fn at(&self) -> MonotonicInstant {
        self.at
    }
}

/// A request to instantiate a plugin component with a capability set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginActivation {
    component: String,
    granted: CapabilitySet,
}

impl PluginActivation {
    /// Creates an activation request.
    #[must_use]
    pub const fn new(component: String, granted: CapabilitySet) -> Self {
        Self { component, granted }
    }

    /// Returns the component name.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Returns the capabilities to install on the instance.
    ///
    /// The plugin host must install these on the instance it is about to create
    /// and must not retain them for any later instantiation.
    #[must_use]
    pub const fn granted(&self) -> &CapabilitySet {
        &self.granted
    }
}

/// A live plugin instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginInstance {
    component: String,
    instance: u64,
}

impl PluginInstance {
    /// Creates a handle to an instance.
    #[must_use]
    pub const fn new(component: String, instance: u64) -> Self {
        Self {
            component,
            instance,
        }
    }

    /// Returns the component name.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Returns the instance number, unique within one run.
    #[must_use]
    pub const fn instance(&self) -> u64 {
        self.instance
    }
}

/// One request arriving at an ingress subsystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRequest {
    method: String,
    principal: Principal,
    session: SessionId,
    payload: String,
}

impl GatewayRequest {
    /// Creates a request.
    #[must_use]
    pub const fn new(
        method: String,
        principal: Principal,
        session: SessionId,
        payload: String,
    ) -> Self {
        Self {
            method,
            principal,
            session,
            payload,
        }
    }

    /// Returns the Gateway method name.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the principal that sent the request.
    ///
    /// This is the principal as established *for this request*. An ingress
    /// subsystem must supply the principal's current rights, not the rights it
    /// captured when the connection was opened.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the addressed session.
    #[must_use]
    pub const fn session(&self) -> &SessionId {
        &self.session
    }

    /// Returns the request payload.
    #[must_use]
    pub fn payload(&self) -> &str {
        &self.payload
    }
}

/// What an ingress subsystem sends back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayResponse {
    body: String,
    events: u64,
}

impl GatewayResponse {
    /// Creates a response.
    #[must_use]
    pub const fn new(body: String, events: u64) -> Self {
        Self { body, events }
    }

    /// Returns the response body.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// Returns how many turn events were streamed while producing it.
    #[must_use]
    pub const fn events(&self) -> u64 {
        self.events
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use claw_domain::SessionId;
    use secrecy::SecretString;

    use super::{
        Capability, CapabilitySet, CredentialLease, CredentialName, InvalidName, ModelName,
        ProviderBinding, ProviderName, RuntimeSettings, Severity, ToolName, ToolOutcome, TurnEvent,
        TurnSummary,
    };
    use crate::composition::clock::{Clock, MonotonicInstant};
    use crate::composition::egress::{
        DnsPort, EgressGuard, EgressPolicy, HostPattern, ResolvedEndpoint,
    };
    use crate::composition::error::SubsystemError;
    use crate::composition::{BoxFuture, id::SubsystemId};

    #[derive(Debug)]
    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now(&self) -> MonotonicInstant {
            MonotonicInstant::from_millis(self.0)
        }
    }

    #[derive(Debug)]
    struct StaticDns(Vec<std::net::IpAddr>);

    impl DnsPort for StaticDns {
        fn lookup<'a>(
            &'a self,
            _host: &'a str,
        ) -> BoxFuture<'a, Result<Vec<std::net::IpAddr>, SubsystemError>> {
            let answer = self.0.clone();
            Box::pin(async move { Ok(answer) })
        }
    }

    async fn endpoint(url: &str, address: &str) -> ResolvedEndpoint {
        let guard = EgressGuard::new(
            EgressPolicy::deny_all().allow_host(HostPattern::parse("*.example.com")),
            std::sync::Arc::new(StaticDns(vec![address.parse().expect("valid address")])),
            std::sync::Arc::new(FixedClock(0)),
        );

        guard.resolve_url(url).await.expect("resolves")
    }

    fn name_error(result: Result<ProviderName, InvalidName>) -> InvalidName {
        result.expect_err("name must be rejected")
    }

    #[test]
    fn a_valid_name_keeps_its_text_and_reports_its_kind_on_failure() {
        assert_eq!(
            ProviderName::new("openai").expect("valid").as_str(),
            "openai"
        );

        let error = name_error(ProviderName::new(""));
        assert_eq!(error.kind(), "provider name");
        assert_eq!(error.reason(), "must not be empty");
        assert_eq!(error.value(), "");
        assert_eq!(
            error.to_string(),
            "invalid provider name \"\": must not be empty"
        );
    }

    #[test]
    fn names_reject_padding_control_characters_and_oversize() {
        assert_eq!(
            name_error(ProviderName::new(" openai")).reason(),
            "must not be padded with whitespace"
        );
        assert_eq!(
            name_error(ProviderName::new("open\nai")).reason(),
            "must not contain control characters"
        );
        assert_eq!(
            name_error(ProviderName::new("a".repeat(129))).reason(),
            "must not exceed 128 bytes"
        );
        assert_eq!(
            ProviderName::new("a".repeat(128))
                .expect("128 bytes is allowed")
                .as_str()
                .len(),
            128
        );
    }

    #[test]
    fn every_name_kind_reports_its_own_label() {
        assert_eq!(ModelName::new("").expect_err("empty").kind(), "model name");
        assert_eq!(ToolName::new("").expect_err("empty").kind(), "tool name");
        assert_eq!(
            CredentialName::new("").expect_err("empty").kind(),
            "credential name"
        );
    }

    #[test]
    fn a_capability_set_is_sorted_deduplicated_and_comparable() {
        let set = CapabilitySet::from_capabilities([
            Capability::Network,
            Capability::ReadWorkspace,
            Capability::Network,
        ]);

        assert_eq!(
            set.as_slice(),
            &[Capability::ReadWorkspace, Capability::Network]
        );
        assert!(set.contains(Capability::Network));
        assert!(!set.contains(Capability::SpawnProcess));
        assert!(set.is_subset_of(&CapabilitySet::all()));
        assert!(!CapabilitySet::all().is_subset_of(&set));
        assert_eq!(set.to_string(), "read-workspace,network");
        assert_eq!(CapabilitySet::empty().to_string(), "none");
        assert!(CapabilitySet::empty().is_empty());
    }

    #[test]
    fn missing_from_names_exactly_what_is_absent() {
        let required = CapabilitySet::from_capabilities([
            Capability::Network,
            Capability::SpawnProcess,
            Capability::ReadWorkspace,
        ]);
        let held = CapabilitySet::from_capabilities([Capability::ReadWorkspace]);

        assert_eq!(
            required.missing_from(&held),
            vec![Capability::Network, Capability::SpawnProcess]
        );
        assert!(held.missing_from(&required).is_empty());
    }

    #[test]
    fn capability_labels_are_distinct() {
        let mut labels: Vec<&str> = Capability::ALL.iter().map(|c| c.label()).collect();
        let count = labels.len();
        labels.sort_unstable();
        labels.dedup();

        assert_eq!(labels.len(), count);
        assert_eq!(count, 5);
    }

    #[tokio::test]
    async fn a_credential_is_bound_to_the_exact_origin_it_was_released_for() {
        let origin = endpoint("https://api.example.com/v1", "203.0.113.10").await;
        let elsewhere = endpoint("https://other.example.com/v1", "203.0.113.11").await;
        let lease = CredentialLease::new(
            CredentialName::new("openai-key").expect("valid"),
            origin.clone(),
            SecretString::from("sk-secret".to_owned()),
        );

        assert!(lease.is_bound_to(&origin));
        assert!(!lease.is_bound_to(&elsewhere));
        assert_eq!(lease.expose(), "sk-secret");
    }

    #[tokio::test]
    async fn a_credential_is_not_bound_to_a_same_named_host_that_resolved_elsewhere() {
        let origin = endpoint("https://api.example.com/v1", "203.0.113.10").await;
        let rebound = endpoint("https://api.example.com/v1", "203.0.113.99").await;
        let lease = CredentialLease::new(
            CredentialName::new("openai-key").expect("valid"),
            origin,
            SecretString::from("sk-secret".to_owned()),
        );

        assert!(!lease.is_bound_to(&rebound));
    }

    #[tokio::test]
    async fn a_credential_never_appears_in_its_debug_output() {
        let origin = endpoint("https://api.example.com/v1", "203.0.113.10").await;
        let lease = CredentialLease::new(
            CredentialName::new("openai-key").expect("valid"),
            origin,
            SecretString::from("sk-super-secret".to_owned()),
        );

        let rendered = format!("{lease:?}");

        assert!(rendered.contains("openai-key"));
        assert!(!rendered.contains("sk-super-secret"));
    }

    #[tokio::test]
    async fn a_provider_binding_reports_only_the_models_it_offers() {
        let origin = endpoint("https://api.example.com/v1", "203.0.113.10").await;
        let binding = ProviderBinding::new(
            ProviderName::new("openai").expect("valid"),
            origin,
            CredentialName::new("openai-key").expect("valid"),
            vec![
                ModelName::new("gpt-5").expect("valid"),
                ModelName::new("gpt-5-mini").expect("valid"),
            ],
        );

        assert!(binding.offers(&ModelName::new("gpt-5").expect("valid")));
        assert!(!binding.offers(&ModelName::new("claude").expect("valid")));
        assert_eq!(binding.models().len(), 2);
        assert_eq!(binding.origin().host(), "api.example.com");
    }

    #[test]
    fn turn_events_expose_their_sequence_and_which_of_them_end_a_turn() {
        let summary = TurnSummary::new(
            "done".to_owned(),
            ProviderName::new("openai").expect("valid"),
            ModelName::new("gpt-5").expect("valid"),
            1,
        );
        let events = [
            TurnEvent::Started { sequence: 0 },
            TurnEvent::AssistantDelta {
                sequence: 1,
                text: "hi".to_owned(),
            },
            TurnEvent::ToolCompleted {
                sequence: 2,
                outcome: ToolOutcome::success(
                    ToolName::new("read").expect("valid"),
                    "ok".to_owned(),
                ),
            },
            TurnEvent::Finished {
                sequence: 3,
                summary,
            },
            TurnEvent::Failed {
                sequence: 4,
                reason: "stopped".to_owned(),
            },
        ];

        let sequences: Vec<u64> = events.iter().map(TurnEvent::sequence).collect();
        let terminal: Vec<bool> = events.iter().map(TurnEvent::is_terminal).collect();

        assert_eq!(sequences, vec![0, 1, 2, 3, 4]);
        assert_eq!(terminal, vec![false, false, false, true, true]);
    }

    #[test]
    fn a_failed_tool_outcome_is_distinguishable_from_a_successful_one() {
        let tool = ToolName::new("read").expect("valid");
        let success = ToolOutcome::success(tool.clone(), "contents".to_owned());
        let failure = ToolOutcome::failure(tool, "no such file".to_owned());

        assert!(!success.failed());
        assert!(failure.failed());
        assert_eq!(failure.output(), "no such file");
    }

    #[test]
    fn settings_report_exactly_what_they_were_built_with() {
        let settings = RuntimeSettings::new(
            vec!["127.0.0.1:0".parse().expect("valid address")],
            ProviderName::new("openai").expect("valid"),
            ModelName::new("gpt-5").expect("valid"),
            4,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );

        assert_eq!(settings.listen().len(), 1);
        assert_eq!(settings.max_concurrent_turns(), 4);
        assert_eq!(settings.turn_deadline(), Duration::from_secs(30));
        assert_eq!(settings.authorization_ttl(), Duration::from_secs(5));
        assert_eq!(settings.default_model().as_str(), "gpt-5");
    }

    #[test]
    fn severity_labels_are_distinct_and_ordered_by_seriousness() {
        assert!(Severity::Debug < Severity::Info);
        assert!(Severity::Info < Severity::Warn);
        assert!(Severity::Warn < Severity::Error);
        assert_eq!(Severity::Error.to_string(), "error");
    }

    #[test]
    fn a_session_record_reports_what_it_was_built_with() {
        let record =
            super::SessionRecord::new(SessionId::new("session-1").expect("valid session id"), 7, 3);

        assert_eq!(record.id().as_str(), "session-1");
        assert_eq!(record.revision(), 7);
        assert_eq!(record.turns(), 3);
    }

    #[test]
    fn a_subsystem_id_is_usable_as_an_observed_event_source() {
        let event = super::ObservedEvent::new(
            SubsystemId::new("gateway").expect("valid"),
            Severity::Info,
            "listening".to_owned(),
            MonotonicInstant::from_millis(5),
        );

        assert_eq!(event.subsystem().as_str(), "gateway");
        assert_eq!(event.severity(), Severity::Info);
        assert_eq!(event.message(), "listening");
        assert_eq!(event.at(), MonotonicInstant::from_millis(5));
    }
}
