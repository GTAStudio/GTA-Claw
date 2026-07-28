//! Slash command registry, authorization and inline directive parsing.
//!
//! This module is a faithful port of the `OpenClaw` command surface, pinned to
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`:
//!
//! | area | upstream source |
//! |---|---|
//! | registry and aliases | `src/auto-reply/commands-registry.shared.ts` |
//! | text resolution | `src/auto-reply/commands-registry-normalize.ts` |
//! | surface routing | `src/auto-reply/commands-text-routing.ts` |
//! | authorization | `src/auto-reply/command-auth.ts`, `src/auto-reply/sender-identity.ts` |
//! | inline directives | `src/auto-reply/reply/directives.ts` |
//! | `/exec` options | `src/auto-reply/reply/exec/directive.ts`, `src/auto-reply/reply/directive-parsing.ts` |
//! | level normalizers | `src/auto-reply/thinking.shared.ts`, `packages/normalization-core/src/string-coerce.ts` |
//! | command gates | `docs/tools/slash-commands.md` |
//!
//! The port takes no dependencies: JavaScript string semantics live in
//! [`text`], the regular expressions in `directives.ts` are reproduced by hand,
//! and the golden fixture format has its own reader in [`golden`].

pub mod authorization;
pub mod directives;
pub mod golden;
pub mod registry;
pub mod text;

pub use authorization::{
    ChannelSettings, CommandDenial, CommandInvocation, CommandsConfig, KNOWN_CHANNEL_IDS,
    MessageContext, SenderAuthorization, authorize_command, resolve_command_authorization,
};
pub use directives::{
    Directive, DirectiveLevel, DirectiveParse, ElevatedLevel, ExecDirectiveParse, FastMode,
    ReasoningLevel, ThinkLevel, TraceLevel, VerboseLevel, extract_directive,
    extract_directive_for_sender, extract_exec_directive, normalize_level,
};
pub use registry::{
    CommandDefinition, CommandFeature, CommandGate, CommandRegistry, CommandScope, CommandSource,
    RegistryError, ResolvedCommand, should_handle_text_commands,
};
