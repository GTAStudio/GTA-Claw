//! Stable integration ports for an optional durable runtime composition.
//!
//! This module composes only durable state. Runtime session TTL/LRU, automatic
//! compaction, and daemon lifecycle remain separate concerns.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::durable::{
    DurableMemoryError, DurableMemoryStore, MemoryMutation, MemoryPage, MemoryReference,
    MemoryTarget,
};
use crate::session::SessionId;
use crate::transcript::{
    DurableTranscriptStore, TranscriptError, TranscriptMessage, TranscriptPage, TranscriptRole,
    TranscriptSearch,
};
use crate::vector::RecordId;

/// Runtime-facing operations over bounded durable memory and user profiles.
///
/// The trait is object-safe so a composition root can inject an
/// `Arc<dyn DurableMemoryPort>` without depending on the file adapter type.
pub trait DurableMemoryPort: Send + Sync + 'static {
    /// Adds an entry, treating an exact duplicate as an idempotent success.
    ///
    /// # Errors
    ///
    /// Returns a validation, capacity, identifier, or persistence error.
    fn add(
        &self,
        scope: &SessionId,
        target: MemoryTarget,
        content: &str,
        unix_millis: u64,
    ) -> Result<MemoryMutation, DurableMemoryError>;

    /// Replaces one entry without changing its stable identifier.
    ///
    /// # Errors
    ///
    /// Returns a validation, reference, capacity, or persistence error.
    fn replace(
        &self,
        scope: &SessionId,
        target: MemoryTarget,
        reference: &MemoryReference,
        content: &str,
        unix_millis: u64,
    ) -> Result<MemoryMutation, DurableMemoryError>;

    /// Removes one entry by stable identifier or unique substring.
    ///
    /// # Errors
    ///
    /// Returns a reference or persistence error.
    fn remove(
        &self,
        scope: &SessionId,
        target: MemoryTarget,
        reference: &MemoryReference,
    ) -> Result<MemoryMutation, DurableMemoryError>;

    /// Lists one deterministic, read-safe page.
    ///
    /// # Errors
    ///
    /// Returns a page-validation or persistence error.
    fn list(
        &self,
        scope: &SessionId,
        target: MemoryTarget,
        offset: usize,
        limit: usize,
    ) -> Result<MemoryPage, DurableMemoryError>;

    /// Renders the read-safe snapshot intended for context assembly.
    ///
    /// # Errors
    ///
    /// Returns a persistence error when the scope cannot be loaded or recovered.
    fn render_prompt_snapshot(&self, scope: &SessionId) -> Result<String, DurableMemoryError>;
}

impl DurableMemoryPort for DurableMemoryStore {
    fn add(
        &self,
        scope: &SessionId,
        target: MemoryTarget,
        content: &str,
        unix_millis: u64,
    ) -> Result<MemoryMutation, DurableMemoryError> {
        Self::add(self, scope, target, content, unix_millis)
    }

    fn replace(
        &self,
        scope: &SessionId,
        target: MemoryTarget,
        reference: &MemoryReference,
        content: &str,
        unix_millis: u64,
    ) -> Result<MemoryMutation, DurableMemoryError> {
        Self::replace(self, scope, target, reference, content, unix_millis)
    }

    fn remove(
        &self,
        scope: &SessionId,
        target: MemoryTarget,
        reference: &MemoryReference,
    ) -> Result<MemoryMutation, DurableMemoryError> {
        Self::remove(self, scope, target, reference)
    }

    fn list(
        &self,
        scope: &SessionId,
        target: MemoryTarget,
        offset: usize,
        limit: usize,
    ) -> Result<MemoryPage, DurableMemoryError> {
        Self::list(self, scope, target, offset, limit)
    }

    fn render_prompt_snapshot(&self, scope: &SessionId) -> Result<String, DurableMemoryError> {
        Self::render_prompt_snapshot(self, scope)
    }
}

/// Runtime-facing operations over bounded durable conversation transcripts.
///
/// Capacity failures never evict existing messages. Callers receive the same
/// explicit error as the concrete store.
pub trait DurableTranscriptPort: Send + Sync + 'static {
    /// Appends one bounded message.
    ///
    /// # Errors
    ///
    /// Returns a content, capacity, identifier, or persistence error.
    fn append(
        &self,
        scope: &SessionId,
        role: TranscriptRole,
        content: &str,
        unix_millis: u64,
    ) -> Result<TranscriptMessage, TranscriptError>;

    /// Browses recent messages or the page before one stable identifier.
    ///
    /// # Errors
    ///
    /// Returns a result-limit, anchor, or persistence error.
    fn browse(
        &self,
        scope: &SessionId,
        before: Option<&RecordId>,
        limit: usize,
    ) -> Result<TranscriptPage, TranscriptError>;

    /// Searches configured history with deterministic ranking.
    ///
    /// # Errors
    ///
    /// Returns a query, result-limit, or persistence error.
    fn search(
        &self,
        scope: &SessionId,
        query: &str,
        limit: usize,
    ) -> Result<TranscriptSearch, TranscriptError>;
}

impl DurableTranscriptPort for DurableTranscriptStore {
    fn append(
        &self,
        scope: &SessionId,
        role: TranscriptRole,
        content: &str,
        unix_millis: u64,
    ) -> Result<TranscriptMessage, TranscriptError> {
        Self::append(self, scope, role, content, unix_millis)
    }

    fn browse(
        &self,
        scope: &SessionId,
        before: Option<&RecordId>,
        limit: usize,
    ) -> Result<TranscriptPage, TranscriptError> {
        Self::browse(self, scope, before, limit)
    }

    fn search(
        &self,
        scope: &SessionId,
        query: &str,
        limit: usize,
    ) -> Result<TranscriptSearch, TranscriptError> {
        Self::search(self, scope, query, limit)
    }
}

/// Explicit settings for opening both durable state ports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableStateConfig {
    root: PathBuf,
    memory_char_limit: usize,
    user_profile_char_limit: usize,
    transcript_max_messages: usize,
    transcript_content_char_limit: usize,
}

impl DurableStateConfig {
    /// Creates a configuration. Limits and the absolute root requirement are
    /// validated by [`DurableStateRuntime::open`].
    #[must_use]
    pub fn new(
        root: impl Into<PathBuf>,
        memory_char_limit: usize,
        user_profile_char_limit: usize,
        transcript_max_messages: usize,
        transcript_content_char_limit: usize,
    ) -> Self {
        Self {
            root: root.into(),
            memory_char_limit,
            user_profile_char_limit,
            transcript_max_messages,
            transcript_content_char_limit,
        }
    }

    /// Returns the configured absolute state root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the general-memory character limit.
    #[must_use]
    pub const fn memory_char_limit(&self) -> usize {
        self.memory_char_limit
    }

    /// Returns the user-profile character limit.
    #[must_use]
    pub const fn user_profile_char_limit(&self) -> usize {
        self.user_profile_char_limit
    }

    /// Returns the retained transcript-message limit.
    #[must_use]
    pub const fn transcript_max_messages(&self) -> usize {
        self.transcript_max_messages
    }

    /// Returns the per-message transcript character limit.
    #[must_use]
    pub const fn transcript_content_char_limit(&self) -> usize {
        self.transcript_content_char_limit
    }
}

/// File-backed durable state ready for injection into a runtime composition.
///
/// Opening this facade never substitutes an in-memory adapter. Both returned
/// ports are concrete file-backed stores rooted at [`Self::config`].
#[derive(Clone, Debug)]
pub struct DurableStateRuntime {
    config: DurableStateConfig,
    memory: Arc<DurableMemoryStore>,
    transcript: Arc<DurableTranscriptStore>,
}

impl DurableStateRuntime {
    /// Opens both durable ports under one explicit absolute state root.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStateRuntimeError::StateRootNotAbsolute`] for a relative
    /// root, or the concrete memory/transcript initialization error.
    pub fn open(config: DurableStateConfig) -> Result<Self, DurableStateRuntimeError> {
        if !config.root.is_absolute() {
            return Err(DurableStateRuntimeError::StateRootNotAbsolute);
        }
        let memory = Arc::new(DurableMemoryStore::new(
            &config.root,
            config.memory_char_limit,
            config.user_profile_char_limit,
        )?);
        let transcript = Arc::new(DurableTranscriptStore::new(
            &config.root,
            config.transcript_max_messages,
            config.transcript_content_char_limit,
        )?);
        Ok(Self {
            config,
            memory,
            transcript,
        })
    }

    /// Returns the validated configuration in force.
    #[must_use]
    pub const fn config(&self) -> &DurableStateConfig {
        &self.config
    }

    /// Returns the injectable durable memory port.
    #[must_use]
    pub fn memory(&self) -> Arc<dyn DurableMemoryPort> {
        self.memory.clone()
    }

    /// Returns the injectable durable transcript port.
    #[must_use]
    pub fn transcript(&self) -> Arc<dyn DurableTranscriptPort> {
        self.transcript.clone()
    }
}

/// A failure to open the durable runtime ports.
#[derive(Debug)]
pub enum DurableStateRuntimeError {
    /// The configured root was relative and therefore process-directory
    /// dependent.
    StateRootNotAbsolute,
    /// Durable memory limits were invalid.
    Memory(DurableMemoryError),
    /// Durable transcript limits were invalid.
    Transcript(TranscriptError),
}

impl Display for DurableStateRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateRootNotAbsolute => {
                formatter.write_str("durable state root must be an absolute path")
            }
            Self::Memory(error) => write!(formatter, "failed to open durable memory: {error}"),
            Self::Transcript(error) => {
                write!(formatter, "failed to open durable transcript: {error}")
            }
        }
    }
}

impl Error for DurableStateRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::StateRootNotAbsolute => None,
            Self::Memory(error) => Some(error),
            Self::Transcript(error) => Some(error),
        }
    }
}

impl From<DurableMemoryError> for DurableStateRuntimeError {
    fn from(error: DurableMemoryError) -> Self {
        Self::Memory(error)
    }
}

impl From<TranscriptError> for DurableStateRuntimeError {
    fn from(error: TranscriptError) -> Self {
        Self::Transcript(error)
    }
}
