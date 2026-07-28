use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, mpsc};

use crate::{ConfigDomain, ConfigError, ConfigSnapshot, parse_json5};

/// Result of atomically publishing a validated reload candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadOutcome {
    /// Domains whose values changed.
    pub changed_domains: Vec<ConfigDomain>,
    /// Changed domains that require a process restart to take effect safely.
    pub restart_required_domains: Vec<ConfigDomain>,
    /// Newly published immutable snapshot.
    pub snapshot: Arc<ConfigSnapshot>,
}

/// Transactional owner of the last-known-good configuration snapshot.
#[derive(Clone, Debug)]
pub struct ReloadManager {
    current: Arc<ConfigSnapshot>,
}

impl ReloadManager {
    /// Creates a manager from an already validated snapshot.
    #[must_use]
    pub fn new(initial: ConfigSnapshot) -> Self {
        Self {
            current: Arc::new(initial),
        }
    }

    /// Returns the currently published last-known-good snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<ConfigSnapshot> {
        Arc::clone(&self.current)
    }

    /// Parses and validates a complete candidate before publishing it.
    ///
    /// Any error leaves the previous snapshot unchanged.
    ///
    /// # Errors
    ///
    /// Returns whatever [`crate::parse_json5`] rejects: [`ConfigError::Syntax`]
    /// for malformed JSON5, [`ConfigError::Decode`] naming the offending field
    /// path, [`ConfigError::UnsupportedVersion`] for a `schema_version` this
    /// build does not implement, and [`ConfigError::Validation`] for a violated
    /// domain invariant. Nothing is published and [`Self::snapshot`] keeps
    /// returning the last-known-good value.
    pub fn reload_json5(
        &mut self,
        source: &str,
        source_name: &str,
    ) -> Result<ReloadOutcome, ConfigError> {
        let candidate = parse_json5(source, source_name)?;
        let changed_domains = changed_domains(&self.current, &candidate);
        let restart_required_domains = changed_domains
            .iter()
            .copied()
            .filter(|domain| restart_required(*domain))
            .collect();
        let snapshot = Arc::new(candidate);
        self.current = Arc::clone(&snapshot);
        Ok(ReloadOutcome {
            changed_domains,
            restart_required_domains,
            snapshot,
        })
    }
}

pub(crate) fn changed_domains(
    previous: &ConfigSnapshot,
    candidate: &ConfigSnapshot,
) -> Vec<ConfigDomain> {
    let previous = previous.core();
    let candidate = candidate.core();
    let comparisons = [
        (ConfigDomain::Auth, previous.auth != candidate.auth),
        (ConfigDomain::Role, previous.role != candidate.role),
        (
            ConfigDomain::Channels,
            previous.channels != candidate.channels,
        ),
        (ConfigDomain::Server, previous.server != candidate.server),
        (ConfigDomain::Logging, previous.logging != candidate.logging),
        (
            ConfigDomain::Sessions,
            previous.sessions != candidate.sessions,
        ),
        (ConfigDomain::Copilot, previous.copilot != candidate.copilot),
        (
            ConfigDomain::LegacySkills,
            previous.legacy_skills != candidate.legacy_skills,
        ),
        (ConfigDomain::Updates, previous.updates != candidate.updates),
        (ConfigDomain::Admin, previous.admin != candidate.admin),
        (ConfigDomain::Network, previous.network != candidate.network),
    ];
    comparisons
        .into_iter()
        .filter_map(|(domain, changed)| changed.then_some(domain))
        .collect()
}

const fn restart_required(domain: ConfigDomain) -> bool {
    matches!(
        domain,
        ConfigDomain::Auth
            | ConfigDomain::Channels
            | ConfigDomain::Server
            | ConfigDomain::Admin
            | ConfigDomain::Network
    )
}

/// One atomically published typed configuration change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigChange {
    /// Previous immutable snapshot.
    pub previous: Arc<ConfigSnapshot>,
    /// Newly published immutable snapshot.
    pub current: Arc<ConfigSnapshot>,
    /// Domains whose values changed.
    pub changed_domains: Vec<ConfigDomain>,
    /// Changed domains that require process restart.
    pub restart_required_domains: Vec<ConfigDomain>,
}

/// Receiving half of one typed configuration subscription.
#[derive(Debug)]
pub struct ConfigSubscription {
    receiver: mpsc::Receiver<ConfigChange>,
}

impl ConfigSubscription {
    /// Blocks until the next change or all publisher handles are dropped.
    ///
    /// # Errors
    ///
    /// Returns [`mpsc::RecvError`] once every [`ConfigHub`] handle has been
    /// dropped and no buffered change remains, which is the normal shutdown
    /// signal for a subscriber loop.
    pub fn recv(&self) -> Result<ConfigChange, mpsc::RecvError> {
        self.receiver.recv()
    }

    /// Receives a pending change without blocking.
    ///
    /// # Errors
    ///
    /// Returns [`mpsc::TryRecvError::Empty`] when no change has been published
    /// since the last receive, and [`mpsc::TryRecvError::Disconnected`] once
    /// every [`ConfigHub`] handle has been dropped.
    pub fn try_recv(&self) -> Result<ConfigChange, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }
}

/// Lock and configuration failure from the concurrent reload hub.
#[derive(Debug)]
pub enum ConfigHubError {
    /// Candidate parsing or file loading failed.
    Config(ConfigError),
    /// A thread panicked while holding an internal synchronization lock.
    LockPoisoned(&'static str),
}

impl Display for ConfigHubError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "{error}"),
            Self::LockPoisoned(lock) => write!(formatter, "configuration {lock} lock is poisoned"),
        }
    }
}

impl Error for ConfigHubError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::LockPoisoned(_) => None,
        }
    }
}

impl From<ConfigError> for ConfigHubError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

/// Concurrent last-known-good owner with typed change subscriptions.
///
/// Readers clone one `Arc` while holding a short read lock. Publication swaps
/// the complete `Arc` under one write lock, so readers can never observe a
/// partially updated snapshot.
#[derive(Clone, Debug)]
pub struct ConfigHub {
    current: Arc<RwLock<Arc<ConfigSnapshot>>>,
    subscribers: Arc<Mutex<Vec<mpsc::Sender<ConfigChange>>>>,
}

impl ConfigHub {
    /// Creates a hub from an already validated snapshot.
    #[must_use]
    pub fn new(initial: ConfigSnapshot) -> Self {
        Self {
            current: Arc::new(RwLock::new(Arc::new(initial))),
            subscribers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns one complete immutable snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigHubError::LockPoisoned`] when a previous publisher
    /// panicked while holding the snapshot cell. The stored snapshot is still a
    /// fully validated value, but the hub refuses to hand it out rather than
    /// hide the panic.
    pub fn snapshot(&self) -> Result<Arc<ConfigSnapshot>, ConfigHubError> {
        self.current
            .read()
            .map(|current| Arc::clone(&current))
            .map_err(|_| ConfigHubError::LockPoisoned("snapshot"))
    }

    /// Adds an independent typed subscription.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigHubError::LockPoisoned`] when a previous publisher
    /// panicked while holding the subscriber list, in which case no subscription
    /// is registered.
    pub fn subscribe(&self) -> Result<ConfigSubscription, ConfigHubError> {
        let (sender, receiver) = mpsc::channel();
        self.subscribers
            .lock()
            .map_err(|_| ConfigHubError::LockPoisoned("subscriber"))?
            .push(sender);
        Ok(ConfigSubscription { receiver })
    }

    /// Validates then atomically publishes a complete candidate.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigHubError::Config`] when `source` is not JSON5, decodes to
    /// the wrong shape, declares an unsupported `schema_version`, or violates a
    /// domain invariant; the published snapshot is then left untouched. Returns
    /// [`ConfigHubError::LockPoisoned`] when a previous publisher panicked while
    /// holding the subscriber list or the snapshot cell.
    pub fn reload_json5(
        &self,
        source: &str,
        source_name: &str,
    ) -> Result<ConfigChange, ConfigHubError> {
        let candidate = Arc::new(parse_json5(source, source_name)?);
        // The subscriber lock spans the whole transaction on purpose: it is what
        // serializes concurrent publishers so notifications are delivered in the
        // same order the snapshots were committed.
        let mut subscribers = self
            .subscribers
            .lock()
            .map_err(|_| ConfigHubError::LockPoisoned("subscriber"))?;
        let change = {
            let mut current = self
                .current
                .write()
                .map_err(|_| ConfigHubError::LockPoisoned("snapshot"))?;
            let previous = std::mem::replace(&mut *current, Arc::clone(&candidate));
            // Readers only need the pointer swap; classifying the change walks
            // every domain, so it happens after the write lock is released.
            drop(current);
            let changed_domains = changed_domains(&previous, &candidate);
            let restart_required_domains = changed_domains
                .iter()
                .copied()
                .filter(|domain| restart_required(*domain))
                .collect();
            ConfigChange {
                previous,
                current: candidate,
                changed_domains,
                restart_required_domains,
            }
        };
        subscribers.retain(|subscriber| subscriber.send(change.clone()).is_ok());
        drop(subscribers);
        Ok(change)
    }
}

/// Poll-based file change detector backed by [`ConfigHub`].
#[derive(Clone, Debug)]
pub struct ConfigFileWatcher {
    path: PathBuf,
    fingerprint: u64,
    hub: ConfigHub,
}

impl ConfigFileWatcher {
    /// Loads a file, publishes it as the initial snapshot, and records its bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigHubError::Config`] wrapping [`ConfigError::Io`] when
    /// `path` cannot be read, [`ConfigError::Syntax`] when its bytes are not
    /// UTF-8 or not well-formed JSON5, and the usual [`ConfigError::Decode`],
    /// [`ConfigError::UnsupportedVersion`], or [`ConfigError::Validation`] when
    /// the document is structurally or semantically invalid. No watcher is
    /// created unless the initial file is fully valid.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigHubError> {
        let path = path.as_ref().to_owned();
        let bytes = fs::read(&path).map_err(|source| ConfigError::io(&path, source))?;
        let source = std::str::from_utf8(&bytes).map_err(|error| ConfigError::Syntax {
            source_name: path.display().to_string(),
            message: error.to_string(),
        })?;
        let initial = parse_json5(source, &path.display().to_string())?;
        Ok(Self {
            path,
            fingerprint: fingerprint(&bytes),
            hub: ConfigHub::new(initial),
        })
    }

    /// Returns a cloneable handle to the publication hub.
    #[must_use]
    pub fn hub(&self) -> ConfigHub {
        self.hub.clone()
    }

    /// Detects changed bytes and publishes a valid candidate.
    ///
    /// A rejected candidate leaves both the last-known-good snapshot and the
    /// successful fingerprint unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigHubError::Config`] wrapping [`ConfigError::Io`] when the
    /// watched file cannot be read this cycle, and [`ConfigError::Syntax`],
    /// [`ConfigError::Decode`], [`ConfigError::UnsupportedVersion`], or
    /// [`ConfigError::Validation`] when the new bytes are invalid, which is the
    /// expected result of catching a half-written editor save. Returns
    /// [`ConfigHubError::LockPoisoned`] when a previous publisher panicked while
    /// holding an internal lock. Because the fingerprint is only advanced after a
    /// successful publication, the same bad bytes are retried on the next poll
    /// and a later repair is still detected.
    pub fn poll(&mut self) -> Result<Option<ConfigChange>, ConfigHubError> {
        let bytes = fs::read(&self.path).map_err(|source| ConfigError::io(&self.path, source))?;
        let next_fingerprint = fingerprint(&bytes);
        if next_fingerprint == self.fingerprint {
            return Ok(None);
        }
        let source = std::str::from_utf8(&bytes).map_err(|error| ConfigError::Syntax {
            source_name: self.path.display().to_string(),
            message: error.to_string(),
        })?;
        let change = self
            .hub
            .reload_json5(source, &self.path.display().to_string())?;
        self.fingerprint = next_fingerprint;
        Ok(Some(change))
    }
}

fn fingerprint(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}
