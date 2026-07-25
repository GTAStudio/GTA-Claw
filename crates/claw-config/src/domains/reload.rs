use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, mpsc};

use crate::{ConfigError, ConfigHubError};

use super::{OpenClawConfig, parse_openclaw_json5};

macro_rules! source_domains {
    ($(($variant:ident, $field:ident, $name:literal)),+ $(,)?) => {
        /// One frozen top-level source configuration domain.
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub enum OpenClawDomain {
            $(
                #[doc = concat!("The `", $name, "` source domain.")]
                $variant,
            )+
        }

        impl OpenClawDomain {
            /// Returns the exact frozen JSON key.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }
        }

        fn changed_domains(
            previous: &OpenClawConfig,
            candidate: &OpenClawConfig,
        ) -> Vec<OpenClawDomain> {
            [
                $((OpenClawDomain::$variant, previous.$field != candidate.$field),)+
            ]
            .into_iter()
            .filter_map(|(domain, changed)| changed.then_some(domain))
            .collect()
        }
    };
}

source_domains!(
    (Schema, schema, "$schema"),
    (Meta, meta, "meta"),
    (Auth, auth, "auth"),
    (AccessGroups, access_groups, "accessGroups"),
    (Acp, acp, "acp"),
    (Env, env, "env"),
    (Wizard, wizard, "wizard"),
    (Diagnostics, diagnostics, "diagnostics"),
    (Logging, logging, "logging"),
    (Audit, audit, "audit"),
    (Security, security, "security"),
    (Cli, cli, "cli"),
    (Crestodian, crestodian, "crestodian"),
    (Update, update, "update"),
    (Browser, browser, "browser"),
    (Ui, ui, "ui"),
    (Tui, tui, "tui"),
    (Secrets, secrets, "secrets"),
    (Marketplaces, marketplaces, "marketplaces"),
    (Skills, skills, "skills"),
    (Plugins, plugins, "plugins"),
    (Surfaces, surfaces, "surfaces"),
    (Models, models, "models"),
    (NodeHost, node_host, "nodeHost"),
    (Agents, agents, "agents"),
    (Tools, tools, "tools"),
    (Bindings, bindings, "bindings"),
    (Broadcast, broadcast, "broadcast"),
    (Audio, audio, "audio"),
    (Media, media, "media"),
    (Messages, messages, "messages"),
    (Commands, commands, "commands"),
    (Approvals, approvals, "approvals"),
    (Session, session, "session"),
    (Web, web, "web"),
    (Channels, channels, "channels"),
    (Cron, cron, "cron"),
    (Transcripts, transcripts, "transcripts"),
    (Commitments, commitments, "commitments"),
    (Hooks, hooks, "hooks"),
    (Discovery, discovery, "discovery"),
    (Talk, talk, "talk"),
    (Gateway, gateway, "gateway"),
    (CloudWorkers, cloud_workers, "cloudWorkers"),
    (Memory, memory, "memory"),
    (Mcp, mcp, "mcp"),
    (Proxy, proxy, "proxy"),
);

/// One atomically published source-configuration change.
#[derive(Clone, Debug, PartialEq)]
pub struct OpenClawConfigChange {
    /// Previous immutable configuration.
    pub previous: Arc<OpenClawConfig>,
    /// Newly published immutable configuration.
    pub current: Arc<OpenClawConfig>,
    /// Exact frozen domains whose typed values changed.
    pub changed_domains: Vec<OpenClawDomain>,
}

/// Receiving half of a source-configuration subscription.
#[derive(Debug)]
pub struct OpenClawConfigSubscription {
    receiver: mpsc::Receiver<()>,
    latest: Arc<Mutex<Option<OpenClawConfigChange>>>,
}

impl OpenClawConfigSubscription {
    /// Blocks until the next source change or publisher shutdown.
    pub fn recv(&self) -> Result<OpenClawConfigChange, mpsc::RecvError> {
        loop {
            self.receiver.recv()?;
            if let Some(change) = self
                .latest
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                return Ok(change);
            }
        }
    }

    /// Receives a pending source change without blocking.
    pub fn try_recv(&self) -> Result<OpenClawConfigChange, mpsc::TryRecvError> {
        self.receiver.try_recv()?;
        self.latest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or(mpsc::TryRecvError::Empty)
    }
}

#[derive(Debug)]
struct SourceSubscriber {
    sender: mpsc::SyncSender<()>,
    latest: Arc<Mutex<Option<OpenClawConfigChange>>>,
}

/// Tear-free source-configuration owner with typed subscriptions.
#[derive(Clone, Debug)]
pub struct OpenClawConfigHub {
    current: Arc<RwLock<Arc<OpenClawConfig>>>,
    subscribers: Arc<Mutex<Vec<SourceSubscriber>>>,
}

impl OpenClawConfigHub {
    /// Creates a hub from an already validated source configuration.
    #[must_use]
    pub fn new(initial: OpenClawConfig) -> Self {
        Self {
            current: Arc::new(RwLock::new(Arc::new(initial))),
            subscribers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns one complete immutable configuration.
    pub fn snapshot(&self) -> Result<Arc<OpenClawConfig>, ConfigHubError> {
        self.current
            .read()
            .map(|current| Arc::clone(&current))
            .map_err(|_| ConfigHubError::LockPoisoned("source snapshot"))
    }

    /// Adds an independent typed source subscription.
    pub fn subscribe(&self) -> Result<OpenClawConfigSubscription, ConfigHubError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let latest = Arc::new(Mutex::new(None));
        self.subscribers
            .lock()
            .map_err(|_| ConfigHubError::LockPoisoned("source subscriber"))?
            .push(SourceSubscriber {
                sender,
                latest: Arc::clone(&latest),
            });
        Ok(OpenClawConfigSubscription { receiver, latest })
    }

    /// Validates and atomically publishes a complete source candidate.
    pub fn reload_json5(
        &self,
        source: &str,
        source_name: &str,
    ) -> Result<OpenClawConfigChange, ConfigHubError> {
        let candidate = Arc::new(parse_openclaw_json5(source, source_name)?);
        let mut subscribers = self
            .subscribers
            .lock()
            .map_err(|_| ConfigHubError::LockPoisoned("source subscriber"))?;
        let change = {
            let mut current = self
                .current
                .write()
                .map_err(|_| ConfigHubError::LockPoisoned("source snapshot"))?;
            let previous = Arc::clone(&current);
            let changed_domains = changed_domains(&previous, &candidate);
            *current = Arc::clone(&candidate);
            OpenClawConfigChange {
                previous,
                current: candidate,
                changed_domains,
            }
        };
        subscribers.retain(|subscriber| {
            let mut latest = subscriber
                .latest
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let notification = latest
                .as_ref()
                .map(|pending| OpenClawConfigChange {
                    previous: Arc::clone(&pending.previous),
                    current: Arc::clone(&change.current),
                    changed_domains: changed_domains(&pending.previous, &change.current),
                })
                .unwrap_or_else(|| change.clone());
            *latest = Some(notification);
            match subscriber.sender.try_send(()) {
                Ok(()) | Err(mpsc::TrySendError::Full(())) => true,
                Err(mpsc::TrySendError::Disconnected(())) => false,
            }
        });
        Ok(change)
    }
}

/// Poll-based source-file change detector backed by [`OpenClawConfigHub`].
#[derive(Clone, Debug)]
pub struct OpenClawConfigFileWatcher {
    path: PathBuf,
    fingerprint: u64,
    hub: OpenClawConfigHub,
}

impl OpenClawConfigFileWatcher {
    /// Loads the initial source file and records its bytes.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigHubError> {
        let path = path.as_ref().to_owned();
        let bytes = fs::read(&path).map_err(|source| ConfigError::io(&path, source))?;
        let source = std::str::from_utf8(&bytes).map_err(|error| ConfigError::Syntax {
            source_name: path.display().to_string(),
            message: error.to_string(),
        })?;
        let initial = parse_openclaw_json5(source, &path.display().to_string())?;
        Ok(Self {
            path,
            fingerprint: fingerprint(&bytes),
            hub: OpenClawConfigHub::new(initial),
        })
    }

    /// Returns a cloneable handle to the publication hub.
    #[must_use]
    pub fn hub(&self) -> OpenClawConfigHub {
        self.hub.clone()
    }

    /// Publishes changed valid bytes while retaining the last-known-good value.
    pub fn poll(&mut self) -> Result<Option<OpenClawConfigChange>, ConfigHubError> {
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
