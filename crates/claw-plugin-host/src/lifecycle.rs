//! Discovery, loading, validation and the full plugin lifecycle.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use claw_plugin_api::abi::{ABI_VERSION, Version, check_compatibility};
use claw_plugin_api::capability::{CapabilityDenial, CapabilitySet};
use claw_plugin_api::limits::ResourceLimits;
use claw_plugin_api::manifest::PluginManifest;
use claw_plugin_api::trust::{
    RejectAllSignatures, SignatureVerifier, TrustDecision, TrustPolicy, VerificationRequest,
    component_sha256,
};
use wasmtime::Store;
use wasmtime::component::Component;

use crate::bindings::Plugin;
use crate::bindings::exports::gta_claw::plugin::guest::EventResponse as WitEventResponse;
use crate::engine::{PluginEngine, epoch_ticks_for};
use crate::error::{GuestFailure, HostError, TerminationCause};
use crate::host_impl::wit_event;
use crate::limiter::HostCallGate;
use crate::services::{HostEvent, HostServices};
use crate::state::{PluginState, PluginStateConfig, ViolationPolicy};

/// The file every plugin directory must contain.
pub const MANIFEST_FILE_NAME: &str = "plugin.json";

/// The only component imports this host will ever satisfy.
///
/// A component that imports anything else is rejected before instantiation, so
/// an attempt to reach `wasi:filesystem`, `wasi:sockets` or any other ambient
/// interface fails as a load error rather than at some later call.
pub const ALLOWED_IMPORTS: [&str; 10] = [
    "gta-claw:plugin/host-clock@1.0.0",
    "gta-claw:plugin/host-config@1.0.0",
    "gta-claw:plugin/host-events@1.0.0",
    "gta-claw:plugin/host-fs@1.0.0",
    "gta-claw:plugin/host-http@1.0.0",
    "gta-claw:plugin/host-log@1.0.0",
    "gta-claw:plugin/host-random@1.0.0",
    "gta-claw:plugin/host-store@1.0.0",
    "gta-claw:plugin/host-tools@1.0.0",
    "gta-claw:plugin/types@1.0.0",
];

/// Where a plugin is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleState {
    /// Instantiated and validated, but `activate` has not been called.
    Loaded,
    /// `activate` returned successfully.
    Active,
    /// `deactivate` returned successfully.
    Inactive,
    /// A guest call was terminated by the sandbox. The instance is gone and
    /// only `unload` or `reload` are allowed.
    Faulted(TerminationCause),
}

impl LifecycleState {
    /// Stable, machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Faulted(_) => "faulted",
        }
    }
}

/// What a discovery pass found in one directory.
#[derive(Debug)]
pub struct Discovered {
    /// The directory that was scanned.
    pub directory: PathBuf,
    /// The parsed manifest, or why it could not be used.
    pub manifest: Result<PluginManifest, HostError>,
}

/// A guest's answer to an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventOutcome {
    /// Whether the plugin consumed the event.
    pub handled: bool,
    /// Optional JSON annotation from the plugin.
    pub note: Option<String>,
}

/// What an instance actually consumed while it was alive.
///
/// The values survive a fault, so an operator can still see that a plugin was
/// killed for growing past its memory ceiling after its store has been dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceUsage {
    /// Highest linear-memory size the instance reached, in bytes.
    pub peak_memory_bytes: usize,
    /// Whether the limiter refused a memory growth request.
    pub hit_memory_ceiling: bool,
    /// Whether the limiter refused a table growth request.
    pub hit_table_ceiling: bool,
    /// Denials dropped because the bounded audit buffer was full.
    pub dropped_denials: u64,
}

impl ResourceUsage {
    fn of(state: &PluginState) -> Self {
        Self {
            peak_memory_bytes: state.peak_memory_bytes(),
            hit_memory_ceiling: state.hit_memory_ceiling(),
            hit_table_ceiling: state.hit_table_ceiling(),
            dropped_denials: state.dropped_denials(),
        }
    }
}

impl From<WitEventResponse> for EventOutcome {
    fn from(response: WitEventResponse) -> Self {
        Self {
            handled: response.handled,
            note: response.note,
        }
    }
}

struct Instance {
    store: Store<PluginState>,
    bindings: Plugin,
}

struct Loaded {
    manifest: PluginManifest,
    directory: PathBuf,
    component_path: PathBuf,
    digest: String,
    state: LifecycleState,
    instance: Option<Instance>,
    last_denials: Vec<CapabilityDenial>,
    last_usage: ResourceUsage,
}

/// Builds a [`PluginHost`].
///
/// Everything starts closed: [`TrustPolicy::deny_all`], a verifier that only
/// accepts unsigned manifests, services that hold nothing, and
/// [`ViolationPolicy::ReturnError`].
pub struct PluginHostBuilder {
    trust: TrustPolicy,
    verifier: Arc<dyn SignatureVerifier>,
    services: HostServices,
    policy: ViolationPolicy,
    max_host_call_concurrency: u32,
}

impl core::fmt::Debug for PluginHostBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PluginHostBuilder")
            .field("trust", &self.trust)
            .field("policy", &self.policy)
            .field("max_host_call_concurrency", &self.max_host_call_concurrency)
            .finish_non_exhaustive()
    }
}

impl Default for PluginHostBuilder {
    fn default() -> Self {
        Self {
            trust: TrustPolicy::deny_all(),
            verifier: Arc::new(RejectAllSignatures),
            services: HostServices::deny_all(),
            policy: ViolationPolicy::ReturnError,
            max_host_call_concurrency: 8,
        }
    }
}

impl PluginHostBuilder {
    /// A fully closed builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the trust policy.
    #[must_use]
    pub fn trust_policy(mut self, policy: TrustPolicy) -> Self {
        self.trust = policy;
        self
    }

    /// Installs a signature verifier.
    #[must_use]
    pub fn verifier(mut self, verifier: Arc<dyn SignatureVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    /// Installs the host services granted capabilities may reach.
    #[must_use]
    pub fn services(mut self, services: HostServices) -> Self {
        self.services = services;
        self
    }

    /// Chooses what happens when a plugin calls something it was not granted.
    #[must_use]
    pub const fn violation_policy(mut self, policy: ViolationPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Sets the host-wide ceiling on concurrent host calls.
    #[must_use]
    pub const fn max_host_call_concurrency(mut self, max: u32) -> Self {
        self.max_host_call_concurrency = max;
        self
    }

    /// Builds the host, which also builds the engine and starts its ticker.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Instantiate`] when the engine cannot be created.
    pub fn build(self) -> Result<PluginHost, HostError> {
        Ok(PluginHost {
            engine: PluginEngine::new()?,
            trust: self.trust,
            verifier: self.verifier,
            services: self.services,
            policy: self.policy,
            gate: HostCallGate::new(self.max_host_call_concurrency),
            plugins: BTreeMap::new(),
        })
    }
}

/// Runs GTA-Claw plugin components inside a deny-by-default sandbox.
pub struct PluginHost {
    engine: PluginEngine,
    trust: TrustPolicy,
    verifier: Arc<dyn SignatureVerifier>,
    services: HostServices,
    policy: ViolationPolicy,
    gate: HostCallGate,
    plugins: BTreeMap<String, Loaded>,
}

impl core::fmt::Debug for PluginHost {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PluginHost")
            .field("loaded", &self.plugins.keys().collect::<Vec<_>>())
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl PluginHost {
    /// A builder with everything closed.
    #[must_use]
    pub fn builder() -> PluginHostBuilder {
        PluginHostBuilder::new()
    }

    /// The trust policy in force.
    #[must_use]
    pub const fn trust_policy(&self) -> &TrustPolicy {
        &self.trust
    }

    /// The ids of every loaded plugin, sorted.
    #[must_use]
    pub fn loaded_ids(&self) -> Vec<&str> {
        self.plugins.keys().map(String::as_str).collect()
    }

    /// The lifecycle state of one plugin.
    #[must_use]
    pub fn state(&self, id: &str) -> Option<LifecycleState> {
        self.plugins.get(id).map(|plugin| plugin.state)
    }

    /// The manifest a plugin was loaded from.
    #[must_use]
    pub fn manifest(&self, id: &str) -> Option<&PluginManifest> {
        self.plugins.get(id).map(|plugin| &plugin.manifest)
    }

    /// The component digest the host actually computed at load time.
    #[must_use]
    pub fn component_digest(&self, id: &str) -> Option<&str> {
        self.plugins.get(id).map(|plugin| plugin.digest.as_str())
    }

    /// Every host call this plugin's live instance has had refused.
    ///
    /// After a fault or an unload the instance is gone; the denials recorded
    /// before it died are retained here so an operator can still see them.
    #[must_use]
    pub fn denials(&self, id: &str) -> Vec<CapabilityDenial> {
        let Some(plugin) = self.plugins.get(id) else {
            return Vec::new();
        };
        plugin.instance.as_ref().map_or_else(
            || plugin.last_denials.clone(),
            |instance| instance.store.data().denials().to_vec(),
        )
    }

    /// What a plugin's instance consumed, retained across a fault.
    #[must_use]
    pub fn resource_usage(&self, id: &str) -> Option<ResourceUsage> {
        let plugin = self.plugins.get(id)?;
        Some(
            plugin
                .instance
                .as_ref()
                .map_or(plugin.last_usage, |i| ResourceUsage::of(i.store.data())),
        )
    }

    /// Scans every trusted root for plugin directories.
    ///
    /// A directory qualifies when it directly contains a
    /// [`MANIFEST_FILE_NAME`]. Unreadable roots are skipped; unreadable or
    /// invalid manifests are reported per directory rather than aborting the
    /// scan, so one broken plugin cannot hide the rest.
    #[must_use]
    pub fn discover(&self) -> Vec<Discovered> {
        let mut found = Vec::new();
        for root in self.trust.roots() {
            let Ok(entries) = std::fs::read_dir(root) else {
                continue;
            };
            let mut directories: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.join(MANIFEST_FILE_NAME).is_file())
                .collect();
            directories.sort();
            for directory in directories {
                let manifest = read_manifest(&directory);
                found.push(Discovered {
                    directory,
                    manifest,
                });
            }
        }
        found
    }

    /// Loads, validates and instantiates the plugin in `directory`.
    ///
    /// The order is deliberate: schema, limits, capabilities and ABI are
    /// checked before the trust policy resolves any path, the digest and
    /// signature are checked before the bytes reach the compiler, and the
    /// component's imports are checked before it is instantiated.
    ///
    /// # Errors
    ///
    /// Returns the first [`HostError`] that stops the plugin from running.
    pub fn load(&mut self, directory: &Path) -> Result<String, HostError> {
        let manifest = read_manifest(directory)?;
        self.load_manifest(directory, manifest)
    }

    fn load_manifest(
        &mut self,
        directory: &Path,
        manifest: PluginManifest,
    ) -> Result<String, HostError> {
        if self.plugins.contains_key(&manifest.id) {
            return Err(HostError::DuplicatePlugin(manifest.id.clone()));
        }

        manifest.limits.validate()?;
        let capabilities = CapabilitySet::new(manifest.capabilities.iter().cloned())?;
        let declared_abi = Version::parse(&manifest.abi_version)?;
        check_compatibility(ABI_VERSION, declared_abi)?;
        let manifest_version = Version::parse(&manifest.version)?;

        let decision: TrustDecision = self.trust.authorize(directory, &manifest)?;

        let metadata = std::fs::metadata(decision.component_path())
            .map_err(|error| HostError::io(decision.component_path(), &error))?;
        if metadata.len() > manifest.limits.max_component_bytes {
            return Err(HostError::ComponentTooLarge {
                actual: metadata.len(),
                limit: manifest.limits.max_component_bytes,
            });
        }
        if metadata.len() != manifest.component.size_bytes {
            return Err(HostError::DigestMismatch {
                expected: format!("{} bytes", manifest.component.size_bytes),
                actual: format!("{} bytes", metadata.len()),
            });
        }

        let bytes = std::fs::read(decision.component_path())
            .map_err(|error| HostError::io(decision.component_path(), &error))?;
        let digest = component_sha256(&bytes);
        if digest != manifest.component.sha256 {
            return Err(HostError::DigestMismatch {
                expected: manifest.component.sha256.clone(),
                actual: digest,
            });
        }
        self.verifier.verify(&VerificationRequest {
            manifest: &manifest,
            component_sha256: &digest,
        })?;

        let (read_roots, write_roots) = canonical_roots(&capabilities)?;

        let component = Component::new(self.engine.engine(), &bytes)
            .map_err(|error| HostError::Instantiate(format!("{error:#}")))?;
        reject_foreign_imports(self.engine.engine(), &component)?;

        let state = PluginState::new(PluginStateConfig {
            plugin_id: manifest.id.clone(),
            capabilities,
            limits: manifest.limits,
            services: self.services.clone(),
            shared_gate: self.gate.clone(),
            policy: self.policy,
            read_roots,
            write_roots,
        });
        let mut store = self.engine.new_store(state)?;
        arm_call(&mut store, &manifest.limits);
        let bindings = Plugin::instantiate(&mut store, &component, self.engine.linker())
            .map_err(|error| HostError::Instantiate(format!("{error:#}")))?;
        disarm_call(&mut store);

        arm_call(&mut store, &manifest.limits);
        let info = bindings
            .gta_claw_plugin_guest()
            .call_describe(&mut store)
            .map_err(|error| classify(&error, store.data()));
        disarm_call(&mut store);
        let info = info?;

        if info.id != manifest.id {
            return Err(HostError::IdentityMismatch {
                field: "id",
                manifest: manifest.id.clone(),
                component: info.id,
            });
        }
        let reported_version =
            Version::new(info.version.major, info.version.minor, info.version.patch);
        if reported_version != manifest_version {
            return Err(HostError::IdentityMismatch {
                field: "version",
                manifest: manifest_version.to_string(),
                component: reported_version.to_string(),
            });
        }
        let reported_abi = Version::new(
            info.abi_version.major,
            info.abi_version.minor,
            info.abi_version.patch,
        );
        check_compatibility(ABI_VERSION, reported_abi)?;
        if reported_abi != declared_abi {
            return Err(HostError::IdentityMismatch {
                field: "abi_version",
                manifest: declared_abi.to_string(),
                component: reported_abi.to_string(),
            });
        }

        let id = manifest.id.clone();
        self.plugins.insert(
            id.clone(),
            Loaded {
                manifest,
                directory: directory.to_path_buf(),
                component_path: decision.component_path().to_path_buf(),
                digest,
                state: LifecycleState::Loaded,
                instance: Some(Instance { store, bindings }),
                last_denials: Vec::new(),
                last_usage: ResourceUsage::default(),
            },
        );
        Ok(id)
    }

    /// Calls `activate` on a loaded or deactivated plugin.
    ///
    /// # Errors
    ///
    /// Returns [`HostError`] when the plugin is unknown, in the wrong state,
    /// traps, or returns an error of its own.
    pub fn activate(&mut self, id: &str) -> Result<(), HostError> {
        self.transition(
            id,
            "activate",
            &[LifecycleState::Loaded, LifecycleState::Inactive],
            LifecycleState::Active,
            |bindings, store| bindings.gta_claw_plugin_guest().call_activate(store),
        )
    }

    /// Calls `deactivate` on an active plugin.
    ///
    /// # Errors
    ///
    /// Returns [`HostError`] when the plugin is unknown, not active, traps, or
    /// returns an error of its own.
    pub fn deactivate(&mut self, id: &str) -> Result<(), HostError> {
        self.transition(
            id,
            "deactivate",
            &[LifecycleState::Active],
            LifecycleState::Inactive,
            |bindings, store| bindings.gta_claw_plugin_guest().call_deactivate(store),
        )
    }

    fn transition(
        &mut self,
        id: &str,
        operation: &'static str,
        allowed: &[LifecycleState],
        next: LifecycleState,
        call: impl FnOnce(
            &Plugin,
            &mut Store<PluginState>,
        ) -> wasmtime::Result<
            Result<(), crate::bindings::gta_claw::plugin::types::Error>,
        >,
    ) -> Result<(), HostError> {
        let limits = {
            let plugin = self
                .plugins
                .get(id)
                .ok_or_else(|| HostError::UnknownPlugin(id.to_owned()))?;
            if let LifecycleState::Faulted(cause) = plugin.state {
                return Err(HostError::Faulted {
                    id: id.to_owned(),
                    cause,
                });
            }
            if !allowed.contains(&plugin.state) {
                return Err(HostError::WrongState {
                    id: id.to_owned(),
                    actual: plugin.state.as_str(),
                    expected: operation,
                });
            }
            plugin.manifest.limits
        };

        let outcome = {
            let plugin = self
                .plugins
                .get_mut(id)
                .ok_or_else(|| HostError::UnknownPlugin(id.to_owned()))?;
            let instance = plugin
                .instance
                .as_mut()
                .ok_or_else(|| HostError::WrongState {
                    id: id.to_owned(),
                    actual: "unloaded",
                    expected: operation,
                })?;
            arm_call(&mut instance.store, &limits);
            let raw = call(&instance.bindings, &mut instance.store);
            disarm_call(&mut instance.store);
            raw.map_err(|error| classify(&error, instance.store.data()))
        };

        match outcome {
            Ok(Ok(())) => {
                if let Some(plugin) = self.plugins.get_mut(id) {
                    plugin.state = next;
                }
                Ok(())
            }
            Ok(Err(error)) => Err(HostError::Guest(guest_failure(&error))),
            Err(error) => {
                self.fault(id, &error);
                Err(error)
            }
        }
    }

    /// Delivers one event to an active plugin.
    ///
    /// # Errors
    ///
    /// Returns [`HostError`] when the plugin is unknown, not active, traps, or
    /// returns an error of its own.
    pub fn handle_event(&mut self, id: &str, event: &HostEvent) -> Result<EventOutcome, HostError> {
        let limits = self.require_active(id, "handle-event")?;
        let wit = wit_event(event);
        let outcome = {
            let plugin = self
                .plugins
                .get_mut(id)
                .ok_or_else(|| HostError::UnknownPlugin(id.to_owned()))?;
            let instance = plugin
                .instance
                .as_mut()
                .ok_or_else(|| HostError::WrongState {
                    id: id.to_owned(),
                    actual: "unloaded",
                    expected: "handle-event",
                })?;
            arm_call(&mut instance.store, &limits);
            let raw = instance
                .bindings
                .gta_claw_plugin_guest()
                .call_handle_event(&mut instance.store, &wit);
            disarm_call(&mut instance.store);
            raw.map_err(|error| classify(&error, instance.store.data()))
        };
        match outcome {
            Ok(Ok(response)) => Ok(EventOutcome::from(response)),
            Ok(Err(error)) => Err(HostError::Guest(guest_failure(&error))),
            Err(error) => {
                self.fault(id, &error);
                Err(error)
            }
        }
    }

    /// Invokes one of an active plugin's tools.
    ///
    /// # Errors
    ///
    /// Returns [`HostError`] when the plugin is unknown, not active, traps, or
    /// returns an error of its own.
    pub fn invoke_tool(&mut self, id: &str, name: &str, input: &str) -> Result<String, HostError> {
        let limits = self.require_active(id, "invoke-tool")?;
        let outcome = {
            let plugin = self
                .plugins
                .get_mut(id)
                .ok_or_else(|| HostError::UnknownPlugin(id.to_owned()))?;
            let instance = plugin
                .instance
                .as_mut()
                .ok_or_else(|| HostError::WrongState {
                    id: id.to_owned(),
                    actual: "unloaded",
                    expected: "invoke-tool",
                })?;
            arm_call(&mut instance.store, &limits);
            let raw = instance.bindings.gta_claw_plugin_guest().call_invoke_tool(
                &mut instance.store,
                name,
                input,
            );
            disarm_call(&mut instance.store);
            raw.map_err(|error| classify(&error, instance.store.data()))
        };
        match outcome {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(HostError::Guest(guest_failure(&error))),
            Err(error) => {
                self.fault(id, &error);
                Err(error)
            }
        }
    }

    fn require_active(
        &self,
        id: &str,
        operation: &'static str,
    ) -> Result<ResourceLimits, HostError> {
        let plugin = self
            .plugins
            .get(id)
            .ok_or_else(|| HostError::UnknownPlugin(id.to_owned()))?;
        if let LifecycleState::Faulted(cause) = plugin.state {
            return Err(HostError::Faulted {
                id: id.to_owned(),
                cause,
            });
        }
        if plugin.state != LifecycleState::Active {
            return Err(HostError::WrongState {
                id: id.to_owned(),
                actual: plugin.state.as_str(),
                expected: operation,
            });
        }
        Ok(plugin.manifest.limits)
    }

    /// Marks a plugin faulted and destroys its instance.
    ///
    /// Only this plugin's store is dropped. Every other plugin keeps running
    /// on its own store, which is what makes a trap non-contagious.
    fn fault(&mut self, id: &str, error: &HostError) {
        let cause = error.termination().unwrap_or(TerminationCause::Trap);
        if let Some(plugin) = self.plugins.get_mut(id) {
            if let Some(instance) = plugin.instance.take() {
                plugin.last_denials = instance.store.data().denials().to_vec();
                plugin.last_usage = ResourceUsage::of(instance.store.data());
            }
            plugin.state = LifecycleState::Faulted(cause);
        }
    }

    /// Drops a plugin's instance and forgets it.
    ///
    /// Deactivation is attempted first for an active plugin, but a guest that
    /// refuses to deactivate cannot keep itself loaded.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::UnknownPlugin`] when no such plugin is loaded.
    pub fn unload(&mut self, id: &str) -> Result<(), HostError> {
        if !self.plugins.contains_key(id) {
            return Err(HostError::UnknownPlugin(id.to_owned()));
        }
        if self.state(id) == Some(LifecycleState::Active) {
            let _ = self.deactivate(id);
        }
        self.plugins.remove(id);
        Ok(())
    }

    /// Unloads a plugin and loads it again from the directory it came from.
    ///
    /// The manifest is re-read and every check is re-run, so a component that
    /// changed on disk is re-validated rather than trusted from a cache. A
    /// faulted plugin can be recovered this way.
    ///
    /// # Errors
    ///
    /// Returns [`HostError`] when the plugin is unknown or fails to reload.
    pub fn reload(&mut self, id: &str) -> Result<String, HostError> {
        let directory = self
            .plugins
            .get(id)
            .map(|plugin| plugin.directory.clone())
            .ok_or_else(|| HostError::UnknownPlugin(id.to_owned()))?;
        self.unload(id)?;
        self.load(&directory)
    }

    /// The path the component was loaded from.
    #[must_use]
    pub fn component_path(&self, id: &str) -> Option<&Path> {
        self.plugins
            .get(id)
            .map(|plugin| plugin.component_path.as_path())
    }
}

fn read_manifest(directory: &Path) -> Result<PluginManifest, HostError> {
    let path = directory.join(MANIFEST_FILE_NAME);
    let bytes = std::fs::read(&path).map_err(|error| HostError::io(&path, &error))?;
    Ok(PluginManifest::parse(&bytes)?)
}

/// Canonicalises every filesystem root once, at load time, so no call-time
/// path resolution ever has to trust a root that might have moved.
fn canonical_roots(
    capabilities: &CapabilitySet,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>), HostError> {
    let resolve = |roots: &[PathBuf]| -> Result<Vec<PathBuf>, HostError> {
        roots
            .iter()
            .map(|root| std::fs::canonicalize(root).map_err(|error| HostError::io(root, &error)))
            .collect()
    };
    let read = capabilities
        .filesystem_read()
        .map_or_else(|| Ok(Vec::new()), |grant| resolve(&grant.roots))?;
    let write = capabilities
        .filesystem_write()
        .map_or_else(|| Ok(Vec::new()), |grant| resolve(&grant.roots))?;
    Ok((read, write))
}

/// Refuses a component that imports anything outside this world.
fn reject_foreign_imports(
    engine: &wasmtime::Engine,
    component: &Component,
) -> Result<(), HostError> {
    let component_type = component.component_type();
    for (name, _) in component_type.imports(engine) {
        if !ALLOWED_IMPORTS.contains(&name) {
            return Err(HostError::UnsatisfiedImport(name.to_owned()));
        }
    }
    Ok(())
}

/// Gives a call its own fuel, epoch deadline and host-call deadline.
fn arm_call(store: &mut Store<PluginState>, limits: &ResourceLimits) {
    let _ = store.set_fuel(limits.fuel);
    store.set_epoch_deadline(epoch_ticks_for(limits.wall_clock_timeout_ms));
    store
        .data_mut()
        .set_deadline(Some(Instant::now() + limits.timeout()));
}

fn disarm_call(store: &mut Store<PluginState>) {
    store.data_mut().set_deadline(None);
}

fn guest_failure(error: &crate::bindings::gta_claw::plugin::types::Error) -> GuestFailure {
    use crate::bindings::gta_claw::plugin::types::ErrorCode;
    let code = match error.code {
        ErrorCode::InvalidInput => "invalid-input",
        ErrorCode::PermissionDenied => "permission-denied",
        ErrorCode::NotFound => "not-found",
        ErrorCode::Conflict => "conflict",
        ErrorCode::ResourceExhausted => "resource-exhausted",
        ErrorCode::Unsupported => "unsupported",
        ErrorCode::Internal => "internal",
    };
    GuestFailure {
        code,
        message: error.message.clone(),
    }
}

/// Turns a Wasmtime error into a host error, naming why the guest stopped.
fn classify(error: &wasmtime::Error, state: &PluginState) -> HostError {
    let detail = format!("{error:#}");
    let cause = match error.downcast_ref::<wasmtime::Trap>() {
        Some(wasmtime::Trap::Interrupt) => TerminationCause::Timeout,
        Some(wasmtime::Trap::OutOfFuel) => TerminationCause::FuelExhausted,
        Some(wasmtime::Trap::StackOverflow) => TerminationCause::StackOverflow,
        Some(_) | None => {
            if state.hit_memory_ceiling() || state.hit_table_ceiling() {
                TerminationCause::ResourceLimit
            } else {
                TerminationCause::Trap
            }
        }
    };
    HostError::Terminated { cause, detail }
}

#[cfg(test)]
mod tests {
    use super::{ALLOWED_IMPORTS, LifecycleState, MANIFEST_FILE_NAME, PluginHost};
    use crate::error::TerminationCause;

    #[test]
    fn the_allowed_import_list_is_exactly_this_world() {
        let mut sorted = ALLOWED_IMPORTS;
        sorted.sort_unstable();
        assert_eq!(sorted, ALLOWED_IMPORTS, "keep the list sorted");
        assert_eq!(ALLOWED_IMPORTS.len(), 10);
        for name in ALLOWED_IMPORTS {
            assert!(
                name.starts_with("gta-claw:plugin/"),
                "{name} is not part of this world"
            );
            assert!(name.ends_with("@1.0.0"), "{name} is not version pinned");
        }
        assert!(
            !ALLOWED_IMPORTS.iter().any(|name| name.starts_with("wasi:")),
            "the host must never satisfy a wasi import"
        );
    }

    #[test]
    fn the_manifest_file_name_is_fixed() {
        assert_eq!(MANIFEST_FILE_NAME, "plugin.json");
    }

    #[test]
    fn lifecycle_state_names_are_stable() {
        assert_eq!(LifecycleState::Loaded.as_str(), "loaded");
        assert_eq!(LifecycleState::Active.as_str(), "active");
        assert_eq!(LifecycleState::Inactive.as_str(), "inactive");
        assert_eq!(
            LifecycleState::Faulted(TerminationCause::Timeout).as_str(),
            "faulted"
        );
    }

    #[test]
    fn a_fresh_host_knows_nothing_and_discovers_nothing() {
        let host = PluginHost::builder().build().expect("host");
        assert_eq!(host.loaded_ids(), Vec::<&str>::new());
        assert_eq!(host.state("anything"), None);
        assert_eq!(host.manifest("anything"), None);
        assert_eq!(host.denials("anything"), Vec::new());
        assert!(host.discover().is_empty());
        assert!(host.trust_policy().roots().is_empty());
    }

    #[test]
    fn operations_on_an_unknown_plugin_name_that_plugin() {
        let mut host = PluginHost::builder().build().expect("host");
        for error in [
            host.activate("ghost").unwrap_err(),
            host.deactivate("ghost").unwrap_err(),
            host.unload("ghost").unwrap_err(),
            host.reload("ghost").unwrap_err(),
        ] {
            match error {
                crate::error::HostError::UnknownPlugin(id) => assert_eq!(id, "ghost"),
                other => panic!("expected an unknown-plugin error, got {other}"),
            }
        }
    }
}
