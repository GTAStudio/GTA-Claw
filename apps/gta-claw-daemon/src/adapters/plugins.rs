//! A plugin host stand-in that instantiates per activation.
//!
//! The interesting property here is negative: this host never keeps a
//! capability set between activations. Each [`PluginActivation`] carries the
//! capabilities that were decided at that moment, and the instance is created
//! with exactly those. Tearing an instance down removes them.
//!
//! That is the shape a real Wasmtime host must copy. The failure it prevents is
//! installing a capability on the linker once at start-up and having every
//! later instance inherit it, including instances created after the grant that
//! justified it had expired.
//!
//! It is only that shape, though: no component is compiled, linked or run here.
//! This stands in for `claw-plugin-host` until it lands.
//!
//! # Lock poisoning
//!
//! The accessors below unwrap the live-instance lock, so each panics if a
//! previous holder panicked while holding it. An operator should restart the
//! daemon and investigate the *first* panic in the log.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use claw_application::composition::{
    BoxFuture, CapabilitySet, Grant, PluginActivation, PluginHostPort, PluginInstance,
    SubsystemError, well_known,
};

/// Instantiates components in memory, one capability set per instance.
#[derive(Debug, Default)]
pub struct PerActivationPluginHost {
    next: AtomicU64,
    live: Mutex<BTreeMap<u64, (String, CapabilitySet)>>,
    activations: AtomicU64,
}

impl PerActivationPluginHost {
    /// Creates an empty host.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns how many instances are currently live.
    ///
    /// # Panics
    ///
    /// Panics if the live-instance lock is poisoned; see the module note on
    /// lock poisoning.
    #[must_use]
    pub fn live_instances(&self) -> usize {
        self.live.lock().expect("uncontended").len()
    }

    /// Returns how many activations have been attempted.
    #[must_use]
    pub fn activations(&self) -> u64 {
        self.activations.load(Ordering::SeqCst)
    }

    /// Returns the capabilities installed on a live instance, if it exists.
    ///
    /// # Panics
    ///
    /// Panics if the live-instance lock is poisoned; see the module note on
    /// lock poisoning.
    #[must_use]
    pub fn capabilities_of(&self, instance: &PluginInstance) -> Option<CapabilitySet> {
        self.live
            .lock()
            .expect("uncontended")
            .get(&instance.instance())
            .map(|(_, capabilities)| capabilities.clone())
    }
}

impl PluginHostPort for PerActivationPluginHost {
    fn activate(
        &self,
        activation: Grant<PluginActivation>,
    ) -> BoxFuture<'_, Result<PluginInstance, SubsystemError>> {
        Box::pin(async move {
            self.activations.fetch_add(1, Ordering::SeqCst);

            let activation = activation
                .redeem()
                .map_err(|denial| SubsystemError::denied(well_known::plugin_host(), &denial))?;

            let number = self.next.fetch_add(1, Ordering::SeqCst);
            self.live.lock().expect("uncontended").insert(
                number,
                (
                    activation.component().to_owned(),
                    activation.granted().clone(),
                ),
            );

            Ok(PluginInstance::new(
                activation.component().to_owned(),
                number,
            ))
        })
    }

    fn teardown(&self, instance: PluginInstance) -> BoxFuture<'_, Result<(), SubsystemError>> {
        Box::pin(async move {
            let removed = self
                .live
                .lock()
                .expect("uncontended")
                .remove(&instance.instance());

            if removed.is_none() {
                return Err(SubsystemError::not_found(
                    well_known::plugin_host(),
                    format!(
                        "instance {} of {} is not live",
                        instance.instance(),
                        instance.component()
                    ),
                ));
            }

            Ok(())
        })
    }
}
