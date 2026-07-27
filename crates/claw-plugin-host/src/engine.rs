//! The Wasmtime engine, its deny-by-default configuration and the epoch ticker
//! that makes wall-clock timeouts real.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use wasmtime::component::{HasSelf, Linker};
use wasmtime::{Config, Engine, OptLevel, Store};

use crate::bindings::Plugin;
use crate::error::HostError;
use crate::state::PluginState;

/// How often the background thread advances the engine epoch, in milliseconds.
///
/// This, not [`EPOCH_TICK`], is the value the deadline arithmetic uses, so a
/// millisecond budget is converted into ticks without ever narrowing the
/// [`Duration::as_millis`] `u128`.
const EPOCH_TICK_MS: u64 = 1;

/// How often the background thread advances the engine epoch.
///
/// One millisecond is the resolution of the wall-clock budget: a guest can
/// overrun its deadline by at most one tick before it is interrupted.
pub const EPOCH_TICK: Duration = Duration::from_millis(EPOCH_TICK_MS);

/// Wasm frames Wasmtime keeps when it builds a trap backtrace.
///
/// Evaluated at compile time, so the `expect` is a build-time assertion rather
/// than a run-time panic path.
const MAX_BACKTRACE_FRAMES: core::num::NonZeroUsize =
    core::num::NonZeroUsize::new(20).expect("20 is not zero");

/// A configured engine plus the linker that only ever exposes this world.
///
/// The linker is built once and holds exactly the nine host interfaces of
/// `gta-claw:plugin@1.0.0`. Nothing adds WASI, so a component that imports
/// `wasi:*` - or anything else - fails to instantiate instead of silently
/// gaining ambient authority.
pub struct PluginEngine {
    engine: Engine,
    linker: Linker<PluginState>,
    ticker: EpochTicker,
}

impl core::fmt::Debug for PluginEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PluginEngine")
            .field("epoch_tick", &EPOCH_TICK)
            .finish_non_exhaustive()
    }
}

impl PluginEngine {
    /// Builds the engine, its configuration and the epoch ticker.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Instantiate`] when Wasmtime rejects this
    /// configuration (the component model, fuel metering and epoch
    /// interruption must all be compiled in and supported on this target),
    /// when one of the world's host functions cannot be added to the linker,
    /// which happens if an import name is defined twice, or when the operating
    /// system refuses to start the epoch ticker thread. The last one is fatal
    /// on purpose: without a ticker nothing advances the epoch, so
    /// `wall_clock_timeout_ms` would silently stop being enforced and a guest
    /// that blocks without burning fuel would never be interrupted.
    pub fn new() -> Result<Self, HostError> {
        let mut config = Config::new();
        config
            .wasm_component_model(true)
            .consume_fuel(true)
            .epoch_interruption(true)
            // `claw-plugin-host` depends on Wasmtime with `default-features =
            // false`, so the threads, GC, relaxed-SIMD and WASI proposals are
            // not compiled into this engine at all. There is therefore no
            // shared memory, no host-dependent relaxed-SIMD result and no WASI
            // implementation available to link, even by mistake.
            .wasm_backtrace_max_frames(Some(MAX_BACKTRACE_FRAMES))
            .wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Disable)
            .cranelift_opt_level(OptLevel::Speed)
            // A deep-recursion guest must trap inside its own stack budget
            // rather than run the host thread's stack out.
            .max_wasm_stack(512 * 1024);

        let engine =
            Engine::new(&config).map_err(|error| HostError::Instantiate(error.to_string()))?;
        let mut linker: Linker<PluginState> = Linker::new(&engine);
        // Refuse to overwrite an already-linked import: a second definition of
        // the same name would be a silent capability escalation.
        linker.allow_shadowing(false);
        Plugin::add_to_linker::<PluginState, HasSelf<PluginState>>(&mut linker, |state| state)
            .map_err(|error| HostError::Instantiate(error.to_string()))?;

        let ticker = EpochTicker::start(&engine).map_err(|error| {
            HostError::Instantiate(format!(
                "the epoch ticker thread could not be started: {error}"
            ))
        })?;
        Ok(Self {
            engine,
            linker,
            ticker,
        })
    }

    /// The underlying engine.
    #[must_use]
    pub const fn engine(&self) -> &Engine {
        &self.engine
    }

    /// The linker holding exactly this world's imports.
    #[must_use]
    pub const fn linker(&self) -> &Linker<PluginState> {
        &self.linker
    }

    /// Number of epoch ticks the ticker has published.
    #[must_use]
    pub fn ticks(&self) -> u64 {
        self.ticker.ticks()
    }

    /// Creates a store wired to this engine with fuel, the epoch deadline and
    /// the per-instance resource limiter already applied.
    ///
    /// The limiter is installed on the store itself, so Wasmtime consults the
    /// instance's memory, table, instance and memory-count ceilings on every
    /// growth request rather than after the fact, and both bounds on execution
    /// (the fuel budget and the epoch deadline) are armed before the store is
    /// ever handed a component.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Instantiate`] when the fuel budget cannot be set,
    /// which only happens if the engine was built without fuel metering. The
    /// store is dropped rather than returned unmetered.
    pub fn new_store(&self, state: PluginState) -> Result<Store<PluginState>, HostError> {
        let fuel = state.limits().fuel;
        let timeout_ms = state.limits().wall_clock_timeout_ms;
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state: &mut PluginState| {
            state.limiter_mut() as &mut dyn wasmtime::ResourceLimiter
        });
        store
            .set_fuel(fuel)
            .map_err(|error| HostError::Instantiate(error.to_string()))?;
        store.epoch_deadline_trap();
        store.set_epoch_deadline(epoch_ticks_for(timeout_ms));
        Ok(store)
    }
}

/// Converts a millisecond budget into epoch ticks, never zero.
#[must_use]
pub(crate) const fn epoch_ticks_for(timeout_ms: u64) -> u64 {
    let ticks = timeout_ms / EPOCH_TICK_MS;
    if ticks == 0 { 1 } else { ticks }
}

/// A background thread that advances the engine epoch on a fixed cadence.
///
/// The thread is stopped and joined when the engine is dropped, so a host that
/// goes away does not leave a ticker behind. Nothing else advances the epoch,
/// so this thread existing is what makes the wall-clock budget real; a host
/// that cannot start it refuses to be built.
struct EpochTicker {
    running: Arc<AtomicBool>,
    ticks: Arc<std::sync::atomic::AtomicU64>,
    handle: Option<JoinHandle<()>>,
}

impl EpochTicker {
    fn start(engine: &Engine) -> std::io::Result<Self> {
        let running = Arc::new(AtomicBool::new(true));
        let ticks = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let engine = engine.clone();
        let thread_running = Arc::clone(&running);
        let thread_ticks = Arc::clone(&ticks);
        let handle = std::thread::Builder::new()
            .name("claw-plugin-epoch".to_owned())
            .spawn(move || {
                while thread_running.load(Ordering::Acquire) {
                    std::thread::sleep(EPOCH_TICK);
                    engine.increment_epoch();
                    thread_ticks.fetch_add(1, Ordering::Release);
                }
            })?;
        Ok(Self {
            running,
            ticks,
            handle: Some(handle),
        })
    }

    fn ticks(&self) -> u64 {
        self.ticks.load(Ordering::Acquire)
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EPOCH_TICK, PluginEngine, epoch_ticks_for};

    #[test]
    fn a_millisecond_budget_maps_to_at_least_one_tick() {
        assert_eq!(EPOCH_TICK.as_millis(), 1);
        assert_eq!(epoch_ticks_for(0), 1);
        assert_eq!(epoch_ticks_for(1), 1);
        assert_eq!(epoch_ticks_for(250), 250);
        assert_eq!(epoch_ticks_for(5_000), 5_000);
    }

    #[test]
    fn the_epoch_ticker_actually_advances() {
        let engine = PluginEngine::new().expect("engine");
        let before = engine.ticks();
        std::thread::sleep(std::time::Duration::from_millis(60));
        let after = engine.ticks();
        assert!(
            after > before,
            "the epoch ticker must advance: {before} -> {after}"
        );
    }

    #[test]
    fn the_engine_builds_and_exposes_a_linker() {
        let engine = PluginEngine::new().expect("engine");
        // Linking the same world twice must fail because shadowing is off,
        // which proves no import can be silently redefined.
        let mut linker = wasmtime::component::Linker::new(engine.engine());
        linker.allow_shadowing(false);
        crate::bindings::Plugin::add_to_linker::<
            crate::state::PluginState,
            wasmtime::component::HasSelf<crate::state::PluginState>,
        >(&mut linker, |state| state)
        .expect("first link");
        let second = crate::bindings::Plugin::add_to_linker::<
            crate::state::PluginState,
            wasmtime::component::HasSelf<crate::state::PluginState>,
        >(&mut linker, |state| state);
        assert!(
            second.is_err(),
            "re-defining an import must be refused, not silently accepted"
        );
    }
}
