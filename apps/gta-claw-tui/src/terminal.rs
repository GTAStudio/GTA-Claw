use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossterm::cursor::{Hide, Show};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture, Event};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use tokio::sync::mpsc;

/// Abstract terminal lifecycle operations, injectable for panic-path tests.
pub trait TerminalControl: Send + Sync + 'static {
    /// Enters interactive terminal mode.
    ///
    /// # Errors
    ///
    /// Returns the underlying terminal error when raw mode or the alternate
    /// screen cannot be entered. Implementations must leave the terminal in its
    /// original state when they report an error.
    fn enter(&self) -> io::Result<()>;
    /// Restores the process terminal. Implementations must be idempotent.
    ///
    /// # Errors
    ///
    /// Returns the underlying terminal error when the alternate screen or raw
    /// mode cannot be left. Callers on a panic or shutdown path should ignore
    /// it: there is nothing left to fall back to.
    fn restore(&self) -> io::Result<()>;
}

/// Crossterm-backed process terminal lifecycle.
#[derive(Debug, Default)]
pub struct CrosstermControl {
    active: AtomicBool,
}

impl TerminalControl for CrosstermControl {
    fn enter(&self) -> io::Result<()> {
        enable_raw_mode()?;
        self.active.store(true, Ordering::Release);
        let result = execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture, Hide);
        if result.is_err() {
            let _ = self.restore();
            return result;
        }
        Ok(())
    }

    fn restore(&self) -> io::Result<()> {
        if !self.active.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        let screen_result = execute!(
            io::stdout(),
            Show,
            DisableMouseCapture,
            LeaveAlternateScreen
        );
        let raw_result = disable_raw_mode();
        screen_result.and(raw_result)
    }
}

/// RAII guard that restores raw mode on return, signal unwinding, or panic.
pub struct TerminalSession<C: TerminalControl> {
    control: Arc<C>,
}

impl<C: TerminalControl> TerminalSession<C> {
    /// Enters terminal mode and returns its restoration guard.
    ///
    /// # Errors
    ///
    /// Propagates the [`TerminalControl::enter`] error. No guard is created in
    /// that case, so nothing needs to be restored.
    pub fn enter(control: Arc<C>) -> io::Result<Self> {
        control.enter()?;
        Ok(Self { control })
    }
}

impl<C: TerminalControl> Drop for TerminalSession<C> {
    fn drop(&mut self) {
        let _ = self.control.restore();
    }
}

/// A background input reader. The render loop never blocks in `event::read`.
pub struct InputThread {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl InputThread {
    /// Starts a bounded Crossterm event pump.
    #[must_use]
    pub fn spawn(capacity: usize) -> (Self, mpsc::Receiver<Event>) {
        let (sender, receiver) = mpsc::channel(capacity);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match crossterm::event::poll(Duration::from_millis(100)) {
                    Ok(true) => match crossterm::event::read() {
                        Ok(event) => {
                            if sender.blocking_send(event).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    },
                    Ok(false) => {}
                    Err(_) => break,
                }
            }
        });
        (
            Self {
                stop,
                handle: Some(handle),
            },
            receiver,
        )
    }
}

impl Drop for InputThread {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Returns whether a full-screen terminal can be used safely.
#[must_use]
pub fn is_interactive() -> bool {
    io::stdout().is_terminal()
        && io::stdin().is_terminal()
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}

static PANIC_HOOK: Once = Once::new();

/// Restores the terminal on panic before the default hook prints.
///
/// Without this the panic message is written *inside* the alternate screen and
/// scrolls away with it, and the shell is handed back in raw mode: the user
/// sees no error and has to run `reset` blind. Installing is idempotent and the
/// previously installed hook still runs, so the usual message and backtrace are
/// preserved.
pub fn install_panic_hook() {
    install_panic_hook_with(best_effort_restore);
}

fn install_panic_hook_with(restore: fn()) {
    PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            previous(info);
        }));
    });
}

/// Writes an emergency restoration sequence before process-level error output.
pub fn best_effort_restore() {
    let _ = execute!(
        io::stdout(),
        Show,
        DisableMouseCapture,
        LeaveAlternateScreen
    );
    let _ = disable_raw_mode();
    let _ = io::stdout().flush();
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::install_panic_hook_with;

    static RESTORED: AtomicUsize = AtomicUsize::new(0);

    fn count_restore() {
        RESTORED.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn panic_hook_restores_the_terminal_once_per_panic_and_installs_once() {
        install_panic_hook_with(count_restore);
        install_panic_hook_with(count_restore);

        assert!(std::panic::catch_unwind(|| panic!("simulated render panic")).is_err());
        assert_eq!(RESTORED.load(Ordering::SeqCst), 1);

        assert!(std::panic::catch_unwind(|| panic!("second simulated panic")).is_err());
        assert_eq!(RESTORED.load(Ordering::SeqCst), 2);
    }
}
