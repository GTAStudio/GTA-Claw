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
        let result = screen_result.and(raw_result);
        if result.is_err() {
            self.active.store(true, Ordering::Release);
        }
        result
    }
}

/// RAII guard that restores raw mode on return, signal unwinding, or panic.
pub struct TerminalSession<C: TerminalControl> {
    control: Option<Arc<C>>,
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
        Ok(Self {
            control: Some(control),
        })
    }

    /// Restores the terminal and reports restoration failures to the caller.
    ///
    /// The `Drop` fallback remains active and is harmless because controls are
    /// required to make restoration idempotent.
    ///
    /// # Errors
    ///
    /// Returns the error reported by the terminal control while leaving raw or
    /// alternate-screen mode.
    pub fn restore(mut self) -> io::Result<()> {
        let Some(control) = self.control.as_ref() else {
            return Ok(());
        };
        let result = control.restore();
        if result.is_ok() {
            self.control.take();
        }
        result
    }
}

impl<C: TerminalControl> Drop for TerminalSession<C> {
    fn drop(&mut self) {
        if let Some(control) = self.control.take() {
            let _ = control.restore();
        }
    }
}

/// A background input reader. The render loop never blocks in `event::read`.
pub struct InputThread {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl InputThread {
    /// Starts a bounded Crossterm event pump.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the reader thread cannot be
    /// created. The caller can then restore a terminal it has already entered.
    pub fn spawn(capacity: usize) -> io::Result<(Self, mpsc::Receiver<Event>)> {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("gta-claw-tui-input".to_owned())
            .spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    match crossterm::event::poll(Duration::from_millis(100)) {
                        Ok(true) => match crossterm::event::read() {
                            Ok(event) => {
                                if !send_input(&sender, event) {
                                    break;
                                }
                            }
                            Err(_) => break,
                        },
                        Ok(false) => {}
                        Err(_) => break,
                    }
                }
            })?;
        Ok((
            Self {
                stop,
                handle: Some(handle),
            },
            receiver,
        ))
    }
}

fn send_input(sender: &mpsc::Sender<Event>, event: Event) -> bool {
    match sender.try_send(event) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
        Err(mpsc::error::TrySendError::Closed(_)) => false,
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

    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

    use super::{install_panic_hook_with, send_input};

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

    #[test]
    fn a_full_input_queue_never_blocks_the_reader_thread() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let key = || Event::Key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::empty()));
        assert!(send_input(&sender, key()));
        assert!(
            send_input(&sender, key()),
            "a full queue drops the new event"
        );
        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_err());
        drop(receiver);
        assert!(!send_input(&sender, key()));
    }
}
