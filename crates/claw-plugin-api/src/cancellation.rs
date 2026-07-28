//! Cooperative cancellation shared across plugin dispatch boundaries.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A cheaply cloned cancellation signal.
///
/// Cancellation is monotonic: once requested, every clone observes it and the
/// token cannot be reset. A fresh invocation that needs an independent lifetime
/// must use a fresh token.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates an uncancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reuses an existing flag as a cancellation token.
    ///
    /// This is the dependency-free bridge for other capability crates: they can
    /// share one `Arc<AtomicBool>` without depending on the plugin host.
    #[must_use]
    pub const fn from_shared_flag(cancelled: Arc<AtomicBool>) -> Self {
        Self { cancelled }
    }

    /// Returns the shared flag backing this token.
    #[must_use]
    pub fn shared_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    /// Requests cancellation of every invocation observing this token.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Reports whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use super::CancellationToken;

    #[test]
    fn cancellation_is_monotonic_and_shared_by_clones() {
        let first = CancellationToken::new();
        let second = first.clone();
        assert!(!first.is_cancelled());
        second.cancel();
        assert!(first.is_cancelled());
        assert!(second.is_cancelled());
    }

    #[test]
    fn a_shared_flag_can_bridge_an_external_dispatcher() {
        let flag = Arc::new(AtomicBool::new(false));
        let token = CancellationToken::from_shared_flag(Arc::clone(&flag));
        let bridged = CancellationToken::from_shared_flag(token.shared_flag());
        bridged.cancel();
        assert!(token.is_cancelled());
    }
}
