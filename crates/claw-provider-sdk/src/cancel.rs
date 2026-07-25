//! Cooperative cancellation shared by transport, retry and streaming layers.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use tokio::sync::watch;

/// A cheaply cloneable cancellation signal.
///
/// Every clone observes the same state. Cancelling is idempotent and wakes all
/// waiters. The token is used by [`crate::http`] to abort an in-flight HTTP
/// request, which drops the underlying connection and closes the socket.
#[derive(Clone)]
pub struct CancelToken {
    sender: Arc<watch::Sender<bool>>,
}

impl CancelToken {
    /// Creates a token that has not been cancelled.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _receiver) = watch::channel(false);
        Self {
            sender: Arc::new(sender),
        }
    }

    /// Creates a token that is already cancelled.
    #[must_use]
    pub fn cancelled_token() -> Self {
        let token = Self::new();
        token.cancel();
        token
    }

    /// Cancels the token and wakes every waiter.
    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }

    /// Returns `true` once [`CancelToken::cancel`] has been called.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    /// Resolves as soon as the token is cancelled.
    ///
    /// Returns immediately when the token is already cancelled, so there is no
    /// window in which a cancellation can be missed.
    pub async fn cancelled(&self) {
        let mut receiver = self.sender.subscribe();
        if *receiver.borrow_and_update() {
            return;
        }
        // The sender is kept alive by `self`, so `changed` cannot fail while
        // this future is being polled.
        let _ = receiver.changed().await;
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for CancelToken {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancelToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn cancellation_is_observed_by_every_clone() {
        let token = CancelToken::new();
        let clone = token.clone();
        assert!(!token.is_cancelled());
        assert!(!clone.is_cancelled());

        let waiter = tokio::spawn(async move {
            clone.cancelled().await;
            clone.is_cancelled()
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        token.cancel();

        assert!(waiter.await.expect("waiter joins"));
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn waiting_on_an_already_cancelled_token_returns_immediately() {
        let token = CancelToken::cancelled_token();
        assert!(token.is_cancelled());
        tokio::time::timeout(Duration::from_millis(50), token.cancelled())
            .await
            .expect("already cancelled tokens must not block");
    }

    #[tokio::test]
    async fn cancelling_twice_is_idempotent() {
        let token = CancelToken::new();
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
        tokio::time::timeout(Duration::from_millis(50), token.cancelled())
            .await
            .expect("second cancel must not block waiters");
    }

    #[test]
    fn debug_reports_state_without_internal_channel_details() {
        let token = CancelToken::new();
        assert_eq!(
            format!("{token:?}"),
            "CancelToken { cancelled: false }".to_owned()
        );
        token.cancel();
        assert_eq!(
            format!("{token:?}"),
            "CancelToken { cancelled: true }".to_owned()
        );
    }
}
