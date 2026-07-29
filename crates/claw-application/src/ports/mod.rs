//! Outbound port traits every GTA Claw adapter implements.
//!
//! Every port method returns a [`PortFuture`], a boxed `Send` future. That keeps the traits
//! object-safe so adapters can be held as `Arc<dyn Port>` and swapped at composition time,
//! without forcing an async runtime dependency into this crate.
//!
//! # Feature gate
//!
//! Gated behind the `runtime-ports` feature, together with
//! [`model`](crate::model), whose types appear in these signatures.

pub mod approval;
pub mod clock;
pub mod context;
pub mod goal;
pub mod provider;
pub mod state;
pub mod tool;

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::pin::Pin;

/// The future returned by every port method.
pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A failure raised by an adapter behind a port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortError {
    /// The backing resource could not be reached.
    Unavailable(String),
    /// The request conflicted with the adapter's current state.
    Conflict(String),
    /// The requested entity does not exist.
    NotFound(String),
    /// The request was malformed or violated an adapter invariant.
    Invalid(String),
    /// The mutation committed, but its publication was not proven power-loss durable.
    ///
    /// Retrying the same request is unsafe because the committed state may already be visible.
    CommittedButNotDurable(String),
    /// The adapter aborted the work because it was cancelled.
    Cancelled,
}

impl PortError {
    /// Returns the stable wire label for this failure class.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "unavailable",
            Self::Conflict(_) => "conflict",
            Self::NotFound(_) => "not_found",
            Self::Invalid(_) => "invalid",
            Self::CommittedButNotDurable(_) => "committed_but_not_durable",
            Self::Cancelled => "cancelled",
        }
    }

    /// Returns whether retrying the same request could succeed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_) | Self::Conflict(_))
    }
}

impl Display for PortError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(detail)
            | Self::Conflict(detail)
            | Self::NotFound(detail)
            | Self::Invalid(detail)
            | Self::CommittedButNotDurable(detail) => {
                write!(formatter, "{}: {detail}", self.label())
            }
            Self::Cancelled => formatter.write_str("cancelled"),
        }
    }
}

impl Error for PortError {}

#[cfg(test)]
mod tests {
    use super::PortError;

    #[test]
    fn port_error_labels_cover_every_variant() {
        let errors = [
            PortError::Unavailable("db down".to_owned()),
            PortError::Conflict("revision 3".to_owned()),
            PortError::NotFound("session-1".to_owned()),
            PortError::Invalid("empty name".to_owned()),
            PortError::CommittedButNotDurable("rename landed".to_owned()),
            PortError::Cancelled,
        ];
        let labels: Vec<&str> = errors.iter().map(PortError::label).collect();

        assert_eq!(
            labels,
            vec![
                "unavailable",
                "conflict",
                "not_found",
                "invalid",
                "committed_but_not_durable",
                "cancelled"
            ]
        );
    }

    #[test]
    fn only_transient_failures_are_retryable() {
        assert!(PortError::Unavailable("x".to_owned()).is_retryable());
        assert!(PortError::Conflict("x".to_owned()).is_retryable());
        assert!(!PortError::NotFound("x".to_owned()).is_retryable());
        assert!(!PortError::Invalid("x".to_owned()).is_retryable());
        assert!(!PortError::CommittedButNotDurable("x".to_owned()).is_retryable());
        assert!(!PortError::Cancelled.is_retryable());
    }

    #[test]
    fn port_errors_render_label_and_detail() {
        assert_eq!(
            PortError::Conflict("revision 3".to_owned()).to_string(),
            "conflict: revision 3"
        );
        assert_eq!(PortError::Cancelled.to_string(), "cancelled");
    }
}
