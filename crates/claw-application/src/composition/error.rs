//! Errors raised while planning a composition and while running its subsystems.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use super::authority::Denial;
use super::id::SubsystemId;
use super::lifecycle::PhaseTransitionError;

/// A composition that cannot be assembled at all.
///
/// Every variant is a static defect in how the daemon was wired, so it is
/// reported before any subsystem is initialized rather than at the moment the
/// broken edge is first traversed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompositionError {
    /// A subsystem identifier did not satisfy the identifier grammar.
    InvalidSubsystemId {
        /// The rejected text.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// Two subsystems in the same composition declared the same identifier.
    DuplicateSubsystem(SubsystemId),
    /// A subsystem depends on an identifier that no subsystem provides.
    UnknownDependency {
        /// The subsystem that declared the dependency.
        subsystem: SubsystemId,
        /// The dependency that nothing provides.
        dependency: SubsystemId,
    },
    /// A subsystem declared itself as its own dependency.
    SelfDependency(SubsystemId),
    /// The dependency edges contain a cycle, reported as the cycle itself.
    ///
    /// The path is listed in traversal order and does not repeat the entry
    /// point, so `[a, b, c]` means `a` depends on `b` depends on `c` depends on
    /// `a`.
    DependencyCycle(Vec<SubsystemId>),
    /// The composition was asked to make an illegal lifecycle transition.
    Phase(PhaseTransitionError),
    /// A subsystem refused to initialize or start, which aborts the whole
    /// composition.
    SubsystemFailed(SubsystemError),
}

impl Display for CompositionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSubsystemId { value, reason } => {
                write!(formatter, "invalid subsystem id {value:?}: {reason}")
            }
            Self::DuplicateSubsystem(id) => write!(formatter, "duplicate subsystem: {id}"),
            Self::UnknownDependency {
                subsystem,
                dependency,
            } => write!(
                formatter,
                "subsystem {subsystem} depends on {dependency}, which is not part of the composition"
            ),
            Self::SelfDependency(id) => write!(formatter, "subsystem {id} depends on itself"),
            Self::DependencyCycle(path) => {
                let rendered = path
                    .iter()
                    .map(SubsystemId::as_str)
                    .collect::<Vec<_>>()
                    .join(" -> ");
                write!(formatter, "dependency cycle: {rendered}")
            }
            Self::Phase(error) => Display::fmt(error, formatter),
            Self::SubsystemFailed(error) => {
                write!(
                    formatter,
                    "the composition could not be brought up: {error}"
                )
            }
        }
    }
}

impl Error for CompositionError {}

impl From<SubsystemError> for CompositionError {
    fn from(error: SubsystemError) -> Self {
        Self::SubsystemFailed(error)
    }
}

impl From<PhaseTransitionError> for CompositionError {
    fn from(error: PhaseTransitionError) -> Self {
        Self::Phase(error)
    }
}

/// The category of a subsystem failure.
///
/// Categories exist so the composition can decide what to do without parsing
/// error text: [`Self::Cancelled`] during drain is expected, [`Self::Denied`]
/// is a policy outcome rather than a fault, and the rest abort startup.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SubsystemErrorKind {
    /// The subsystem or a resource it needs is not reachable.
    Unavailable,
    /// The caller supplied something the subsystem rejects.
    Invalid,
    /// The action conflicts with state the subsystem already holds.
    Conflict,
    /// The addressed object does not exist.
    NotFound,
    /// Policy refused the action.
    Denied,
    /// The action stopped because shutdown was requested.
    Cancelled,
    /// The subsystem failed for a reason its caller cannot act on.
    Internal,
}

impl SubsystemErrorKind {
    /// Returns the stable lowercase label used in error text and telemetry.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Invalid => "invalid",
            Self::Conflict => "conflict",
            Self::NotFound => "not found",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::Internal => "internal",
        }
    }
}

/// A failure produced by a subsystem behind a composition port.
///
/// The failing subsystem is always named, because the composition owns
/// heterogeneous subsystems and an unattributed error is not actionable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubsystemError {
    subsystem: SubsystemId,
    kind: SubsystemErrorKind,
    detail: String,
}

impl SubsystemError {
    /// Creates a failure attributed to `subsystem`.
    #[must_use]
    pub fn new(
        subsystem: SubsystemId,
        kind: SubsystemErrorKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            subsystem,
            kind,
            detail: detail.into(),
        }
    }

    /// Creates an [`SubsystemErrorKind::Unavailable`] failure.
    #[must_use]
    pub fn unavailable(subsystem: SubsystemId, detail: impl Into<String>) -> Self {
        Self::new(subsystem, SubsystemErrorKind::Unavailable, detail)
    }

    /// Creates an [`SubsystemErrorKind::Invalid`] failure.
    #[must_use]
    pub fn invalid(subsystem: SubsystemId, detail: impl Into<String>) -> Self {
        Self::new(subsystem, SubsystemErrorKind::Invalid, detail)
    }

    /// Creates a [`SubsystemErrorKind::Conflict`] failure.
    #[must_use]
    pub fn conflict(subsystem: SubsystemId, detail: impl Into<String>) -> Self {
        Self::new(subsystem, SubsystemErrorKind::Conflict, detail)
    }

    /// Creates a [`SubsystemErrorKind::NotFound`] failure.
    #[must_use]
    pub fn not_found(subsystem: SubsystemId, detail: impl Into<String>) -> Self {
        Self::new(subsystem, SubsystemErrorKind::NotFound, detail)
    }

    /// Creates a [`SubsystemErrorKind::Cancelled`] failure.
    #[must_use]
    pub fn cancelled(subsystem: SubsystemId) -> Self {
        Self::new(subsystem, SubsystemErrorKind::Cancelled, String::new())
    }

    /// Creates an [`SubsystemErrorKind::Internal`] failure.
    #[must_use]
    pub fn internal(subsystem: SubsystemId, detail: impl Into<String>) -> Self {
        Self::new(subsystem, SubsystemErrorKind::Internal, detail)
    }

    /// Creates a [`SubsystemErrorKind::Denied`] failure from a policy denial.
    #[must_use]
    pub fn denied(subsystem: SubsystemId, denial: &Denial) -> Self {
        Self::new(subsystem, SubsystemErrorKind::Denied, denial.to_string())
    }

    /// Returns the subsystem that failed.
    #[must_use]
    pub const fn subsystem(&self) -> &SubsystemId {
        &self.subsystem
    }

    /// Returns the failure category.
    #[must_use]
    pub const fn kind(&self) -> SubsystemErrorKind {
        self.kind
    }

    /// Returns the human-readable detail, which may be empty.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl Display for SubsystemError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            write!(formatter, "{}: {}", self.subsystem, self.kind.label())
        } else {
            write!(
                formatter,
                "{}: {}: {}",
                self.subsystem,
                self.kind.label(),
                self.detail
            )
        }
    }
}

impl Error for SubsystemError {}

#[cfg(test)]
mod tests {
    use super::{CompositionError, SubsystemError, SubsystemErrorKind};
    use crate::composition::authority::Denial;
    use crate::composition::id::SubsystemId;

    fn id(value: &str) -> SubsystemId {
        SubsystemId::new(value).expect("valid subsystem id")
    }

    #[test]
    fn a_cycle_renders_as_the_path_that_closes_it() {
        let error =
            CompositionError::DependencyCycle(vec![id("gateway"), id("engine"), id("tools")]);

        assert_eq!(
            error.to_string(),
            "dependency cycle: gateway -> engine -> tools"
        );
    }

    #[test]
    fn an_unknown_dependency_names_both_ends_of_the_edge() {
        let error = CompositionError::UnknownDependency {
            subsystem: id("gateway"),
            dependency: id("engine"),
        };

        assert_eq!(
            error.to_string(),
            "subsystem gateway depends on engine, which is not part of the composition"
        );
    }

    #[test]
    fn a_cancelled_failure_omits_the_empty_detail() {
        let error = SubsystemError::cancelled(id("providers"));

        assert_eq!(error.to_string(), "providers: cancelled");
        assert_eq!(error.detail(), "");
        assert_eq!(error.kind(), SubsystemErrorKind::Cancelled);
    }

    #[test]
    fn a_detailed_failure_names_the_subsystem_then_the_category() {
        let error = SubsystemError::unavailable(id("persistence"), "database file is locked");

        assert_eq!(
            error.to_string(),
            "persistence: unavailable: database file is locked"
        );
    }

    #[test]
    fn a_denial_is_carried_into_the_subsystem_error_text() {
        let error = SubsystemError::denied(id("tools"), &Denial::EpochClosed);

        assert_eq!(error.kind(), SubsystemErrorKind::Denied);
        assert_eq!(
            error.to_string(),
            "tools: denied: the daemon left the run epoch the grant was minted in"
        );
    }

    #[test]
    fn every_kind_has_a_distinct_label() {
        let kinds = [
            SubsystemErrorKind::Unavailable,
            SubsystemErrorKind::Invalid,
            SubsystemErrorKind::Conflict,
            SubsystemErrorKind::NotFound,
            SubsystemErrorKind::Denied,
            SubsystemErrorKind::Cancelled,
            SubsystemErrorKind::Internal,
        ];
        let mut labels: Vec<&str> = kinds.iter().map(|kind| kind.label()).collect();
        labels.sort_unstable();
        labels.dedup();

        assert_eq!(labels.len(), kinds.len());
    }
}
