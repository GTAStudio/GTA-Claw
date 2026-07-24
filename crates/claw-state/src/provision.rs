use std::path::Path;

use crate::StateError;

/// Result of an offline LinuxProtected namespace initialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LinuxProtectedInitialization {
    /// A fresh namespace, or exact initializer-owned progress, completed runtime handoff.
    Initialized,
    /// The namespace had already crossed the selector commit boundary and was verified.
    AlreadyInitialized,
}

/// Initializes or verifies an already precreated LinuxProtected namespace offline.
///
/// `service_uid` and `service_gid` are the nonzero numeric credentials that
/// will run the daemon after provisioning. They are deliberately explicit and
/// are not inferred from the root provisioner process. On Linux this operation
/// requires both the real and effective UID to be zero. It never creates,
/// renames, unlinks, chmods, or chowns namespace entries and never runs
/// application migrations or claims the application writer row.
///
/// The namespace must already contain exactly the accepted eight fixed regular
/// files. A fresh namespace is initialized only when all eight entries,
/// including the database and WAL, are empty. Exact versioned initializer-owned
/// preparation, transition, or committed-cleanup records can be resumed
/// idempotently under the fixed writer lock. Every unknown, ambiguous, or
/// noncanonical partial state is rejected rather than repaired. Off Linux this function returns
/// [`crate::StateErrorKind::UnsupportedPlatform`].
pub fn initialize_linux_protected_offline(
    namespace: impl AsRef<Path>,
    service_uid: u32,
    service_gid: u32,
) -> Result<LinuxProtectedInitialization, StateError> {
    #[cfg(target_os = "linux")]
    {
        crate::linux_protected::initialize_offline(namespace.as_ref(), service_uid, service_gid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (namespace, service_uid, service_gid);
        Err(StateError::InvalidValue {
            field: "state platform",
            reason: "offline LinuxProtected initialization requires Linux",
        })
    }
}
