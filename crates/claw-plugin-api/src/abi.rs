//! ABI version and the host/guest compatibility policy.
//!
//! The WIT world in `wit/gta-claw-plugin/world.wit` carries the ABI version in
//! its package name (`gta-claw:plugin@1.0.0`). This module mirrors that version
//! into Rust and defines exactly when a host will accept a guest.
//!
//! # Compatibility policy
//!
//! * **major** - incompatible generation. A removal, a renamed interface or any
//!   change to an existing function signature bumps major. A host loads a guest
//!   only when `guest.major == host.major`.
//! * **minor** - additive. New host imports, or new guest exports that the host
//!   treats as optional, bump minor. A host accepts any guest with
//!   `guest.minor <= host.minor`; a guest built against a *newer* minor may
//!   reference imports this host does not provide, so it is rejected.
//! * **patch** - editorial. Documentation and comment changes only. Patch is
//!   never used for compatibility decisions.

use core::fmt;

use serde::{Deserialize, Serialize};

/// The ABI version implemented by this workspace.
///
/// Must stay identical to the package version in
/// `wit/gta-claw-plugin/world.wit`.
pub const ABI_VERSION: Version = Version {
    major: 1,
    minor: 0,
    patch: 0,
};

/// Fully qualified name of the exported guest interface for [`ABI_VERSION`].
pub const GUEST_INTERFACE: &str = "gta-claw:plugin/guest@1.0.0";

/// A semantic version triple.
///
/// Pre-release and build metadata are intentionally not modelled: they are not
/// part of the plugin ABI surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Version {
    /// Incompatible generation.
    pub major: u32,
    /// Additive revision.
    pub minor: u32,
    /// Editorial revision.
    pub patch: u32,
}

impl Version {
    /// Builds a version triple.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parses a strict `major.minor.patch` triple.
    ///
    /// Leading zeroes, extra components, whitespace, pre-release suffixes and
    /// build metadata are all rejected.
    ///
    /// # Errors
    ///
    /// Returns [`VersionParseError`] when `input` is not a strict triple.
    pub fn parse(input: &str) -> Result<Self, VersionParseError> {
        let mut parts = input.split('.');
        let major = parse_component(parts.next(), input)?;
        let minor = parse_component(parts.next(), input)?;
        let patch = parse_component(parts.next(), input)?;
        if parts.next().is_some() {
            return Err(VersionParseError {
                input: input.to_owned(),
            });
        }
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

fn parse_component(part: Option<&str>, input: &str) -> Result<u32, VersionParseError> {
    let err = || VersionParseError {
        input: input.to_owned(),
    };
    let part = part.ok_or_else(err)?;
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err());
    }
    if part.len() > 1 && part.starts_with('0') {
        return Err(err());
    }
    part.parse::<u32>().map_err(|_| err())
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// `input` was not a strict `major.minor.patch` triple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionParseError {
    input: String,
}

impl VersionParseError {
    /// The rejected input.
    #[must_use]
    pub fn input(&self) -> &str {
        &self.input
    }
}

impl fmt::Display for VersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{}` is not a strict major.minor.patch version",
            self.input
        )
    }
}

impl core::error::Error for VersionParseError {}

/// Why a guest ABI version was rejected by a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiIncompatibility {
    /// The guest targets a different incompatible generation.
    MajorMismatch {
        /// ABI generation implemented by the host.
        host: u32,
        /// ABI generation requested by the guest.
        guest: u32,
    },
    /// The guest targets a newer additive revision than this host implements.
    MinorTooNew {
        /// Highest additive revision implemented by the host.
        host: u32,
        /// Additive revision requested by the guest.
        guest: u32,
    },
}

impl fmt::Display for AbiIncompatibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MajorMismatch { host, guest } => write!(
                f,
                "guest ABI generation {guest} cannot run on host ABI generation {host}"
            ),
            Self::MinorTooNew { host, guest } => write!(
                f,
                "guest requires additive ABI revision {guest} but this host implements {host}"
            ),
        }
    }
}

impl core::error::Error for AbiIncompatibility {}

/// Applies the compatibility policy for a host/guest ABI version pair.
///
/// # Errors
///
/// Returns [`AbiIncompatibility`] when the guest may not run on the host.
pub const fn check_compatibility(host: Version, guest: Version) -> Result<(), AbiIncompatibility> {
    if host.major != guest.major {
        return Err(AbiIncompatibility::MajorMismatch {
            host: host.major,
            guest: guest.major,
        });
    }
    if guest.minor > host.minor {
        return Err(AbiIncompatibility::MinorTooNew {
            host: host.minor,
            guest: guest.minor,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ABI_VERSION, AbiIncompatibility, GUEST_INTERFACE, Version, check_compatibility};

    #[test]
    fn abi_version_matches_the_wit_package_and_interface_name() {
        assert_eq!(ABI_VERSION, Version::new(1, 0, 0));
        assert_eq!(GUEST_INTERFACE, "gta-claw:plugin/guest@1.0.0");
    }

    #[test]
    fn parse_accepts_a_strict_triple() {
        assert_eq!(Version::parse("1.0.0"), Ok(Version::new(1, 0, 0)));
        assert_eq!(Version::parse("12.34.56"), Ok(Version::new(12, 34, 56)));
        assert_eq!(Version::parse("0.0.0"), Ok(Version::new(0, 0, 0)));
    }

    #[test]
    fn parse_rejects_loose_versions() {
        for input in [
            "1.0",
            "1.0.0.0",
            "1.0.0-rc.1",
            "1.0.0+build",
            "01.0.0",
            "1.0.0 ",
            " 1.0.0",
            "v1.0.0",
            "1..0",
            "",
            "1.0.x",
        ] {
            let parsed = Version::parse(input);
            assert!(parsed.is_err(), "`{input}` should not parse");
            assert_eq!(parsed.unwrap_err().input(), input);
        }
    }

    #[test]
    fn display_round_trips_through_parse() {
        let version = Version::new(3, 7, 11);
        assert_eq!(version.to_string(), "3.7.11");
        assert_eq!(Version::parse("3.7.11"), Ok(version));
    }

    #[test]
    fn equal_versions_are_compatible() {
        assert_eq!(
            check_compatibility(Version::new(1, 4, 2), Version::new(1, 4, 2)),
            Ok(())
        );
    }

    #[test]
    fn older_guest_minor_and_any_patch_is_accepted() {
        assert_eq!(
            check_compatibility(Version::new(1, 4, 2), Version::new(1, 0, 9)),
            Ok(())
        );
    }

    #[test]
    fn newer_guest_minor_is_rejected() {
        assert_eq!(
            check_compatibility(Version::new(1, 4, 0), Version::new(1, 5, 0)),
            Err(AbiIncompatibility::MinorTooNew { host: 4, guest: 5 })
        );
    }

    #[test]
    fn different_major_is_rejected_in_both_directions() {
        assert_eq!(
            check_compatibility(Version::new(1, 0, 0), Version::new(2, 0, 0)),
            Err(AbiIncompatibility::MajorMismatch { host: 1, guest: 2 })
        );
        assert_eq!(
            check_compatibility(Version::new(2, 0, 0), Version::new(1, 9, 9)),
            Err(AbiIncompatibility::MajorMismatch { host: 2, guest: 1 })
        );
    }
}
