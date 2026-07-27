//! Offline ClawHub marketplace lifecycle for plugins and skills.
//!
//! Upstream sources at
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`:
//!
//! - `src/plugins/clawhub.ts` — registry search, install, update, publish.
//! - `src/skills/lifecycle/clawhub.ts` — installed-set lifecycle and uninstall.
//! - `src/infra/clawhub-install-trust.ts` — publisher trust and the risk
//!   acknowledgement gate that guards every install and update.
//!
//! # No network, ever
//!
//! This module never performs I/O. The registry is a [`Registry`] port, and
//! attestation checking is a [`TrustPolicy`] port. [`StaticRegistry`] and
//! [`PinnedTrustStore`] are the in-memory implementations used by tests and by
//! any host that wants deterministic behaviour; a production host injects its
//! own. The crate has no transport dependency at all, so an accidental network
//! call is not expressible here.
//!
//! # What [`PinnedTrustStore`] does and does not prove
//!
//! It implements **pinning**, not cryptography. A release carries an opaque
//! [`Attestation`] digest produced elsewhere, and the store compares it against
//! a digest an operator pinned in advance. No signature is verified and none is
//! claimed. A host that has real signature verification injects it as its own
//! [`TrustPolicy`]; the pinning store is the fail-closed default, because an
//! unpinned release is rejected rather than admitted.
//!
//! # Fail-closed rules
//!
//! Every gate below rejects by default and names the reason it rejected:
//!
//! - Risk acknowledgement is **exact**. A declared risk that was not
//!   acknowledged is [`ClawHubError::RiskNotAcknowledged`]; an acknowledgement
//!   for a risk the release does not declare is
//!   [`ClawHubError::RiskNotDeclared`], so a blanket "acknowledge everything"
//!   list cannot be carried from one release to the next.
//! - An untrusted publisher, a missing attestation, an unpinned release and a
//!   mismatched digest are all [`ClawHubError::Untrusted`], carrying the
//!   [`TrustError`] that decided it.
//! - An update may not downgrade, and may not silently change publisher.
//! - A publish must be authenticated as the publisher it names, must carry an
//!   attestation, and must strictly increase the published version.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Longest accepted package name.
pub const MAX_PACKAGE_NAME_BYTES: usize = 64;

/// Validated ClawHub package name.
///
/// Upstream package names are lowercase ASCII kebab identifiers. The
/// constructor is the only way to build one, so an unvalidated name cannot
/// reach the registry or the installed set.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageName(String);

impl PackageName {
    /// Validates and wraps one package name.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] when the value is empty, longer than
    /// [`MAX_PACKAGE_NAME_BYTES`], contains a character outside `a-z`, `0-9`
    /// and `-`, does not start with a letter, ends with `-`, or contains two
    /// consecutive `-`.
    pub fn new(value: &str) -> Result<Self, InvalidPackageName> {
        if value.is_empty() {
            return Err(InvalidPackageName::Empty);
        }
        if value.len() > MAX_PACKAGE_NAME_BYTES {
            return Err(InvalidPackageName::TooLong {
                actual: value.len(),
                limit: MAX_PACKAGE_NAME_BYTES,
            });
        }
        if !value.starts_with(|first: char| first.is_ascii_lowercase()) {
            return Err(InvalidPackageName::MustStartWithLetter);
        }
        if value.ends_with('-') {
            return Err(InvalidPackageName::TrailingSeparator);
        }
        if value.contains("--") {
            return Err(InvalidPackageName::RepeatedSeparator);
        }
        if let Some(character) = value
            .chars()
            .find(|character| !matches!(character, 'a'..='z' | '0'..='9' | '-'))
        {
            return Err(InvalidPackageName::UnexpectedCharacter(character));
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for PackageName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Reason a package name was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidPackageName {
    /// The name was empty.
    Empty,
    /// The name exceeded the byte ceiling.
    TooLong {
        /// Supplied length.
        actual: usize,
        /// Accepted maximum.
        limit: usize,
    },
    /// The name did not start with an ASCII lowercase letter.
    MustStartWithLetter,
    /// The name ended with a separator.
    TrailingSeparator,
    /// The name contained two consecutive separators.
    RepeatedSeparator,
    /// The name contained a character outside the accepted set.
    UnexpectedCharacter(char),
}

impl Display for InvalidPackageName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("package name is empty"),
            Self::TooLong { actual, limit } => {
                write!(
                    formatter,
                    "package name is {actual} bytes; limit is {limit}"
                )
            }
            Self::MustStartWithLetter => {
                formatter.write_str("package name must start with a lowercase letter")
            }
            Self::TrailingSeparator => formatter.write_str("package name ends with `-`"),
            Self::RepeatedSeparator => formatter.write_str("package name contains `--`"),
            Self::UnexpectedCharacter(character) => {
                write!(formatter, "package name contains `{character}`")
            }
        }
    }
}

impl Error for InvalidPackageName {}

/// Three-component release version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Version {
    /// Major component.
    pub major: u32,
    /// Minor component.
    pub minor: u32,
    /// Patch component.
    pub patch: u32,
}

impl Version {
    /// Builds a version from its components.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parses an exact `major.minor.patch` version.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidVersion`] when the value does not have exactly three
    /// components, when a component is empty, carries a leading zero, or is not
    /// an ASCII decimal number that fits in a [`u32`].
    pub fn parse(value: &str) -> Result<Self, InvalidVersion> {
        let mut components = value.split('.');
        let (Some(major), Some(minor), Some(patch), None) = (
            components.next(),
            components.next(),
            components.next(),
            components.next(),
        ) else {
            return Err(InvalidVersion::ComponentCount);
        };
        Ok(Self {
            major: parse_component(major)?,
            minor: parse_component(minor)?,
            patch: parse_component(patch)?,
        })
    }
}

fn parse_component(value: &str) -> Result<u32, InvalidVersion> {
    if value.is_empty() {
        return Err(InvalidVersion::EmptyComponent);
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err(InvalidVersion::LeadingZero);
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(InvalidVersion::NotANumber);
    }
    value.parse().map_err(|_| InvalidVersion::OutOfRange)
}

impl Display for Version {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Reason a version string was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidVersion {
    /// The value did not have exactly three dot-separated components.
    ComponentCount,
    /// A component was empty.
    EmptyComponent,
    /// A component carried a leading zero.
    LeadingZero,
    /// A component was not an ASCII decimal number.
    NotANumber,
    /// A component did not fit in a `u32`.
    OutOfRange,
}

impl Display for InvalidVersion {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ComponentCount => "version must be `major.minor.patch`",
            Self::EmptyComponent => "version component is empty",
            Self::LeadingZero => "version component has a leading zero",
            Self::NotANumber => "version component is not a number",
            Self::OutOfRange => "version component does not fit in 32 bits",
        })
    }
}

impl Error for InvalidVersion {}

/// Publisher identity recorded on a release.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublisherId(String);

impl PublisherId {
    /// Wraps a publisher identity.
    #[must_use]
    pub fn new(value: &str) -> Self {
        Self(value.to_owned())
    }

    /// Returns the publisher identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for PublisherId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Opaque content attestation digest carried by a release.
///
/// This crate never computes and never verifies it; it only compares it against
/// what an operator pinned. See the module documentation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Attestation(String);

impl Attestation {
    /// Wraps an opaque attestation digest.
    #[must_use]
    pub fn new(value: &str) -> Self {
        Self(value.to_owned())
    }

    /// Returns the opaque digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for Attestation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Closed set of capabilities a release must declare before it may be run.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RiskFlag {
    /// Reads or writes files outside the package directory.
    FilesystemAccess,
    /// Opens outbound network connections.
    NetworkAccess,
    /// Spawns operating-system processes.
    ProcessExecution,
    /// Reads operator credentials or tokens.
    CredentialAccess,
    /// Downloads and runs code that is not part of the published release.
    RemoteCodeFetch,
}

impl RiskFlag {
    /// Every declared risk, in the order acknowledgement failures report them.
    pub const ALL: [Self; 5] = [
        Self::FilesystemAccess,
        Self::NetworkAccess,
        Self::ProcessExecution,
        Self::CredentialAccess,
        Self::RemoteCodeFetch,
    ];

    /// Returns the exact wire identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemAccess => "filesystem-access",
            Self::NetworkAccess => "network-access",
            Self::ProcessExecution => "process-execution",
            Self::CredentialAccess => "credential-access",
            Self::RemoteCodeFetch => "remote-code-fetch",
        }
    }
}

impl Display for RiskFlag {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One published ClawHub release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Release {
    /// Validated package name.
    pub name: PackageName,
    /// Release version.
    pub version: Version,
    /// Publishing identity.
    pub publisher: PublisherId,
    /// One-line summary used by search.
    pub summary: String,
    /// Search keywords.
    pub keywords: BTreeSet<String>,
    /// Capabilities the operator must acknowledge before install.
    pub risks: BTreeSet<RiskFlag>,
    /// Opaque attestation digest, absent when the publisher supplied none.
    pub attestation: Option<Attestation>,
}

/// Registry port. Implementations never need to perform I/O.
pub trait Registry {
    /// Returns every release whose name, summary or keywords match `text`.
    ///
    /// Matching is case-insensitive and substring-based. An empty `text`
    /// matches every release.
    fn search(&self, text: &str) -> Vec<Release>;

    /// Returns every published version of one package, oldest first.
    fn versions(&self, name: &PackageName) -> Vec<Release>;

    /// Records a new release.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryRejection`] when the backing registry refuses the
    /// release for a reason the caller-side gates did not already cover.
    fn publish(&mut self, release: Release) -> Result<(), RegistryRejection>;
}

/// Registry-side refusal of a publish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryRejection {
    /// The registry is not accepting writes.
    ReadOnly,
    /// The registry already stores this exact release.
    DuplicateRelease,
    /// The registry reached its release ceiling.
    QuotaExhausted,
}

impl Display for RegistryRejection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ReadOnly => "registry is read-only",
            Self::DuplicateRelease => "registry already stores this release",
            Self::QuotaExhausted => "registry release quota is exhausted",
        })
    }
}

impl Error for RegistryRejection {}

/// In-memory [`Registry`] holding a fixed set of releases.
#[derive(Clone, Debug, Default)]
pub struct StaticRegistry {
    releases: BTreeMap<PackageName, BTreeMap<Version, Release>>,
    read_only: bool,
    capacity: Option<usize>,
}

impl StaticRegistry {
    /// Creates an empty writable registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a registry that refuses every publish.
    #[must_use]
    pub fn read_only() -> Self {
        Self {
            read_only: true,
            ..Self::default()
        }
    }

    /// Caps the total number of stored releases.
    #[must_use]
    pub const fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = Some(capacity);
        self
    }

    /// Seeds one release, replacing any release with the same name and version.
    #[must_use]
    pub fn with_release(mut self, release: Release) -> Self {
        self.insert(release);
        self
    }

    /// Returns the number of stored releases.
    #[must_use]
    pub fn len(&self) -> usize {
        self.releases.values().map(BTreeMap::len).sum()
    }

    /// Reports whether the registry stores no releases.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insert(&mut self, release: Release) {
        self.releases
            .entry(release.name.clone())
            .or_default()
            .insert(release.version, release);
    }
}

impl Registry for StaticRegistry {
    fn search(&self, text: &str) -> Vec<Release> {
        let needle = text.to_lowercase();
        self.releases
            .values()
            .flat_map(|versions| versions.values())
            .filter(|release| {
                needle.is_empty()
                    || release.name.as_str().to_lowercase().contains(&needle)
                    || release.summary.to_lowercase().contains(&needle)
                    || release
                        .keywords
                        .iter()
                        .any(|keyword| keyword.to_lowercase().contains(&needle))
            })
            .cloned()
            .collect()
    }

    fn versions(&self, name: &PackageName) -> Vec<Release> {
        self.releases
            .get(name)
            .map(|versions| versions.values().cloned().collect())
            .unwrap_or_default()
    }

    fn publish(&mut self, release: Release) -> Result<(), RegistryRejection> {
        if self.read_only {
            return Err(RegistryRejection::ReadOnly);
        }
        if self
            .releases
            .get(&release.name)
            .is_some_and(|versions| versions.contains_key(&release.version))
        {
            return Err(RegistryRejection::DuplicateRelease);
        }
        if self.capacity.is_some_and(|capacity| self.len() >= capacity) {
            return Err(RegistryRejection::QuotaExhausted);
        }
        self.insert(release);
        Ok(())
    }
}

/// Reason a release failed the trust gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustError {
    /// The publisher is not on the operator's trusted list.
    PublisherNotTrusted(PublisherId),
    /// The release carried no attestation at all.
    AttestationMissing,
    /// No attestation was pinned for this exact name and version.
    AttestationUnpinned {
        /// Package the release names.
        name: PackageName,
        /// Version the release names.
        version: Version,
    },
    /// The release attestation differs from the pinned one.
    AttestationMismatch {
        /// Attestation the operator pinned.
        pinned: Attestation,
        /// Attestation the release carried.
        offered: Attestation,
    },
}

impl Display for TrustError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublisherNotTrusted(publisher) => {
                write!(formatter, "publisher `{publisher}` is not trusted")
            }
            Self::AttestationMissing => formatter.write_str("release carries no attestation"),
            Self::AttestationUnpinned { name, version } => {
                write!(formatter, "no attestation is pinned for {name}@{version}")
            }
            Self::AttestationMismatch { pinned, offered } => {
                write!(
                    formatter,
                    "release attestation `{offered}` does not match pinned `{pinned}`"
                )
            }
        }
    }
}

impl Error for TrustError {}

/// Trust port evaluated before every install, update and publish.
pub trait TrustPolicy {
    /// Decides whether one release may be admitted.
    ///
    /// # Errors
    ///
    /// Returns the [`TrustError`] that decided the refusal. An implementation
    /// must reject by default: returning `Ok` for a release it cannot evaluate
    /// defeats the whole gate.
    fn evaluate(&self, release: &Release) -> Result<(), TrustError>;
}

/// Fail-closed [`TrustPolicy`] built from an explicit publisher list and pinned
/// attestation digests.
#[derive(Clone, Debug, Default)]
pub struct PinnedTrustStore {
    publishers: BTreeSet<PublisherId>,
    pins: BTreeMap<(PackageName, Version), Attestation>,
}

impl PinnedTrustStore {
    /// Creates a store that trusts nobody and pins nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one trusted publisher.
    #[must_use]
    pub fn trusting(mut self, publisher: PublisherId) -> Self {
        self.publishers.insert(publisher);
        self
    }

    /// Pins the attestation expected for one exact release.
    #[must_use]
    pub fn pinning(
        mut self,
        name: PackageName,
        version: Version,
        attestation: Attestation,
    ) -> Self {
        self.pins.insert((name, version), attestation);
        self
    }

    /// Reports whether a publisher is trusted.
    #[must_use]
    pub fn trusts(&self, publisher: &PublisherId) -> bool {
        self.publishers.contains(publisher)
    }
}

impl TrustPolicy for PinnedTrustStore {
    fn evaluate(&self, release: &Release) -> Result<(), TrustError> {
        if !self.publishers.contains(&release.publisher) {
            return Err(TrustError::PublisherNotTrusted(release.publisher.clone()));
        }
        let Some(offered) = release.attestation.as_ref() else {
            return Err(TrustError::AttestationMissing);
        };
        let Some(pinned) = self.pins.get(&(release.name.clone(), release.version)) else {
            return Err(TrustError::AttestationUnpinned {
                name: release.name.clone(),
                version: release.version,
            });
        };
        if pinned != offered {
            return Err(TrustError::AttestationMismatch {
                pinned: pinned.clone(),
                offered: offered.clone(),
            });
        }
        Ok(())
    }
}

/// One search result, annotated with the operator's trust decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchHit {
    /// Matched release.
    pub release: Release,
    /// Trust outcome for this exact release, `None` when it passed.
    ///
    /// Search never hides an untrusted release, because an operator has to be
    /// able to see that a name they expected resolves to something they do not
    /// trust. Installing it still fails.
    pub trust: Option<TrustError>,
}

impl SearchHit {
    /// Reports whether this release would pass the trust gate.
    #[must_use]
    pub const fn is_trusted(&self) -> bool {
        self.trust.is_none()
    }
}

/// Install request carrying the operator's explicit risk acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallRequest {
    /// Package to install.
    pub name: PackageName,
    /// Exact version, or `None` for the newest published version.
    pub version: Option<Version>,
    /// Risks the operator acknowledged for this exact release.
    pub acknowledged_risks: BTreeSet<RiskFlag>,
}

impl InstallRequest {
    /// Builds a request for the newest published version.
    #[must_use]
    pub fn latest(name: PackageName) -> Self {
        Self {
            name,
            version: None,
            acknowledged_risks: BTreeSet::new(),
        }
    }

    /// Builds a request for one exact version.
    #[must_use]
    pub fn exact(name: PackageName, version: Version) -> Self {
        Self {
            name,
            version: Some(version),
            acknowledged_risks: BTreeSet::new(),
        }
    }

    /// Acknowledges one risk.
    #[must_use]
    pub fn acknowledging(mut self, risk: RiskFlag) -> Self {
        self.acknowledged_risks.insert(risk);
        self
    }
}

/// Update request carrying the operator's acknowledgement for the new release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateRequest {
    /// Installed package to update.
    pub name: PackageName,
    /// Exact target version, or `None` for the newest published version.
    pub version: Option<Version>,
    /// Risks the operator acknowledged for the target release.
    pub acknowledged_risks: BTreeSet<RiskFlag>,
}

impl UpdateRequest {
    /// Builds an update to the newest published version.
    #[must_use]
    pub fn latest(name: PackageName) -> Self {
        Self {
            name,
            version: None,
            acknowledged_risks: BTreeSet::new(),
        }
    }

    /// Builds an update to one exact version.
    #[must_use]
    pub fn exact(name: PackageName, version: Version) -> Self {
        Self {
            name,
            version: Some(version),
            acknowledged_risks: BTreeSet::new(),
        }
    }

    /// Acknowledges one risk.
    #[must_use]
    pub fn acknowledging(mut self, risk: RiskFlag) -> Self {
        self.acknowledged_risks.insert(risk);
        self
    }
}

/// Result of an accepted update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateOutcome {
    /// The installed version is already the requested one.
    AlreadyCurrent {
        /// Installed version.
        version: Version,
    },
    /// The package moved to a newer version.
    Updated {
        /// Previously installed version.
        from: Version,
        /// Newly installed version.
        to: Version,
    },
}

/// Authenticated publishing identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherCredentials {
    publisher: PublisherId,
}

impl PublisherCredentials {
    /// Wraps the identity an external authenticator already established.
    #[must_use]
    pub const fn authenticated(publisher: PublisherId) -> Self {
        Self { publisher }
    }

    /// Returns the authenticated publisher.
    #[must_use]
    pub const fn publisher(&self) -> &PublisherId {
        &self.publisher
    }
}

/// One package recorded in the installed set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledPackage {
    /// Installed package name.
    pub name: PackageName,
    /// Installed version.
    pub version: Version,
    /// Publisher pinned at install time; an update may not change it.
    pub publisher: PublisherId,
    /// Risks the operator acknowledged for the installed release.
    pub acknowledged_risks: BTreeSet<RiskFlag>,
    /// Attestation recorded at install time.
    pub attestation: Attestation,
}

/// Every way a ClawHub lifecycle operation can be refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClawHubError {
    /// The registry publishes no release under this name.
    PackageNotFound {
        /// Requested package.
        name: PackageName,
    },
    /// The registry publishes the package but not this version.
    VersionNotFound {
        /// Requested package.
        name: PackageName,
        /// Requested version.
        version: Version,
    },
    /// The package is already in the installed set.
    AlreadyInstalled {
        /// Requested package.
        name: PackageName,
        /// Installed version.
        version: Version,
    },
    /// The package is not in the installed set.
    NotInstalled {
        /// Requested package.
        name: PackageName,
    },
    /// A declared risk was not acknowledged.
    RiskNotAcknowledged {
        /// Release that declares the risk.
        name: PackageName,
        /// Version that declares the risk.
        version: Version,
        /// The unacknowledged risk.
        risk: RiskFlag,
    },
    /// A risk was acknowledged that the release does not declare.
    RiskNotDeclared {
        /// Release the acknowledgement targeted.
        name: PackageName,
        /// Version the acknowledgement targeted.
        version: Version,
        /// The undeclared risk.
        risk: RiskFlag,
    },
    /// The trust gate refused the release.
    Untrusted {
        /// Release the gate refused.
        name: PackageName,
        /// Version the gate refused.
        version: Version,
        /// Reason the gate refused it.
        reason: TrustError,
    },
    /// An update would move to an older or equal version.
    DowngradeRejected {
        /// Installed package.
        name: PackageName,
        /// Installed version.
        installed: Version,
        /// Offered version.
        offered: Version,
    },
    /// An update would change the publisher pinned at install time.
    PublisherChanged {
        /// Installed package.
        name: PackageName,
        /// Publisher pinned at install time.
        installed: PublisherId,
        /// Publisher of the offered release.
        offered: PublisherId,
    },
    /// The authenticated publisher does not own the release being published.
    PublisherMismatch {
        /// Authenticated identity.
        authenticated: PublisherId,
        /// Identity the release claims.
        release: PublisherId,
    },
    /// The registry already publishes this exact version.
    VersionAlreadyPublished {
        /// Package being published.
        name: PackageName,
        /// Version being published.
        version: Version,
    },
    /// A publish did not strictly increase the published version.
    VersionNotIncreasing {
        /// Package being published.
        name: PackageName,
        /// Newest published version.
        latest: Version,
        /// Offered version.
        offered: Version,
    },
    /// The registry itself refused the publish.
    RegistryRejected {
        /// Package being published.
        name: PackageName,
        /// Reason the registry refused it.
        reason: RegistryRejection,
    },
}

impl Display for ClawHubError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackageNotFound { name } => {
                write!(formatter, "clawhub publishes no package `{name}`")
            }
            Self::VersionNotFound { name, version } => {
                write!(formatter, "clawhub publishes no {name}@{version}")
            }
            Self::AlreadyInstalled { name, version } => {
                write!(formatter, "{name}@{version} is already installed")
            }
            Self::NotInstalled { name } => write!(formatter, "`{name}` is not installed"),
            Self::RiskNotAcknowledged {
                name,
                version,
                risk,
            } => write!(
                formatter,
                "{name}@{version} declares risk `{risk}`, which was not acknowledged"
            ),
            Self::RiskNotDeclared {
                name,
                version,
                risk,
            } => write!(
                formatter,
                "risk `{risk}` was acknowledged but {name}@{version} does not declare it"
            ),
            Self::Untrusted {
                name,
                version,
                reason,
            } => write!(formatter, "{name}@{version} is not trusted: {reason}"),
            Self::DowngradeRejected {
                name,
                installed,
                offered,
            } => write!(
                formatter,
                "`{name}` is installed at {installed}; refusing to move to {offered}"
            ),
            Self::PublisherChanged {
                name,
                installed,
                offered,
            } => write!(
                formatter,
                "`{name}` was installed from `{installed}`; refusing an update from `{offered}`"
            ),
            Self::PublisherMismatch {
                authenticated,
                release,
            } => write!(
                formatter,
                "`{authenticated}` may not publish a release owned by `{release}`"
            ),
            Self::VersionAlreadyPublished { name, version } => {
                write!(formatter, "{name}@{version} is already published")
            }
            Self::VersionNotIncreasing {
                name,
                latest,
                offered,
            } => write!(
                formatter,
                "`{name}` is published at {latest}; refusing to publish {offered}"
            ),
            Self::RegistryRejected { name, reason } => {
                write!(formatter, "registry refused `{name}`: {reason}")
            }
        }
    }
}

impl Error for ClawHubError {}

/// ClawHub lifecycle over an injected registry and trust policy.
#[derive(Clone, Debug)]
pub struct ClawHub<R, T> {
    registry: R,
    trust: T,
    installed: BTreeMap<PackageName, InstalledPackage>,
}

impl<R: Registry, T: TrustPolicy> ClawHub<R, T> {
    /// Creates a lifecycle with an empty installed set.
    pub const fn new(registry: R, trust: T) -> Self {
        Self {
            registry,
            trust,
            installed: BTreeMap::new(),
        }
    }

    /// Returns the injected registry.
    pub const fn registry(&self) -> &R {
        &self.registry
    }

    /// Returns one installed package.
    pub fn installed(&self, name: &PackageName) -> Option<&InstalledPackage> {
        self.installed.get(name)
    }

    /// Returns every installed package, ordered by name.
    pub fn installed_packages(&self) -> Vec<&InstalledPackage> {
        self.installed.values().collect()
    }

    /// Searches the registry and annotates every hit with its trust outcome.
    ///
    /// Results are ordered: exact name matches first, then name-prefix matches,
    /// then the rest; ties break by name and then by descending version, so the
    /// order is total and does not depend on registry iteration order.
    pub fn search(&self, text: &str) -> Vec<SearchHit> {
        let needle = text.to_lowercase();
        let mut hits = self
            .registry
            .search(text)
            .into_iter()
            .map(|release| SearchHit {
                trust: self.trust.evaluate(&release).err(),
                release,
            })
            .collect::<Vec<_>>();
        hits.sort_by(|left, right| {
            rank(&left.release, &needle)
                .cmp(&rank(&right.release, &needle))
                .then_with(|| left.release.name.cmp(&right.release.name))
                .then_with(|| right.release.version.cmp(&left.release.version))
        });
        hits
    }

    /// Installs one release after the trust and risk gates both pass.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] naming the gate that refused: an unknown
    /// package or version, an already-installed package, an unacknowledged or
    /// undeclared risk, or a trust refusal.
    pub fn install(&mut self, request: &InstallRequest) -> Result<&InstalledPackage, ClawHubError> {
        if let Some(existing) = self.installed.get(&request.name) {
            return Err(ClawHubError::AlreadyInstalled {
                name: existing.name.clone(),
                version: existing.version,
            });
        }
        let release = self.resolve(&request.name, request.version)?;
        let attestation = self.admit(&release, &request.acknowledged_risks)?;
        let record = InstalledPackage {
            name: release.name.clone(),
            version: release.version,
            publisher: release.publisher.clone(),
            acknowledged_risks: request.acknowledged_risks.clone(),
            attestation,
        };
        Ok(self.installed.entry(release.name).or_insert(record))
    }

    /// Moves one installed package to a newer release.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] naming the gate that refused: the package is
    /// not installed, the target version is unknown, the move is a downgrade,
    /// the publisher changed, a newly declared risk was not acknowledged, or
    /// the trust gate refused the target.
    pub fn update(&mut self, request: &UpdateRequest) -> Result<UpdateOutcome, ClawHubError> {
        let Some(installed) = self.installed.get(&request.name) else {
            return Err(ClawHubError::NotInstalled {
                name: request.name.clone(),
            });
        };
        let installed_version = installed.version;
        let installed_publisher = installed.publisher.clone();
        let release = self.resolve(&request.name, request.version)?;
        if release.publisher != installed_publisher {
            return Err(ClawHubError::PublisherChanged {
                name: release.name,
                installed: installed_publisher,
                offered: release.publisher,
            });
        }
        if release.version == installed_version {
            // Still gate the unchanged release, so a trust or acknowledgement
            // regression cannot be hidden behind a no-op update.
            self.admit(&release, &request.acknowledged_risks)?;
            return Ok(UpdateOutcome::AlreadyCurrent {
                version: installed_version,
            });
        }
        if release.version < installed_version {
            return Err(ClawHubError::DowngradeRejected {
                name: release.name,
                installed: installed_version,
                offered: release.version,
            });
        }
        let attestation = self.admit(&release, &request.acknowledged_risks)?;
        self.installed.insert(
            release.name.clone(),
            InstalledPackage {
                name: release.name,
                version: release.version,
                publisher: release.publisher,
                acknowledged_risks: request.acknowledged_risks.clone(),
                attestation,
            },
        );
        Ok(UpdateOutcome::Updated {
            from: installed_version,
            to: release.version,
        })
    }

    /// Publishes one release as the authenticated publisher.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] naming the gate that refused: the credentials
    /// do not own the release, the version is already published or does not
    /// strictly increase, the trust gate refused the release, or the registry
    /// itself refused the write.
    pub fn publish(
        &mut self,
        credentials: &PublisherCredentials,
        release: Release,
    ) -> Result<(), ClawHubError> {
        if credentials.publisher() != &release.publisher {
            return Err(ClawHubError::PublisherMismatch {
                authenticated: credentials.publisher().clone(),
                release: release.publisher,
            });
        }
        let published = self.registry.versions(&release.name);
        if published
            .iter()
            .any(|existing| existing.version == release.version)
        {
            return Err(ClawHubError::VersionAlreadyPublished {
                name: release.name,
                version: release.version,
            });
        }
        if let Some(latest) = published.iter().map(|existing| existing.version).max()
            && release.version < latest
        {
            return Err(ClawHubError::VersionNotIncreasing {
                name: release.name,
                latest,
                offered: release.version,
            });
        }
        if let Err(reason) = self.trust.evaluate(&release) {
            return Err(ClawHubError::Untrusted {
                name: release.name,
                version: release.version,
                reason,
            });
        }
        let name = release.name.clone();
        self.registry
            .publish(release)
            .map_err(|reason| ClawHubError::RegistryRejected { name, reason })
    }

    /// Removes one installed package and returns its record.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError::NotInstalled`] when the package is absent.
    pub fn uninstall(&mut self, name: &PackageName) -> Result<InstalledPackage, ClawHubError> {
        self.installed
            .remove(name)
            .ok_or_else(|| ClawHubError::NotInstalled { name: name.clone() })
    }

    fn resolve(
        &self,
        name: &PackageName,
        version: Option<Version>,
    ) -> Result<Release, ClawHubError> {
        let published = self.registry.versions(name);
        if published.is_empty() {
            return Err(ClawHubError::PackageNotFound { name: name.clone() });
        }
        match version {
            Some(version) => published
                .into_iter()
                .find(|release| release.version == version)
                .ok_or_else(|| ClawHubError::VersionNotFound {
                    name: name.clone(),
                    version,
                }),
            None => published
                .into_iter()
                .max_by_key(|release| release.version)
                .ok_or_else(|| ClawHubError::PackageNotFound { name: name.clone() }),
        }
    }

    /// Runs the trust gate and the exact risk-acknowledgement gate.
    fn admit(
        &self,
        release: &Release,
        acknowledged: &BTreeSet<RiskFlag>,
    ) -> Result<Attestation, ClawHubError> {
        if let Err(reason) = self.trust.evaluate(release) {
            return Err(ClawHubError::Untrusted {
                name: release.name.clone(),
                version: release.version,
                reason,
            });
        }
        for risk in RiskFlag::ALL {
            if release.risks.contains(&risk) && !acknowledged.contains(&risk) {
                return Err(ClawHubError::RiskNotAcknowledged {
                    name: release.name.clone(),
                    version: release.version,
                    risk,
                });
            }
            if acknowledged.contains(&risk) && !release.risks.contains(&risk) {
                return Err(ClawHubError::RiskNotDeclared {
                    name: release.name.clone(),
                    version: release.version,
                    risk,
                });
            }
        }
        // The trust gate above rejects a release without an attestation, so a
        // trust policy that accepted one is the only way to reach this point
        // without one. Fail closed rather than record an empty attestation.
        release
            .attestation
            .clone()
            .ok_or_else(|| ClawHubError::Untrusted {
                name: release.name.clone(),
                version: release.version,
                reason: TrustError::AttestationMissing,
            })
    }
}

fn rank(release: &Release, needle: &str) -> u8 {
    let name = release.name.as_str().to_lowercase();
    if needle.is_empty() {
        2
    } else if name == needle {
        0
    } else if name.starts_with(needle) {
        1
    } else {
        2
    }
}
