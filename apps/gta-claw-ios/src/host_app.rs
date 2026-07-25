//! iOS host-application declarations that platform features depend on.
//!
//! Local-network discovery on iOS does not fail loudly when the host
//! application is missing its `Info.plist` declarations. The system simply
//! returns nothing, which is byte-for-byte indistinguishable from a network
//! with no Gateway on it. This module exists so that the difference is a
//! reported condition rather than an empty result set.
//!
//! Nothing here reads `Info.plist` or the code-signing entitlements. Reading
//! either requires Foundation or Security framework interop and the workspace
//! forbids `unsafe_code`, so every status in this module is one the embedder
//! *declared*, and the default for an undeclared status is
//! [`DeclarationStatus::Unknown`] — never [`DeclarationStatus::Declared`].
//!
//! # Two preconditions, not one, and only one of them is a plist key
//!
//! `Info.plist` declarations are not the whole gate. Apple's TN3179,
//! *Understanding local network privacy*, records that on iOS sending or
//! receiving UDP multicast additionally requires the
//! `com.apple.developer.networking.multicast` entitlement, which is not a key
//! a developer may simply add: Apple grants it case by case on written
//! request. See [`HostAppEntitlement`], whose state is tracked by its own
//! [`EntitlementStatus`] rather than by [`DeclarationStatus`], because a
//! capability a third party grants is a different kind of thing from text a
//! developer writes.
//!
//! Whether that entitlement is required depends on *how* discovery is
//! implemented, and "how" is a property of the backend rather than a choice the
//! caller makes. [`HostAppDeclarations::discovery_precondition`] is therefore
//! generic over a [`LocalDiscoveryBackend`], and reads both the mechanism and
//! the service type from that backend's own descriptor:
//!
//! | Backend mechanism | Requires |
//! | --- | --- |
//! | [`DiscoveryMechanism::SystemDnsSd`] | both plist keys, and the backend's service type among the declared entries |
//! | [`DiscoveryMechanism::InProcessMulticast`] | the above, **and** a confirmed multicast entitlement |
//!
//! Per TN3179's own tables, registering, browsing and resolving a **specific,
//! declared** Bonjour service type through the system's DNS-SD APIs does not
//! require the entitlement — the system daemon performs the multicast outside
//! the application's process. Only "working with arbitrary Bonjour service
//! types" and "browsing for all advertised service types" do. An in-process
//! mDNS implementation that binds its own multicast sockets is squarely the
//! entitlement-requiring case, whatever service types it browses.
//!
//! The returned [`DiscoveryPermit`] is parameterised by the backend it was
//! issued for, rather than carrying a mode field, so a permit obtained for a
//! system-DNS-SD backend cannot be spent starting a raw-socket one. A runtime
//! field would leave that to a reviewer to notice; a type parameter makes it
//! unsayable.
//!
//! # This crate does not own the service type
//!
//! It is read from [`LocalDiscoveryBackend::DNS_SD_SERVICE_TYPE`]. The
//! Gateway's DNS-SD service type belongs to the discovery contract and is
//! owned by the discovery backend, not by an iOS application crate. Declaring
//! it here would create a second copy that can drift from the first silently,
//! and this crate would have no way to notice.
//!
//! Note also that the plist entry and the browsed type are not the same
//! string: `NSBonjourServices` carries the application-label form such as
//! `_example._tcp`, while the fully qualified `_example._tcp.local.` belongs
//! inside the discovery implementation. Only the fully qualified form is
//! declared, and the plist form is *derived* from it, for the same
//! no-second-copy reason.
//!
//! # Two conditions this module deliberately does not gate
//!
//! *The runtime Local Network privilege.* TN3179 gives it three states —
//! undetermined, allowed, denied — and the alert that resolves it is raised
//! **by** the first local-network operation. Gating on it would block the very
//! call that produces the prompt, so it is not modelled as a precondition. It
//! is modelled *after the fact* instead: [`diagnose_empty_result`] turns an
//! empty peer list plus the privilege state into a reason, so that a caller
//! never reports "no Gateways found" when the truthful answer is "we were not
//! allowed to look". The background-and-undetermined case is called out
//! separately, because TN3179 records that iOS then denies the operation
//! without showing an alert and without recording a decision.
//!
//! *The simulator.* TN3179 states plainly that the simulator does not support
//! local network privacy and that this behaviour must be tested on a real
//! device.
//!
//! # Acceptance boundary
//!
//! A simulator run, or any CI job this project could plausibly build, can prove
//! that this crate compiles and that the policy logic here behaves as written.
//! It cannot prove anything about local network privacy or discovery behaviour.
//! **Only a physical iOS device on a real local network can do that**, and no
//! such run has happened.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;

/// Maximum accepted service type text, in UTF-8 bytes.
const MAX_SERVICE_TYPE_BYTES: usize = 64;

/// Maximum service name length in characters, per RFC 6763 section 7.
const MAX_SERVICE_NAME_CHARS: usize = 15;

/// Maximum number of service types an embedder may declare.
const MAX_DECLARED_SERVICE_TYPES: usize = 16;

/// An `Info.plist` declaration the host application must carry.
///
/// This is a closed set of the `Info.plist` keys features in *this* crate's
/// scope depend on. It is deliberately not a general model of iOS bundle
/// configuration. Entitlements are **not** members of this set — they are
/// modelled separately by [`HostAppEntitlement`], because
/// `com.apple.developer.networking.multicast` is not a plist key and a caller
/// that treats it as one will look for it in the wrong file.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HostAppDeclaration {
    /// The user-facing reason the application uses the local network.
    LocalNetworkUsage,
    /// The exact DNS-SD service types the application may browse.
    BonjourServices,
}

impl HostAppDeclaration {
    /// Every declaration this crate depends on, in source order.
    pub const ALL: [Self; 2] = [Self::LocalNetworkUsage, Self::BonjourServices];

    /// Returns the exact `Info.plist` key.
    #[must_use]
    pub const fn plist_key(self) -> &'static str {
        match self {
            Self::LocalNetworkUsage => "NSLocalNetworkUsageDescription",
            Self::BonjourServices => "NSBonjourServices",
        }
    }

    /// Returns what iOS does when the key is absent.
    #[must_use]
    pub const fn consequence_when_absent(self) -> &'static str {
        match self {
            Self::LocalNetworkUsage => {
                "iOS never prompts for local-network access and every browse returns nothing"
            }
            Self::BonjourServices => {
                "iOS refuses to browse any service type, including one the app asks for by name"
            }
        }
    }
}

impl Display for HostAppDeclaration {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.plist_key())
    }
}

/// A code-signing entitlement the host application must carry.
///
/// This is separate from [`HostAppDeclaration`] because it is a different kind
/// of thing with a different failure mode. A plist key is text a developer
/// adds; this is a capability Apple grants, and a build made from source by
/// anyone who has not been granted it will not have it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HostAppEntitlement {
    /// Permission to send or receive IP multicast or broadcast on iOS.
    MulticastNetworking,
}

impl HostAppEntitlement {
    /// Every entitlement this crate depends on, in source order.
    pub const ALL: [Self; 1] = [Self::MulticastNetworking];

    /// Returns the exact entitlement key.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::MulticastNetworking => "com.apple.developer.networking.multicast",
        }
    }

    /// Returns whether Apple must approve this entitlement before it can be used.
    ///
    /// When this is `true` the entitlement is not something a developer can
    /// switch on: it is a decision by a third party, on a written request, for
    /// a specific application identifier.
    #[must_use]
    pub const fn requires_apple_approval(self) -> bool {
        match self {
            Self::MulticastNetworking => true,
        }
    }

    /// Returns where the entitlement is requested from Apple.
    #[must_use]
    pub const fn request_url(self) -> &'static str {
        match self {
            Self::MulticastNetworking => {
                "https://developer.apple.com/contact/request/networking-multicast"
            }
        }
    }

    /// Returns what iOS does when the entitlement is missing.
    #[must_use]
    pub const fn consequence_when_absent(self) -> &'static str {
        match self {
            Self::MulticastNetworking => {
                "the sockets still bind and the send calls still report success, but no multicast \
                 packet reaches the network and none is delivered back, so discovery is silent \
                 rather than failed"
            }
        }
    }
}

impl Display for HostAppEntitlement {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.key())
    }
}

/// How local-network discovery would be implemented.
///
/// A backend declares its mechanism as a `const` on
/// [`LocalDiscoveryBackend`], and [`HostAppDeclarations::discovery_precondition`]
/// reads it from there. It is deliberately not an argument: how packets leave
/// the process is a property of the backend being started, and a value passed
/// alongside a backend can be passed wrongly.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DiscoveryMechanism {
    /// The system's DNS-SD service, browsing only declared service types.
    ///
    /// The multicast happens in the platform's own daemon rather than in this
    /// process, so per Apple's TN3179 the multicast entitlement is not
    /// required. Reaching these APIs from Rust needs C interop, which this
    /// workspace's `unsafe_code` setting currently forbids, so recording this
    /// variant is a statement about iOS and not a claim that the crate can use
    /// it today.
    SystemDnsSd,
    /// An mDNS implementation inside this process, binding its own sockets.
    ///
    /// This is the shape of every pure-Rust mDNS crate, including `mdns-sd`.
    /// It sends and receives UDP multicast directly, so it requires the
    /// multicast entitlement no matter how narrow its service-type list is.
    InProcessMulticast,
}

impl DiscoveryMechanism {
    /// Every mechanism considered, in source order.
    pub const ALL: [Self; 2] = [Self::SystemDnsSd, Self::InProcessMulticast];

    /// Returns the entitlements this mechanism additionally requires.
    #[must_use]
    pub const fn required_entitlements(self) -> &'static [HostAppEntitlement] {
        match self {
            Self::SystemDnsSd => &[],
            Self::InProcessMulticast => &[HostAppEntitlement::MulticastNetworking],
        }
    }

    /// Returns text safe to render on a diagnostics screen.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SystemDnsSd => "system DNS-SD",
            Self::InProcessMulticast => "in-process mDNS",
        }
    }
}

impl Display for DiscoveryMechanism {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// What the embedder was able to say about a declaration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeclarationStatus {
    /// The embedder confirmed the key is present in the shipped bundle.
    Declared,
    /// The embedder confirmed the key is absent from the shipped bundle.
    Absent,
    /// Nobody has told this crate either way.
    ///
    /// This is the default, and it is treated exactly as strictly as
    /// [`DeclarationStatus::Absent`]. An unverified permission is not a
    /// permission.
    #[default]
    Unknown,
}

impl DeclarationStatus {
    /// Returns whether the embedder positively confirmed the declaration.
    #[must_use]
    pub const fn is_declared(self) -> bool {
        matches!(self, Self::Declared)
    }

    /// Returns text safe to render beside the key on a diagnostics screen.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Absent => "absent",
            Self::Unknown => "unknown",
        }
    }
}

impl Display for DeclarationStatus {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What the embedder was able to say about a restricted entitlement.
///
/// Deliberately a separate type from [`DeclarationStatus`]. An `Info.plist`
/// key is text a developer adds; a restricted entitlement is a capability a
/// third party grants for a specific application identifier, and conflating
/// the two invites a caller to think a build can be fixed locally when it
/// cannot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EntitlementStatus {
    /// The embedder confirmed the shipped build is signed with the entitlement.
    Granted,
    /// The embedder confirmed the shipped build is not signed with it.
    ///
    /// This covers a refused request and a pending one alike, because the two
    /// are operationally identical: the capability is absent either way, and a
    /// build that behaves as though a pending request were a grant is the
    /// defect this type exists to prevent.
    NotGranted,
    /// Nobody has told this crate either way.
    ///
    /// This is the default, and it is treated exactly as strictly as
    /// [`EntitlementStatus::NotGranted`]. It is kept distinct from it because
    /// the remedies differ: one is answered by checking the signing profile,
    /// the other by asking Apple.
    #[default]
    Unknown,
}

impl EntitlementStatus {
    /// Returns whether the embedder positively confirmed the grant.
    #[must_use]
    pub const fn is_granted(self) -> bool {
        matches!(self, Self::Granted)
    }

    /// Returns text safe to render beside the entitlement key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::NotGranted => "not granted or still pending",
            Self::Unknown => "unknown",
        }
    }
}

impl Display for EntitlementStatus {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A DNS-SD service type such as `_gtaclaw._tcp`.
///
/// The grammar is constrained hard on purpose. An `NSBonjourServices` entry is
/// caller-supplied text that ends up in a diagnostics view, and the fleet rule
/// is that a field is credential-bearing based on what it *can* hold. Rather
/// than redact this type, [`BonjourServiceType::parse`] narrows the domain
/// until it cannot hold a secret: at most fifteen characters of ASCII letters,
/// digits and hyphens, with no dots, colons, slashes, at-signs or whitespace.
/// A bearer token does not fit, so deriving [`Debug`] here is safe.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BonjourServiceType {
    text: String,
}

impl BonjourServiceType {
    /// Parses a service type in the RFC 6763 `_name._tcp` or `_name._udp` form.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceTypeError`] when the text is empty, oversized, lacks a
    /// `._tcp` or `._udp` suffix, lacks the leading underscore, has a name that
    /// is empty, too long, contains a character outside `[A-Za-z0-9-]`, starts
    /// or ends with a hyphen, or contains no letter at all.
    pub fn parse(input: &str) -> Result<Self, ServiceTypeError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ServiceTypeError::Empty);
        }
        if trimmed.len() > MAX_SERVICE_TYPE_BYTES {
            return Err(ServiceTypeError::TooLong {
                actual: trimmed.len(),
                limit: MAX_SERVICE_TYPE_BYTES,
            });
        }
        let name = match trimmed
            .strip_suffix("._tcp")
            .or_else(|| trimmed.strip_suffix("._udp"))
        {
            Some(name) => name,
            None => return Err(ServiceTypeError::MissingTransportSuffix),
        };
        let name = match name.strip_prefix('_') {
            Some(name) => name,
            None => return Err(ServiceTypeError::MissingLeadingUnderscore),
        };
        if name.is_empty() {
            return Err(ServiceTypeError::EmptyName);
        }
        let name_chars = name.chars().count();
        if name_chars > MAX_SERVICE_NAME_CHARS {
            return Err(ServiceTypeError::NameTooLong {
                actual: name_chars,
                limit: MAX_SERVICE_NAME_CHARS,
            });
        }
        if let Some(character) = name
            .chars()
            .find(|character| !character.is_ascii_alphanumeric() && *character != '-')
        {
            return Err(ServiceTypeError::DisallowedCharacter { character });
        }
        if name.starts_with('-') || name.ends_with('-') {
            return Err(ServiceTypeError::EdgeHyphen);
        }
        if !name
            .chars()
            .any(|character| character.is_ascii_alphabetic())
        {
            return Err(ServiceTypeError::NoLetter);
        }
        Ok(Self {
            text: trimmed.to_owned(),
        })
    }

    /// Returns the validated service type text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl Display for BonjourServiceType {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Why a service type was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceTypeError {
    /// The text was empty or only whitespace.
    Empty,
    /// The text exceeded the accepted byte length.
    TooLong {
        /// Length of the supplied text, in bytes.
        actual: usize,
        /// Maximum accepted length, in bytes.
        limit: usize,
    },
    /// The text did not end in `._tcp` or `._udp`.
    MissingTransportSuffix,
    /// The service name did not begin with an underscore.
    MissingLeadingUnderscore,
    /// The service name was empty.
    EmptyName,
    /// The service name exceeded fifteen characters.
    NameTooLong {
        /// Length of the supplied name, in characters.
        actual: usize,
        /// Maximum accepted length, in characters.
        limit: usize,
    },
    /// The service name held a character outside `[A-Za-z0-9-]`.
    DisallowedCharacter {
        /// The first offending character.
        character: char,
    },
    /// The service name started or ended with a hyphen.
    EdgeHyphen,
    /// The service name held no letter.
    NoLetter,
}

impl Display for ServiceTypeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("service type is empty"),
            Self::TooLong { actual, limit } => {
                write!(
                    formatter,
                    "service type is {actual} bytes, limit is {limit}"
                )
            }
            Self::MissingTransportSuffix => {
                formatter.write_str("service type must end in ._tcp or ._udp")
            }
            Self::MissingLeadingUnderscore => {
                formatter.write_str("service name must begin with an underscore")
            }
            Self::EmptyName => formatter.write_str("service name is empty"),
            Self::NameTooLong { actual, limit } => write!(
                formatter,
                "service name is {actual} characters, limit is {limit}"
            ),
            Self::DisallowedCharacter { character } => write!(
                formatter,
                "service name holds disallowed character {character:?}"
            ),
            Self::EdgeHyphen => {
                formatter.write_str("service name must not start or end with a hyphen")
            }
            Self::NoLetter => formatter.write_str("service name must contain at least one letter"),
        }
    }
}

impl Error for ServiceTypeError {}

/// The host application's declarations, as reported by the embedder.
///
/// Everything defaults to [`DeclarationStatus::Unknown`], so a caller that
/// forgets to describe its bundle gets a blocked precondition with a reason,
/// not a silent green light.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostAppDeclarations {
    local_network_usage: DeclarationStatus,
    bonjour_services: DeclarationStatus,
    multicast_entitlement: EntitlementStatus,
    service_types: Vec<BonjourServiceType>,
}

impl HostAppDeclarations {
    /// Creates a record in which nothing has been declared.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            local_network_usage: DeclarationStatus::Unknown,
            bonjour_services: DeclarationStatus::Unknown,
            multicast_entitlement: EntitlementStatus::Unknown,
            service_types: Vec::new(),
        }
    }

    /// Records what the embedder knows about `NSLocalNetworkUsageDescription`.
    #[must_use]
    pub const fn with_local_network_usage(mut self, status: DeclarationStatus) -> Self {
        self.local_network_usage = status;
        self
    }

    /// Records what the embedder knows about `NSBonjourServices`.
    ///
    /// The service types are the ones actually listed in the bundle. Declaring
    /// the key with an empty list is a real and common iOS mistake, so it is
    /// kept distinguishable from not declaring the key at all.
    #[must_use]
    pub fn with_bonjour_services(
        mut self,
        status: DeclarationStatus,
        service_types: impl IntoIterator<Item = BonjourServiceType>,
    ) -> Self {
        self.bonjour_services = status;
        self.service_types = service_types
            .into_iter()
            .take(MAX_DECLARED_SERVICE_TYPES)
            .collect();
        self
    }

    /// Records what the embedder knows about a restricted entitlement.
    ///
    /// [`EntitlementStatus::Granted`] here asserts that the shipped build is
    /// *signed* with the entitlement, which for
    /// [`HostAppEntitlement::MulticastNetworking`] means Apple granted it for
    /// this application identifier. A build made from source by someone who has
    /// not been granted it must report [`EntitlementStatus::NotGranted`].
    #[must_use]
    pub const fn with_entitlement(
        mut self,
        entitlement: HostAppEntitlement,
        status: EntitlementStatus,
    ) -> Self {
        match entitlement {
            HostAppEntitlement::MulticastNetworking => self.multicast_entitlement = status,
        }
        self
    }

    /// Returns the recorded status of a declaration.
    ///
    /// A user interface must render from this method, because it is the same
    /// record the gate decides from — see
    /// [`HostAppDeclarations::discovery_precondition`].
    #[must_use]
    pub const fn status(&self, declaration: HostAppDeclaration) -> DeclarationStatus {
        match declaration {
            HostAppDeclaration::LocalNetworkUsage => self.local_network_usage,
            HostAppDeclaration::BonjourServices => self.bonjour_services,
        }
    }

    /// Returns the recorded status of an entitlement.
    ///
    /// A user interface must render from this method, for the same reason as
    /// [`HostAppDeclarations::status`].
    #[must_use]
    pub const fn entitlement_status(&self, entitlement: HostAppEntitlement) -> EntitlementStatus {
        match entitlement {
            HostAppEntitlement::MulticastNetworking => self.multicast_entitlement,
        }
    }

    /// Returns the service types the embedder said the bundle lists.
    #[must_use]
    pub fn declared_service_types(&self) -> &[BonjourServiceType] {
        &self.service_types
    }

    /// Decides whether a specific discovery backend may browse its service type.
    ///
    /// The backend is named by **type**, not chosen by argument. Both the
    /// mechanism and the service type come from the backend's own descriptor,
    /// so a caller cannot ask for the weaker system-DNS-SD check and then start
    /// a raw-socket browser: the returned [`DiscoveryPermit`] is parameterised
    /// by `B`, and a permit for one backend will not type-check against
    /// another.
    ///
    /// This crate does not name the service type. It is read from
    /// [`LocalDiscoveryBackend::DNS_SD_SERVICE_TYPE`], which belongs to the
    /// discovery contract, and the `Info.plist` form is *derived* from it rather
    /// than written down a second time — a second copy is a thing that can
    /// drift with nothing able to notice.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryUnavailable`] naming the exact `Info.plist` key,
    /// service type or entitlement at fault. Callers must surface that text
    /// instead of reporting that no Gateway was found, because the two look
    /// identical from the outside. When the entitlement is the cause,
    /// [`DiscoveryUnavailable::awaits_apple_approval`] is `true`, because that
    /// is not a condition the person reading the message can fix.
    pub fn discovery_precondition<B: LocalDiscoveryBackend>(
        &self,
    ) -> Result<DiscoveryPermit<'_, B>, DiscoveryUnavailable> {
        let required = B::bonjour_service_type().map_err(|error| {
            DiscoveryUnavailable::BackendServiceTypeInvalid {
                service_type: B::DNS_SD_SERVICE_TYPE,
                error,
            }
        })?;
        let matched = self.declaration_precondition(&required)?;
        for entitlement in B::MECHANISM.required_entitlements() {
            match self.entitlement_status(*entitlement) {
                EntitlementStatus::Granted => {}
                EntitlementStatus::NotGranted => {
                    return Err(DiscoveryUnavailable::EntitlementNotGranted {
                        entitlement: *entitlement,
                        mechanism: B::MECHANISM,
                    });
                }
                EntitlementStatus::Unknown => {
                    return Err(DiscoveryUnavailable::EntitlementUndetermined {
                        entitlement: *entitlement,
                        mechanism: B::MECHANISM,
                    });
                }
            }
        }
        Ok(DiscoveryPermit {
            service_type: matched,
            backend: PhantomData,
        })
    }

    /// Checks the declarations every backend needs, returning the matched entry.
    fn declaration_precondition(
        &self,
        required: &BonjourServiceType,
    ) -> Result<&BonjourServiceType, DiscoveryUnavailable> {
        for declaration in HostAppDeclaration::ALL {
            match self.status(declaration) {
                DeclarationStatus::Declared => {}
                DeclarationStatus::Absent => {
                    return Err(DiscoveryUnavailable::NotDeclared(declaration));
                }
                DeclarationStatus::Unknown => {
                    return Err(DiscoveryUnavailable::Undetermined(declaration));
                }
            }
        }
        if self.service_types.is_empty() {
            return Err(DiscoveryUnavailable::NoDeclaredServiceTypes);
        }
        self.service_types
            .iter()
            .find(|declared| *declared == required)
            .ok_or_else(|| DiscoveryUnavailable::ServiceTypeNotDeclared {
                requested: required.clone(),
            })
    }
}

/// A local-discovery backend, described at the type level.
///
/// This mirrors the backend contract agreed with the `claw-nodes` owner. It is
/// **not** yet present in that crate: as of PR #57 head `237b386e`,
/// `crates/claw-nodes/src/dns_sd.rs` exports `GATEWAY_SERVICE_TYPE` and
/// `MdnsBrowser` but no descriptor trait. This is therefore a deliberate
/// private mirror rather than a re-export, kept here so that iOS does not
/// create a cross-PR dependency, and shaped so that replacing it with the real
/// trait is mechanical.
///
/// Both associated items are `const`, so a caller cannot override them for a
/// backend it is about to construct. That is the whole point: the mechanism
/// describes how packets leave the process, which is what decides the platform
/// prerequisites, so it must travel with the backend rather than be chosen
/// alongside it.
///
/// The `Info.plist` form is derived by [`LocalDiscoveryBackend::bonjour_service_type`]
/// rather than declared separately, because two hand-written copies of the same
/// name can disagree and nothing would notice.
pub trait LocalDiscoveryBackend {
    /// How this backend puts packets on the network.
    const MECHANISM: DiscoveryMechanism;

    /// The fully qualified DNS-SD type this backend browses.
    ///
    /// This is the value the discovery crate uses on the wire, for example
    /// `_openclaw-gw._tcp.local.`. It is **not** the string that goes into
    /// `NSBonjourServices`.
    const DNS_SD_SERVICE_TYPE: &'static str;

    /// Derives the `NSBonjourServices` entry this backend requires.
    ///
    /// The plist carries the application-label form, so the mDNS domain is
    /// stripped. A type in some other domain will not narrow to
    /// [`BonjourServiceType`] and is reported rather than silently truncated.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceTypeError`] if the declared type has no representable
    /// `NSBonjourServices` form.
    fn bonjour_service_type() -> Result<BonjourServiceType, ServiceTypeError> {
        let trimmed = Self::DNS_SD_SERVICE_TYPE
            .strip_suffix('.')
            .unwrap_or(Self::DNS_SD_SERVICE_TYPE);
        let trimmed = trimmed.strip_suffix(".local").unwrap_or(trimmed);
        BonjourServiceType::parse(trimmed)
    }
}

/// The pure-Rust mDNS backend `claw-nodes` browses the Gateway with.
///
/// Uninhabited: it exists only as a type-level descriptor, and there is no
/// reason to hold a value of it.
///
/// `DNS_SD_SERVICE_TYPE` mirrors `claw_nodes::dns_sd::GATEWAY_SERVICE_TYPE`,
/// which is documented there as the frozen local Gateway service type. The
/// mirror exists because `claw-nodes` is not on `main` yet; it is deliberately
/// a copy of the *value* rather than a citation of a line, because the value is
/// the stable part — the constant has been read at three different heads of the
/// owning branch and moved line twice. Replacement with a direct dependency is
/// mechanical once that crate lands.
///
/// `MECHANISM` is [`DiscoveryMechanism::InProcessMulticast`] because that
/// browser is built on `mdns-sd`, which binds its own UDP multicast sockets in
/// this process.
///
/// Scope limit worth knowing: `claw-nodes` also exposes a zone-parameterised
/// browser over `_openclaw-gw._tcp.{zone}`. That form has no
/// `NSBonjourServices` representation derivable from a service type alone, so
/// [`HostAppDeclarations::discovery_precondition`] refuses it rather than
/// truncating it to something that looks right. This descriptor covers the
/// `.local.` browser only.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GatewayMdnsBackend {}

impl LocalDiscoveryBackend for GatewayMdnsBackend {
    const MECHANISM: DiscoveryMechanism = DiscoveryMechanism::InProcessMulticast;
    const DNS_SD_SERVICE_TYPE: &'static str = "_openclaw-gw._tcp.local.";
}

/// Proof that the gate was consulted and passed, **for one backend**.
///
/// Discovery code takes a permit rather than a bare service type, so the check
/// cannot be skipped by a caller that forgot it exists. The permit is
/// parameterised by the backend it was issued for, rather than carrying a mode
/// field, because a field would leave "this is the wrong kind of permission" to
/// a reviewer to notice, whereas a type parameter makes it unsayable.
///
/// The field is private and there is no public constructor, so
/// [`HostAppDeclarations::discovery_precondition`] is the only source.
pub struct DiscoveryPermit<'a, B: LocalDiscoveryBackend> {
    service_type: &'a BonjourServiceType,
    backend: PhantomData<fn() -> B>,
}

impl<B: LocalDiscoveryBackend> DiscoveryPermit<'_, B> {
    /// Returns the exact declared entry that matched the backend's requirement.
    #[must_use]
    pub const fn service_type(&self) -> &BonjourServiceType {
        self.service_type
    }

    /// Returns the mechanism this permit was checked against.
    #[must_use]
    pub const fn mechanism(&self) -> DiscoveryMechanism {
        B::MECHANISM
    }
}

impl<B: LocalDiscoveryBackend> Clone for DiscoveryPermit<'_, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<B: LocalDiscoveryBackend> Copy for DiscoveryPermit<'_, B> {}

impl<B: LocalDiscoveryBackend> fmt::Debug for DiscoveryPermit<'_, B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveryPermit")
            .field("mechanism", &B::MECHANISM)
            .field("service_type", &self.service_type)
            .finish()
    }
}

impl<B: LocalDiscoveryBackend> PartialEq for DiscoveryPermit<'_, B> {
    fn eq(&self, other: &Self) -> bool {
        self.service_type == other.service_type
    }
}

impl<B: LocalDiscoveryBackend> Eq for DiscoveryPermit<'_, B> {}

/// Why local-network discovery must not be attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryUnavailable {
    /// The embedder confirmed the declaration is missing from the bundle.
    NotDeclared(HostAppDeclaration),
    /// Nobody established whether the declaration is present.
    Undetermined(HostAppDeclaration),
    /// The embedder confirmed the build is not signed with the entitlement.
    EntitlementNotGranted {
        /// The entitlement the mechanism needs.
        entitlement: HostAppEntitlement,
        /// The mechanism that needs it.
        mechanism: DiscoveryMechanism,
    },
    /// Nobody established whether the build carries the entitlement.
    EntitlementUndetermined {
        /// The entitlement the mechanism needs.
        entitlement: HostAppEntitlement,
        /// The mechanism that needs it.
        mechanism: DiscoveryMechanism,
    },
    /// `NSBonjourServices` is present but lists nothing to browse.
    NoDeclaredServiceTypes,
    /// `NSBonjourServices` lists entries, but not the one asked for.
    ///
    /// iOS browses only the declared types, so asking for an undeclared one
    /// returns nothing rather than failing. A bundle declaring some *other*
    /// service is the case most likely to be mistaken for an empty network,
    /// because the key is present and looks correct.
    ServiceTypeNotDeclared {
        /// The service type the caller asked to browse.
        requested: BonjourServiceType,
    },
    /// The backend's DNS-SD type has no representable `NSBonjourServices` form.
    ///
    /// This is a defect in the backend descriptor rather than in the host
    /// bundle, so it names the offending constant. The stored value is a
    /// compile-time `const` from a [`LocalDiscoveryBackend`] impl, which cannot
    /// be produced from runtime data and therefore cannot carry a credential.
    BackendServiceTypeInvalid {
        /// The backend's declared `DNS_SD_SERVICE_TYPE`.
        service_type: &'static str,
        /// Why no `NSBonjourServices` entry could be derived from it.
        error: ServiceTypeError,
    },
}

impl DiscoveryUnavailable {
    /// Returns whether resolving this needs a decision by Apple.
    ///
    /// This separates the conditions a developer can fix from the one that
    /// waits on a third party, which are worth telling a user apart.
    #[must_use]
    pub const fn awaits_apple_approval(&self) -> bool {
        match self {
            Self::EntitlementNotGranted { entitlement, .. }
            | Self::EntitlementUndetermined { entitlement, .. } => {
                entitlement.requires_apple_approval()
            }
            Self::NotDeclared(_)
            | Self::Undetermined(_)
            | Self::NoDeclaredServiceTypes
            | Self::ServiceTypeNotDeclared { .. }
            | Self::BackendServiceTypeInvalid { .. } => false,
        }
    }
}

impl Display for DiscoveryUnavailable {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotDeclared(declaration) => write!(
                formatter,
                "local network discovery is unavailable: this build does not declare {}, so {}",
                declaration.plist_key(),
                declaration.consequence_when_absent()
            ),
            Self::Undetermined(declaration) => write!(
                formatter,
                "local network discovery was not attempted: nothing confirmed that this build \
                 declares {}, and an unverified declaration is treated as absent",
                declaration.plist_key()
            ),
            Self::EntitlementNotGranted {
                entitlement,
                mechanism,
            } => write!(
                formatter,
                "local network discovery is unavailable: {mechanism} discovery requires the {} \
                 entitlement and this build is not signed with it, so {}. Apple grants this \
                 entitlement case by case on written request at {}; it is not a setting that can \
                 be switched on locally, so a build made from source does not have it.",
                entitlement.key(),
                entitlement.consequence_when_absent(),
                entitlement.request_url()
            ),
            Self::EntitlementUndetermined {
                entitlement,
                mechanism,
            } => write!(
                formatter,
                "local network discovery was not attempted: {mechanism} discovery requires the {} \
                 entitlement and nothing confirmed that this build carries it. An unverified \
                 entitlement is treated as absent, because when it is absent {}.",
                entitlement.key(),
                entitlement.consequence_when_absent()
            ),
            Self::NoDeclaredServiceTypes => formatter.write_str(
                "local network discovery is unavailable: NSBonjourServices is present but lists \
                 no service types, so iOS will browse nothing",
            ),
            Self::ServiceTypeNotDeclared { requested } => write!(
                formatter,
                "local network discovery is unavailable: NSBonjourServices does not list \
                 {requested}, and iOS browses only the service types a bundle declares, so a \
                 browse for it returns nothing rather than failing"
            ),
            Self::BackendServiceTypeInvalid {
                service_type,
                error,
            } => write!(
                formatter,
                "local network discovery is unavailable: the discovery backend browses \
                 {service_type:?}, which has no NSBonjourServices form ({error}), so no bundle \
                 declaration could authorise it"
            ),
        }
    }
}

impl Error for DiscoveryUnavailable {}

/// The runtime Local Network privilege, as iOS decides it per install.
///
/// This is **not** a gate and must never be used as one. Per Apple's TN3179 the
/// privilege is tri-state, there is no API to query it, and the consent alert is
/// raised *by* the first local-network operation — so refusing to make that
/// operation is refusing to produce the prompt that would grant it.
///
/// It is instead an input to [`diagnose_empty_result`], consulted **after** a
/// browse comes back empty, so that "nobody is there" and "we were not allowed
/// to look" are distinguishable to whoever is reading the screen.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LocalNetworkPrivacy {
    /// The user has not been asked yet, or was asked and did not answer.
    #[default]
    Undetermined,
    /// The user refused, or refused earlier and has not changed it.
    Denied,
    /// The user allowed it.
    Granted,
}

/// Whether the host app was in the foreground when discovery ran.
///
/// This matters only in combination with [`LocalNetworkPrivacy::Undetermined`],
/// where iOS declines the operation without showing an alert and without
/// recording a decision.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AppRunState {
    /// The app is frontmost and can present the consent alert.
    #[default]
    Foreground,
    /// The app is backgrounded or suspended.
    Background,
}

/// Why a discovery browse returned nothing.
///
/// An empty peer list is the one result that must never be reported bare on
/// this platform, because every unavailable condition here produces exactly the
/// same empty list as a quiet network.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EmptyResultDiagnosis {
    /// The privilege is granted and the app was frontmost: nothing was found.
    ///
    /// This is the only case where an empty list may be reported as an empty
    /// network, and even then only if the preconditions were also met.
    NoResponders,
    /// The consent alert is expected but has not been answered yet.
    AwaitingConsentPrompt,
    /// Undetermined **and** backgrounded: denied silently, nothing recorded.
    ///
    /// TN3179 states the operation is denied, no alert is shown, and the
    /// decision is not recorded — so a retry in the foreground is the correct
    /// next step and the user has not in fact refused anything.
    SilentlyDeniedInBackground,
    /// The user refused the Local Network privilege.
    DeniedByUser,
}

impl EmptyResultDiagnosis {
    /// Returns whether the empty list may be reported as an empty network.
    #[must_use]
    pub const fn means_nothing_was_there(self) -> bool {
        matches!(self, Self::NoResponders)
    }

    /// Returns what to tell the person looking at the empty list.
    #[must_use]
    pub const fn explanation(self) -> &'static str {
        match self {
            Self::NoResponders => {
                "no Gateway answered on this network. The local network privilege is granted, so \
                 this result means nothing responded rather than that discovery was blocked."
            }
            Self::AwaitingConsentPrompt => {
                "discovery has not been permitted yet. iOS raises the local network consent alert \
                 from the first browse rather than in advance, so this empty result is expected \
                 until that alert is answered. It is not evidence that the network is empty."
            }
            Self::SilentlyDeniedInBackground => {
                "discovery was denied without asking. iOS refuses local network access while the \
                 app is backgrounded and the privilege is still undetermined, and it neither \
                 shows an alert nor records a decision, so this empty result says nothing about \
                 the network. Retry with the app in the foreground."
            }
            Self::DeniedByUser => {
                "discovery is not permitted. The local network privilege was refused, so no \
                 responses can arrive; this empty result says nothing about the network. It is \
                 changed in Settings under Privacy & Security > Local Network."
            }
        }
    }
}

impl Display for EmptyResultDiagnosis {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.explanation())
    }
}

/// Explains an empty discovery result from the runtime privilege state.
///
/// Call this **after** a browse returns nothing, never before starting one.
/// Gating on the privilege would suppress the very operation that raises the
/// consent alert.
#[must_use]
pub const fn diagnose_empty_result(
    privacy: LocalNetworkPrivacy,
    run_state: AppRunState,
) -> EmptyResultDiagnosis {
    match privacy {
        LocalNetworkPrivacy::Granted => EmptyResultDiagnosis::NoResponders,
        LocalNetworkPrivacy::Denied => EmptyResultDiagnosis::DeniedByUser,
        LocalNetworkPrivacy::Undetermined => match run_state {
            AppRunState::Foreground => EmptyResultDiagnosis::AwaitingConsentPrompt,
            AppRunState::Background => EmptyResultDiagnosis::SilentlyDeniedInBackground,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppRunState, BonjourServiceType, DeclarationStatus, DiscoveryMechanism,
        DiscoveryUnavailable, EmptyResultDiagnosis, EntitlementStatus, GatewayMdnsBackend,
        HostAppDeclaration, HostAppDeclarations, HostAppEntitlement, LocalDiscoveryBackend,
        LocalNetworkPrivacy, ServiceTypeError, diagnose_empty_result,
    };

    /// Stands in for the `claw-nodes` browser: raw sockets, test service type.
    enum TestMdnsBackend {}

    impl LocalDiscoveryBackend for TestMdnsBackend {
        const MECHANISM: DiscoveryMechanism = DiscoveryMechanism::InProcessMulticast;
        const DNS_SD_SERVICE_TYPE: &'static str = "_gtaclaw._tcp.local.";
    }

    /// Stands in for a future system-DNS-SD adapter browsing the same type.
    enum TestSystemBackend {}

    impl LocalDiscoveryBackend for TestSystemBackend {
        const MECHANISM: DiscoveryMechanism = DiscoveryMechanism::SystemDnsSd;
        const DNS_SD_SERVICE_TYPE: &'static str = "_gtaclaw._tcp.local.";
    }

    /// A backend whose browsed type has no `NSBonjourServices` form.
    enum TestUnrepresentableBackend {}

    impl LocalDiscoveryBackend for TestUnrepresentableBackend {
        const MECHANISM: DiscoveryMechanism = DiscoveryMechanism::SystemDnsSd;
        const DNS_SD_SERVICE_TYPE: &'static str = "_gtaclaw._tcp.example.com.";
    }

    fn service_type(text: &str) -> BonjourServiceType {
        BonjourServiceType::parse(text)
            .unwrap_or_else(|error| panic!("{text:?} should parse, but failed with {error}"))
    }

    fn gateway_service() -> BonjourServiceType {
        service_type("_gtaclaw._tcp")
    }

    fn fully_declared() -> HostAppDeclarations {
        HostAppDeclarations::new()
            .with_local_network_usage(DeclarationStatus::Declared)
            .with_bonjour_services(DeclarationStatus::Declared, [gateway_service()])
    }

    #[test]
    fn an_undeclared_bundle_blocks_discovery_instead_of_returning_nothing() {
        let declarations = HostAppDeclarations::new();

        let error = declarations
            .discovery_precondition::<TestSystemBackend>()
            .expect_err("an undeclared bundle must not permit discovery");

        assert_eq!(
            error,
            DiscoveryUnavailable::Undetermined(HostAppDeclaration::LocalNetworkUsage),
            "unknown must be reported as undetermined, not silently permitted"
        );
        assert!(
            error.to_string().contains("NSLocalNetworkUsageDescription"),
            "the reason must name the exact plist key, but read {error}"
        );
    }

    #[test]
    fn the_default_status_of_every_declaration_is_unknown() {
        let declarations = HostAppDeclarations::new();

        for declaration in HostAppDeclaration::ALL {
            let status = declarations.status(declaration);
            assert_eq!(
                status,
                DeclarationStatus::Unknown,
                "{declaration} defaulted to {status} instead of unknown"
            );
            assert!(
                !status.is_declared(),
                "{declaration} reported itself declared while its status was {status}"
            );
        }
    }

    #[test]
    fn a_confirmed_absent_declaration_names_the_key_and_the_consequence() {
        let declarations = fully_declared().with_local_network_usage(DeclarationStatus::Absent);

        let error = declarations
            .discovery_precondition::<TestSystemBackend>()
            .expect_err("an absent declaration must not permit discovery");

        assert_eq!(
            error,
            DiscoveryUnavailable::NotDeclared(HostAppDeclaration::LocalNetworkUsage),
            "an absent key must be reported as not declared"
        );
        let text = error.to_string();
        assert!(
            text.contains("NSLocalNetworkUsageDescription") && text.contains("never prompts"),
            "the reason must explain what iOS does, but read {text}"
        );
    }

    #[test]
    fn declaring_bonjour_services_with_an_empty_list_still_blocks_discovery() {
        let declarations = HostAppDeclarations::new()
            .with_local_network_usage(DeclarationStatus::Declared)
            .with_bonjour_services(DeclarationStatus::Declared, []);

        let error = declarations
            .discovery_precondition::<TestSystemBackend>()
            .expect_err("an empty service type list must not permit discovery");

        assert_eq!(
            error,
            DiscoveryUnavailable::NoDeclaredServiceTypes,
            "an empty NSBonjourServices list must be its own reported condition"
        );
    }

    #[test]
    fn declaring_only_some_other_service_type_blocks_the_one_that_was_asked_for() {
        let declarations = HostAppDeclarations::new()
            .with_local_network_usage(DeclarationStatus::Declared)
            .with_bonjour_services(DeclarationStatus::Declared, [service_type("_printer._tcp")]);
        let wanted = gateway_service();

        let error = declarations
            .discovery_precondition::<TestSystemBackend>()
            .expect_err("a non-empty list of the wrong types must not permit discovery");

        assert_eq!(
            error,
            DiscoveryUnavailable::ServiceTypeNotDeclared {
                requested: wanted.clone(),
            },
            "a declared-but-different service list must name the type that was requested"
        );
        let text = error.to_string();
        assert!(
            text.contains(wanted.as_str()),
            "the reason must name the requested service type {wanted}, but read {text}"
        );
    }

    #[test]
    fn a_witness_carries_the_exact_declared_entry_that_matched() {
        let declarations = HostAppDeclarations::new()
            .with_local_network_usage(DeclarationStatus::Declared)
            .with_bonjour_services(
                DeclarationStatus::Declared,
                [service_type("_printer._tcp"), gateway_service()],
            );

        let permitted = declarations
            .discovery_precondition::<TestSystemBackend>()
            .expect("a bundle declaring the requested type must permit discovery");

        assert_eq!(
            permitted.service_type().as_str(),
            "_gtaclaw._tcp",
            "the witness must carry the matched entry, not the whole declared list"
        );
    }

    #[test]
    fn a_plist_complete_bundle_still_blocks_raw_multicast_without_the_entitlement() {
        let declarations = fully_declared();

        let permitted = declarations.discovery_precondition::<TestSystemBackend>();
        assert!(
            permitted.is_ok(),
            "the system DNS-SD path needs no entitlement, but was refused with {:?}",
            permitted.err()
        );

        let error = declarations
            .discovery_precondition::<TestMdnsBackend>()
            .expect_err("a raw-socket mDNS backend must not run without the entitlement");

        assert_eq!(
            error,
            DiscoveryUnavailable::EntitlementUndetermined {
                entitlement: HostAppEntitlement::MulticastNetworking,
                mechanism: DiscoveryMechanism::InProcessMulticast,
            },
            "an unverified entitlement must be reported, not assumed granted"
        );
    }

    #[test]
    fn a_missing_multicast_entitlement_explains_that_apple_must_grant_it() {
        let declarations = fully_declared().with_entitlement(
            HostAppEntitlement::MulticastNetworking,
            EntitlementStatus::NotGranted,
        );

        let error = declarations
            .discovery_precondition::<TestMdnsBackend>()
            .expect_err("an ungranted entitlement must not permit raw multicast");

        let text = error.to_string();
        assert!(
            text.contains("com.apple.developer.networking.multicast"),
            "the reason must name the exact entitlement key, but read {text}"
        );
        assert!(
            text.contains("report success"),
            "the reason must state that the failure is silent rather than an error, but read \
             {text}"
        );
        assert!(
            text.contains("https://developer.apple.com/contact/request/networking-multicast"),
            "the reason must say where the entitlement is requested, but read {text}"
        );
        assert!(
            error.awaits_apple_approval(),
            "an entitlement Apple grants case by case must be distinguishable from a condition \
             a developer can fix, but {error:?} reported otherwise"
        );
    }

    #[test]
    fn not_granted_and_unknown_are_reported_as_different_conditions() {
        let not_granted = fully_declared()
            .with_entitlement(
                HostAppEntitlement::MulticastNetworking,
                EntitlementStatus::NotGranted,
            )
            .discovery_precondition::<TestMdnsBackend>()
            .expect_err("NotGranted must block");
        let unknown = fully_declared()
            .discovery_precondition::<TestMdnsBackend>()
            .expect_err("Unknown must block");

        assert_ne!(
            not_granted, unknown,
            "a refused or pending grant must be told apart from an unverified one, but both \
             reported {not_granted:?}"
        );
        assert!(
            not_granted.awaits_apple_approval() && unknown.awaits_apple_approval(),
            "both must be attributed to Apple rather than to the developer, but got \
             {not_granted:?} and {unknown:?}"
        );
    }

    #[test]
    fn a_granted_entitlement_permits_raw_multicast() {
        let declarations = fully_declared().with_entitlement(
            HostAppEntitlement::MulticastNetworking,
            EntitlementStatus::Granted,
        );

        let permitted = declarations
            .discovery_precondition::<TestMdnsBackend>()
            .expect("a granted entitlement plus complete declarations must permit discovery");

        assert_eq!(
            permitted.service_type().as_str(),
            "_gtaclaw._tcp",
            "the raw-multicast witness must carry the matched entry"
        );
    }

    #[test]
    fn the_default_status_of_every_entitlement_is_unknown() {
        let declarations = HostAppDeclarations::new();

        for entitlement in HostAppEntitlement::ALL {
            let status = declarations.entitlement_status(entitlement);
            assert_eq!(
                status,
                EntitlementStatus::Unknown,
                "{entitlement} defaulted to {status} instead of unknown"
            );
            assert!(
                !status.is_granted(),
                "{entitlement} reported itself granted while its status was {status}"
            );
        }
    }

    #[test]
    fn only_the_in_process_mechanism_requires_an_entitlement() {
        for mechanism in DiscoveryMechanism::ALL {
            let required = mechanism.required_entitlements();
            match mechanism {
                DiscoveryMechanism::SystemDnsSd => assert!(
                    required.is_empty(),
                    "{mechanism} must need no entitlement per Apple TN3179, but required \
                     {required:?}"
                ),
                DiscoveryMechanism::InProcessMulticast => assert_eq!(
                    required,
                    [HostAppEntitlement::MulticastNetworking],
                    "{mechanism} sends and receives UDP multicast directly, so it must require \
                     the multicast entitlement, but required {required:?}"
                ),
            }
        }
    }

    #[test]
    fn the_mirrored_backend_carries_the_frozen_gateway_service_type() {
        assert_eq!(
            GatewayMdnsBackend::DNS_SD_SERVICE_TYPE,
            "_openclaw-gw._tcp.local.",
            "the mirror must match claw_nodes::dns_sd::GATEWAY_SERVICE_TYPE"
        );

        let derived = GatewayMdnsBackend::bonjour_service_type()
            .expect("the frozen gateway type must have an NSBonjourServices form");

        assert_eq!(
            derived.as_str(),
            "_openclaw-gw._tcp",
            "the plist entry is the application-label form, without the mDNS domain"
        );
        assert_eq!(
            format!("{derived}.local."),
            GatewayMdnsBackend::DNS_SD_SERVICE_TYPE,
            "the plist form must be the browsed form minus the domain; if this fails the two \
             names have drifted and the plist entry would silently not match"
        );
    }

    #[test]
    fn the_gateway_backend_binds_its_own_sockets_so_it_needs_the_entitlement() {
        assert_eq!(
            GatewayMdnsBackend::MECHANISM,
            DiscoveryMechanism::InProcessMulticast,
            "claw-nodes browses with mdns-sd, which binds its own multicast sockets"
        );

        let gateway = GatewayMdnsBackend::bonjour_service_type().expect("must derive");
        let declarations = HostAppDeclarations::new()
            .with_local_network_usage(DeclarationStatus::Declared)
            .with_bonjour_services(DeclarationStatus::Declared, [gateway]);

        let error = declarations
            .discovery_precondition::<GatewayMdnsBackend>()
            .expect_err("declaring the plist keys alone must not authorise a raw-socket browser");

        assert_eq!(
            error,
            DiscoveryUnavailable::EntitlementUndetermined {
                entitlement: HostAppEntitlement::MulticastNetworking,
                mechanism: DiscoveryMechanism::InProcessMulticast,
            },
            "the mechanism must be read from the backend descriptor, not chosen by the caller"
        );
    }

    #[test]
    fn declaring_the_test_type_does_not_authorise_the_real_gateway_backend() {
        let declarations = fully_declared().with_entitlement(
            HostAppEntitlement::MulticastNetworking,
            EntitlementStatus::Granted,
        );

        let permitted = declarations.discovery_precondition::<TestMdnsBackend>();
        assert!(
            permitted.is_ok(),
            "the declared test type must be permitted, but was refused with {:?}",
            permitted.err()
        );

        let error = declarations
            .discovery_precondition::<GatewayMdnsBackend>()
            .expect_err("a bundle declaring only _gtaclaw._tcp must not permit _openclaw-gw._tcp");

        let requested = GatewayMdnsBackend::bonjour_service_type().expect("must derive");
        assert_eq!(
            error,
            DiscoveryUnavailable::ServiceTypeNotDeclared { requested },
            "the gate must compare against the backend's own type, not any declared type"
        );
    }

    #[test]
    fn a_backend_type_with_no_plist_form_is_reported_rather_than_truncated() {
        let error = fully_declared()
            .discovery_precondition::<TestUnrepresentableBackend>()
            .expect_err("a type outside the mDNS domain has no NSBonjourServices form");

        assert_eq!(
            error,
            DiscoveryUnavailable::BackendServiceTypeInvalid {
                service_type: "_gtaclaw._tcp.example.com.",
                error: ServiceTypeError::MissingTransportSuffix,
            },
            "an underivable plist entry must be reported against the backend constant"
        );
        assert!(
            error.to_string().contains("_gtaclaw._tcp.example.com."),
            "the reason must name the offending constant, but read {error}"
        );
    }

    #[test]
    fn a_permit_names_the_mechanism_it_was_checked_against() {
        let declarations = fully_declared();
        let permitted = declarations
            .discovery_precondition::<TestSystemBackend>()
            .expect("the system path needs no entitlement");

        assert_eq!(
            permitted.mechanism(),
            DiscoveryMechanism::SystemDnsSd,
            "a permit must report the mechanism it was issued for, but read {permitted:?}"
        );
        assert!(
            format!("{permitted:?}").contains("_gtaclaw._tcp"),
            "the permit debug must show the matched entry, but read {permitted:?}"
        );
    }

    #[test]
    fn an_empty_result_is_only_an_empty_network_when_the_privilege_was_granted() {
        for run_state in [AppRunState::Foreground, AppRunState::Background] {
            for privacy in [
                LocalNetworkPrivacy::Undetermined,
                LocalNetworkPrivacy::Denied,
                LocalNetworkPrivacy::Granted,
            ] {
                let diagnosis = diagnose_empty_result(privacy, run_state);
                let expected = privacy == LocalNetworkPrivacy::Granted;
                assert_eq!(
                    diagnosis.means_nothing_was_there(),
                    expected,
                    "privacy {privacy:?} in {run_state:?} produced {diagnosis:?}, which reports \
                     an empty network as {}",
                    diagnosis.means_nothing_was_there()
                );
            }
        }
    }

    #[test]
    fn an_undetermined_privilege_in_the_background_is_a_distinct_silent_denial() {
        let foreground =
            diagnose_empty_result(LocalNetworkPrivacy::Undetermined, AppRunState::Foreground);
        let background =
            diagnose_empty_result(LocalNetworkPrivacy::Undetermined, AppRunState::Background);

        assert_eq!(
            foreground,
            EmptyResultDiagnosis::AwaitingConsentPrompt,
            "a frontmost app raises the consent alert from the browse itself, but reported \
             {foreground:?}"
        );
        assert_eq!(
            background,
            EmptyResultDiagnosis::SilentlyDeniedInBackground,
            "per TN3179 a backgrounded app is denied with no alert and no recorded decision, but \
             reported {background:?}"
        );
        assert!(
            background.explanation().contains("foreground"),
            "the background denial must say what to do next, but read {background}"
        );
    }

    #[test]
    fn the_default_privacy_state_does_not_claim_an_empty_network() {
        let diagnosis =
            diagnose_empty_result(LocalNetworkPrivacy::default(), AppRunState::default());

        assert!(
            !diagnosis.means_nothing_was_there(),
            "the default state must not license reporting zero peers, but produced {diagnosis:?}"
        );
    }

    #[test]
    fn a_fully_qualified_service_type_is_refused_so_it_cannot_reach_a_plist_entry() {
        let error = BonjourServiceType::parse("_gtaclaw._tcp.local.")
            .expect_err("the fully qualified browse form must not be accepted as a plist entry");

        assert_eq!(
            error,
            ServiceTypeError::MissingTransportSuffix,
            "NSBonjourServices carries the application-label form, so the .local. form must be \
             refused, but parsing reported {error}"
        );
    }

    #[test]
    fn a_subtype_form_is_refused_until_a_frozen_descriptor_requires_one() {
        let error = BonjourServiceType::parse("_gtaclaw._sub._tcp")
            .expect_err("no frozen descriptor uses a subtype, so the form must be refused");

        assert_eq!(
            error,
            ServiceTypeError::DisallowedCharacter { character: '.' },
            "the subtype form must be refused by the grammar, but parsing reported {error}"
        );
    }

    #[test]
    fn a_service_type_cannot_hold_credential_shaped_text() {
        let candidates = [
            "https://gateway.example/token",
            "user:secret@host",
            "_gtaclaw._tcp.eyJhbGciOiJIUzI1NiJ9",
            "_averyverylongservicename._tcp",
        ];

        for candidate in candidates {
            let outcome = BonjourServiceType::parse(candidate);
            assert!(
                outcome.is_err(),
                "{candidate:?} was accepted as a service type and parsed to {outcome:?}"
            );
        }
    }

    #[test]
    fn service_type_grammar_is_enforced_character_by_character() {
        assert_eq!(BonjourServiceType::parse(""), Err(ServiceTypeError::Empty));
        assert_eq!(
            BonjourServiceType::parse("_gtaclaw._sctp"),
            Err(ServiceTypeError::MissingTransportSuffix)
        );
        assert_eq!(
            BonjourServiceType::parse("gtaclaw._tcp"),
            Err(ServiceTypeError::MissingLeadingUnderscore)
        );
        assert_eq!(
            BonjourServiceType::parse("_._tcp"),
            Err(ServiceTypeError::EmptyName)
        );
        assert_eq!(
            BonjourServiceType::parse("_gta claw._tcp"),
            Err(ServiceTypeError::DisallowedCharacter { character: ' ' })
        );
        assert_eq!(
            BonjourServiceType::parse("_-gtaclaw._tcp"),
            Err(ServiceTypeError::EdgeHyphen)
        );
        assert_eq!(
            BonjourServiceType::parse("_1234._tcp"),
            Err(ServiceTypeError::NoLetter)
        );
        assert_eq!(
            BonjourServiceType::parse("_gtaclaw._udp")
                .as_ref()
                .map(BonjourServiceType::as_str),
            Ok("_gtaclaw._udp")
        );
    }
}
