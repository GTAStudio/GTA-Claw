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
//! implemented, which is why there are two gates returning two **different
//! witness types**:
//!
//! | Backend | Gate | Requires |
//! | --- | --- | --- |
//! | system DNS-SD | [`HostAppDeclarations::system_dns_sd_precondition`] | both plist keys, and the requested service type among the declared entries |
//! | in-process mDNS | [`HostAppDeclarations::raw_multicast_precondition`] | the above, **and** a confirmed multicast entitlement |
//!
//! Per TN3179's own tables, registering, browsing and resolving a **specific,
//! declared** Bonjour service type through the system's DNS-SD APIs does not
//! require the entitlement — the system daemon performs the multicast outside
//! the application's process. Only "working with arbitrary Bonjour service
//! types" and "browsing for all advertised service types" do. An in-process
//! mDNS implementation that binds its own multicast sockets is squarely the
//! entitlement-requiring case, whatever service types it browses.
//!
//! The two witnesses are separate types rather than one type carrying a mode
//! field so that a raw-socket backend is *unable* to accept the weaker
//! permission. A runtime field would leave that to a reviewer to notice.
//!
//! # This crate does not own the service type
//!
//! Both gates take the required [`BonjourServiceType`] as an argument. The
//! Gateway's DNS-SD service type belongs to the discovery contract and is
//! owned by the discovery backend, not by an iOS application crate. Declaring
//! it here would create a second copy that can drift from the first silently,
//! and this crate would have no way to notice.
//!
//! Note also that the plist entry and the browsed type are not the same
//! string: `NSBonjourServices` carries the application-label form such as
//! `_example._tcp`, while the fully qualified `_example._tcp.local.` belongs
//! inside the discovery implementation.
//!
//! # Two conditions this module deliberately does not gate
//!
//! *The runtime Local Network privilege.* TN3179 gives it three states —
//! undetermined, allowed, denied — and the alert that resolves it is raised
//! **by** the first local-network operation. Gating on it would block the very
//! call that produces the prompt, so it is not modelled as a precondition.
//! It remains a distinct silent-failure mode and a caller that sees an empty
//! result after passing every check here should report it as a possible denial
//! rather than as an absence of peers.
//!
//! *The simulator.* TN3179 states plainly that the simulator does not support
//! local network privacy and that this behaviour must be tested on a real
//! device. No simulator run, and therefore no CI job that this project could
//! plausibly build, can validate anything in this module.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

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
/// Each variant has its own gate returning its own witness type —
/// [`HostAppDeclarations::system_dns_sd_precondition`] and
/// [`HostAppDeclarations::raw_multicast_precondition`]. This enum is the
/// descriptor those gates report against; it is not itself the gate, because a
/// mode passed as an argument can be passed wrongly whereas two types cannot be
/// confused by a caller.
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
    /// record the two gates decide from — see
    /// [`HostAppDeclarations::system_dns_sd_precondition`].
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

    /// Decides whether the **system DNS-SD** backend may browse a service type.
    ///
    /// This is the weaker of the two gates. Per Apple's TN3179 the system
    /// DNS-SD path needs the two `Info.plist` keys and no entitlement, because
    /// the multicast happens in the platform daemon rather than in this
    /// process. It must not be used to authorise a backend that binds its own
    /// sockets — see [`HostAppDeclarations::raw_multicast_precondition`], which
    /// returns a different type for exactly that reason.
    ///
    /// `required` is supplied by the caller rather than held here, because the
    /// service type belongs to the discovery contract and this crate is not its
    /// owner. Hardcoding it here would let the two drift apart silently.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryUnavailable`] naming the exact `Info.plist` key or
    /// the service type at fault. Callers must surface that text instead of
    /// reporting that no Gateway was found, because the two look identical
    /// from the outside.
    pub fn system_dns_sd_precondition<'a>(
        &'a self,
        required: &BonjourServiceType,
    ) -> Result<SystemDnsSdDiscoveryPermitted<'a>, DiscoveryUnavailable> {
        let matched = self.declaration_precondition(required)?;
        Ok(SystemDnsSdDiscoveryPermitted {
            service_type: matched,
        })
    }

    /// Decides whether a **raw-multicast** backend may browse a service type.
    ///
    /// This is the stricter gate, and the one that must be consulted before
    /// starting any in-process mDNS implementation — every pure-Rust mDNS crate
    /// is one. It requires both `Info.plist` keys, the requested service type
    /// among the declared entries, **and** a confirmed
    /// `com.apple.developer.networking.multicast` grant in the shipped signing
    /// profile.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryUnavailable`] naming the exact key, service type or
    /// entitlement at fault. When the entitlement is the cause,
    /// [`DiscoveryUnavailable::awaits_apple_approval`] is `true`, because that
    /// is not a condition the person reading the message can fix.
    pub fn raw_multicast_precondition<'a>(
        &'a self,
        required: &BonjourServiceType,
    ) -> Result<RawMulticastDiscoveryPermitted<'a>, DiscoveryUnavailable> {
        let matched = self.declaration_precondition(required)?;
        for entitlement in DiscoveryMechanism::InProcessMulticast.required_entitlements() {
            match self.entitlement_status(*entitlement) {
                EntitlementStatus::Granted => {}
                EntitlementStatus::NotGranted => {
                    return Err(DiscoveryUnavailable::EntitlementNotGranted {
                        entitlement: *entitlement,
                        mechanism: DiscoveryMechanism::InProcessMulticast,
                    });
                }
                EntitlementStatus::Unknown => {
                    return Err(DiscoveryUnavailable::EntitlementUndetermined {
                        entitlement: *entitlement,
                        mechanism: DiscoveryMechanism::InProcessMulticast,
                    });
                }
            }
        }
        Ok(RawMulticastDiscoveryPermitted {
            service_type: matched,
        })
    }

    /// Checks the declarations both backends need, returning the matched entry.
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

/// Proof that the **system DNS-SD** gate was consulted and passed.
///
/// Discovery code takes a witness rather than a bare service type, so the check
/// cannot be skipped by a caller that forgot it exists. This witness and
/// [`RawMulticastDiscoveryPermitted`] are deliberately **different types**
/// rather than one type carrying a mode field: a backend that binds its own
/// multicast sockets must be unable to accept this one, and a runtime field
/// would leave that to a reviewer to notice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemDnsSdDiscoveryPermitted<'a> {
    service_type: &'a BonjourServiceType,
}

impl SystemDnsSdDiscoveryPermitted<'_> {
    /// Returns the exact declared entry that matched the request.
    #[must_use]
    pub const fn service_type(&self) -> &BonjourServiceType {
        self.service_type
    }
}

/// Proof that the **raw-multicast** gate was consulted and passed.
///
/// Obtaining this requires both `Info.plist` keys, the requested service type
/// among the declared entries, and a confirmed multicast entitlement. It is the
/// witness an in-process mDNS browser must be handed before it starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawMulticastDiscoveryPermitted<'a> {
    service_type: &'a BonjourServiceType,
}

impl RawMulticastDiscoveryPermitted<'_> {
    /// Returns the exact declared entry that matched the request.
    #[must_use]
    pub const fn service_type(&self) -> &BonjourServiceType {
        self.service_type
    }
}

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
            | Self::ServiceTypeNotDeclared { .. } => false,
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
        }
    }
}

impl Error for DiscoveryUnavailable {}

#[cfg(test)]
mod tests {
    use super::{
        BonjourServiceType, DeclarationStatus, DiscoveryMechanism, DiscoveryUnavailable,
        EntitlementStatus, HostAppDeclaration, HostAppDeclarations, HostAppEntitlement,
        ServiceTypeError,
    };

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
            .system_dns_sd_precondition(&gateway_service())
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
            .system_dns_sd_precondition(&gateway_service())
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
            .system_dns_sd_precondition(&gateway_service())
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
            .system_dns_sd_precondition(&wanted)
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
            .system_dns_sd_precondition(&gateway_service())
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
        let wanted = gateway_service();

        let permitted = declarations.system_dns_sd_precondition(&wanted);
        assert!(
            permitted.is_ok(),
            "the system DNS-SD path needs no entitlement, but was refused with {:?}",
            permitted.err()
        );

        let error = declarations
            .raw_multicast_precondition(&wanted)
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
            .raw_multicast_precondition(&gateway_service())
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
        let wanted = gateway_service();
        let not_granted = fully_declared()
            .with_entitlement(
                HostAppEntitlement::MulticastNetworking,
                EntitlementStatus::NotGranted,
            )
            .raw_multicast_precondition(&wanted)
            .expect_err("NotGranted must block");
        let unknown = fully_declared()
            .raw_multicast_precondition(&wanted)
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
            .raw_multicast_precondition(&gateway_service())
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
