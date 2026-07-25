//! iOS host-application declarations that platform features depend on.
//!
//! Local-network discovery on iOS does not fail loudly when the host
//! application is missing its `Info.plist` declarations. The system simply
//! returns nothing, which is byte-for-byte indistinguishable from a network
//! with no Gateway on it. This module exists so that the difference is a
//! reported condition rather than an empty result set.
//!
//! Nothing here reads `Info.plist`. Reading the bundle requires Foundation
//! interop and the workspace forbids `unsafe_code`, so every status in this
//! module is one the embedder *declared*, and the default for an undeclared
//! status is [`DeclarationStatus::Unknown`] — never
//! [`DeclarationStatus::Declared`].

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
/// This is a closed set of the declarations features in *this* crate's scope
/// depend on. It is deliberately not a general model of iOS entitlements.
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
    service_types: Vec<BonjourServiceType>,
}

impl HostAppDeclarations {
    /// Creates a record in which nothing has been declared.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            local_network_usage: DeclarationStatus::Unknown,
            bonjour_services: DeclarationStatus::Unknown,
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

    /// Returns the recorded status of a declaration.
    ///
    /// A user interface must render from this method, because it is the same
    /// record [`HostAppDeclarations::discovery_precondition`] decides from.
    #[must_use]
    pub const fn status(&self, declaration: HostAppDeclaration) -> DeclarationStatus {
        match declaration {
            HostAppDeclaration::LocalNetworkUsage => self.local_network_usage,
            HostAppDeclaration::BonjourServices => self.bonjour_services,
        }
    }

    /// Returns the service types the embedder said the bundle lists.
    #[must_use]
    pub fn declared_service_types(&self) -> &[BonjourServiceType] {
        &self.service_types
    }

    /// Decides whether local-network discovery may even be attempted.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryUnavailable`] naming the exact `Info.plist` key at
    /// fault. Callers must surface that text instead of reporting that no
    /// Gateway was found, because the two look identical from the outside.
    pub fn discovery_precondition(&self) -> Result<DiscoveryPermitted<'_>, DiscoveryUnavailable> {
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
        Ok(DiscoveryPermitted {
            service_types: &self.service_types,
        })
    }
}

/// Proof that [`HostAppDeclarations::discovery_precondition`] was consulted.
///
/// Discovery code takes this witness rather than a bare service-type list, so
/// that the check cannot be skipped by a caller that forgot it exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryPermitted<'a> {
    service_types: &'a [BonjourServiceType],
}

impl DiscoveryPermitted<'_> {
    /// Returns the service types discovery is permitted to browse.
    #[must_use]
    pub const fn service_types(&self) -> &[BonjourServiceType] {
        self.service_types
    }
}

/// Why local-network discovery must not be attempted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryUnavailable {
    /// The embedder confirmed the declaration is missing from the bundle.
    NotDeclared(HostAppDeclaration),
    /// Nobody established whether the declaration is present.
    Undetermined(HostAppDeclaration),
    /// `NSBonjourServices` is present but lists nothing to browse.
    NoDeclaredServiceTypes,
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
            Self::NoDeclaredServiceTypes => formatter.write_str(
                "local network discovery is unavailable: NSBonjourServices is present but lists \
                 no service types, so iOS will browse nothing",
            ),
        }
    }
}

impl Error for DiscoveryUnavailable {}

#[cfg(test)]
mod tests {
    use super::{
        BonjourServiceType, DeclarationStatus, DiscoveryUnavailable, HostAppDeclaration,
        HostAppDeclarations, ServiceTypeError,
    };

    fn service_type(text: &str) -> BonjourServiceType {
        BonjourServiceType::parse(text)
            .unwrap_or_else(|error| panic!("{text:?} should parse, but failed with {error}"))
    }

    fn fully_declared() -> HostAppDeclarations {
        HostAppDeclarations::new()
            .with_local_network_usage(DeclarationStatus::Declared)
            .with_bonjour_services(DeclarationStatus::Declared, [service_type("_gtaclaw._tcp")])
    }

    #[test]
    fn an_undeclared_bundle_blocks_discovery_instead_of_returning_nothing() {
        let declarations = HostAppDeclarations::new();

        let error = declarations
            .discovery_precondition()
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
            .discovery_precondition()
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
            .discovery_precondition()
            .expect_err("an empty service type list must not permit discovery");

        assert_eq!(
            error,
            DiscoveryUnavailable::NoDeclaredServiceTypes,
            "an empty NSBonjourServices list must be its own reported condition"
        );
    }

    #[test]
    fn a_fully_declared_bundle_permits_exactly_the_declared_service_types() {
        let declarations = fully_declared();

        let permitted = declarations
            .discovery_precondition()
            .expect("a fully declared bundle must permit discovery");

        let browsed: Vec<&str> = permitted
            .service_types()
            .iter()
            .map(BonjourServiceType::as_str)
            .collect();
        assert_eq!(
            browsed,
            vec!["_gtaclaw._tcp"],
            "discovery must browse exactly what the bundle declares"
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
