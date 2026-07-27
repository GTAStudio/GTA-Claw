//! Secret references and resolver port without inline secret values.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;

use secrecy::SecretString;
use serde::{Serialize, Serializer};

use crate::audit::{AuditAction, AuditEvent, AuditOutcome, AuditReason, AuditSink, AuditSubject};

const MAX_IDENTIFIER_BYTES: usize = 128;

/// Supported deferred secret backends.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecretScheme {
    /// Operating-system keyring adapter, deferred to `claw-platform`.
    Keyring,
    /// Already-open file descriptor supplied by a process supervisor.
    FileDescriptor,
    /// Service credential adapter, deferred to `claw-platform`.
    Service,
}

impl SecretScheme {
    /// Returns the canonical URI scheme.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keyring => "keyring",
            Self::FileDescriptor => "fd",
            Self::Service => "service",
        }
    }
}

/// Validated reference to secret material held by a platform adapter.
///
/// This type never contains resolved secret bytes. Its formatter and serializer
/// intentionally redact even the backend identifier because account and service
/// names may be operationally sensitive.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SecretRef {
    scheme: SecretScheme,
    identifier: String,
}

impl SecretRef {
    /// Returns the closed backend scheme.
    #[must_use]
    pub const fn scheme(&self) -> SecretScheme {
        self.scheme
    }

    /// Returns the validated backend identifier for resolver implementations.
    ///
    /// Callers must not log or serialize this value.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
}

impl FromStr for SecretRef {
    type Err = SecretRefError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_secret_ref(value)
    }
}

impl Debug for SecretRef {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretRef([REDACTED])")
    }
}

impl Display for SecretRef {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret-ref:[REDACTED]")
    }
}

impl Serialize for SecretRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("secret-ref:[REDACTED]")
    }
}

fn parse_secret_ref(value: &str) -> Result<SecretRef, SecretRefError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(SecretRefError::InvalidSyntax);
    }
    if value.contains(['?', '#', '@', '%']) {
        return Err(SecretRefError::InvalidSyntax);
    }
    let (scheme, identifier) = value
        .split_once("://")
        .ok_or(SecretRefError::InlineSecretForbidden)?;
    match scheme {
        "keyring" => parse_two_part(SecretScheme::Keyring, identifier),
        "service" => parse_two_part(SecretScheme::Service, identifier),
        "fd" => parse_file_descriptor(identifier),
        _ => Err(SecretRefError::UnsupportedScheme),
    }
}

fn parse_two_part(scheme: SecretScheme, identifier: &str) -> Result<SecretRef, SecretRefError> {
    let mut parts = identifier.split('/');
    let first = parts.next().ok_or(SecretRefError::InvalidIdentifier)?;
    let second = parts.next().ok_or(SecretRefError::InvalidIdentifier)?;
    if parts.next().is_some() || !valid_identifier_part(first) || !valid_identifier_part(second) {
        return Err(SecretRefError::InvalidIdentifier);
    }
    if identifier.len() > MAX_IDENTIFIER_BYTES {
        return Err(SecretRefError::IdentifierTooLong);
    }
    Ok(SecretRef {
        scheme,
        identifier: identifier.to_owned(),
    })
}

fn valid_identifier_part(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn parse_file_descriptor(identifier: &str) -> Result<SecretRef, SecretRefError> {
    if identifier.is_empty()
        || !identifier.bytes().all(|byte| byte.is_ascii_digit())
        || (identifier.len() > 1 && identifier.starts_with('0'))
    {
        return Err(SecretRefError::InvalidIdentifier);
    }
    identifier
        .parse::<u32>()
        .map_err(|_| SecretRefError::InvalidIdentifier)?;
    Ok(SecretRef {
        scheme: SecretScheme::FileDescriptor,
        identifier: identifier.to_owned(),
    })
}

/// Invalid or unsafe secret reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretRefError {
    /// Plaintext and strings without a supported reference scheme are forbidden.
    InlineSecretForbidden,
    /// The scheme is not backed by an explicit port.
    UnsupportedScheme,
    /// Reference syntax is malformed.
    InvalidSyntax,
    /// Backend identifier is malformed.
    InvalidIdentifier,
    /// Backend identifier exceeds its bound.
    IdentifierTooLong,
}

impl Display for SecretRefError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InlineSecretForbidden => {
                formatter.write_str("inline secret values are forbidden")
            }
            Self::UnsupportedScheme => formatter.write_str("unsupported secret reference scheme"),
            Self::InvalidSyntax => formatter.write_str("invalid secret reference syntax"),
            Self::InvalidIdentifier => formatter.write_str("invalid secret reference identifier"),
            Self::IdentifierTooLong => {
                formatter.write_str("secret reference identifier is too long")
            }
        }
    }
}

impl Error for SecretRefError {}

/// Platform resolver for one validated reference.
///
/// Returned values are owned secrecy wrappers and zeroize when dropped. The
/// trait intentionally has no serialization or persistence convenience method.
/// OS keyring, file-descriptor, and service credential adapters are deferred.
pub trait SecretResolver {
    /// Concrete backend error that must not contain secret bytes.
    type Error: Error + Send + Sync + 'static;

    /// Resolves for the caller's current use and returns owned secret material.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the backend refused or could not complete
    /// the lookup — a locked or absent keyring entry, a closed file descriptor,
    /// a denied service credential, or an unreachable adapter. Implementations
    /// must not place resolved secret bytes, or any fragment of them, into that
    /// error: it is formatted by [`SecretResolutionError`] and reaches logs.
    fn resolve(
        &self,
        reference: &SecretRef,
        permit: ResolutionPermit<'_>,
    ) -> Result<SecretString, Self::Error>;
}

/// Unforgeable proof that mandatory audit persistence authorized one lookup.
///
/// Only `resolve_audited` can construct this value. Its lifetime binds the
/// capability to the reference being resolved.
pub struct ResolutionPermit<'a> {
    _reference: PhantomData<&'a SecretRef>,
}

/// Secret-resolution failure preserving concrete adapter and audit errors.
#[derive(Debug)]
pub enum SecretResolutionError<ResolverError, AuditError> {
    /// Concrete resolver failure.
    Resolver(ResolverError),
    /// Mandatory audit persistence failure.
    Audit(AuditError),
}

impl<ResolverError: Display, AuditError: Display> Display
    for SecretResolutionError<ResolverError, AuditError>
{
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolver(error) => write!(formatter, "secret resolver failed: {error}"),
            Self::Audit(error) => write!(formatter, "mandatory audit persistence failed: {error}"),
        }
    }
}

impl<ResolverError, AuditError> Error for SecretResolutionError<ResolverError, AuditError>
where
    ResolverError: Error + 'static,
    AuditError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Resolver(error) => Some(error),
            Self::Audit(error) => Some(error),
        }
    }
}

/// Resolves a secret only when its decision is durably audited.
///
/// On audit failure after a successful backend lookup, the secrecy wrapper is
/// dropped and zeroized before the error is returned.
///
/// # Errors
///
/// - [`SecretResolutionError::Audit`] when `audit` could not persist the
///   pre-lookup authorization record, in which case the resolver is never
///   called; or when it could not persist the post-lookup outcome, in which
///   case a secret that was already read is dropped and zeroized instead of
///   being returned. An unauditable resolution never yields a secret.
/// - [`SecretResolutionError::Resolver`] when the backend refused or failed.
///   The denial is audited before this is returned.
pub fn resolve_audited<R, A>(
    resolver: &R,
    reference: &SecretRef,
    unix_millis: u64,
    audit: &mut A,
) -> Result<SecretString, SecretResolutionError<R::Error, A::Error>>
where
    R: SecretResolver,
    A: AuditSink,
{
    let authorized = AuditEvent {
        action: AuditAction::SecretResolutionAuthorized,
        subject: AuditSubject::SecretScheme(reference.scheme().as_str()),
        outcome: AuditOutcome::Allowed,
        reason: AuditReason::PolicySatisfied,
        unix_millis,
    };
    audit
        .persist(&authorized)
        .map_err(SecretResolutionError::Audit)?;
    let permit = ResolutionPermit {
        _reference: PhantomData,
    };
    match resolver.resolve(reference, permit) {
        Ok(secret) => {
            let event = resolution_event(
                reference,
                AuditOutcome::Allowed,
                AuditReason::PolicySatisfied,
                unix_millis,
            );
            audit
                .persist(&event)
                .map_err(SecretResolutionError::Audit)?;
            Ok(secret)
        }
        Err(error) => {
            let event = resolution_event(
                reference,
                AuditOutcome::Denied,
                AuditReason::ResolverFailed,
                unix_millis,
            );
            audit
                .persist(&event)
                .map_err(SecretResolutionError::Audit)?;
            Err(SecretResolutionError::Resolver(error))
        }
    }
}

const fn resolution_event(
    reference: &SecretRef,
    outcome: AuditOutcome,
    reason: AuditReason,
    unix_millis: u64,
) -> AuditEvent {
    AuditEvent {
        action: AuditAction::SecretResolved,
        subject: AuditSubject::SecretScheme(reference.scheme().as_str()),
        outcome,
        reason,
        unix_millis,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use secrecy::ExposeSecret;

    use super::*;

    #[derive(Debug)]
    struct TestError(&'static str);

    impl Display for TestError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl Error for TestError {}

    struct Resolver {
        secret: &'static str,
    }

    impl SecretResolver for Resolver {
        type Error = TestError;

        fn resolve(
            &self,
            _reference: &SecretRef,
            _permit: ResolutionPermit<'_>,
        ) -> Result<SecretString, Self::Error> {
            Ok(SecretString::from(self.secret.to_owned()))
        }
    }

    struct Audit {
        fail: bool,
        writes: Cell<usize>,
        events: Vec<AuditEvent>,
    }

    impl AuditSink for Audit {
        type Error = TestError;

        fn persist(&mut self, event: &AuditEvent) -> Result<(), Self::Error> {
            self.writes.set(self.writes.get() + 1);
            if self.fail {
                Err(TestError("sink unavailable"))
            } else {
                self.events.push(event.clone());
                Ok(())
            }
        }
    }

    #[test]
    fn parses_only_supported_strict_references() {
        let cases = [
            ("keyring://gta-claw/github-token", SecretScheme::Keyring),
            ("fd://3", SecretScheme::FileDescriptor),
            ("service://github/copilot", SecretScheme::Service),
        ];
        for (value, scheme) in cases {
            assert_eq!(value.parse::<SecretRef>().expect("valid").scheme(), scheme);
        }
        for value in [
            "plain-secret",
            "env://TOKEN",
            "keyring://service",
            "keyring://service/account/extra",
            "fd://03",
            "fd://-1",
            "service://a/b?secret=x",
            " service://a/b",
        ] {
            assert!(value.parse::<SecretRef>().is_err(), "{value}");
        }
    }

    #[test]
    fn debug_display_and_serialization_never_leak_identifier() {
        let reference: SecretRef = "keyring://private-service/private-account"
            .parse()
            .expect("valid");
        for rendered in [
            format!("{reference:?}"),
            reference.to_string(),
            serde_json::to_string(&reference).expect("serialize redaction"),
        ] {
            assert!(rendered.contains("REDACTED"));
            assert!(!rendered.contains("private-service"));
            assert!(!rendered.contains("private-account"));
        }
    }

    #[test]
    fn audited_resolution_returns_secrecy_wrapper_without_event_leakage() {
        let reference: SecretRef = "service://github/copilot".parse().expect("valid");
        let resolver = Resolver {
            secret: "top-secret-value",
        };
        let mut audit = Audit {
            fail: false,
            writes: Cell::new(0),
            events: Vec::new(),
        };
        let secret =
            resolve_audited(&resolver, &reference, 42, &mut audit).expect("resolved and audited");
        assert_eq!(secret.expose_secret(), "top-secret-value");
        assert_eq!(audit.events.len(), 2);
        let event_text = format!("{:?}", audit.events);
        assert!(!event_text.contains("top-secret-value"));
        assert!(!event_text.contains("copilot"));
    }

    #[test]
    fn audit_failure_prevents_secret_release() {
        let reference: SecretRef = "service://github/copilot".parse().expect("valid");
        let resolver = Resolver {
            secret: "never-returned",
        };
        let mut audit = Audit {
            fail: true,
            writes: Cell::new(0),
            events: Vec::new(),
        };
        let error = resolve_audited(&resolver, &reference, 42, &mut audit)
            .expect_err("audit failure is fail-closed");
        let rendered = error.to_string();
        assert!(rendered.contains("audit"));
        assert!(!rendered.contains("never-returned"));
    }
}
