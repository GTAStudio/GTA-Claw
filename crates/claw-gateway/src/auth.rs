//! Server-side authentication: challenge issuance, shared-credential checks,
//! device-proof verification, and role/scope granting.
//!
//! The pure reducer in `claw-protocol` decides protocol compatibility and state
//! transitions; this module supplies the external decisions that reducer needs.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use claw_protocol::gateway::{
    AuthCredentials, AuthenticationDecision, AuthenticationPort, AuthenticationRequest,
    ChallengeNonce, ConnectChallenge, ConnectErrorDetailCode, DeviceProof, DeviceProofDecision,
    HandshakeRejection, Name, NonNegativeInteger, OperatorScope, PREAUTH_MAX_FRAME_BYTES,
    PairingRequiredCode, PairingRequiredDetails, PairingRequiredReason, Role,
};
use claw_security::authorization::{Role as SecurityRole, Scope, ScopeSet};
use claw_security::identity::{
    DevicePublicKey, DeviceSignature, GatewayDeviceSigningInput, HandshakeSigningInput,
};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::SecretString;
use subtle::ConstantTimeEq;

use crate::authority::{AuthorizationSource, DeviceDirectory};
use crate::clock::Clock;

/// Number of random bytes in an issued challenge nonce.
pub const CHALLENGE_NONCE_BYTES: usize = 32;

/// Failure raised when the process random source is unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeError;

impl fmt::Display for ChallengeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("the system random source could not produce a challenge nonce")
    }
}

impl std::error::Error for ChallengeError {}

/// Issues a fresh `connect.challenge` payload.
///
/// # Errors
///
/// Returns [`ChallengeError`] when the operating-system random source refuses
/// to fill the [`CHALLENGE_NONCE_BYTES`] nonce buffer. The handshake has no
/// fallback for that: a predictable nonce would let a replayed device proof
/// authenticate, so the connection is refused rather than served with weaker
/// freshness.
#[expect(
    clippy::missing_panics_doc,
    reason = "the base64url encoding of a fixed 32-byte nonce is always 43 ASCII characters, \
              which is non-empty and far inside the 64 KiB pre-authentication bound, so the \
              only fallible construction here cannot fail at runtime"
)]
pub fn issue_challenge(clock: &dyn Clock) -> Result<ConnectChallenge, ChallengeError> {
    let mut bytes = [0_u8; CHALLENGE_NONCE_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| ChallengeError)?;
    let nonce = ChallengeNonce::new(URL_SAFE_NO_PAD.encode(bytes), PREAUTH_MAX_FRAME_BYTES)
        .expect("encoded nonce is non-empty and bounded");
    Ok(ConnectChallenge {
        nonce,
        ts: NonNegativeInteger::new(clock.unix_millis()),
    })
}

/// The shared credential this server requires before device policy runs.
pub enum CredentialPolicy {
    /// No shared credential is configured; device policy alone gates access.
    None,
    /// A shared token must be presented as `auth.token`.
    Token(SecretString),
    /// A shared password must be presented as `auth.password`.
    Password(SecretString),
}

impl Debug for CredentialPolicy {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::None => "CredentialPolicy::None",
            Self::Token(_) => "CredentialPolicy::Token([REDACTED])",
            Self::Password(_) => "CredentialPolicy::Password([REDACTED])",
        })
    }
}

/// The role and scopes a paired device is entitled to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    /// Granted ordinary Gateway role.
    pub role: Role,
    /// Granted closed operator scopes.
    pub scopes: Vec<OperatorScope>,
}

impl Grant {
    /// Creates a grant with deduplicated, canonically ordered scopes.
    #[must_use]
    pub fn new(role: Role, scopes: impl IntoIterator<Item = OperatorScope>) -> Self {
        let mut scopes: Vec<OperatorScope> = scopes.into_iter().collect();
        scopes.sort_unstable();
        scopes.dedup();
        Self { role, scopes }
    }
}

/// Authenticator backed by an explicit in-memory device directory.
///
/// Every decision is fail-closed: an unknown device, an unverifiable proof, a
/// stale signature, or a request for scopes beyond the recorded grant all
/// produce a typed [`HandshakeRejection`].
pub struct StaticAuthenticator {
    credential: CredentialPolicy,
    devices: DeviceDirectory,
    max_signature_age_ms: u64,
    clock: Arc<dyn Clock>,
}

impl Debug for StaticAuthenticator {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticAuthenticator")
            .field("credential", &self.credential)
            .field("paired_devices", &self.devices.len())
            .field("max_signature_age_ms", &self.max_signature_age_ms)
            .finish_non_exhaustive()
    }
}

impl StaticAuthenticator {
    /// Default tolerance applied to device-proof signature timestamps.
    pub const DEFAULT_MAX_SIGNATURE_AGE_MS: u64 = 120_000;

    /// Creates an authenticator with no paired devices.
    #[must_use]
    pub fn new(credential: CredentialPolicy, clock: Arc<dyn Clock>) -> Self {
        Self::with_devices(credential, clock, DeviceDirectory::new())
    }

    /// Creates an authenticator over an existing shared device directory.
    ///
    /// Use this when the same directory must be shared with something that
    /// mutates pairings at runtime; the handshake and every live connection
    /// then read one source of truth.
    #[must_use]
    pub fn with_devices(
        credential: CredentialPolicy,
        clock: Arc<dyn Clock>,
        devices: DeviceDirectory,
    ) -> Self {
        Self {
            credential,
            devices,
            max_signature_age_ms: Self::DEFAULT_MAX_SIGNATURE_AGE_MS,
            clock,
        }
    }

    /// Records the grant for one paired device, replacing any previous grant.
    #[must_use]
    pub fn with_paired_device(self, device_wire_id: impl Into<String>, grant: Grant) -> Self {
        self.devices.pair(device_wire_id, grant);
        self
    }

    /// Returns a handle to the shared device directory.
    ///
    /// This is the same directory the handshake consults, so pairing or
    /// revoking through it takes effect on the next handshake *and* on every
    /// connection that is already open.
    #[must_use]
    pub fn devices(&self) -> DeviceDirectory {
        self.devices.clone()
    }

    /// Overrides the accepted device-proof signature age.
    #[must_use]
    pub const fn with_max_signature_age_ms(mut self, max_signature_age_ms: u64) -> Self {
        self.max_signature_age_ms = max_signature_age_ms;
        self
    }

    /// Returns the grant recorded for a device wire identity.
    #[must_use]
    pub fn grant(&self, device_wire_id: &str) -> Option<Grant> {
        self.devices.current_grant(device_wire_id)
    }

    fn check_credential(
        &self,
        auth: Option<&AuthCredentials>,
    ) -> Result<(), Box<HandshakeRejection>> {
        match &self.credential {
            CredentialPolicy::None => Ok(()),
            CredentialPolicy::Token(expected) => {
                let Some(presented) = auth.and_then(|auth| auth.token.as_deref()) else {
                    return Err(reject(
                        ConnectErrorDetailCode::AuthTokenMissing,
                        "this gateway requires a shared token",
                    ));
                };
                if secret_eq(presented, expected) {
                    Ok(())
                } else {
                    Err(reject(
                        ConnectErrorDetailCode::AuthTokenMismatch,
                        "shared token does not match",
                    ))
                }
            }
            CredentialPolicy::Password(expected) => {
                let Some(presented) = auth.and_then(|auth| auth.password.as_deref()) else {
                    return Err(reject(
                        ConnectErrorDetailCode::AuthPasswordMissing,
                        "this gateway requires a shared password",
                    ));
                };
                if secret_eq(presented, expected) {
                    Ok(())
                } else {
                    Err(reject(
                        ConnectErrorDetailCode::AuthPasswordMismatch,
                        "shared password does not match",
                    ))
                }
            }
        }
    }

    fn verify_device(
        &self,
        request: &AuthenticationRequest<'_>,
        device: &DeviceProof,
    ) -> Result<String, Box<HandshakeRejection>> {
        let key_bytes = URL_SAFE_NO_PAD
            .decode(device.public_key.as_str())
            .map_err(|_| {
                reject(
                    ConnectErrorDetailCode::DeviceAuthPublicKeyInvalid,
                    "device public key is not url-safe base64",
                )
            })?;
        let public_key = DevicePublicKey::decode(&key_bytes).map_err(|_| {
            reject(
                ConnectErrorDetailCode::DeviceAuthPublicKeyInvalid,
                "device public key is not a canonical Ed25519 key",
            )
        })?;
        let wire_id = public_key.device_id().gateway_wire_id();
        if wire_id != device.id.as_str() {
            return Err(reject(
                ConnectErrorDetailCode::DeviceAuthDeviceIdMismatch,
                "device id does not match the supplied public key",
            ));
        }
        if device.nonce.as_str() != request.challenge().nonce.as_str() {
            return Err(reject(
                ConnectErrorDetailCode::DeviceAuthNonceMismatch,
                "device proof does not cover the issued challenge nonce",
            ));
        }
        let now = self.clock.unix_millis();
        let signed_at = device.signed_at.get();
        if now.abs_diff(signed_at) > self.max_signature_age_ms {
            return Err(reject(
                ConnectErrorDetailCode::DeviceAuthSignatureExpired,
                "device proof timestamp is outside the accepted window",
            ));
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(device.signature.as_str())
            .map_err(|_| {
                reject(
                    ConnectErrorDetailCode::DeviceAuthSignatureInvalid,
                    "device signature is not url-safe base64",
                )
            })?;
        let signature = DeviceSignature::decode(&signature_bytes).map_err(|_| {
            reject(
                ConnectErrorDetailCode::DeviceAuthSignatureInvalid,
                "device signature is not a canonical Ed25519 signature",
            )
        })?;

        let params = request.params();
        let requested_scopes = parse_requested_scopes(params.scopes.as_deref())?;
        let security_role =
            SecurityRole::parse(request.requested_role().as_str()).map_err(|_| {
                reject(
                    ConnectErrorDetailCode::AuthUnauthorized,
                    "requested role is outside the closed gateway role set",
                )
            })?;
        let token = signature_token(params.auth.as_ref());
        public_key
            .verify_gateway_device(
                GatewayDeviceSigningInput {
                    client_id: params.client.id.as_str(),
                    client_mode: params.client.mode.as_str(),
                    role: security_role,
                    scopes: scope_set(&requested_scopes),
                    signed_at_unix_millis: signed_at,
                    token: token.as_ref(),
                    nonce: device.nonce.as_str(),
                    platform: params.client.platform.as_str(),
                    device_family: params.client.device_family.as_ref().map(Name::as_str),
                },
                &signature,
            )
            .map_err(|_| {
                reject(
                    ConnectErrorDetailCode::DeviceAuthSignatureInvalid,
                    "device proof signature verification failed",
                )
            })?;
        Ok(wire_id)
    }
}

impl AuthenticationPort for StaticAuthenticator {
    fn authenticate(&self, request: AuthenticationRequest<'_>) -> AuthenticationDecision {
        match self.decide(&request) {
            Ok(decision) => decision,
            Err(rejection) => AuthenticationDecision::Rejected(*rejection),
        }
    }
}

impl StaticAuthenticator {
    fn decide(
        &self,
        request: &AuthenticationRequest<'_>,
    ) -> Result<AuthenticationDecision, Box<HandshakeRejection>> {
        let params = request.params();
        self.check_credential(params.auth.as_ref())?;

        let requested_role = request.requested_role();
        let requested_scopes = parse_requested_scopes(params.scopes.as_deref())?;

        let Some(device) = params.device.as_ref() else {
            return Err(reject(
                ConnectErrorDetailCode::DeviceIdentityRequired,
                "this gateway requires a device identity proof",
            ));
        };
        let wire_id = self.verify_device(request, device)?;

        let Some(grant) = self.devices.current_grant(&wire_id) else {
            return Err(pairing_required(
                PairingRequiredReason::NotPaired,
                &wire_id,
                requested_role,
                &requested_scopes,
                None,
            ));
        };
        if grant.role != requested_role {
            return Err(pairing_required(
                PairingRequiredReason::RoleUpgrade,
                &wire_id,
                requested_role,
                &requested_scopes,
                Some(&grant),
            ));
        }
        if let Some(excess) = requested_scopes
            .iter()
            .find(|scope| !grant.scopes.contains(scope))
        {
            let excess = excess.as_str();
            return Err(reject(
                ConnectErrorDetailCode::AuthScopeMismatch,
                format!("device `{wire_id}` is not granted `{excess}`"),
            ));
        }
        let effective = if requested_scopes.is_empty() {
            grant.scopes.clone()
        } else {
            requested_scopes
        };
        Ok(AuthenticationDecision::Accepted {
            role: grant.role,
            scopes: effective,
            device_proof: DeviceProofDecision::Verified,
        })
    }
}

fn pairing_required(
    reason: PairingRequiredReason,
    wire_id: &str,
    requested_role: Role,
    requested_scopes: &[OperatorScope],
    grant: Option<&Grant>,
) -> Box<HandshakeRejection> {
    Box::new(HandshakeRejection::pairing(
        format!("device `{wire_id}` requires pairing approval"),
        PairingRequiredDetails {
            code: PairingRequiredCode::PairingRequired,
            reason: Some(reason),
            request_id: None,
            remediation_hint: Some(
                "approve this device with `device.pair.approve` on an operator session".to_owned(),
            ),
            recommended_next_step: None,
            retryable: Some(false),
            pause_reconnect: Some(true),
            device_id: Some(wire_id.to_owned()),
            requested_role: Some(requested_role.as_str().to_owned()),
            requested_scopes: Some(
                requested_scopes
                    .iter()
                    .map(|scope| scope.as_str().to_owned())
                    .collect(),
            ),
            approved_roles: grant.map(|grant| vec![grant.role.as_str().to_owned()]),
            approved_scopes: grant.map(|grant| {
                grant
                    .scopes
                    .iter()
                    .map(|scope| scope.as_str().to_owned())
                    .collect()
            }),
        },
    ))
}

/// Boxes a handshake rejection.
///
/// `HandshakeRejection` carries rich pairing diagnostics, so returning it by
/// value from the fallible handshake helpers would make every `Result` in this
/// module several hundred bytes wide on the success path too.
fn reject(code: ConnectErrorDetailCode, message: impl Into<String>) -> Box<HandshakeRejection> {
    Box::new(HandshakeRejection::new(code, message))
}

fn parse_requested_scopes(
    scopes: Option<&[Name]>,
) -> Result<Vec<OperatorScope>, Box<HandshakeRejection>> {
    let mut parsed = Vec::new();
    for scope in scopes.unwrap_or_default() {
        let scope = OperatorScope::from_identity(scope.as_str()).ok_or_else(|| {
            reject(
                ConnectErrorDetailCode::AuthScopeMismatch,
                format!("`{}` is not a closed operator scope", scope.as_str()),
            )
        })?;
        if !parsed.contains(&scope) {
            parsed.push(scope);
        }
    }
    parsed.sort_unstable();
    Ok(parsed)
}

fn scope_set(scopes: &[OperatorScope]) -> ScopeSet {
    ScopeSet::from_scopes(scopes.iter().map(|scope| {
        Scope::parse(scope.as_str()).expect("closed protocol scopes are closed security scopes")
    }))
}

fn signature_token(auth: Option<&AuthCredentials>) -> Option<SecretString> {
    let auth = auth?;
    auth.token
        .as_ref()
        .or(auth.bootstrap_token.as_ref())
        .map(|token| SecretString::from(token.clone()))
}

fn secret_eq(presented: &str, expected: &SecretString) -> bool {
    use secrecy::ExposeSecret as _;
    let presented = digest(&SHA256, presented.as_bytes());
    let expected = digest(&SHA256, expected.expose_secret().as_bytes());
    presented.as_ref().ct_eq(expected.as_ref()).into()
}

/// Verifies a pairing-time handshake proof produced by
/// [`claw_security::identity::DeviceIdentity::sign_handshake`].
///
/// This is exposed so a pairing workflow can reuse the same strict verification
/// the connect path uses without duplicating decoding rules.
#[must_use]
pub fn verify_pairing_proof(
    public_key: &DevicePublicKey,
    input: HandshakeSigningInput<'_>,
    signature: &DeviceSignature,
) -> bool {
    public_key.verify_handshake(input, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    #[test]
    fn issued_nonces_are_unique_and_carry_the_clock_timestamp() {
        let clock = ManualClock::new(1_700_000_000_000);
        let first = issue_challenge(&clock).expect("challenge");
        let second = issue_challenge(&clock).expect("challenge");
        assert_ne!(first.nonce.as_str(), second.nonce.as_str());
        assert_eq!(first.ts.get(), 1_700_000_000_000);
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(first.nonce.as_str())
                .expect("nonce is url-safe base64")
                .len(),
            CHALLENGE_NONCE_BYTES
        );
    }

    #[test]
    fn secret_comparison_accepts_only_the_exact_value() {
        let expected = SecretString::from("s3cret".to_owned());
        assert!(secret_eq("s3cret", &expected));
        assert!(!secret_eq("s3cre", &expected));
        assert!(!secret_eq("s3crets", &expected));
        assert!(!secret_eq("S3cret", &expected));
        assert!(!secret_eq("", &expected));
    }

    #[test]
    fn grant_normalizes_and_deduplicates_scopes() {
        let grant = Grant::new(
            Role::Operator,
            [
                OperatorScope::Write,
                OperatorScope::Read,
                OperatorScope::Write,
            ],
        );
        assert_eq!(grant.role, Role::Operator);
        assert_eq!(
            grant.scopes,
            vec![OperatorScope::Read, OperatorScope::Write]
        );
    }

    #[test]
    fn requested_scope_parsing_rejects_unknown_identities() {
        let scopes = vec![Name::new("operator.superuser", 64).expect("name")];
        let rejection = parse_requested_scopes(Some(&scopes)).expect_err("unknown scope");
        assert_eq!(rejection.code(), ConnectErrorDetailCode::AuthScopeMismatch);
    }

    #[test]
    fn requested_scope_parsing_deduplicates_and_orders() {
        let scopes = vec![
            Name::new("operator.write", 64).expect("name"),
            Name::new("operator.read", 64).expect("name"),
            Name::new("operator.write", 64).expect("name"),
        ];
        assert_eq!(
            parse_requested_scopes(Some(&scopes)).expect("valid scopes"),
            vec![OperatorScope::Read, OperatorScope::Write]
        );
    }

    #[test]
    fn signature_token_prefers_token_then_bootstrap_and_ignores_password() {
        use secrecy::ExposeSecret as _;
        let bootstrap = AuthCredentials {
            bootstrap_token: Some("boot".to_owned()),
            ..AuthCredentials::default()
        };
        assert_eq!(
            signature_token(Some(&bootstrap))
                .as_ref()
                .map(|token| token.expose_secret().to_owned()),
            Some("boot".to_owned())
        );
        let both = AuthCredentials {
            token: Some("plain".to_owned()),
            bootstrap_token: Some("boot".to_owned()),
            ..AuthCredentials::default()
        };
        assert_eq!(
            signature_token(Some(&both))
                .as_ref()
                .map(|token| token.expose_secret().to_owned()),
            Some("plain".to_owned())
        );
        let password = AuthCredentials {
            password: Some("pw".to_owned()),
            ..AuthCredentials::default()
        };
        assert!(signature_token(Some(&password)).is_none());
        assert!(signature_token(None).is_none());
    }

    #[test]
    fn scope_set_maps_every_closed_protocol_scope() {
        for scope in [
            OperatorScope::Admin,
            OperatorScope::Read,
            OperatorScope::Write,
            OperatorScope::Approvals,
            OperatorScope::Pairing,
            OperatorScope::TalkSecrets,
        ] {
            let set = scope_set(&[scope]);
            let identities: Vec<&str> = set.iter().map(Scope::as_str).collect();
            assert_eq!(identities, vec![scope.as_str()]);
        }
    }
}
