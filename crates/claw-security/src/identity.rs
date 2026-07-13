//! Ed25519 device identity with versioned fingerprints and signed handshakes.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};

use crate::authorization::{ClientClass, Role, ScopeSet};

const DEVICE_ID_PREFIX: &str = "claw-device-v1:";
const HANDSHAKE_DOMAIN: &[u8] = b"GTA-Claw/handshake-proof/v1\0";

/// Stable public identifier: SHA-256 over the canonical 32-byte Ed25519 key.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    /// Derives the version-one fingerprint from a public key.
    #[must_use]
    pub fn from_public_key(public_key: &DevicePublicKey) -> Self {
        let digest = Sha256::digest(public_key.as_bytes());
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    /// Parses only the lowercase, versioned canonical representation.
    pub fn parse(value: &str) -> Result<Self, DeviceIdError> {
        let encoded = value
            .strip_prefix(DEVICE_ID_PREFIX)
            .ok_or(DeviceIdError::UnsupportedVersion)?;
        if encoded.len() != 64 {
            return Err(DeviceIdError::InvalidLength);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = decode_hex_pair(pair)?;
        }
        Ok(Self(bytes))
    }

    /// Returns raw fingerprint bytes for deterministic signed-payload encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Debug for DeviceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, formatter)
    }
}

impl Display for DeviceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(DEVICE_ID_PREFIX)?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn decode_hex_pair(pair: &[u8]) -> Result<u8, DeviceIdError> {
    let high = decode_hex_digit(pair[0])?;
    let low = decode_hex_digit(pair[1])?;
    Ok((high << 4) | low)
}

fn decode_hex_digit(value: u8) -> Result<u8, DeviceIdError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(DeviceIdError::NonCanonicalEncoding),
    }
}

/// Invalid public fingerprint representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceIdError {
    /// The algorithm/version prefix is not supported.
    UnsupportedVersion,
    /// The digest text is not exactly 64 hexadecimal bytes.
    InvalidLength,
    /// Uppercase, Unicode, or non-hexadecimal text was supplied.
    NonCanonicalEncoding,
}

impl Display for DeviceIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => formatter.write_str("unsupported device id version"),
            Self::InvalidLength => formatter.write_str("invalid device id length"),
            Self::NonCanonicalEncoding => formatter.write_str("non-canonical device id encoding"),
        }
    }
}

impl Error for DeviceIdError {}

/// Strictly decoded Ed25519 public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevicePublicKey(VerifyingKey);

impl DevicePublicKey {
    /// Decodes exactly 32 canonical Ed25519 public-key bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, KeyDecodeError> {
        let bytes: &[u8; 32] = bytes
            .try_into()
            .map_err(|_| KeyDecodeError::InvalidLength)?;
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| KeyDecodeError::InvalidEncoding)
    }

    /// Returns canonical public bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Returns the stable versioned device fingerprint.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_public_key(self)
    }

    /// Strictly verifies a domain-separated handshake proof.
    pub fn verify_handshake(
        &self,
        input: HandshakeSigningInput<'_>,
        signature: &DeviceSignature,
    ) -> Result<(), SignatureError> {
        let message = encode_handshake(input);
        self.0
            .verify_strict(&message, &signature.0)
            .map_err(|_| SignatureError::VerificationFailed)
    }
}

/// Public-key decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyDecodeError {
    /// Input was not exactly 32 bytes.
    InvalidLength,
    /// Bytes do not encode an accepted Ed25519 public key.
    InvalidEncoding,
}

impl Display for KeyDecodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => formatter.write_str("invalid Ed25519 public key length"),
            Self::InvalidEncoding => formatter.write_str("invalid Ed25519 public key encoding"),
        }
    }
}

impl Error for KeyDecodeError {}

/// Strictly decoded Ed25519 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceSignature(Signature);

impl DeviceSignature {
    /// Decodes exactly 64 signature bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SignatureDecodeError> {
        Signature::from_slice(bytes)
            .map(Self)
            .map_err(|_| SignatureDecodeError::InvalidLength)
    }

    /// Returns canonical signature bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 64] {
        self.0.to_bytes()
    }
}

/// Signature decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureDecodeError {
    /// Input was not exactly 64 bytes.
    InvalidLength,
}

impl Display for SignatureDecodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Ed25519 signature length")
    }
}

impl Error for SignatureDecodeError {}

/// Exact typed claims included in a version-one handshake signature.
#[derive(Clone, Copy, Debug)]
pub struct HandshakeSigningInput<'a> {
    /// Expected public device fingerprint.
    pub device_id: &'a DeviceId,
    /// Exact gateway role.
    pub role: Role,
    /// Exact closed scope set.
    pub scopes: ScopeSet,
    /// Negotiated gateway protocol version.
    pub protocol_version: u16,
    /// Compatibility client class.
    pub client_class: ClientClass,
    /// Wall-clock signature timestamp.
    pub signed_at_unix_millis: u64,
    /// Exact challenge nonce bytes.
    pub nonce: &'a [u8],
    /// Exact opaque challenge bytes.
    pub challenge: &'a [u8],
}

fn encode_handshake(input: HandshakeSigningInput<'_>) -> Vec<u8> {
    let nonce_len = u32::try_from(input.nonce.len()).expect("pairing bounds nonce length");
    let challenge_len =
        u32::try_from(input.challenge.len()).expect("pairing bounds challenge length");
    let mut message = Vec::with_capacity(
        HANDSHAKE_DOMAIN.len()
            + 32
            + 1
            + 1
            + 2
            + 1
            + 8
            + 4
            + input.nonce.len()
            + 4
            + input.challenge.len(),
    );
    message.extend_from_slice(HANDSHAKE_DOMAIN);
    message.extend_from_slice(input.device_id.as_bytes());
    message.push(input.role.ordinal());
    message.push(input.scopes.bits());
    message.extend_from_slice(&input.protocol_version.to_be_bytes());
    message.push(input.client_class.ordinal());
    message.extend_from_slice(&input.signed_at_unix_millis.to_be_bytes());
    message.extend_from_slice(&nonce_len.to_be_bytes());
    message.extend_from_slice(input.nonce);
    message.extend_from_slice(&challenge_len.to_be_bytes());
    message.extend_from_slice(input.challenge);
    message
}

/// In-memory Ed25519 signer.
///
/// The private key cannot be cloned, displayed, serialized, or exported. The
/// underlying RustCrypto key zeroizes on drop. A later platform adapter may
/// create identities from an OS keyring, but this crate provides no persistence.
pub struct DeviceIdentity {
    signing_key: SigningKey,
}

impl DeviceIdentity {
    /// Generates an identity using a caller-supplied cryptographic RNG.
    pub fn generate<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + ?Sized,
    {
        Self {
            signing_key: SigningKey::generate(rng),
        }
    }

    /// Returns the public key.
    #[must_use]
    pub fn public_key(&self) -> DevicePublicKey {
        DevicePublicKey(self.signing_key.verifying_key())
    }

    /// Returns the versioned public device identifier.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.public_key().device_id()
    }

    /// Signs the deterministic, domain-separated handshake payload.
    #[must_use]
    pub fn sign_handshake(&self, input: HandshakeSigningInput<'_>) -> DeviceSignature {
        DeviceSignature(self.signing_key.sign(&encode_handshake(input)))
    }
}

impl Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceIdentity")
            .field("private_key", &"[REDACTED]")
            .field("device_id", &self.device_id())
            .finish()
    }
}

/// Signature verification failed without exposing signed bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// Signature did not verify for the exact domain and claims.
    VerificationFailed,
}

impl Display for SignatureError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("device signature verification failed")
    }
}

impl Error for SignatureError {}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer;
    use rand_chacha::{
        ChaCha20Rng,
        rand_core::{Rng, SeedableRng},
    };

    use super::*;
    use crate::authorization::{ClientClass, Role, Scope, ScopeSet};

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| decode_hex_pair(pair).expect("test vector hex"))
            .collect()
    }

    fn input<'a>(
        device_id: &'a DeviceId,
        nonce: &'a [u8],
        challenge: &'a [u8],
    ) -> HandshakeSigningInput<'a> {
        HandshakeSigningInput {
            device_id,
            role: Role::Operator,
            scopes: ScopeSet::from_scopes([Scope::OperatorRead]),
            protocol_version: 4,
            client_class: ClientClass::General,
            signed_at_unix_millis: 1_700_000_000_000,
            nonce,
            challenge,
        }
    }

    #[test]
    fn verifies_rfc8032_test_vector_one() {
        let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_signature = hex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        let signing_key = SigningKey::from_bytes(seed.as_slice().try_into().expect("32-byte seed"));
        assert_eq!(signing_key.verifying_key().as_bytes(), public.as_slice());
        let signature: Signature = signing_key.sign(b"");
        assert_eq!(signature.to_bytes().as_slice(), expected_signature);
        signing_key
            .verifying_key()
            .verify_strict(b"", &signature)
            .expect("RFC signature verifies");
    }

    #[test]
    fn generates_signs_verifies_and_rejects_tampering() {
        let mut rng = ChaCha20Rng::from_seed([7_u8; 32]);
        let identity = DeviceIdentity::generate(&mut rng);
        let public = identity.public_key();
        let device_id = identity.device_id();
        let nonce = rng.next_u64().to_be_bytes();
        let mut challenge = rng.next_u64().to_be_bytes();
        let signature = identity.sign_handshake(input(&device_id, &nonce, &challenge));

        public
            .verify_handshake(input(&device_id, &nonce, &challenge), &signature)
            .expect("valid proof");
        challenge[0] ^= 1;
        assert_eq!(
            public.verify_handshake(input(&device_id, &nonce, &challenge), &signature),
            Err(SignatureError::VerificationFailed)
        );
    }

    #[test]
    fn domain_and_claims_are_separated() {
        let mut rng = ChaCha20Rng::from_seed([8_u8; 32]);
        let identity = DeviceIdentity::generate(&mut rng);
        let public = identity.public_key();
        let device_id = identity.device_id();
        let combined = rng.next_u64().to_be_bytes();
        let (nonce, challenge) = combined[..3].split_at(2);
        let signature = identity.sign_handshake(input(&device_id, nonce, challenge));

        let (different_nonce, different_challenge) = combined[..3].split_at(1);
        assert_eq!(
            public.verify_handshake(
                input(&device_id, different_nonce, different_challenge),
                &signature
            ),
            Err(SignatureError::VerificationFailed)
        );
        let mut changed = input(&device_id, nonce, challenge);
        changed.protocol_version = 3;
        assert_eq!(
            public.verify_handshake(changed, &signature),
            Err(SignatureError::VerificationFailed)
        );
    }

    #[test]
    fn strict_decoders_reject_malformed_lengths_and_encodings() {
        assert_eq!(
            DevicePublicKey::decode(&[0_u8; 31]),
            Err(KeyDecodeError::InvalidLength)
        );
        assert_eq!(
            DeviceSignature::decode(&[0_u8; 63]),
            Err(SignatureDecodeError::InvalidLength)
        );
        assert_eq!(
            DeviceId::parse("claw-device-v1:AA"),
            Err(DeviceIdError::InvalidLength)
        );
        let uppercase = format!("claw-device-v1:{}", "A".repeat(64));
        assert_eq!(
            DeviceId::parse(&uppercase),
            Err(DeviceIdError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn private_debug_is_redacted() {
        let mut rng = ChaCha20Rng::from_seed([9_u8; 32]);
        let identity = DeviceIdentity::generate(&mut rng);
        let debug = format!("{identity:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("signing_key"));
    }
}
