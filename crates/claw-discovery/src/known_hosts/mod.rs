//! The OpenSSH `known_hosts` grammar and its fail-closed host-key verdicts.
//!
//! A host-key check is the only thing standing between an SSH client and a
//! machine-in-the-middle, so every ambiguous outcome here resolves to a
//! rejection that names its cause. In particular:
//!
//! * a `@revoked` line beats an accepting line for the same key no matter which
//!   one appears first in the file;
//! * a `@cert-authority` line never accepts a plain host key, because it
//!   delegates trust to a certificate that a plain key does not carry;
//! * a negated pattern removes a line from consideration even when a positive
//!   pattern on the same line matches;
//! * a malformed line is an error, never a silently skipped line, because
//!   skipping a line the operator believed was protecting them is exactly how a
//!   revocation stops taking effect.

pub mod digest;

use core::fmt;
use std::error::Error;

use sha2::{Digest, Sha256};

use digest::{base64_decode, base64_encode, hmac_sha1};

const HASH_MAGIC: &str = "|1|";
const MAX_LINE_BYTES: usize = 8192;

/// A host key as presented by a server or recorded in `known_hosts`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostKey {
    /// Key algorithm name, for example `ssh-ed25519`.
    pub algorithm: String,
    /// Raw public key blob.
    pub blob: Vec<u8>,
}

impl HostKey {
    /// Builds a host key from an algorithm name and a raw blob.
    #[must_use]
    pub fn new(algorithm: impl Into<String>, blob: impl Into<Vec<u8>>) -> Self {
        Self {
            algorithm: algorithm.into(),
            blob: blob.into(),
        }
    }

    /// Parses the `<algorithm> <base64 blob>` pair used inside `known_hosts`.
    ///
    /// # Errors
    ///
    /// Returns [`KnownHostsError::MalformedKey`] for a missing field, an unknown
    /// base64 character or a zero-length blob.
    pub fn parse(algorithm: &str, encoded: &str) -> Result<Self, KnownHostsError> {
        if algorithm.is_empty() {
            return Err(KnownHostsError::MalformedKey("empty algorithm".to_owned()));
        }
        let blob = base64_decode(encoded)
            .ok_or_else(|| KnownHostsError::MalformedKey("key blob is not base64".to_owned()))?;
        if blob.is_empty() {
            return Err(KnownHostsError::MalformedKey("empty key blob".to_owned()));
        }
        Ok(Self {
            algorithm: algorithm.to_owned(),
            blob,
        })
    }

    /// Returns the OpenSSH `SHA256:` fingerprint, base64 without padding.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(&self.blob);
        format!("SHA256:{}", base64_encode(&digest, false))
    }
}

/// The marker a `known_hosts` line may carry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Marker {
    /// `@cert-authority`: the key signs host certificates, it is not a host key.
    CertAuthority,
    /// `@revoked`: the key must never be accepted for the matching hosts.
    Revoked,
}

/// Why a host key was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionCause {
    /// A `@revoked` line matched the host and the presented key.
    Revoked,
    /// The host is known but every recorded key differs from the presented one.
    Mismatch,
    /// No line matched the host at all.
    Unknown,
    /// Only `@cert-authority` lines matched, so no plain key is authorised.
    CertificateAuthorityOnly,
}

impl fmt::Display for RejectionCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Revoked => "revoked",
            Self::Mismatch => "mismatch",
            Self::Unknown => "unknown",
            Self::CertificateAuthorityOnly => "certificate-authority-only",
        })
    }
}

impl RejectionCause {
    /// Returns non-secret operator guidance for resolving this refusal safely.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::Revoked => {
                "do not connect; remove the revocation only after re-establishing host trust"
            }
            Self::Mismatch => {
                "verify the host out of band before replacing the recorded known_hosts key"
            }
            Self::Unknown => {
                "pair and record the host key through a trusted channel before connecting"
            }
            Self::CertificateAuthorityOnly => {
                "use a host certificate signed by the recorded authority or add an explicit host key"
            }
        }
    }
}

/// A refusal, carrying both its machine-readable cause and an operator message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostKeyRejection {
    /// Machine-readable cause.
    pub cause: RejectionCause,
    /// Human-readable detail naming the offending line and fingerprints.
    pub detail: String,
}

/// The outcome of verifying a presented host key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostKeyVerdict {
    /// The key is recorded for the host and is not revoked.
    Accepted {
        /// One-based line number of the accepting entry.
        line: usize,
    },
    /// The key must not be used. Every non-accepting outcome lands here.
    Rejected(HostKeyRejection),
}

impl HostKeyVerdict {
    /// Returns `true` only for [`HostKeyVerdict::Accepted`].
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    /// Returns the rejection cause, or `None` when the key was accepted.
    #[must_use]
    pub const fn cause(&self) -> Option<RejectionCause> {
        match self {
            Self::Accepted { .. } => None,
            Self::Rejected(rejection) => Some(rejection.cause),
        }
    }

    /// Returns the operator-facing detail, or `None` when the key was accepted.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Accepted { .. } => None,
            Self::Rejected(rejection) => Some(&rejection.detail),
        }
    }

    /// Returns safe operator guidance for a rejection.
    #[must_use]
    pub const fn remediation(&self) -> Option<&'static str> {
        match self {
            Self::Accepted { .. } => None,
            Self::Rejected(rejection) => Some(rejection.cause.remediation()),
        }
    }
}

#[derive(Clone, Debug)]
enum HostMatcher {
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
    Patterns(Vec<HostPattern>),
}

#[derive(Clone, Debug)]
struct HostPattern {
    negated: bool,
    pattern: String,
}

/// One parsed `known_hosts` line.
#[derive(Clone, Debug)]
pub struct KnownHostEntry {
    line: usize,
    marker: Option<Marker>,
    matcher: HostMatcher,
    key: HostKey,
}

impl KnownHostEntry {
    /// Returns the one-based line number this entry came from.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// Returns the marker on this line, if any.
    #[must_use]
    pub const fn marker(&self) -> Option<Marker> {
        self.marker
    }

    /// Returns the recorded key.
    #[must_use]
    pub const fn key(&self) -> &HostKey {
        &self.key
    }

    /// Returns `true` when this entry applies to `host_port`.
    #[must_use]
    pub fn matches(&self, host_port: &str) -> bool {
        match &self.matcher {
            HostMatcher::Hashed { salt, hash } => {
                let computed = hmac_sha1(salt, host_port.as_bytes());
                // Hashed entries are compared over a fixed-width digest, so a
                // length check alone cannot leak the salt or the host.
                hash.len() == computed.len()
                    && hash
                        .iter()
                        .zip(computed.iter())
                        .fold(0u8, |accumulator, (left, right)| {
                            accumulator | (left ^ right)
                        })
                        == 0
            }
            HostMatcher::Patterns(patterns) => {
                let mut positive = false;
                for pattern in patterns {
                    if !wildcard_match(pattern.pattern.as_bytes(), host_port.as_bytes()) {
                        continue;
                    }
                    if pattern.negated {
                        // A negation vetoes the whole line, so a later positive
                        // pattern can never resurrect it.
                        return false;
                    }
                    positive = true;
                }
                positive
            }
        }
    }
}

/// A parsed `known_hosts` file.
#[derive(Clone, Debug, Default)]
pub struct KnownHosts {
    entries: Vec<KnownHostEntry>,
}

impl KnownHosts {
    /// Parses a whole `known_hosts` file.
    ///
    /// Blank lines and `#` comments are ignored. Every other line must be
    /// well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`KnownHostsError::LineTooLong`], [`KnownHostsError::Malformed`],
    /// [`KnownHostsError::UnknownMarker`], [`KnownHostsError::MalformedHashedHost`]
    /// or [`KnownHostsError::MalformedKey`], each naming the offending line.
    pub fn parse(text: &str) -> Result<Self, KnownHostsError> {
        let mut entries = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let number = index + 1;
            if raw.len() > MAX_LINE_BYTES {
                return Err(KnownHostsError::LineTooLong(number, raw.len()));
            }
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            entries.push(parse_entry(number, line)?);
        }
        Ok(Self { entries })
    }

    /// Returns every parsed entry in file order.
    #[must_use]
    pub fn entries(&self) -> &[KnownHostEntry] {
        &self.entries
    }

    /// Renders the match key OpenSSH uses: `host` on port 22, `[host]:port`
    /// otherwise. The host part is lowercased, because DNS names are
    /// case-insensitive.
    #[must_use]
    pub fn match_key(host: &str, port: u16) -> String {
        let host = host.to_lowercase();
        if port == 22 {
            host
        } else {
            format!("[{host}]:{port}")
        }
    }

    /// Decides whether `key` may be accepted for `host` on `port`.
    ///
    /// Revocation is evaluated before acceptance, so file order cannot be used
    /// to shadow a `@revoked` line with an earlier accepting one.
    #[must_use]
    pub fn verify(&self, host: &str, port: u16, key: &HostKey) -> HostKeyVerdict {
        let subject = Self::match_key(host, port);
        let mut accepted = None;
        let mut recorded = Vec::new();
        let mut saw_authority = None;
        for entry in self.entries.iter().filter(|entry| entry.matches(&subject)) {
            if entry.marker == Some(Marker::Revoked) && entry.key == *key {
                return HostKeyVerdict::Rejected(HostKeyRejection {
                    cause: RejectionCause::Revoked,
                    detail: format!(
                        "host {subject} key {} is revoked by known_hosts line {}",
                        key.fingerprint(),
                        entry.line
                    ),
                });
            }
            match entry.marker {
                Some(Marker::Revoked) => {}
                Some(Marker::CertAuthority) => saw_authority = Some(entry.line),
                None => {
                    if entry.key == *key {
                        accepted.get_or_insert(entry.line);
                    } else {
                        recorded.push(entry.key.fingerprint());
                    }
                }
            }
        }

        if let Some(line) = accepted {
            return HostKeyVerdict::Accepted { line };
        }
        if !recorded.is_empty() {
            return HostKeyVerdict::Rejected(HostKeyRejection {
                cause: RejectionCause::Mismatch,
                detail: format!(
                    "host {subject} presented {} but known_hosts records {}",
                    key.fingerprint(),
                    recorded.join(", ")
                ),
            });
        }
        if let Some(line) = saw_authority {
            return HostKeyVerdict::Rejected(HostKeyRejection {
                cause: RejectionCause::CertificateAuthorityOnly,
                detail: format!(
                    "host {subject} is only covered by the @cert-authority entry on line {line}, \
                     which cannot authorise the plain host key {}",
                    key.fingerprint()
                ),
            });
        }
        HostKeyVerdict::Rejected(HostKeyRejection {
            cause: RejectionCause::Unknown,
            detail: format!(
                "host {subject} has no known_hosts entry for key {}",
                key.fingerprint()
            ),
        })
    }
}

fn parse_entry(number: usize, line: &str) -> Result<KnownHostEntry, KnownHostsError> {
    let mut fields = line.split_whitespace();
    let first = fields
        .next()
        .ok_or_else(|| KnownHostsError::Malformed(number, "empty line".to_owned()))?;
    let (marker, hosts) = if first.starts_with('@') {
        let marker = match first {
            "@cert-authority" => Marker::CertAuthority,
            "@revoked" => Marker::Revoked,
            other => return Err(KnownHostsError::UnknownMarker(number, other.to_owned())),
        };
        let hosts = fields.next().ok_or_else(|| {
            KnownHostsError::Malformed(number, "marker without a host field".to_owned())
        })?;
        (Some(marker), hosts)
    } else {
        (None, first)
    };

    let algorithm = fields
        .next()
        .ok_or_else(|| KnownHostsError::Malformed(number, "missing key algorithm".to_owned()))?;
    let encoded = fields
        .next()
        .ok_or_else(|| KnownHostsError::Malformed(number, "missing key blob".to_owned()))?;
    let key = HostKey::parse(algorithm, encoded).map_err(|error| annotate(number, error))?;

    let matcher = if let Some(rest) = hosts.strip_prefix(HASH_MAGIC) {
        let (salt, hash) = rest.split_once('|').ok_or_else(|| {
            KnownHostsError::MalformedHashedHost(number, "missing salt separator".to_owned())
        })?;
        let salt = base64_decode(salt).ok_or_else(|| {
            KnownHostsError::MalformedHashedHost(number, "salt is not base64".to_owned())
        })?;
        let hash = base64_decode(hash).ok_or_else(|| {
            KnownHostsError::MalformedHashedHost(number, "hash is not base64".to_owned())
        })?;
        if hash.len() != 20 {
            return Err(KnownHostsError::MalformedHashedHost(
                number,
                format!("hash is {} bytes, HMAC-SHA1 is 20", hash.len()),
            ));
        }
        HostMatcher::Hashed { salt, hash }
    } else {
        let mut patterns = Vec::new();
        for element in hosts.split(',') {
            let (negated, pattern) = element
                .strip_prefix('!')
                .map_or((false, element), |rest| (true, rest));
            if pattern.is_empty() {
                return Err(KnownHostsError::Malformed(
                    number,
                    "empty host pattern".to_owned(),
                ));
            }
            patterns.push(HostPattern {
                negated,
                pattern: pattern.to_lowercase(),
            });
        }
        HostMatcher::Patterns(patterns)
    };

    Ok(KnownHostEntry {
        line: number,
        marker,
        matcher,
        key,
    })
}

fn annotate(number: usize, error: KnownHostsError) -> KnownHostsError {
    match error {
        KnownHostsError::MalformedKey(detail) => KnownHostsError::Malformed(number, detail),
        other => other,
    }
}

fn wildcard_match(pattern: &[u8], value: &[u8]) -> bool {
    let mut pattern_index = 0usize;
    let mut value_index = 0usize;
    let mut star: Option<usize> = None;
    let mut resume = 0usize;
    while value_index < value.len() {
        match pattern.get(pattern_index) {
            Some(b'*') => {
                star = Some(pattern_index);
                resume = value_index;
                pattern_index += 1;
            }
            Some(b'?') => {
                pattern_index += 1;
                value_index += 1;
            }
            Some(byte) if byte.eq_ignore_ascii_case(&value[value_index]) => {
                pattern_index += 1;
                value_index += 1;
            }
            _ => match star {
                Some(position) => {
                    pattern_index = position + 1;
                    resume += 1;
                    value_index = resume;
                }
                None => return false,
            },
        }
    }
    pattern[pattern_index..].iter().all(|&byte| byte == b'*')
}

/// Every way a `known_hosts` file can fail to parse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KnownHostsError {
    /// A line exceeded the 8192-byte ceiling.
    LineTooLong(usize, usize),
    /// A line was structurally invalid.
    Malformed(usize, String),
    /// A line began with `@` but not with a marker this parser knows.
    UnknownMarker(usize, String),
    /// A `|1|` hashed host field was invalid.
    MalformedHashedHost(usize, String),
    /// A key field was invalid, before a line number was known.
    MalformedKey(String),
}

impl fmt::Display for KnownHostsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTooLong(line, length) => write!(
                formatter,
                "known_hosts line {line} is {length} bytes, limit is {MAX_LINE_BYTES}"
            ),
            Self::Malformed(line, detail) => {
                write!(formatter, "known_hosts line {line} is malformed: {detail}")
            }
            Self::UnknownMarker(line, marker) => {
                write!(
                    formatter,
                    "known_hosts line {line} has unknown marker {marker}"
                )
            }
            Self::MalformedHashedHost(line, detail) => write!(
                formatter,
                "known_hosts line {line} has a malformed hashed host: {detail}"
            ),
            Self::MalformedKey(detail) => write!(formatter, "malformed host key: {detail}"),
        }
    }
}

impl Error for KnownHostsError {}
