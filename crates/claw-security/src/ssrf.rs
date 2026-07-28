//! Network-free SSRF target validation and DNS/redirect revalidation policy.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use url::{Host, Url};

/// Exact-host allowlist with no suffix or substring matching.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAllowlist {
    hosts: BTreeSet<String>,
}

impl HostAllowlist {
    /// Validates and canonicalizes exact host entries.
    ///
    /// # Errors
    ///
    /// - [`TargetError::InvalidHost`] when an entry is neither a parsable IP
    ///   literal nor a DNS name of one to 253 bytes with at least one dot and
    ///   labels of one to 63 alphanumeric-or-hyphen bytes that neither start
    ///   nor end with a hyphen.
    /// - [`TargetError::BlockedHost`] when an entry is `localhost` or ends in
    ///   `.localhost`.
    /// - [`TargetError::BlockedAddress`] when an IP-literal entry is in a
    ///   loopback, private, link-local, or otherwise special-use range;
    ///   allowlisting one would defeat the point of the allowlist.
    pub fn new<I, S>(hosts: I) -> Result<Self, TargetError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let hosts = hosts
            .into_iter()
            .map(|host| canonicalize_host_entry(host.as_ref()))
            .collect::<Result<_, _>>()?;
        Ok(Self { hosts })
    }

    #[must_use = "an ignored allowlist check silently admits an unlisted host"]
    fn contains(&self, host: &str) -> bool {
        self.hosts.contains(host)
    }
}

/// Destination restriction applied in addition to public-address checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetPolicy {
    /// Any syntactically valid public Internet target.
    PublicInternet,
    /// Only exact canonical hosts in the set; subdomains are not implied.
    ExactHosts(HostAllowlist),
}

/// Canonical target host without leaking `url` framework types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetHost {
    /// Canonical lowercase ASCII/IDNA DNS name.
    Dns(String),
    /// Canonical IP literal.
    Ip(IpAddr),
}

impl TargetHost {
    /// Returns a canonical textual host.
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::Dns(host) => host.clone(),
            Self::Ip(address) => address.to_string(),
        }
    }
}

/// Canonical HTTP(S) target that still requires caller-supplied DNS validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedTarget {
    canonical_url: String,
    host: TargetHost,
    port: u16,
}

impl ValidatedTarget {
    /// Canonical URL for a transport adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical_url
    }

    /// Canonical validated host.
    #[must_use]
    pub const fn host(&self) -> &TargetHost {
        &self.host
    }

    /// Explicit or scheme-default port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Validates every caller-resolved address immediately before connection.
    ///
    /// Call this for every connection attempt, not only during configuration,
    /// so DNS rebinding cannot reuse a prior result.
    ///
    /// # Errors
    ///
    /// - [`ResolutionError::NoAddresses`] when `addresses` is empty; an empty
    ///   answer is a refusal, never an implicit pass.
    /// - [`ResolutionError::BlockedAddress`] when *any* answer is loopback,
    ///   private, link-local, or otherwise special-use. Every address is
    ///   checked, because a transport may fall back to any of them.
    /// - [`ResolutionError::LiteralAddressMismatch`] when the target is an IP
    ///   literal and an answer is a different address.
    #[must_use = "an ignored resolution check leaves the connection open to DNS rebinding"]
    pub fn validate_resolution(&self, addresses: &[IpAddr]) -> Result<(), ResolutionError> {
        if addresses.is_empty() {
            return Err(ResolutionError::NoAddresses);
        }
        for address in addresses {
            validate_public_address(*address).map_err(|_| ResolutionError::BlockedAddress)?;
            if let TargetHost::Ip(expected) = self.host
                && *address != expected
            {
                return Err(ResolutionError::LiteralAddressMismatch);
            }
        }
        Ok(())
    }
}

/// Parses, canonicalizes, and validates one HTTP(S) destination.
///
/// # Errors
///
/// - [`TargetError::InvalidUrl`] when `input` contains whitespace or control
///   characters, has no `://`, or the URL parser rejects it.
/// - [`TargetError::UnsupportedScheme`] for any scheme other than `http` or
///   `https`, checked on the raw text as well as the parsed URL.
/// - [`TargetError::MissingHost`] when the authority is empty.
/// - [`TargetError::UserInfoForbidden`] when the authority carries `@` or the
///   parsed URL has a username or password, which could disguise the real host.
/// - [`TargetError::FragmentForbidden`] when the URL carries a fragment.
/// - [`TargetError::AmbiguousIpLiteral`] when the authority is percent-encoded,
///   or the host is a decimal/octal/hexadecimal shorthand for an address that
///   is not a canonical dotted quad.
/// - [`TargetError::InvalidHost`] when the DNS name fails the label rules, or
///   an unbracketed authority contains more than one colon.
/// - [`TargetError::BlockedHost`] when the host is `localhost` or ends in
///   `.localhost`.
/// - [`TargetError::BlockedAddress`] when an IP-literal host is loopback,
///   private, link-local, or otherwise special-use.
/// - [`TargetError::InvalidPort`] when the port text is empty, not all digits,
///   zero, or the scheme has no default.
/// - [`TargetError::HostNotAllowlisted`] when `policy` is
///   [`TargetPolicy::ExactHosts`] and the canonical host is not an exact
///   member; no suffix or subdomain matching is implied.
pub fn validate_target(input: &str, policy: &TargetPolicy) -> Result<ValidatedTarget, TargetError> {
    validate_raw_authority(input)?;
    if input.chars().any(char::is_whitespace) || input.chars().any(char::is_control) {
        return Err(TargetError::InvalidUrl);
    }
    let mut url = Url::parse(input).map_err(|_| TargetError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(TargetError::UnsupportedScheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(TargetError::UserInfoForbidden);
    }
    if url.fragment().is_some() {
        return Err(TargetError::FragmentForbidden);
    }
    let host = match url.host().ok_or(TargetError::MissingHost)? {
        Host::Domain(domain) => {
            let canonical = canonicalize_dns_name(domain)?;
            url.set_host(Some(&canonical))
                .map_err(|_| TargetError::InvalidHost)?;
            TargetHost::Dns(canonical)
        }
        Host::Ipv4(address) => {
            validate_public_address(IpAddr::V4(address))?;
            TargetHost::Ip(IpAddr::V4(address))
        }
        Host::Ipv6(address) => {
            validate_public_address(IpAddr::V6(address))?;
            TargetHost::Ip(IpAddr::V6(address))
        }
    };
    let host_text = host.as_str();
    if let TargetPolicy::ExactHosts(allowlist) = policy
        && !allowlist.contains(&host_text)
    {
        return Err(TargetError::HostNotAllowlisted);
    }
    let port = url
        .port_or_known_default()
        .ok_or(TargetError::InvalidPort)?;
    if port == 0 {
        return Err(TargetError::InvalidPort);
    }
    Ok(ValidatedTarget {
        canonical_url: url.into(),
        host,
        port,
    })
}

/// Resolves and revalidates a redirect destination without performing I/O.
///
/// The returned target still requires `validate_resolution` on every DNS answer.
///
/// # Errors
///
/// Returns [`TargetError::InvalidUrl`] when `current` no longer parses or when
/// `location` cannot be joined onto it. Otherwise the joined destination is put
/// through [`validate_target`] from scratch and can fail with any of its
/// errors: a redirect gets no credit for the hop that produced it, so it cannot
/// be used to reach a blocked address or an unlisted host.
pub fn validate_redirect(
    current: &ValidatedTarget,
    location: &str,
    policy: &TargetPolicy,
) -> Result<ValidatedTarget, TargetError> {
    let base = Url::parse(current.as_str()).map_err(|_| TargetError::InvalidUrl)?;
    let destination = base.join(location).map_err(|_| TargetError::InvalidUrl)?;
    validate_target(destination.as_str(), policy)
}

fn canonicalize_host_entry(value: &str) -> Result<String, TargetError> {
    if let Ok(address) = IpAddr::from_str(value) {
        validate_public_address(address)?;
        return Ok(address.to_string());
    }
    canonicalize_dns_name(value)
}

fn canonicalize_dns_name(value: &str) -> Result<String, TargetError> {
    let canonical = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    if canonical.is_empty() || canonical.len() > 253 || !canonical.contains('.') {
        return Err(TargetError::InvalidHost);
    }
    if canonical == "localhost" || canonical.ends_with(".localhost") {
        return Err(TargetError::BlockedHost);
    }
    for label in canonical.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(TargetError::InvalidHost);
        }
    }
    Ok(canonical)
}

fn validate_raw_authority(input: &str) -> Result<(), TargetError> {
    let marker = input.find("://").ok_or(TargetError::InvalidUrl)?;
    let scheme = &input[..marker];
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(TargetError::UnsupportedScheme);
    }
    let remainder = &input[marker + 3..];
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() {
        return Err(TargetError::MissingHost);
    }
    if authority.contains('@') {
        return Err(TargetError::UserInfoForbidden);
    }
    if authority.contains('%') {
        return Err(TargetError::AmbiguousIpLiteral);
    }
    let raw_host = if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed.find(']').ok_or(TargetError::InvalidHost)?;
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        if !suffix.is_empty()
            && (!suffix.starts_with(':')
                || suffix.len() == 1
                || !suffix[1..].bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(TargetError::InvalidPort);
        }
        host
    } else {
        let colon_count = authority.bytes().filter(|byte| *byte == b':').count();
        if colon_count > 1 {
            return Err(TargetError::InvalidHost);
        }
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, port)| {
                if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                    ""
                } else {
                    host
                }
            })
    };
    if raw_host.is_empty() {
        return Err(TargetError::InvalidPort);
    }
    if looks_like_noncanonical_ipv4(raw_host) && Ipv4Addr::from_str(raw_host).is_err() {
        return Err(TargetError::AmbiguousIpLiteral);
    }
    Ok(())
}

fn looks_like_noncanonical_ipv4(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.bytes().all(|byte| byte.is_ascii_digit()) {
        return true;
    }
    let mut saw_numeric_label = false;
    for label in host.split('.') {
        let numeric = label.bytes().all(|byte| byte.is_ascii_digit());
        let hexadecimal = label
            .strip_prefix("0x")
            .or_else(|| label.strip_prefix("0X"))
            .is_some_and(|digits| {
                !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
        if !numeric && !hexadecimal {
            return false;
        }
        saw_numeric_label = true;
    }
    saw_numeric_label
}

fn validate_public_address(address: IpAddr) -> Result<(), TargetError> {
    match address {
        IpAddr::V4(address) if blocked_ipv4(address) => Err(TargetError::BlockedAddress),
        IpAddr::V6(address) if blocked_ipv6(address) => Err(TargetError::BlockedAddress),
        _ => Ok(()),
    }
}

#[must_use = "an ignored address check silently permits a private-range connection"]
fn blocked_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _d] = address.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && matches!(b, 18 | 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
}

#[must_use = "an ignored address check silently permits a private-range connection"]
fn blocked_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.to_ipv4_mapped().is_some()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || segments[0] & 0xffc0 == 0xfec0
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0])
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1)
        || (segments[0] == 0x0100 && segments[1..4] == [0, 0, 0])
        || (segments[0] == 0x2001 && segments[1] <= 0x01ff)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x2002
        || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
        || segments[0] == 0x5f00
        || segments[..6] == [0, 0, 0, 0, 0, 0]
}

/// Invalid or forbidden target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetError {
    /// URL parser rejected the value.
    InvalidUrl,
    /// Only HTTP and HTTPS are accepted.
    UnsupportedScheme,
    /// Host is absent.
    MissingHost,
    /// Username/password URL components are forbidden.
    UserInfoForbidden,
    /// Fragments are forbidden at this request boundary.
    FragmentForbidden,
    /// Port is malformed or zero.
    InvalidPort,
    /// DNS name or literal syntax is invalid.
    InvalidHost,
    /// Hostname is intrinsically local.
    BlockedHost,
    /// Address belongs to a non-public or special-use range.
    BlockedAddress,
    /// Numeric/hex/octal shorthand or encoded host was detected.
    AmbiguousIpLiteral,
    /// Exact-host policy rejected the canonical host.
    HostNotAllowlisted,
}

impl Display for TargetError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidUrl => "invalid target URL",
            Self::UnsupportedScheme => "unsupported target scheme",
            Self::MissingHost => "target host is required",
            Self::UserInfoForbidden => "target userinfo is forbidden",
            Self::FragmentForbidden => "target fragment is forbidden",
            Self::InvalidPort => "invalid target port",
            Self::InvalidHost => "invalid target host",
            Self::BlockedHost => "target host is blocked",
            Self::BlockedAddress => "target address is blocked",
            Self::AmbiguousIpLiteral => "ambiguous IP literal is forbidden",
            Self::HostNotAllowlisted => "target host is not allowlisted",
        };
        formatter.write_str(message)
    }
}

impl Error for TargetError {}

/// DNS result rejected before transport connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionError {
    /// Resolver returned no answers.
    NoAddresses,
    /// At least one answer is private or special-use.
    BlockedAddress,
    /// An IP-literal target resolved to a different address.
    LiteralAddressMismatch,
}

impl Display for ResolutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAddresses => formatter.write_str("DNS resolution returned no addresses"),
            Self::BlockedAddress => {
                formatter.write_str("DNS resolution returned a blocked address")
            }
            Self::LiteralAddressMismatch => {
                formatter.write_str("resolved address does not match target literal")
            }
        }
    }
}

impl Error for ResolutionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn public() -> TargetPolicy {
        TargetPolicy::PublicInternet
    }

    #[test]
    fn accepts_and_canonicalizes_dns_idna_and_trailing_dot() {
        let target = validate_target("HTTPS://BÜCHER.example./a?q=1", &public()).expect("valid");
        assert_eq!(
            target.host(),
            &TargetHost::Dns("xn--bcher-kva.example".into())
        );
        assert_eq!(target.port(), 443);
        assert!(!target.as_str().contains("BÜCHER"));
    }

    #[test]
    fn rejects_schemes_userinfo_fragments_and_invalid_ports() {
        for value in [
            "file:///etc/passwd",
            "http://user@example.com/",
            "http://example.com/#fragment",
            "http://example.com:0/",
            "http://example.com:99999/",
        ] {
            assert!(validate_target(value, &public()).is_err(), "{value}");
        }
    }

    #[test]
    fn rejects_decimal_octal_hex_and_short_ipv4_forms() {
        for value in [
            "http://2130706433/",
            "http://0177.0.0.1/",
            "http://0x7f.0x0.0x0.0x1/",
            "http://127.1/",
            "http://0x7f000001/",
        ] {
            assert_eq!(
                validate_target(value, &public()),
                Err(TargetError::AmbiguousIpLiteral),
                "{value}"
            );
        }
    }

    #[test]
    fn blocks_localhost_private_documentation_and_mapped_ranges() {
        for value in [
            "http://localhost/",
            "http://api.localhost./",
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://169.254.169.254/",
            "http://192.0.2.1/",
            "http://198.51.100.1/",
            "http://203.0.113.1/",
            "http://[::1]/",
            "http://[fc00::1]/",
            "http://[fe80::1]/",
            "http://[fec0::1]/",
            "http://[2001:db8::1]/",
            "http://[::ffff:8.8.8.8]/",
            "http://[64:ff9b::a9fe:a9fe]/",
            "http://[ff02::1]/",
        ] {
            assert!(validate_target(value, &public()).is_err(), "{value}");
        }
    }

    #[test]
    fn exact_allowlist_has_no_suffix_confusion() {
        let policy = TargetPolicy::ExactHosts(
            HostAllowlist::new(["api.example.com"]).expect("valid allowlist"),
        );
        assert!(validate_target("https://api.example.com/data", &policy).is_ok());
        for value in [
            "https://api.example.com.evil.test/",
            "https://evil-api.example.com/",
            "https://sub.api.example.com/",
        ] {
            assert_eq!(
                validate_target(value, &policy),
                Err(TargetError::HostNotAllowlisted)
            );
        }
    }

    #[test]
    fn validates_every_dns_answer_and_rebinding_attempt() {
        let target = validate_target("https://example.com/", &public()).expect("valid");
        assert_eq!(
            target.validate_resolution(&[
                "8.8.8.8".parse().expect("IP"),
                "2606:4700:4700::1111".parse().expect("IP"),
            ]),
            Ok(())
        );
        assert_eq!(
            target.validate_resolution(&[
                "8.8.8.8".parse().expect("IP"),
                "10.0.0.1".parse().expect("IP"),
            ]),
            Err(ResolutionError::BlockedAddress)
        );
        assert_eq!(
            target.validate_resolution(&["127.0.0.1".parse().expect("IP")]),
            Err(ResolutionError::BlockedAddress),
            "a later resolution is revalidated against rebinding"
        );
    }

    #[test]
    fn redirects_are_reparsed_and_require_fresh_dns_validation() {
        let current = validate_target("https://example.com/start", &public()).expect("valid");
        let relative = validate_redirect(&current, "/next", &public()).expect("valid redirect");
        assert_eq!(relative.host(), current.host());
        assert_eq!(
            validate_redirect(&current, "http://127.0.0.1/admin", &public()),
            Err(TargetError::BlockedAddress)
        );
        let external =
            validate_redirect(&current, "https://example.net/next", &public()).expect("valid");
        assert_eq!(
            external.validate_resolution(&["10.0.0.2".parse().expect("IP")]),
            Err(ResolutionError::BlockedAddress)
        );
    }
}
