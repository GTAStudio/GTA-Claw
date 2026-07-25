//! Outbound destinations, parsed and checked once, then carried as objects.
//!
//! Three sibling crates shipped the same server-side request forgery bug: they
//! validated a hostname, then handed the *hostname* to the transport, which
//! looked it up again. A second DNS answer — or a second parse — silently moved
//! the request somewhere else.
//!
//! This module removes the second lookup. [`EgressGuard::resolve`] parses the
//! destination, checks the host against policy, resolves it, and checks every
//! address that came back. What it returns is a [`ResolvedEndpoint`] holding
//! those exact [`IpAddr`] values. Transports connect to
//! [`ResolvedEndpoint::addresses`]; they are never given the host as something
//! to resolve.
//!
//! `ResolvedEndpoint` has no public constructor. The only way to obtain one is
//! to pass the guard, which is what makes the rule structural rather than a
//! convention someone can forget.

use std::fmt::{self, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use url::Url;

use super::BoxFuture;
use super::clock::{Clock, MonotonicInstant};
use super::error::SubsystemError;

/// The default age past which a resolution is no longer trusted.
pub const DEFAULT_MAX_RESOLUTION_AGE: Duration = Duration::from_secs(30);

/// The transport an endpoint will be reached over.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Scheme {
    /// TLS.
    Https,
    /// Cleartext, refused unless the policy explicitly permits it.
    Http,
}

impl Scheme {
    /// Returns the scheme as it appears in a URL.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
        }
    }

    /// Returns the port used when a URL does not specify one.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Https => 443,
            Self::Http => 80,
        }
    }
}

impl Display for Scheme {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A destination that has been parsed but not yet checked or resolved.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EndpointRequest {
    scheme: Scheme,
    host: String,
    port: u16,
}

impl EndpointRequest {
    /// Parses an absolute URL into its scheme, host and port.
    ///
    /// Only the parts that decide *where bytes go* are kept. Path, query,
    /// fragment and userinfo are deliberately discarded, and userinfo is
    /// rejected outright rather than dropped, because a URL carrying
    /// credentials is nearly always an attempt to smuggle an authority past a
    /// naive parser.
    ///
    /// # Errors
    ///
    /// Returns [`EgressDenial`] when the URL will not parse, uses a scheme other
    /// than `http` or `https`, carries userinfo, or has no host.
    pub fn parse(url: &str) -> Result<Self, EgressDenial> {
        let parsed = Url::parse(url).map_err(|error| EgressDenial::InvalidUrl {
            url: url.to_owned(),
            reason: error.to_string(),
        })?;

        let scheme = match parsed.scheme() {
            "https" => Scheme::Https,
            "http" => Scheme::Http,
            other => {
                return Err(EgressDenial::UnsupportedScheme {
                    scheme: other.to_owned(),
                });
            }
        };

        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(EgressDenial::CredentialsInUrl {
                url: url.to_owned(),
            });
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| EgressDenial::MissingHost {
                url: url.to_owned(),
            })?
            .to_ascii_lowercase();

        if host.is_empty() {
            return Err(EgressDenial::MissingHost {
                url: url.to_owned(),
            });
        }

        Ok(Self {
            scheme,
            port: parsed.port().unwrap_or_else(|| scheme.default_port()),
            host,
        })
    }

    /// Builds a request from already separated parts.
    ///
    /// # Errors
    ///
    /// Returns [`EgressDenial::MissingHost`] when `host` is empty.
    pub fn new(scheme: Scheme, host: &str, port: u16) -> Result<Self, EgressDenial> {
        if host.is_empty() {
            return Err(EgressDenial::MissingHost { url: String::new() });
        }

        Ok(Self {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// Returns the scheme.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Returns the lowercased host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the port, defaulted from the scheme when the URL omitted it.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl Display for EndpointRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// One entry in the egress allowlist.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum HostPattern {
    /// Matches exactly one host.
    Exact(String),
    /// Matches any strict subdomain of the held suffix.
    ///
    /// `Suffix("example.com")` matches `api.example.com` but matches neither
    /// `example.com` itself nor `notexample.com`, because matching is done on
    /// label boundaries.
    Suffix(String),
}

impl HostPattern {
    /// Parses `*.example.com` into a suffix pattern and anything else into an
    /// exact pattern, lowercasing either way.
    #[must_use]
    pub fn parse(pattern: &str) -> Self {
        let lowered = pattern.to_ascii_lowercase();

        if let Some(suffix) = lowered.strip_prefix("*.") {
            return Self::Suffix(suffix.to_owned());
        }

        Self::Exact(lowered)
    }

    /// Returns whether `host` matches.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(expected) => expected == host,
            Self::Suffix(suffix) => host
                .len()
                .checked_sub(suffix.len())
                .is_some_and(|boundary| {
                    boundary > 0
                        && host.as_bytes().get(boundary - 1) == Some(&b'.')
                        && &host[boundary..] == suffix
                }),
        }
    }
}

/// What outbound traffic is permitted.
///
/// The policy starts closed: a freshly created policy allows no host at all.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EgressPolicy {
    allowed: Vec<HostPattern>,
    allow_plain_http: bool,
    allow_private_addresses: bool,
    max_resolution_age: Option<Duration>,
}

impl EgressPolicy {
    /// Creates a policy that denies everything.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Allows hosts matching `pattern`.
    #[must_use]
    pub fn allow_host(mut self, pattern: HostPattern) -> Self {
        self.allowed.push(pattern);
        self
    }

    /// Permits cleartext HTTP.
    #[must_use]
    pub fn allow_plain_http(mut self) -> Self {
        self.allow_plain_http = true;
        self
    }

    /// Permits loopback and other non-public addresses.
    ///
    /// This exists so a developer can point the daemon at a provider running on
    /// `127.0.0.1`. It must not be enabled in a deployed configuration: it is
    /// exactly the switch that turns a URL-taking feature into a port scanner.
    #[must_use]
    pub fn allow_private_addresses(mut self) -> Self {
        self.allow_private_addresses = true;
        self
    }

    /// Overrides how long a resolution stays usable.
    #[must_use]
    pub fn with_max_resolution_age(mut self, age: Duration) -> Self {
        self.max_resolution_age = Some(age);
        self
    }

    /// Returns how long a resolution stays usable.
    #[must_use]
    pub fn max_resolution_age(&self) -> Duration {
        self.max_resolution_age
            .unwrap_or(DEFAULT_MAX_RESOLUTION_AGE)
    }

    /// Returns whether `host` is on the allowlist.
    #[must_use]
    pub fn permits_host(&self, host: &str) -> bool {
        self.allowed.iter().any(|pattern| pattern.matches(host))
    }
}

/// Why an outbound destination was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EgressDenial {
    /// The URL would not parse.
    InvalidUrl {
        /// The URL as supplied.
        url: String,
        /// The parser's explanation.
        reason: String,
    },
    /// The URL used a scheme other than `http` or `https`.
    UnsupportedScheme {
        /// The scheme that was supplied.
        scheme: String,
    },
    /// The URL carried a username or password.
    CredentialsInUrl {
        /// The URL as supplied.
        url: String,
    },
    /// The URL had no host component.
    MissingHost {
        /// The URL as supplied.
        url: String,
    },
    /// Cleartext was requested but the policy requires TLS.
    PlainHttpRefused {
        /// The host that was requested.
        host: String,
    },
    /// The host is not on the allowlist.
    HostNotAllowed {
        /// The host that was requested.
        host: String,
    },
    /// Name resolution failed.
    LookupFailed {
        /// The host that was being resolved.
        host: String,
        /// The resolver's explanation.
        detail: String,
    },
    /// Name resolution returned nothing.
    NoAddresses {
        /// The host that was being resolved.
        host: String,
    },
    /// An address the host resolved to is not permitted.
    ///
    /// A host is refused when *any* of its addresses is blocked, not merely when
    /// all of them are. Filtering instead of refusing would let a split-horizon
    /// answer choose the interesting address on a later attempt.
    BlockedAddress {
        /// The host that was being resolved.
        host: String,
        /// The offending address.
        address: IpAddr,
        /// What kind of address it is.
        classification: &'static str,
    },
    /// The resolution is too old to act on.
    StaleResolution {
        /// The host the stale resolution belongs to.
        host: String,
        /// How long ago it was resolved.
        age: Duration,
        /// The configured limit.
        limit: Duration,
    },
}

impl Display for EgressDenial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl { url, reason } => {
                write!(formatter, "cannot parse destination {url:?}: {reason}")
            }
            Self::UnsupportedScheme { scheme } => {
                write!(formatter, "unsupported destination scheme: {scheme}")
            }
            Self::CredentialsInUrl { url } => {
                write!(
                    formatter,
                    "destination {url:?} carries embedded credentials"
                )
            }
            Self::MissingHost { url } => write!(formatter, "destination {url:?} has no host"),
            Self::PlainHttpRefused { host } => {
                write!(formatter, "cleartext http to {host} is not permitted")
            }
            Self::HostNotAllowed { host } => {
                write!(formatter, "host {host} is not on the egress allowlist")
            }
            Self::LookupFailed { host, detail } => {
                write!(formatter, "cannot resolve {host}: {detail}")
            }
            Self::NoAddresses { host } => write!(formatter, "{host} resolved to no addresses"),
            Self::BlockedAddress {
                host,
                address,
                classification,
            } => write!(
                formatter,
                "{host} resolved to {address}, which is a {classification} address"
            ),
            Self::StaleResolution { host, age, limit } => write!(
                formatter,
                "the resolution of {host} is {}ms old, past the {}ms limit",
                age.as_millis(),
                limit.as_millis()
            ),
        }
    }
}

impl std::error::Error for EgressDenial {}

/// A destination that has been checked, carrying the addresses that were checked.
///
/// There is no public constructor: the only source is [`EgressGuard::resolve`].
/// A transport handed one of these must connect to [`Self::addresses`]. It must
/// not resolve [`Self::host`] — that value exists for TLS server-name
/// indication and for the `Host` header, not for name resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedEndpoint {
    scheme: Scheme,
    host: String,
    port: u16,
    addresses: Vec<IpAddr>,
    resolved_at: MonotonicInstant,
}

impl ResolvedEndpoint {
    /// Returns the scheme.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Returns the host, for TLS server-name indication and the `Host` header.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the addresses that were checked, in resolver order.
    ///
    /// A transport must connect to one of these and nothing else.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Returns when the check was performed.
    #[must_use]
    pub const fn resolved_at(&self) -> MonotonicInstant {
        self.resolved_at
    }

    /// Returns `host:port`, for logging and for the `Host` header.
    #[must_use]
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Returns how old the resolution is at `now`.
    #[must_use]
    pub fn age_at(&self, now: MonotonicInstant) -> Duration {
        now.saturating_since(self.resolved_at)
    }

    /// Checks that this resolution is still young enough to act on.
    ///
    /// # Errors
    ///
    /// Returns [`EgressDenial::StaleResolution`] when the resolution is older
    /// than `limit`.
    pub fn ensure_fresh(&self, now: MonotonicInstant, limit: Duration) -> Result<(), EgressDenial> {
        let age = self.age_at(now);

        if age > limit {
            return Err(EgressDenial::StaleResolution {
                host: self.host.clone(),
                age,
                limit,
            });
        }

        Ok(())
    }
}

impl Display for ResolvedEndpoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// Name resolution, as a port.
///
/// The daemon implements this over the operating system resolver; tests
/// implement it over a script, which is how the rebinding regression below can
/// be written at all.
pub trait DnsPort: Send + Sync + 'static {
    /// Resolves `host` to addresses.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] describing why resolution failed.
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, SubsystemError>>;
}

/// Turns a destination into a [`ResolvedEndpoint`], or refuses it.
#[derive(Clone)]
pub struct EgressGuard {
    policy: EgressPolicy,
    dns: Arc<dyn DnsPort>,
    clock: Arc<dyn Clock>,
}

impl EgressGuard {
    /// Creates a guard.
    #[must_use]
    pub fn new(policy: EgressPolicy, dns: Arc<dyn DnsPort>, clock: Arc<dyn Clock>) -> Self {
        Self { policy, dns, clock }
    }

    /// Returns the policy in force.
    #[must_use]
    pub const fn policy(&self) -> &EgressPolicy {
        &self.policy
    }

    /// Parses, checks and resolves `url` in one step.
    ///
    /// # Errors
    ///
    /// Returns the [`EgressDenial`] that stopped it.
    pub async fn resolve_url(&self, url: &str) -> Result<ResolvedEndpoint, EgressDenial> {
        self.resolve(&EndpointRequest::parse(url)?).await
    }

    /// Checks and resolves an already parsed destination.
    ///
    /// The order matters: scheme and allowlist are cheap and are checked before
    /// anything is sent to the resolver, so a denied host is never even looked
    /// up.
    ///
    /// # Errors
    ///
    /// Returns the [`EgressDenial`] that stopped it.
    pub async fn resolve(
        &self,
        request: &EndpointRequest,
    ) -> Result<ResolvedEndpoint, EgressDenial> {
        if request.scheme == Scheme::Http && !self.policy.allow_plain_http {
            return Err(EgressDenial::PlainHttpRefused {
                host: request.host.clone(),
            });
        }

        if !self.policy.permits_host(&request.host) {
            return Err(EgressDenial::HostNotAllowed {
                host: request.host.clone(),
            });
        }

        let addresses = if let Ok(literal) = request.host.parse::<IpAddr>() {
            vec![literal]
        } else {
            self.dns
                .lookup(&request.host)
                .await
                .map_err(|error| EgressDenial::LookupFailed {
                    host: request.host.clone(),
                    detail: error.to_string(),
                })?
        };

        if addresses.is_empty() {
            return Err(EgressDenial::NoAddresses {
                host: request.host.clone(),
            });
        }

        if !self.policy.allow_private_addresses {
            for address in &addresses {
                if let Some(classification) = classify(*address) {
                    return Err(EgressDenial::BlockedAddress {
                        host: request.host.clone(),
                        address: *address,
                        classification,
                    });
                }
            }
        }

        Ok(ResolvedEndpoint {
            scheme: request.scheme,
            host: request.host.clone(),
            port: request.port,
            addresses,
            resolved_at: self.clock.now(),
        })
    }
}

impl fmt::Debug for EgressGuard {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EgressGuard")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Returns why an address is not publicly routable, or `None` when it is.
fn classify(address: IpAddr) -> Option<&'static str> {
    match address {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(address: Ipv4Addr) -> Option<&'static str> {
    let octets = address.octets();

    if address.is_unspecified() {
        return Some("unspecified");
    }
    if address.is_loopback() {
        return Some("loopback");
    }
    if address.is_private() {
        return Some("private");
    }
    if address.is_link_local() {
        return Some("link-local");
    }
    if address.is_broadcast() {
        return Some("broadcast");
    }
    if address.is_multicast() {
        return Some("multicast");
    }
    if octets[0] == 100 && (64..128).contains(&octets[1]) {
        return Some("carrier-grade NAT");
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return Some("IETF protocol assignment");
    }
    if octets[0] >= 240 {
        return Some("reserved");
    }

    None
}

fn classify_v6(address: Ipv6Addr) -> Option<&'static str> {
    if address.is_unspecified() {
        return Some("unspecified");
    }
    if address.is_loopback() {
        return Some("loopback");
    }
    if address.is_multicast() {
        return Some("multicast");
    }
    if let Some(embedded) = address.to_ipv4() {
        return classify_v4(embedded).or(Some("IPv4-in-IPv6"));
    }

    let segments = address.segments();

    if segments[0] & 0xfe00 == 0xfc00 {
        return Some("unique-local");
    }
    if segments[0] & 0xffc0 == 0xfe80 {
        return Some("link-local");
    }

    None
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::{
        BoxFuture, Clock, DnsPort, EgressDenial, EgressGuard, EgressPolicy, EndpointRequest,
        HostPattern, MonotonicInstant, Scheme, SubsystemError, classify,
    };
    use crate::composition::id::SubsystemId;

    #[derive(Debug, Default)]
    struct StepClock(AtomicUsize);

    impl Clock for StepClock {
        fn now(&self) -> MonotonicInstant {
            MonotonicInstant::from_millis(self.0.fetch_add(1, Ordering::SeqCst) as u64)
        }
    }

    #[derive(Debug, Default)]
    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now(&self) -> MonotonicInstant {
            MonotonicInstant::from_millis(self.0)
        }
    }

    /// Answers each lookup from a script, so a second lookup can return a
    /// different address than the first.
    #[derive(Debug)]
    struct ScriptedDns {
        answers: Vec<Vec<IpAddr>>,
        calls: AtomicUsize,
    }

    impl ScriptedDns {
        fn new(answers: Vec<Vec<&str>>) -> Self {
            Self {
                answers: answers
                    .into_iter()
                    .map(|answer| {
                        answer
                            .into_iter()
                            .map(|address| address.parse().expect("valid address"))
                            .collect()
                    })
                    .collect(),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl DnsPort for ScriptedDns {
        fn lookup<'a>(
            &'a self,
            host: &'a str,
        ) -> BoxFuture<'a, Result<Vec<IpAddr>, SubsystemError>> {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            let answer = self.answers.get(index).cloned();

            Box::pin(async move {
                answer.ok_or_else(|| {
                    SubsystemError::unavailable(
                        SubsystemId::new("egress").expect("valid id"),
                        format!("no scripted answer for {host}"),
                    )
                })
            })
        }
    }

    fn guard(policy: EgressPolicy, dns: Arc<ScriptedDns>) -> EgressGuard {
        EgressGuard::new(policy, dns, Arc::new(StepClock::default()))
    }

    fn open_policy() -> EgressPolicy {
        EgressPolicy::deny_all().allow_host(HostPattern::parse("*.example.com"))
    }

    #[test]
    fn a_url_is_reduced_to_the_parts_that_decide_where_bytes_go() {
        let request =
            EndpointRequest::parse("https://API.Example.com/v1/chat?key=1#top").expect("parses");

        assert_eq!(request.scheme(), Scheme::Https);
        assert_eq!(request.host(), "api.example.com");
        assert_eq!(request.port(), 443);
        assert_eq!(request.to_string(), "https://api.example.com:443");
    }

    #[test]
    fn an_explicit_port_beats_the_scheme_default() {
        let request = EndpointRequest::parse("http://api.example.com:8080/v1").expect("parses");

        assert_eq!(request.port(), 8080);
        assert_eq!(
            EndpointRequest::parse("http://api.example.com/v1")
                .expect("parses")
                .port(),
            80
        );
    }

    #[test]
    fn a_url_carrying_credentials_is_refused_rather_than_silently_stripped() {
        let denial = EndpointRequest::parse("https://user:secret@api.example.com/v1")
            .expect_err("userinfo is refused");

        assert_eq!(
            denial,
            EgressDenial::CredentialsInUrl {
                url: "https://user:secret@api.example.com/v1".to_owned(),
            }
        );
    }

    #[test]
    fn only_http_and_https_are_understood() {
        let denial =
            EndpointRequest::parse("file:///etc/passwd").expect_err("file urls are refused");

        assert_eq!(
            denial,
            EgressDenial::UnsupportedScheme {
                scheme: "file".to_owned(),
            }
        );
    }

    #[test]
    fn a_malformed_url_reports_the_parser_reason() {
        let denial = EndpointRequest::parse("not a url").expect_err("garbage is refused");

        match denial {
            EgressDenial::InvalidUrl { url, reason } => {
                assert_eq!(url, "not a url");
                assert_eq!(reason, "relative URL without a base");
            }
            other => panic!("expected an invalid url denial, got {other}"),
        }
    }

    #[test]
    fn suffix_patterns_match_on_label_boundaries_only() {
        let pattern = HostPattern::parse("*.example.com");

        assert!(pattern.matches("api.example.com"));
        assert!(pattern.matches("a.b.example.com"));
        assert!(!pattern.matches("example.com"));
        assert!(!pattern.matches("notexample.com"));
        assert!(!pattern.matches("example.com.evil.test"));
        assert_eq!(pattern, HostPattern::Suffix("example.com".to_owned()));
    }

    #[test]
    fn exact_patterns_match_nothing_else() {
        let pattern = HostPattern::parse("Example.COM");

        assert_eq!(pattern, HostPattern::Exact("example.com".to_owned()));
        assert!(pattern.matches("example.com"));
        assert!(!pattern.matches("api.example.com"));
    }

    #[tokio::test]
    async fn a_denied_host_is_never_sent_to_the_resolver() {
        let dns = Arc::new(ScriptedDns::new(vec![vec!["203.0.113.10"]]));
        let guard = guard(open_policy(), Arc::clone(&dns));

        let denial = guard
            .resolve_url("https://attacker.test/v1")
            .await
            .expect_err("host is not allowed");

        assert_eq!(
            denial,
            EgressDenial::HostNotAllowed {
                host: "attacker.test".to_owned(),
            }
        );
        assert_eq!(dns.calls(), 0);
    }

    #[tokio::test]
    async fn cleartext_is_refused_unless_the_policy_opts_in() {
        let dns = Arc::new(ScriptedDns::new(vec![vec!["203.0.113.10"]]));
        let guard = guard(open_policy(), Arc::clone(&dns));

        let denial = guard
            .resolve_url("http://api.example.com/v1")
            .await
            .expect_err("cleartext is refused");

        assert_eq!(
            denial,
            EgressDenial::PlainHttpRefused {
                host: "api.example.com".to_owned(),
            }
        );
        assert_eq!(dns.calls(), 0);
    }

    #[tokio::test]
    async fn an_allowed_host_carries_its_checked_addresses_forward() {
        let dns = Arc::new(ScriptedDns::new(vec![vec!["203.0.113.10", "2001:db8::1"]]));
        let guard = guard(open_policy(), Arc::clone(&dns));

        let endpoint = guard
            .resolve_url("https://api.example.com/v1/chat")
            .await
            .expect("resolves");

        assert_eq!(endpoint.host(), "api.example.com");
        assert_eq!(endpoint.port(), 443);
        assert_eq!(endpoint.authority(), "api.example.com:443");
        assert_eq!(
            endpoint.addresses(),
            &[
                "203.0.113.10".parse::<IpAddr>().expect("valid"),
                "2001:db8::1".parse::<IpAddr>().expect("valid"),
            ]
        );
        assert_eq!(dns.calls(), 1);
    }

    #[tokio::test]
    async fn a_rebinding_answer_cannot_move_a_destination_after_it_was_checked() {
        // The first answer is public and passes. The second is loopback: a
        // transport that re-resolved the host would connect there instead.
        let dns = Arc::new(ScriptedDns::new(vec![
            vec!["203.0.113.10"],
            vec!["127.0.0.1"],
        ]));
        let guard = guard(open_policy(), Arc::clone(&dns));

        let endpoint = guard
            .resolve_url("https://api.example.com/v1")
            .await
            .expect("resolves");

        assert_eq!(
            endpoint.addresses(),
            &["203.0.113.10".parse::<IpAddr>().expect("valid")]
        );
        assert_eq!(
            dns.calls(),
            1,
            "the guard must resolve exactly once per checked endpoint"
        );

        // Holding the endpoint and reading it again never consults DNS, so the
        // second scripted answer is unreachable through this object.
        assert_eq!(
            endpoint.addresses(),
            &["203.0.113.10".parse::<IpAddr>().expect("valid")]
        );
        assert_eq!(dns.calls(), 1);
    }

    #[tokio::test]
    async fn a_host_is_refused_when_any_of_its_addresses_is_blocked() {
        let dns = Arc::new(ScriptedDns::new(vec![vec![
            "203.0.113.10",
            "169.254.169.254",
        ]]));
        let guard = guard(open_policy(), Arc::clone(&dns));

        let denial = guard
            .resolve_url("https://api.example.com/v1")
            .await
            .expect_err("a mixed answer is refused wholesale");

        assert_eq!(
            denial,
            EgressDenial::BlockedAddress {
                host: "api.example.com".to_owned(),
                address: "169.254.169.254".parse().expect("valid"),
                classification: "link-local",
            }
        );
    }

    #[tokio::test]
    async fn an_ip_literal_host_is_classified_without_a_lookup() {
        let dns = Arc::new(ScriptedDns::new(vec![]));
        let policy = EgressPolicy::deny_all().allow_host(HostPattern::parse("127.0.0.1"));
        let guard = guard(policy, Arc::clone(&dns));

        let denial = guard
            .resolve_url("https://127.0.0.1:8443/v1")
            .await
            .expect_err("loopback literals are still classified");

        assert_eq!(
            denial,
            EgressDenial::BlockedAddress {
                host: "127.0.0.1".to_owned(),
                address: "127.0.0.1".parse().expect("valid"),
                classification: "loopback",
            }
        );
        assert_eq!(dns.calls(), 0);
    }

    #[tokio::test]
    async fn loopback_is_reachable_only_when_the_policy_opts_in() {
        let dns = Arc::new(ScriptedDns::new(vec![]));
        let policy = EgressPolicy::deny_all()
            .allow_host(HostPattern::parse("127.0.0.1"))
            .allow_private_addresses();
        let guard = guard(policy, Arc::clone(&dns));

        let endpoint = guard
            .resolve_url("https://127.0.0.1:8443/v1")
            .await
            .expect("the opt-in permits loopback");

        assert_eq!(
            endpoint.addresses(),
            &["127.0.0.1".parse::<IpAddr>().expect("valid")]
        );
        assert_eq!(endpoint.port(), 8443);
    }

    #[tokio::test]
    async fn an_empty_answer_is_refused_distinctly_from_a_failure() {
        let dns = Arc::new(ScriptedDns::new(vec![vec![]]));
        let guard = guard(open_policy(), Arc::clone(&dns));

        let denial = guard
            .resolve_url("https://api.example.com/v1")
            .await
            .expect_err("an empty answer is refused");

        assert_eq!(
            denial,
            EgressDenial::NoAddresses {
                host: "api.example.com".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn a_resolver_failure_is_reported_with_its_reason() {
        let dns = Arc::new(ScriptedDns::new(vec![]));
        let guard = guard(open_policy(), Arc::clone(&dns));

        let denial = guard
            .resolve_url("https://api.example.com/v1")
            .await
            .expect_err("the scripted resolver runs out of answers");

        assert_eq!(
            denial,
            EgressDenial::LookupFailed {
                host: "api.example.com".to_owned(),
                detail: "egress: unavailable: no scripted answer for api.example.com".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn a_resolution_expires_against_the_clock_reading_taken_when_it_is_used() {
        let dns = Arc::new(ScriptedDns::new(vec![vec!["203.0.113.10"]]));
        let egress = EgressGuard::new(open_policy(), dns, Arc::new(FixedClock(1_000)));

        let endpoint = egress
            .resolve_url("https://api.example.com/v1")
            .await
            .expect("resolves");

        assert_eq!(endpoint.resolved_at(), MonotonicInstant::from_millis(1_000));
        endpoint
            .ensure_fresh(
                MonotonicInstant::from_millis(1_500),
                Duration::from_millis(500),
            )
            .expect("exactly at the limit is still fresh");

        let denial = endpoint
            .ensure_fresh(
                MonotonicInstant::from_millis(1_501),
                Duration::from_millis(500),
            )
            .expect_err("one millisecond past the limit is stale");

        assert_eq!(
            denial,
            EgressDenial::StaleResolution {
                host: "api.example.com".to_owned(),
                age: Duration::from_millis(501),
                limit: Duration::from_millis(500),
            }
        );
        assert_eq!(
            endpoint.age_at(MonotonicInstant::from_millis(1_501)),
            Duration::from_millis(501)
        );
    }

    #[test]
    fn the_default_resolution_age_is_thirty_seconds_and_is_overridable() {
        assert_eq!(
            EgressPolicy::deny_all().max_resolution_age(),
            Duration::from_secs(30)
        );
        assert_eq!(
            EgressPolicy::deny_all()
                .with_max_resolution_age(Duration::from_secs(5))
                .max_resolution_age(),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn non_routable_addresses_are_classified_and_routable_ones_are_not() {
        let blocked = [
            ("0.0.0.0", "unspecified"),
            ("127.0.0.1", "loopback"),
            ("10.0.0.1", "private"),
            ("172.16.5.4", "private"),
            ("192.168.1.1", "private"),
            ("169.254.169.254", "link-local"),
            ("255.255.255.255", "broadcast"),
            ("224.0.0.1", "multicast"),
            ("100.64.0.1", "carrier-grade NAT"),
            ("192.0.0.1", "IETF protocol assignment"),
            ("240.0.0.1", "reserved"),
            ("::", "unspecified"),
            ("::1", "loopback"),
            ("ff02::1", "multicast"),
            ("fc00::1", "unique-local"),
            ("fe80::1", "link-local"),
            ("::ffff:127.0.0.1", "loopback"),
            ("::ffff:203.0.113.10", "IPv4-in-IPv6"),
        ];

        for (address, classification) in blocked {
            assert_eq!(
                classify(address.parse().expect("valid address")),
                Some(classification),
                "{address} was classified wrongly"
            );
        }

        for address in ["203.0.113.10", "8.8.8.8", "2001:db8::1", "2606:4700::1"] {
            assert_eq!(
                classify(address.parse().expect("valid address")),
                None,
                "{address} should be routable"
            );
        }
    }

    #[test]
    fn a_denied_scheme_and_a_stale_resolution_render_distinctly() {
        assert_eq!(
            EgressDenial::UnsupportedScheme {
                scheme: "ftp".to_owned()
            }
            .to_string(),
            "unsupported destination scheme: ftp"
        );
        assert_eq!(
            EgressDenial::StaleResolution {
                host: "api.example.com".to_owned(),
                age: Duration::from_millis(750),
                limit: Duration::from_millis(500),
            }
            .to_string(),
            "the resolution of api.example.com is 750ms old, past the 500ms limit"
        );
        assert_eq!(
            EgressDenial::BlockedAddress {
                host: "api.example.com".to_owned(),
                address: "127.0.0.1".parse().expect("valid"),
                classification: "loopback",
            }
            .to_string(),
            "api.example.com resolved to 127.0.0.1, which is a loopback address"
        );
    }

    #[test]
    fn a_request_can_be_built_from_parts_without_a_url() {
        let request = EndpointRequest::new(Scheme::Https, "API.example.com", 8443).expect("valid");

        assert_eq!(request.host(), "api.example.com");
        assert_eq!(request.port(), 8443);
        assert_eq!(
            EndpointRequest::new(Scheme::Https, "", 443).expect_err("empty host is refused"),
            EgressDenial::MissingHost { url: String::new() }
        );
    }
}
