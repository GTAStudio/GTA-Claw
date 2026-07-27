//! One reviewed outbound proxy policy.
//!
//! The legacy Node client configured proxying in `src/utils/proxy.ts`: it read
//! one proxy URL from a fixed list of environment variables, installed a single
//! global `undici` dispatcher, logged the URL with its userinfo redacted, and —
//! when the URL could not be turned into an agent — logged the failure and
//! continued without a proxy. `compat/legacy/ledger/behaviors.json` freezes that
//! as `behavior.proxy.precedence` and `behavior.proxy.invalid`.
//!
//! This module is the typed replacement. It owns the decision only; it opens no
//! socket, so any transport in the workspace can adopt it without inheriting
//! this crate's `hyper` stack.
//!
//! # Environment precedence
//!
//! [`PROXY_VARIABLES`] is consulted in order and the first variable with a
//! non-empty value wins, exactly as the legacy `||` chain did. The order is
//! scheme-independent because the legacy dispatcher was global: a lone
//! `HTTP_PROXY` therefore also carries `https` traffic, which is what the
//! frozen contract describes and what `curl`, whose convention is per-scheme,
//! would not do.
//!
//! # Deliberate differences from the legacy behavior
//!
//! * `NO_PROXY`/`no_proxy` is honoured ([`NoProxy`]). The legacy client had no
//!   bypass list at all — `undici`'s `ProxyAgent` ignores the variable — so
//!   every destination went through the proxy. Ignoring an operator's bypass
//!   list is worse than the small compatibility gap of observing it.
//! * A malformed proxy URL is reported **without** the URL. The legacy error
//!   path logged `proxy: proxyUrl` in full, userinfo included, which published
//!   a credential to every log sink. The failure behavior itself is preserved:
//!   the process continues, direct.
//! * Loopback destinations are never proxied, whatever the policy says. Sending
//!   traffic bound for this machine to an external proxy is never what an
//!   operator means, and for a plaintext local endpoint it would put an
//!   `authorization` header on a routable wire.
//!
//! # Adoption
//!
//! [`crate::http::HttpTransport`] resolves this policy and applies it to every
//! provider request. It is the only adopter today. The obligation recorded for
//! `src/utils/proxy.ts` — that provider, role, channel and skill transports all
//! share one reviewed proxy policy — is therefore **not** discharged: this
//! module is the policy those transports can adopt, not evidence that they
//! have.

use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::net::IpAddr;
use std::sync::Once;

use url::Url;

use crate::secret::{REDACTED, SecretString};

/// Environment variables naming a proxy, in the order the legacy client read
/// them.
///
/// The first variable with a non-empty value is selected; a variable set to the
/// empty string is skipped, because the legacy `||` chain treated it as absent.
pub const PROXY_VARIABLES: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// Environment variables naming a bypass list, in precedence order.
pub const NO_PROXY_VARIABLES: [&str; 2] = ["NO_PROXY", "no_proxy"];

/// The scheme a proxy is reached over.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProxyScheme {
    /// The proxy hop itself is plaintext. The tunnelled session is not: a
    /// `CONNECT` tunnel is still end-to-end TLS to the destination.
    Http,
    /// The proxy hop is itself wrapped in TLS.
    Https,
}

impl ProxyScheme {
    /// Returns the URL scheme.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// Returns the port used when the proxy URL names none.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// Why a proxy URL cannot be used.
///
/// No variant carries the URL. A proxy URL routinely embeds `user:password@`,
/// so the text of a rejected URL is exactly as disclosing as an accepted one.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProxyUrlError {
    /// The value was empty or only whitespace.
    Empty,
    /// The value is not a URL.
    Malformed,
    /// The scheme is neither `http` nor `https`. SOCKS is not supported, and
    /// the legacy `ProxyAgent` rejected it too.
    UnsupportedScheme,
    /// The URL names no host.
    MissingHost,
}

impl Display for ProxyUrlError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "the proxy URL is empty",
            Self::Malformed => "the proxy URL is not a valid URL",
            Self::UnsupportedScheme => "the proxy URL scheme is not http or https",
            Self::MissingHost => "the proxy URL names no host",
        })
    }
}

impl std::error::Error for ProxyUrlError {}

/// A validated proxy endpoint.
///
/// The credential is held as a [`SecretString`] containing the finished
/// `Proxy-Authorization` value, so no call site has to re-derive it and none
/// can print it by accident.
#[derive(Clone)]
pub struct ProxyUrl {
    scheme: ProxyScheme,
    /// Host without IPv6 brackets, ready for a TLS server name.
    host: String,
    port: u16,
    /// `host:port`, with IPv6 brackets, ready for a URI authority.
    authority: String,
    credentials: Option<SecretString>,
}

impl ProxyUrl {
    /// Parses a proxy URL.
    ///
    /// Userinfo is percent-decoded and pre-encoded into a Basic
    /// `Proxy-Authorization` value, matching what the legacy `ProxyAgent` put
    /// on the wire.
    ///
    /// # Errors
    ///
    /// Returns a [`ProxyUrlError`] describing the defect. The URL itself is
    /// never carried into the error.
    pub fn parse(value: &str) -> Result<Self, ProxyUrlError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ProxyUrlError::Empty);
        }
        let url = Url::parse(trimmed).map_err(|_| ProxyUrlError::Malformed)?;
        let scheme = match url.scheme() {
            "http" => ProxyScheme::Http,
            "https" => ProxyScheme::Https,
            _ => return Err(ProxyUrlError::UnsupportedScheme),
        };
        let host = url.host_str().ok_or(ProxyUrlError::MissingHost)?;
        if host.is_empty() {
            return Err(ProxyUrlError::MissingHost);
        }
        let port = url.port().unwrap_or_else(|| scheme.default_port());
        Ok(Self {
            scheme,
            host: unbracket(host).to_owned(),
            port,
            authority: format!("{host}:{port}"),
            credentials: basic_credentials(url.username(), url.password().unwrap_or_default()),
        })
    }

    /// Returns the scheme the proxy hop uses.
    #[must_use]
    pub const fn scheme(&self) -> ProxyScheme {
        self.scheme
    }

    /// Returns the proxy host, without IPv6 brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the proxy port, defaulted from the scheme when the URL named
    /// none.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns `host:port`, with IPv6 brackets where the host needs them.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Returns the finished `Proxy-Authorization` header value, if the URL
    /// carried userinfo.
    #[must_use]
    pub const fn proxy_authorization(&self) -> Option<&SecretString> {
        self.credentials.as_ref()
    }

    /// Returns `true` when the proxy URL carried userinfo.
    #[must_use]
    pub const fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }
}

impl Debug for ProxyUrl {
    /// Renders the endpoint without its userinfo.
    ///
    /// The host and port are rendered through `authority`, which is the form
    /// every call site uses.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyUrl")
            .field("scheme", &self.scheme.as_str())
            .field("authority", &self.authority)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl Display for ProxyUrl {
    /// Renders the endpoint as a URL whose userinfo is replaced by
    /// [`REDACTED`], which is the shape the legacy client logged.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}://", self.scheme.as_str())?;
        if self.credentials.is_some() {
            write!(formatter, "{REDACTED}@")?;
        }
        formatter.write_str(&self.authority)
    }
}

impl PartialEq for ProxyUrl {
    /// Two endpoints are equal when they address the same proxy with the same
    /// credential.
    fn eq(&self, other: &Self) -> bool {
        self.scheme == other.scheme
            && self.authority == other.authority
            && self.credentials == other.credentials
    }
}

impl Eq for ProxyUrl {}

/// Where a proxy setting came from.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProxySource {
    /// One of [`PROXY_VARIABLES`] or [`NO_PROXY_VARIABLES`].
    Environment(&'static str),
    /// An explicitly configured policy rather than the environment.
    Configuration,
}

impl Display for ProxySource {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment(name) => formatter.write_str(name),
            Self::Configuration => formatter.write_str("the configured proxy policy"),
        }
    }
}

/// A problem found while resolving a proxy policy.
///
/// Rendering a diagnostic never discloses a proxy URL or a bypass entry, so it
/// is safe to put on any log sink.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProxyDiagnostic {
    /// A proxy was configured but cannot be used, so traffic goes direct.
    ///
    /// This is the security-relevant case: the operator asked for a proxy and
    /// is not getting one.
    UnusableProxy {
        /// Where the rejected URL came from.
        source: ProxySource,
        /// Why it was rejected.
        error: ProxyUrlError,
    },
    /// A bypass-list entry was not understood and is ignored.
    UnusableBypassEntry {
        /// Where the list came from.
        source: ProxySource,
        /// The 1-based position of the entry in the list.
        position: usize,
    },
}

impl Display for ProxyDiagnostic {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnusableProxy { source, error } => write!(
                formatter,
                "the proxy URL from {source} is unusable ({error}); continuing without a proxy"
            ),
            Self::UnusableBypassEntry { source, position } => write!(
                formatter,
                "bypass-list entry {position} from {source} was not understood and is ignored"
            ),
        }
    }
}

/// One parsed `NO_PROXY` entry.
#[derive(Clone, Debug, Eq, PartialEq)]
enum BypassRule {
    /// A domain, matching itself and any subdomain of it.
    Domain {
        /// Lower-cased, without a leading `.` or `*.`.
        domain: String,
        /// Set when the entry named a port.
        port: Option<u16>,
    },
    /// A literal address.
    Address {
        /// The address the destination must equal.
        address: IpAddr,
        /// Set when the entry named a port.
        port: Option<u16>,
    },
    /// A CIDR block.
    Network {
        /// The network address.
        network: IpAddr,
        /// The prefix length, in bits.
        prefix: u32,
        /// Set when the entry named a port.
        port: Option<u16>,
    },
}

impl BypassRule {
    /// Returns `true` when this rule covers the destination.
    fn matches(&self, host: &str, address: Option<IpAddr>, port: u16) -> bool {
        match self {
            Self::Domain {
                domain,
                port: expected,
            } => {
                port_matches(*expected, port)
                    && (host == domain
                        || (host.len() > domain.len()
                            && host.ends_with(domain)
                            && host
                                .as_bytes()
                                .get(host.len() - domain.len() - 1)
                                .is_some_and(|byte| *byte == b'.')))
            }
            Self::Address {
                address: expected,
                port: expected_port,
            } => port_matches(*expected_port, port) && address == Some(*expected),
            Self::Network {
                network,
                prefix,
                port: expected_port,
            } => {
                port_matches(*expected_port, port)
                    && address.is_some_and(|address| in_network(address, *network, *prefix))
            }
        }
    }
}

/// Returns `true` when a rule's port qualifier admits `port`.
const fn port_matches(expected: Option<u16>, port: u16) -> bool {
    match expected {
        None => true,
        Some(expected) => expected == port,
    }
}

/// Returns `true` when `address` falls inside `network/prefix`.
fn in_network(address: IpAddr, network: IpAddr, prefix: u32) -> bool {
    match (address, network) {
        (IpAddr::V4(address), IpAddr::V4(network)) => {
            let shift = 32_u32.saturating_sub(prefix);
            let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
            address.to_bits() & mask == network.to_bits() & mask
        }
        (IpAddr::V6(address), IpAddr::V6(network)) => {
            let shift = 128_u32.saturating_sub(prefix);
            let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
            address.to_bits() & mask == network.to_bits() & mask
        }
        // A v4 destination is never inside a v6 block, and the reverse.
        _ => false,
    }
}

/// A parsed `NO_PROXY` bypass list.
///
/// An entry matches the host it names and any subdomain of it, so
/// `example.com`, `.example.com` and `*.example.com` behave alike. `*` on its
/// own bypasses everything. An entry may be an address or a CIDR block, and any
/// entry may be qualified with `:port`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NoProxy {
    everything: bool,
    rules: Vec<BypassRule>,
}

impl NoProxy {
    /// Parses a comma-separated bypass list, ignoring entries it cannot
    /// understand.
    ///
    /// Use [`ProxyRules`] when the ignored entries need to be reported.
    #[must_use]
    pub fn parse(list: &str) -> Self {
        Self::parse_reporting(list, ProxySource::Configuration, &mut Vec::new())
    }

    /// Parses a bypass list, recording each entry it had to ignore.
    fn parse_reporting(
        list: &str,
        source: ProxySource,
        diagnostics: &mut Vec<ProxyDiagnostic>,
    ) -> Self {
        let mut parsed = Self::default();
        for (index, entry) in list.split(',').enumerate() {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if entry == "*" {
                parsed.everything = true;
                continue;
            }
            match parse_bypass_entry(entry) {
                Some(rule) => parsed.rules.push(rule),
                None => diagnostics.push(ProxyDiagnostic::UnusableBypassEntry {
                    source,
                    position: index + 1,
                }),
            }
        }
        parsed
    }

    /// Returns `true` when the list bypasses `host:port`.
    ///
    /// `host` may carry IPv6 brackets, a trailing root dot, or any case; all
    /// three are normalised before matching.
    #[must_use]
    pub fn matches(&self, host: &str, port: u16) -> bool {
        if self.everything {
            return true;
        }
        let host = normalize_host(host);
        let address = host.parse::<IpAddr>().ok();
        self.rules
            .iter()
            .any(|rule| rule.matches(&host, address, port))
    }

    /// Returns `true` when the list holds no entry.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.everything && self.rules.is_empty()
    }
}

/// Parses one bypass entry, returning `None` when it is not understood.
fn parse_bypass_entry(entry: &str) -> Option<BypassRule> {
    let (host, port) = split_bypass_port(entry)?;
    let host = normalize_host(host);
    if let Some((network, prefix)) = host.split_once('/') {
        let network = network.parse::<IpAddr>().ok()?;
        let prefix = prefix.parse::<u32>().ok()?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        if prefix > width {
            return None;
        }
        return Some(BypassRule::Network {
            network,
            prefix,
            port,
        });
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return Some(BypassRule::Address { address, port });
    }
    let domain = host
        .strip_prefix("*.")
        .or_else(|| host.strip_prefix('.'))
        .unwrap_or(&host);
    if domain.is_empty() {
        return None;
    }
    Some(BypassRule::Domain {
        domain: domain.to_owned(),
        port,
    })
}

/// Splits an optional `:port` qualifier off a bypass entry.
///
/// A bracketed IPv6 literal keeps its brackets so the caller can tell
/// `[::1]:8080` from the address `::1`.
fn split_bypass_port(entry: &str) -> Option<(&str, Option<u16>)> {
    if let Some(end) = entry.rfind(']') {
        let (host, rest) = entry.split_at(end + 1);
        return match rest.strip_prefix(':') {
            None if rest.is_empty() => Some((host, None)),
            None => None,
            Some(port) => Some((host, Some(port.parse().ok()?))),
        };
    }
    // An unbracketed address with several colons is an IPv6 literal, never a
    // host with a port.
    if entry.matches(':').count() > 1 {
        return Some((entry, None));
    }
    match entry.split_once(':') {
        None => Some((entry, None)),
        Some((host, port)) => Some((host, Some(port.parse().ok()?))),
    }
}

/// Which proxy, if any, a resolved policy selected.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Selection {
    /// The policy forbids proxying.
    Disabled,
    /// Nothing named a proxy.
    NotConfigured,
    /// A proxy was named but rejected; the diagnostics say why.
    Unusable,
    /// The selected proxy.
    Proxy(ProxyUrl),
}

/// Why a destination is being reached directly.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DirectReason {
    /// The policy forbids proxying.
    Disabled,
    /// No environment variable or configuration named a proxy.
    NotConfigured,
    /// A proxy was configured and could not be used. See
    /// [`ProxyRules::diagnostics`]; this is a bypass the operator did not ask
    /// for.
    Unusable,
    /// The destination is on this machine.
    Loopback,
    /// A bypass-list entry matched the destination.
    Bypassed,
}

impl Display for DirectReason {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Disabled => "the proxy policy is disabled",
            Self::NotConfigured => "no proxy is configured",
            Self::Unusable => "the configured proxy is unusable",
            Self::Loopback => "the destination is on this machine",
            Self::Bypassed => "a bypass-list entry matches the destination",
        })
    }
}

/// What a policy decided for one destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyDecision {
    /// Connect straight to the destination.
    Direct(DirectReason),
    /// Reach the destination through this proxy.
    Proxy(ProxyUrl),
}

impl ProxyDecision {
    /// Returns the proxy to use, if any.
    #[must_use]
    pub const fn proxy(&self) -> Option<&ProxyUrl> {
        match self {
            Self::Direct(_) => None,
            Self::Proxy(proxy) => Some(proxy),
        }
    }

    /// Returns `true` when the destination is reached directly.
    #[must_use]
    pub const fn is_direct(&self) -> bool {
        matches!(self, Self::Direct(_))
    }
}

/// A resolved proxy policy: one proxy, one bypass list, and everything that
/// went wrong while working them out.
///
/// Resolution happens once. [`ProxyRules::intercept`] is then a pure decision
/// over an already-parsed policy, so it can run on every connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyRules {
    selection: Selection,
    no_proxy: NoProxy,
    diagnostics: Vec<ProxyDiagnostic>,
}

impl ProxyRules {
    /// Returns rules that never proxy.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            selection: Selection::Disabled,
            no_proxy: NoProxy::default(),
            diagnostics: Vec::new(),
        }
    }

    /// Resolves the policy from this process's environment.
    ///
    /// A variable whose value is not UTF-8 is treated as unset, because a proxy
    /// URL that cannot be a `str` cannot be a URL either.
    #[must_use]
    pub fn from_environment() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Resolves the policy from an arbitrary variable lookup.
    ///
    /// Tests use this: `std::env::set_var` is `unsafe` in edition 2024 and this
    /// workspace forbids `unsafe`, so environment precedence is proved against
    /// an injected lookup rather than a mutated process environment.
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let mut diagnostics = Vec::new();
        let selection = match select_variable(&lookup, &PROXY_VARIABLES) {
            None => Selection::NotConfigured,
            Some((name, value)) => select(&value, ProxySource::Environment(name), &mut diagnostics),
        };
        let no_proxy = match select_variable(&lookup, &NO_PROXY_VARIABLES) {
            None => NoProxy::default(),
            Some((name, list)) => {
                NoProxy::parse_reporting(&list, ProxySource::Environment(name), &mut diagnostics)
            }
        };
        Self {
            selection,
            no_proxy,
            diagnostics,
        }
    }

    /// Resolves an explicitly configured proxy and bypass list.
    #[must_use]
    pub fn explicit(url: &str, no_proxy: Option<&str>) -> Self {
        let mut diagnostics = Vec::new();
        let selection = select(url, ProxySource::Configuration, &mut diagnostics);
        let no_proxy = no_proxy.map_or_else(NoProxy::default, |list| {
            NoProxy::parse_reporting(list, ProxySource::Configuration, &mut diagnostics)
        });
        Self {
            selection,
            no_proxy,
            diagnostics,
        }
    }

    /// Returns the selected proxy, if the policy resolved to one.
    #[must_use]
    pub const fn proxy(&self) -> Option<&ProxyUrl> {
        match &self.selection {
            Selection::Proxy(proxy) => Some(proxy),
            _ => None,
        }
    }

    /// Returns the bypass list in force.
    #[must_use]
    pub const fn no_proxy(&self) -> &NoProxy {
        &self.no_proxy
    }

    /// Returns every problem found while resolving the policy.
    #[must_use]
    pub fn diagnostics(&self) -> &[ProxyDiagnostic] {
        &self.diagnostics
    }

    /// Returns `true` when a proxy was configured, could not be used, and
    /// traffic is therefore going direct.
    ///
    /// This is the state an operator most needs to see: they asked for a proxy
    /// and are not getting one.
    #[must_use]
    pub const fn fell_back_to_direct(&self) -> bool {
        matches!(self.selection, Selection::Unusable)
    }

    /// Returns the decision for one destination.
    ///
    /// The proxy choice is scheme-independent, matching the legacy global
    /// dispatcher, so only the host and port are needed. A transport that
    /// refuses to proxy some schemes — this crate's does, for plaintext —
    /// enforces that itself.
    #[must_use]
    pub fn intercept(&self, host: &str, port: u16) -> ProxyDecision {
        let proxy = match &self.selection {
            Selection::Disabled => return ProxyDecision::Direct(DirectReason::Disabled),
            Selection::NotConfigured => {
                return ProxyDecision::Direct(DirectReason::NotConfigured);
            }
            Selection::Unusable => return ProxyDecision::Direct(DirectReason::Unusable),
            Selection::Proxy(proxy) => proxy,
        };
        if is_loopback_host(host) {
            return ProxyDecision::Direct(DirectReason::Loopback);
        }
        if self.no_proxy.matches(host, port) {
            return ProxyDecision::Direct(DirectReason::Bypassed);
        }
        ProxyDecision::Proxy(proxy.clone())
    }

    /// Returns the decision for a destination URL.
    #[must_use]
    pub fn intercept_url(&self, url: &Url) -> ProxyDecision {
        let Some(host) = url.host_str() else {
            return ProxyDecision::Direct(DirectReason::NotConfigured);
        };
        let port = url
            .port_or_known_default()
            .unwrap_or_else(|| if url.scheme() == "https" { 443 } else { 80 });
        self.intercept(host, port)
    }

    /// Writes every diagnostic to `sink`, at most once per `announced`.
    ///
    /// The legacy client logged this at startup and continued. There is no
    /// logging port in this crate, so the caller supplies the sink and the
    /// once-flag; the transport passes a process-wide flag so a broken proxy
    /// URL is announced once rather than on every transport it builds.
    ///
    /// Returns `true` when it wrote. Write errors are dropped: a diagnostic
    /// that cannot be reported must not fail the request it is about.
    pub fn announce(&self, announced: &Once, sink: &mut dyn io::Write) -> bool {
        if self.diagnostics.is_empty() {
            return false;
        }
        let mut wrote = false;
        announced.call_once(|| {
            for diagnostic in &self.diagnostics {
                let _ = writeln!(sink, "claw-provider-sdk: {diagnostic}");
            }
            wrote = true;
        });
        wrote
    }
}

impl Default for ProxyRules {
    /// Resolves from the environment, which is what the legacy client did at
    /// startup.
    fn default() -> Self {
        Self::from_environment()
    }
}

/// Returns the first variable in `names` with a non-empty value.
fn select_variable(
    lookup: &impl Fn(&str) -> Option<String>,
    names: &[&'static str],
) -> Option<(&'static str, String)> {
    names.iter().find_map(|name| {
        let value = lookup(name)?;
        (!value.is_empty()).then_some((*name, value))
    })
}

/// Parses a selected proxy URL into a [`Selection`], recording a diagnostic
/// when it cannot be used.
fn select(value: &str, source: ProxySource, diagnostics: &mut Vec<ProxyDiagnostic>) -> Selection {
    match ProxyUrl::parse(value) {
        Ok(proxy) => Selection::Proxy(proxy),
        Err(error) => {
            diagnostics.push(ProxyDiagnostic::UnusableProxy { source, error });
            Selection::Unusable
        }
    }
}

/// Builds the `Proxy-Authorization` value for a URL's userinfo.
///
/// Both halves are percent-decoded first, because a password containing `@`,
/// `:` or `/` can only appear in a URL encoded.
fn basic_credentials(username: &str, password: &str) -> Option<SecretString> {
    if username.is_empty() && password.is_empty() {
        return None;
    }
    let mut plain = percent_decode(username);
    plain.push(b':');
    plain.extend_from_slice(&percent_decode(password));
    Some(SecretString::new(format!(
        "Basic {}",
        encode_base64(&plain)
    )))
}

/// Returns `true` when a host names the local machine.
///
/// Loopback traffic is never proxied. Sending it to an external proxy would be
/// meaningless for a local inference server and actively harmful for a
/// plaintext request, so this is checked independently of whatever `NO_PROXY`
/// happens to say.
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    let host = normalize_host(host);
    if let Ok(address) = host.parse::<IpAddr>() {
        return address.is_loopback();
    }
    host == "localhost" || host.ends_with(".localhost")
}

/// Lower-cases a host and strips IPv6 brackets and the root dot.
fn normalize_host(host: &str) -> String {
    let host = unbracket(host.trim());
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// Removes the brackets around an IPv6 literal.
fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host)
}

/// Percent-decodes a URL component, leaving any invalid escape as written.
fn percent_decode(value: &str) -> Vec<u8> {
    let raw = value.as_bytes();
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while let Some(&byte) = raw.get(index) {
        if byte == b'%'
            && let Some(high) = raw.get(index + 1).copied().and_then(hex_value)
            && let Some(low) = raw.get(index + 2).copied().and_then(hex_value)
        {
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(byte);
            index += 1;
        }
    }
    decoded
}

/// Returns the numeric value of one hexadecimal digit.
fn hex_value(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

/// Encodes bytes as standard padded base64.
///
/// Written out rather than taken from a crate: the workspace pins its
/// dependency graph, and this is the only base64 the SDK needs.
fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let mut group = [0_u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let sextets = [
            group[0] >> 2,
            ((group[0] & 0b0000_0011) << 4) | (group[1] >> 4),
            ((group[1] & 0b0000_1111) << 2) | (group[2] >> 6),
            group[2] & 0b0011_1111,
        ];
        encoded.push(char::from(ALPHABET[usize::from(sextets[0])]));
        encoded.push(char::from(ALPHABET[usize::from(sextets[1])]));
        encoded.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(sextets[2])])
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(sextets[3])])
        } else {
            '='
        });
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a lookup over a fixed table, standing in for the process
    /// environment.
    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn https_proxy_outranks_every_other_variable() {
        let rules = ProxyRules::from_lookup(lookup(&[
            ("HTTPS_PROXY", "http://secure.example:1"),
            ("https_proxy", "http://secure-lower.example:2"),
            ("HTTP_PROXY", "http://plain.example:3"),
            ("http_proxy", "http://plain-lower.example:4"),
            ("ALL_PROXY", "http://all.example:5"),
            ("all_proxy", "http://all-lower.example:6"),
        ]));
        assert_eq!(
            rules.proxy().map(ProxyUrl::authority),
            Some("secure.example:1")
        );
    }

    #[test]
    fn the_precedence_chain_falls_through_in_the_legacy_order() {
        let expected = [
            ("HTTPS_PROXY", "secure.example:1"),
            ("https_proxy", "secure-lower.example:2"),
            ("HTTP_PROXY", "plain.example:3"),
            ("http_proxy", "plain-lower.example:4"),
            ("ALL_PROXY", "all.example:5"),
            ("all_proxy", "all-lower.example:6"),
        ];
        for skipped in 0..expected.len() {
            let table: Vec<(&str, String)> = expected
                .iter()
                .skip(skipped)
                .map(|(name, authority)| (*name, format!("http://{authority}")))
                .collect();
            let rules = ProxyRules::from_lookup(|name| {
                table
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone())
            });
            assert_eq!(
                rules.proxy().map(ProxyUrl::authority),
                Some(expected[skipped].1),
                "with {skipped} variables removed"
            );
        }
    }

    #[test]
    fn a_lowercase_variable_is_honoured_on_its_own() {
        let rules =
            ProxyRules::from_lookup(lookup(&[("https_proxy", "http://proxy.example:8080")]));
        assert_eq!(
            rules.proxy().map(ProxyUrl::authority),
            Some("proxy.example:8080")
        );
    }

    #[test]
    fn an_empty_variable_is_skipped_exactly_as_the_legacy_chain_skipped_it() {
        let rules = ProxyRules::from_lookup(lookup(&[
            ("HTTPS_PROXY", ""),
            ("HTTP_PROXY", "http://plain.example:3128"),
        ]));
        assert_eq!(
            rules.proxy().map(ProxyUrl::authority),
            Some("plain.example:3128")
        );
        assert!(rules.diagnostics().is_empty());
    }

    #[test]
    fn a_whitespace_only_variable_is_selected_and_then_reported_as_unusable() {
        // The legacy chain treated " " as present, so it never reached
        // `HTTP_PROXY`; the URL construction then failed and the process
        // continued without a proxy.
        let rules = ProxyRules::from_lookup(lookup(&[
            ("HTTPS_PROXY", " "),
            ("HTTP_PROXY", "http://plain.example:3128"),
        ]));
        assert!(rules.proxy().is_none());
        assert!(rules.fell_back_to_direct());
        assert_eq!(
            rules.diagnostics(),
            [ProxyDiagnostic::UnusableProxy {
                source: ProxySource::Environment("HTTPS_PROXY"),
                error: ProxyUrlError::Empty,
            }]
        );
    }

    #[test]
    fn no_proxy_outranks_its_lowercase_spelling() {
        let rules = ProxyRules::from_lookup(lookup(&[
            ("HTTPS_PROXY", "http://proxy.example:3128"),
            ("NO_PROXY", "upper.example"),
            ("no_proxy", "lower.example"),
        ]));
        assert!(rules.intercept("upper.example", 443).is_direct());
        assert!(!rules.intercept("lower.example", 443).is_direct());
    }

    #[test]
    fn an_absent_proxy_is_not_a_diagnostic() {
        let rules = ProxyRules::from_lookup(lookup(&[]));
        assert!(rules.diagnostics().is_empty());
        assert!(!rules.fell_back_to_direct());
        assert_eq!(
            rules.intercept("api.example.com", 443),
            ProxyDecision::Direct(DirectReason::NotConfigured)
        );
    }

    #[test]
    fn a_disabled_policy_never_proxies() {
        let rules = ProxyRules::disabled();
        assert_eq!(
            rules.intercept("api.example.com", 443),
            ProxyDecision::Direct(DirectReason::Disabled)
        );
        assert!(rules.proxy().is_none());
    }

    #[test]
    fn default_ports_come_from_the_proxy_scheme() {
        assert_eq!(
            ProxyUrl::parse("http://proxy.example")
                .expect("parse")
                .port(),
            80
        );
        assert_eq!(
            ProxyUrl::parse("https://proxy.example")
                .expect("parse")
                .port(),
            443
        );
        assert_eq!(
            ProxyUrl::parse("http://proxy.example:3128")
                .expect("parse")
                .port(),
            3128
        );
    }

    #[test]
    fn an_ipv6_proxy_keeps_its_brackets_in_the_authority_only() {
        let proxy = ProxyUrl::parse("http://[::1]:3128").expect("parse");
        assert_eq!(proxy.authority(), "[::1]:3128");
        assert_eq!(proxy.host(), "::1");
    }

    #[test]
    fn every_rejected_proxy_url_names_its_defect_without_quoting_the_url() {
        for (value, expected) in [
            ("", ProxyUrlError::Empty),
            ("   ", ProxyUrlError::Empty),
            // `host:port` parses as a URL whose scheme is the host, which is
            // how the legacy `new URL(...)` read it too: it is rejected for its
            // scheme, not for its shape.
            ("proxy.example:3128", ProxyUrlError::UnsupportedScheme),
            ("127.0.0.1:3128", ProxyUrlError::Malformed),
            ("not a url", ProxyUrlError::Malformed),
            (
                "socks5://proxy.example:1080",
                ProxyUrlError::UnsupportedScheme,
            ),
            ("ftp://proxy.example", ProxyUrlError::UnsupportedScheme),
            ("http://", ProxyUrlError::Malformed),
        ] {
            assert_eq!(ProxyUrl::parse(value), Err(expected), "for {value:?}");
        }
    }

    #[test]
    fn userinfo_becomes_a_basic_credential_matching_the_legacy_wire_form() {
        let proxy = ProxyUrl::parse("http://Aladdin:opensesame@proxy.example:3128").expect("parse");
        assert_eq!(
            proxy
                .proxy_authorization()
                .map(|credential| credential.expose().to_owned()),
            Some("Basic QWxhZGRpbjpvcGVuc2VzYW1l".to_owned())
        );
        assert!(proxy.has_credentials());
    }

    #[test]
    fn percent_encoded_userinfo_is_decoded_before_it_is_encoded() {
        let proxy =
            ProxyUrl::parse("http://user%40corp:pass%3Aword@proxy.example:3128").expect("parse");
        let credential = proxy
            .proxy_authorization()
            .expect("the URL carried userinfo")
            .expose()
            .to_owned();
        assert_eq!(
            credential,
            format!("Basic {}", encode_base64(b"user@corp:pass:word"))
        );
    }

    #[test]
    fn a_proxy_url_without_userinfo_sends_no_credential() {
        let proxy = ProxyUrl::parse("http://proxy.example:3128").expect("parse");
        assert!(proxy.proxy_authorization().is_none());
        assert!(!proxy.has_credentials());
    }

    #[test]
    fn no_rendering_of_a_proxy_url_discloses_its_userinfo() {
        let proxy =
            ProxyUrl::parse("http://corp-user:corp-secret@proxy.internal:3128").expect("parse");
        let rules = ProxyRules::explicit("http://corp-user:corp-secret@proxy.internal:3128", None);
        let decision = rules.intercept("api.example.com", 443);
        let rendered = format!("{proxy} {proxy:?} {rules:?} {decision:?}");
        assert!(!rendered.contains("corp-user"), "{rendered}");
        assert!(!rendered.contains("corp-secret"), "{rendered}");
        assert!(rendered.contains("proxy.internal:3128"), "{rendered}");
        assert_eq!(
            format!("{proxy}"),
            format!("http://{REDACTED}@proxy.internal:3128")
        );
    }

    #[test]
    fn a_proxy_url_without_credentials_renders_as_itself() {
        let proxy = ProxyUrl::parse("https://proxy.internal:8443").expect("parse");
        assert_eq!(format!("{proxy}"), "https://proxy.internal:8443");
    }

    #[test]
    fn a_malformed_proxy_url_falls_back_to_direct_and_says_so() {
        let rules =
            ProxyRules::explicit("socks5://corp-user:corp-secret@proxy.internal:1080", None);
        assert!(rules.proxy().is_none());
        assert!(rules.fell_back_to_direct());
        assert_eq!(
            rules.intercept("api.example.com", 443),
            ProxyDecision::Direct(DirectReason::Unusable)
        );
        let rendered = rules
            .diagnostics()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!rendered.contains("corp-secret"), "{rendered}");
        assert!(!rendered.contains("proxy.internal"), "{rendered}");
        assert!(
            rendered.contains("continuing without a proxy"),
            "{rendered}"
        );
    }

    #[test]
    fn diagnostics_are_announced_once_and_carry_no_credential() {
        let rules =
            ProxyRules::explicit("socks5://corp-user:corp-secret@proxy.internal:1080", None);
        let announced = Once::new();
        let mut first = Vec::new();
        assert!(rules.announce(&announced, &mut first));
        let mut second = Vec::new();
        assert!(!rules.announce(&announced, &mut second));
        assert!(second.is_empty());
        let text = String::from_utf8(first).expect("the diagnostic is UTF-8");
        assert!(text.contains("continuing without a proxy"), "{text}");
        assert!(!text.contains("corp-secret"), "{text}");
    }

    #[test]
    fn a_clean_policy_announces_nothing_and_leaves_the_flag_unused() {
        let rules = ProxyRules::explicit("http://proxy.internal:3128", None);
        let announced = Once::new();
        let mut sink = Vec::new();
        assert!(!rules.announce(&announced, &mut sink));
        assert!(sink.is_empty());
        assert!(!announced.is_completed());
    }

    #[test]
    fn a_wildcard_bypasses_every_destination() {
        let rules = ProxyRules::explicit("http://proxy.internal:3128", Some("*"));
        assert_eq!(
            rules.intercept("api.example.com", 443),
            ProxyDecision::Direct(DirectReason::Bypassed)
        );
        assert!(!rules.no_proxy().is_empty());
    }

    #[test]
    fn a_dot_suffix_entry_covers_the_apex_and_its_subdomains_only() {
        let no_proxy = NoProxy::parse(".example.com");
        assert!(no_proxy.matches("example.com", 443));
        assert!(no_proxy.matches("api.example.com", 443));
        assert!(no_proxy.matches("a.b.example.com", 443));
        assert!(!no_proxy.matches("notexample.com", 443));
        assert!(!no_proxy.matches("example.com.evil.test", 443));
    }

    #[test]
    fn a_star_dot_entry_and_a_bare_entry_behave_like_the_dot_suffix() {
        for list in [".example.com", "*.example.com", "example.com"] {
            let no_proxy = NoProxy::parse(list);
            assert!(no_proxy.matches("example.com", 443), "{list}");
            assert!(no_proxy.matches("api.example.com", 443), "{list}");
            assert!(!no_proxy.matches("example.org", 443), "{list}");
        }
    }

    #[test]
    fn bypass_matching_ignores_case_brackets_and_the_root_dot() {
        let no_proxy = NoProxy::parse("Example.COM, [::1], 10.0.0.7");
        assert!(no_proxy.matches("API.Example.com.", 443));
        assert!(no_proxy.matches("[::1]", 443));
        assert!(no_proxy.matches("::1", 443));
        assert!(no_proxy.matches("10.0.0.7", 443));
        assert!(!no_proxy.matches("10.0.0.8", 443));
    }

    #[test]
    fn a_cidr_entry_matches_only_addresses_inside_the_block() {
        let no_proxy = NoProxy::parse("10.0.0.0/8, fd00::/8, 192.168.1.0/24");
        assert!(no_proxy.matches("10.255.3.1", 443));
        assert!(!no_proxy.matches("11.0.0.1", 443));
        assert!(no_proxy.matches("192.168.1.44", 443));
        assert!(!no_proxy.matches("192.168.2.44", 443));
        assert!(no_proxy.matches("fd00::5", 443));
        assert!(!no_proxy.matches("fe80::5", 443));
        // A name that merely looks numeric is not an address.
        assert!(!no_proxy.matches("10.example.com", 443));
        // A v4 destination is never inside a v6 block.
        assert!(!NoProxy::parse("::/0").matches("10.0.0.1", 443));
        assert!(NoProxy::parse("0.0.0.0/0").matches("10.0.0.1", 443));
    }

    #[test]
    fn a_port_qualified_entry_matches_only_that_port() {
        let no_proxy = NoProxy::parse("example.com:8443, [::1]:9000, 10.0.0.0/8:7000");
        assert!(no_proxy.matches("example.com", 8443));
        assert!(!no_proxy.matches("example.com", 443));
        assert!(no_proxy.matches("::1", 9000));
        assert!(!no_proxy.matches("::1", 443));
        assert!(no_proxy.matches("10.1.2.3", 7000));
        assert!(!no_proxy.matches("10.1.2.3", 443));
    }

    #[test]
    fn an_unbracketed_ipv6_entry_is_read_as_an_address_and_not_as_a_port() {
        let no_proxy = NoProxy::parse("fd00::1");
        assert!(no_proxy.matches("fd00::1", 443));
        assert!(no_proxy.matches("[fd00::1]", 8443));
    }

    #[test]
    fn an_unusable_bypass_entry_is_reported_and_the_rest_still_apply() {
        let rules = ProxyRules::explicit(
            "http://proxy.internal:3128",
            Some("good.example, 10.0.0.0/99, other.example"),
        );
        assert_eq!(
            rules.diagnostics(),
            [ProxyDiagnostic::UnusableBypassEntry {
                source: ProxySource::Configuration,
                position: 2,
            }]
        );
        assert!(rules.intercept("good.example", 443).is_direct());
        assert!(rules.intercept("other.example", 443).is_direct());
        assert!(!rules.intercept("api.example.com", 443).is_direct());
        assert!(rules.proxy().is_some());
    }

    #[test]
    fn an_empty_bypass_list_matches_nothing() {
        let no_proxy = NoProxy::parse("  , ,");
        assert!(no_proxy.is_empty());
        assert!(!no_proxy.matches("example.com", 443));
    }

    #[test]
    fn loopback_is_never_proxied_however_the_policy_reads() {
        let rules = ProxyRules::explicit("http://proxy.internal:3128", None);
        for host in [
            "127.0.0.1",
            "127.5.5.5",
            "[::1]",
            "localhost",
            "LOCALHOST",
            "ollama.localhost",
        ] {
            assert_eq!(
                rules.intercept(host, 443),
                ProxyDecision::Direct(DirectReason::Loopback),
                "{host}"
            );
        }
        assert!(!is_loopback_host("127.0.0.1.example.test"));
        assert!(!is_loopback_host("10.0.0.5"));
        assert!(!is_loopback_host("example.test"));
    }

    #[test]
    fn a_destination_url_is_intercepted_by_host_and_effective_port() {
        let rules =
            ProxyRules::explicit("http://proxy.internal:3128", Some("bypassed.example:443"));
        let proxied = Url::parse("https://api.example.com/v1/models").expect("parse");
        let bypassed = Url::parse("https://bypassed.example/v1/models").expect("parse");
        let other_port = Url::parse("https://bypassed.example:8443/v1/models").expect("parse");
        assert!(!rules.intercept_url(&proxied).is_direct());
        assert!(rules.intercept_url(&bypassed).is_direct());
        assert!(!rules.intercept_url(&other_port).is_direct());
    }

    #[test]
    fn a_decision_exposes_the_proxy_it_selected() {
        let rules = ProxyRules::explicit("http://proxy.internal:3128", None);
        let decision = rules.intercept("api.example.com", 443);
        assert_eq!(
            decision.proxy().map(ProxyUrl::authority),
            Some("proxy.internal:3128")
        );
        assert!(!decision.is_direct());
        assert!(
            ProxyDecision::Direct(DirectReason::Loopback)
                .proxy()
                .is_none()
        );
    }

    #[test]
    fn direct_reasons_and_sources_render_as_prose() {
        assert_eq!(
            DirectReason::Unusable.to_string(),
            "the configured proxy is unusable"
        );
        assert_eq!(
            DirectReason::Loopback.to_string(),
            "the destination is on this machine"
        );
        assert_eq!(
            DirectReason::Disabled.to_string(),
            "the proxy policy is disabled"
        );
        assert_eq!(
            DirectReason::NotConfigured.to_string(),
            "no proxy is configured"
        );
        assert_eq!(
            DirectReason::Bypassed.to_string(),
            "a bypass-list entry matches the destination"
        );
        assert_eq!(
            ProxySource::Environment("HTTPS_PROXY").to_string(),
            "HTTPS_PROXY"
        );
        assert_eq!(
            ProxySource::Configuration.to_string(),
            "the configured proxy policy"
        );
    }

    #[test]
    fn proxy_schemes_report_their_wire_form_and_default_port() {
        assert_eq!(ProxyScheme::Http.as_str(), "http");
        assert_eq!(ProxyScheme::Https.as_str(), "https");
        assert_eq!(ProxyScheme::Http.default_port(), 80);
        assert_eq!(ProxyScheme::Https.default_port(), 443);
        assert_eq!(
            ProxyUrl::parse("https://proxy.example")
                .expect("parse")
                .scheme(),
            ProxyScheme::Https
        );
    }

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
        assert_eq!(encode_base64(b"foob"), "Zm9vYg==");
        assert_eq!(encode_base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode_base64(&[0xFF, 0xFF, 0xFF]), "////");
        assert_eq!(encode_base64(&[0xFB, 0xF0]), "+/A=");
    }

    #[test]
    fn percent_decoding_leaves_invalid_escapes_alone() {
        assert_eq!(percent_decode("plain"), b"plain");
        assert_eq!(percent_decode("a%20b"), b"a b");
        assert_eq!(percent_decode("%2F%2f"), b"//");
        assert_eq!(percent_decode("100%"), b"100%");
        assert_eq!(percent_decode("%zz"), b"%zz");
        assert_eq!(percent_decode("%4"), b"%4");
    }

    #[test]
    fn resolving_from_the_process_environment_never_panics() {
        // The values depend on the machine, so only machine-independent
        // invariants are asserted: a decision is either a proxy this policy
        // selected or a direct connection, and resolving twice agrees.
        let rules = ProxyRules::from_environment();
        match rules.intercept("api.example.com", 443) {
            ProxyDecision::Proxy(selected) => {
                assert_eq!(rules.proxy(), Some(&selected));
            }
            ProxyDecision::Direct(_) => {}
        }
        assert_eq!(ProxyRules::default(), rules);
    }
}
