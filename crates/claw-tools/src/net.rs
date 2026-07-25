//! Capability-gated outbound network access with SSRF policy.
//!
//! This crate performs no I/O of its own. A transport is a port the host
//! supplies; the default implementations refuse every request, so a test or a
//! misconfigured deployment cannot reach the network by accident.
//!
//! Every destination is validated through [`claw_security::ssrf`], which
//! rejects loopback, link-local, private, carrier-grade NAT, documentation and
//! other special-use addresses, plus ambiguous numeric host encodings. On top
//! of that this module applies an explicit host denylist covering cloud
//! metadata services, a port allowlist, and per-hop revalidation of redirects
//! and DNS answers.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;

use claw_security::ssrf::{
    HostAllowlist, ResolutionError, TargetError, TargetHost, TargetPolicy, ValidatedTarget,
    validate_redirect, validate_target,
};
use serde_json::json;

use crate::error::ToolError;
use crate::permission::{Authorization, Capability, PermissionDescriptor, Resource, RiskLevel};
use crate::schema::{Arguments, Field, FieldType, ParameterSchema};
use crate::tool::{Tool, ToolContext, ToolDescriptor, ToolOutput};

/// Inclusive maximum byte length of a request URL.
const MAX_URL_BYTES: usize = 2048;
/// Inclusive maximum byte length of a search query.
const MAX_QUERY_BYTES: usize = 1024;
/// Inclusive maximum number of search results.
const MAX_SEARCH_RESULTS: u64 = 25;

/// Host suffixes that name internal infrastructure on common platforms.
const DENIED_HOST_SUFFIXES: [&str; 6] = [
    ".internal",
    ".local",
    ".localdomain",
    ".svc",
    ".arpa",
    ".onion",
];

/// Exact hostnames that front cloud instance metadata services.
const DENIED_HOSTS: [&str; 4] = [
    "metadata.goog",
    "metadata.google.internal",
    "instance-data.ec2.internal",
    "kubernetes.default.svc",
];

const FETCH_SCHEMA: ParameterSchema = ParameterSchema::new(&[
    Field {
        name: "url",
        description: "Absolute http or https URL; credentials and fragments are refused",
        required: true,
        ty: FieldType::Text {
            max_bytes: MAX_URL_BYTES,
        },
    },
    Field {
        name: "method",
        description: "HTTP method, restricted to safe read methods",
        required: false,
        ty: FieldType::Choice {
            values: &["GET", "HEAD"],
        },
    },
]);

const SEARCH_SCHEMA: ParameterSchema = ParameterSchema::new(&[
    Field {
        name: "query",
        description: "Search query passed to the configured provider",
        required: true,
        ty: FieldType::Text {
            max_bytes: MAX_QUERY_BYTES,
        },
    },
    Field {
        name: "max_results",
        description: "Maximum number of results to return",
        required: false,
        ty: FieldType::Count {
            max: MAX_SEARCH_RESULTS,
        },
    },
]);

/// Whether a policy permits destinations that are otherwise blocked.
///
/// The default refuses every private, loopback and link-local destination.
/// An operator opts in one exact origin at a time; nothing is implied by a
/// parent host, a subnet, or a port range.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivateOriginExceptions {
    origins: BTreeSet<String>,
}

impl PrivateOriginExceptions {
    /// Creates an empty exception set.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Permits exactly one origin such as `http://127.0.0.1:8080`.
    ///
    /// The origin must be lowercase, carry an explicit port, and contain no
    /// path, query, fragment or credentials.
    pub fn allow_origin(&mut self, origin: &str) -> Result<(), NetworkError> {
        let rest = origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"))
            .ok_or(NetworkError::InvalidExceptionOrigin)?;
        if rest.is_empty()
            || rest.contains(['/', '?', '#', '@', '\\'])
            || rest != rest.to_ascii_lowercase()
        {
            return Err(NetworkError::InvalidExceptionOrigin);
        }
        let (_host, port) = rest
            .rsplit_once(':')
            .ok_or(NetworkError::InvalidExceptionOrigin)?;
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(NetworkError::InvalidExceptionOrigin);
        }
        if port
            .parse::<u16>()
            .map_err(|_| NetworkError::InvalidExceptionOrigin)?
            == 0
        {
            return Err(NetworkError::InvalidExceptionOrigin);
        }
        self.origins.insert(origin.to_owned());
        Ok(())
    }

    /// Returns the permitted origins in stable order.
    #[must_use]
    pub fn origins(&self) -> Vec<String> {
        self.origins.iter().cloned().collect()
    }

    /// Matches a request URL against the exact permitted origins.
    ///
    /// Matching is a literal origin prefix followed by end of input, `/` or
    /// `?`, so `http://127.0.0.1:80.evil.test/` and
    /// `http://127.0.0.1:80@evil.test/` both fail.
    fn permits(&self, url: &str) -> Option<String> {
        if url.contains(['@', '#', '\\'])
            || url
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return None;
        }
        self.origins
            .iter()
            .find(|origin| match url.strip_prefix(origin.as_str()) {
                Some("") => true,
                Some(rest) => rest.starts_with('/') || rest.starts_with('?'),
                None => false,
            })
            .cloned()
    }
}

/// Destination policy applied to every outbound request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UrlPolicy {
    target: TargetPolicy,
    denied_hosts: BTreeSet<String>,
    denied_suffixes: BTreeSet<String>,
    allowed_ports: BTreeSet<u16>,
    exceptions: PrivateOriginExceptions,
    max_redirects: u8,
    max_body_bytes: usize,
}

impl Default for UrlPolicy {
    fn default() -> Self {
        Self {
            target: TargetPolicy::PublicInternet,
            denied_hosts: DENIED_HOSTS.iter().map(|host| (*host).to_owned()).collect(),
            denied_suffixes: DENIED_HOST_SUFFIXES
                .iter()
                .map(|suffix| (*suffix).to_owned())
                .collect(),
            allowed_ports: [80, 443].into_iter().collect(),
            exceptions: PrivateOriginExceptions::none(),
            max_redirects: 3,
            max_body_bytes: 1024 * 1024,
        }
    }
}

impl UrlPolicy {
    /// Creates the default policy: public Internet, ports 80 and 443 only.
    #[must_use]
    pub fn public_internet() -> Self {
        Self::default()
    }

    /// Restricts destinations to an exact host allowlist.
    pub fn exact_hosts<I, S>(hosts: I) -> Result<Self, NetworkError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let allowlist = HostAllowlist::new(hosts).map_err(NetworkError::Target)?;
        Ok(Self {
            target: TargetPolicy::ExactHosts(allowlist),
            ..Self::default()
        })
    }

    /// Adds one more exactly-denied host.
    pub fn deny_host(&mut self, host: &str) {
        self.denied_hosts.insert(host.to_ascii_lowercase());
    }

    /// Replaces the allowed port set.
    #[must_use]
    pub fn with_allowed_ports<I: IntoIterator<Item = u16>>(mut self, ports: I) -> Self {
        self.allowed_ports = ports.into_iter().filter(|port| *port != 0).collect();
        self
    }

    /// Replaces the private-origin exception set.
    #[must_use]
    pub fn with_exceptions(mut self, exceptions: PrivateOriginExceptions) -> Self {
        self.exceptions = exceptions;
        self
    }

    /// Replaces the redirect budget.
    #[must_use]
    pub const fn with_max_redirects(mut self, max_redirects: u8) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    /// Replaces the response body cap.
    #[must_use]
    pub const fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// Returns the redirect budget.
    #[must_use]
    pub const fn max_redirects(&self) -> u8 {
        self.max_redirects
    }

    /// Returns the response body cap.
    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Validates one destination against the whole policy.
    pub fn validate(&self, url: &str) -> Result<Destination, NetworkError> {
        if url.len() > MAX_URL_BYTES {
            return Err(NetworkError::UrlTooLong);
        }
        if let Some(origin) = self.exceptions.permits(url) {
            return Ok(Destination::PrivateException {
                url: url.to_owned(),
                origin,
            });
        }
        let target = validate_target(url, &self.target).map_err(NetworkError::Target)?;
        self.check_host_and_port(&target)?;
        Ok(Destination::Public(Box::new(target)))
    }

    /// Validates a redirect hop against the whole policy.
    pub fn validate_hop(
        &self,
        current: &ValidatedTarget,
        location: &str,
    ) -> Result<ValidatedTarget, NetworkError> {
        if location.len() > MAX_URL_BYTES {
            return Err(NetworkError::UrlTooLong);
        }
        let target =
            validate_redirect(current, location, &self.target).map_err(NetworkError::Target)?;
        self.check_host_and_port(&target)?;
        Ok(target)
    }

    fn check_host_and_port(&self, target: &ValidatedTarget) -> Result<(), NetworkError> {
        if !self.allowed_ports.contains(&target.port()) {
            return Err(NetworkError::PortNotAllowed);
        }
        if let TargetHost::Dns(host) = target.host() {
            if self.denied_hosts.contains(host) {
                return Err(NetworkError::HostDenied);
            }
            if self
                .denied_suffixes
                .iter()
                .any(|suffix| host.ends_with(suffix.as_str()))
            {
                return Err(NetworkError::HostDenied);
            }
        }
        Ok(())
    }
}

/// A destination that passed policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Destination {
    /// A public Internet target requiring DNS revalidation before connecting.
    Public(Box<ValidatedTarget>),
    /// An explicitly excepted private origin.
    PrivateException {
        /// Full request URL.
        url: String,
        /// Origin entry that permitted it.
        origin: String,
    },
}

impl Destination {
    /// Returns the URL a transport should request.
    #[must_use]
    pub fn url(&self) -> &str {
        match self {
            Self::Public(target) => target.as_str(),
            Self::PrivateException { url, .. } => url,
        }
    }

    /// Returns the canonical host identity used for grants and audit records.
    #[must_use]
    pub fn host(&self) -> String {
        match self {
            Self::Public(target) => target.host().as_str(),
            Self::PrivateException { origin, .. } => origin.clone(),
        }
    }
}

/// One outbound request a transport should perform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequest {
    /// Absolute, already-validated URL.
    pub url: String,
    /// HTTP method, restricted to safe read methods by the tool.
    pub method: String,
    /// Maximum number of response body bytes the caller will accept.
    pub max_body_bytes: usize,
}

/// One response returned by a transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// `Location` header when the response is a redirect.
    pub location: Option<String>,
    /// Response body, already capped by the transport.
    pub body: Vec<u8>,
}

/// Host-supplied outbound HTTP port.
///
/// Implementations must resolve through [`HttpTransport::resolve`] and must
/// not follow redirects themselves: redirect policy belongs to this crate.
pub trait HttpTransport {
    /// Resolves a host to the addresses a connection would use.
    fn resolve(&mut self, host: &str) -> Result<Vec<IpAddr>, NetworkError>;

    /// Performs exactly one request without following redirects.
    fn fetch(&mut self, request: &HttpRequest) -> Result<HttpResponse, NetworkError>;
}

/// Transport that refuses every request.
///
/// This is the default so that no configuration mistake and no test can reach
/// the network.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DenyAllTransport;

impl HttpTransport for DenyAllTransport {
    fn resolve(&mut self, _host: &str) -> Result<Vec<IpAddr>, NetworkError> {
        Err(NetworkError::TransportRefused)
    }

    fn fetch(&mut self, _request: &HttpRequest) -> Result<HttpResponse, NetworkError> {
        Err(NetworkError::TransportRefused)
    }
}

/// One search result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchHit {
    /// Result title.
    pub title: String,
    /// Result URL, revalidated against the policy before it is returned.
    pub url: String,
    /// Short snippet.
    pub snippet: String,
}

/// Host-supplied search port.
pub trait SearchProvider {
    /// Stable provider identity used for grants and audit records.
    fn name(&self) -> &str;

    /// Runs one query.
    fn search(&mut self, query: &str, max_results: usize) -> Result<Vec<SearchHit>, NetworkError>;
}

/// Search provider that refuses every query.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DenyAllSearchProvider;

impl SearchProvider for DenyAllSearchProvider {
    fn name(&self) -> &str {
        "denied"
    }

    fn search(
        &mut self,
        _query: &str,
        _max_results: usize,
    ) -> Result<Vec<SearchHit>, NetworkError> {
        Err(NetworkError::TransportRefused)
    }
}

/// Performs a policy-checked outbound HTTP read.
pub struct NetFetchTool<T: HttpTransport> {
    policy: UrlPolicy,
    transport: std::cell::RefCell<T>,
}

impl<T: HttpTransport> NetFetchTool<T> {
    /// Creates the tool from a policy and a transport port.
    pub fn new(policy: UrlPolicy, transport: T) -> Self {
        Self {
            policy,
            transport: std::cell::RefCell::new(transport),
        }
    }

    /// Returns the policy in force.
    #[must_use]
    pub const fn policy(&self) -> &UrlPolicy {
        &self.policy
    }

    /// Runs the validated request loop, revalidating every hop.
    fn run(&self, destination: Destination, method: &str) -> Result<FetchOutcome, NetworkError> {
        let mut transport = self.transport.borrow_mut();
        let mut hops: Vec<String> = vec![destination.url().to_owned()];
        let mut current = destination;
        let mut redirects = 0_u8;
        loop {
            if let Destination::Public(target) = &current {
                // DNS is revalidated on every hop so a rebinding answer cannot
                // reuse an earlier decision.
                let host = target.host().as_str();
                let addresses = transport.resolve(host.as_str())?;
                target
                    .validate_resolution(&addresses)
                    .map_err(NetworkError::Resolution)?;
            }
            let request = HttpRequest {
                url: current.url().to_owned(),
                method: method.to_owned(),
                max_body_bytes: self.policy.max_body_bytes,
            };
            let response = transport.fetch(&request)?;
            if !(300..400).contains(&response.status) {
                return Ok(FetchOutcome {
                    status: response.status,
                    body: response.body,
                    host: current.host(),
                    hops,
                });
            }
            let location = response.location.ok_or(NetworkError::MalformedRedirect)?;
            if redirects >= self.policy.max_redirects {
                return Err(NetworkError::TooManyRedirects);
            }
            redirects += 1;
            let next = match &current {
                Destination::Public(target) => {
                    Destination::Public(Box::new(self.policy.validate_hop(target, &location)?))
                }
                // A private exception never becomes a licence to roam: the
                // redirect is revalidated from scratch against the policy.
                Destination::PrivateException { .. } => self.policy.validate(&location)?,
            };
            hops.push(next.url().to_owned());
            current = next;
        }
    }
}

struct FetchOutcome {
    status: u16,
    body: Vec<u8>,
    host: String,
    hops: Vec<String>,
}

impl<T: HttpTransport> Tool for NetFetchTool<T> {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "net_fetch",
            title: "Fetch a URL",
            description: "Performs a read-only HTTP request to an allowlisted public destination. \
                          Loopback, link-local, private and cloud-metadata destinations are \
                          refused, and every redirect hop is revalidated.",
            schema: FETCH_SCHEMA,
            permission: PermissionDescriptor {
                capability: Capability::NetworkFetch,
                risk: RiskLevel::High,
                requires_approval: true,
                gateway_scope: "operator.write",
            },
        }
    }

    fn resource(
        &self,
        arguments: &Arguments,
        _context: &ToolContext<'_>,
    ) -> Result<Resource, ToolError> {
        let url = arguments.required_text("url")?;
        let destination = self.policy.validate(url)?;
        Ok(Resource::Host(destination.host()))
    }

    fn invoke(
        &self,
        arguments: &Arguments,
        _context: &ToolContext<'_>,
        _authorization: &Authorization<'_>,
    ) -> Result<ToolOutput, ToolError> {
        let url = arguments.required_text("url")?;
        let method = arguments.text("method").unwrap_or("GET");
        let destination = self.policy.validate(url)?;
        let outcome = self.run(destination, method)?;
        let truncated = outcome.body.len() >= self.policy.max_body_bytes;
        let body = String::from_utf8_lossy(&outcome.body).into_owned();
        Ok(ToolOutput::new(
            body.clone(),
            json!({
                "status": outcome.status,
                "host": outcome.host,
                "hops": outcome.hops,
                "body": body,
                "bytes": outcome.body.len(),
            }),
        )
        .truncated(truncated))
    }
}

/// Queries a configured search provider and revalidates every result URL.
pub struct WebSearchTool<P: SearchProvider> {
    policy: UrlPolicy,
    provider: std::cell::RefCell<P>,
    provider_name: String,
}

impl<P: SearchProvider> WebSearchTool<P> {
    /// Creates the tool from a policy and a provider port.
    pub fn new(policy: UrlPolicy, provider: P) -> Self {
        let provider_name = provider.name().to_owned();
        Self {
            policy,
            provider: std::cell::RefCell::new(provider),
            provider_name,
        }
    }
}

impl<P: SearchProvider> Tool for WebSearchTool<P> {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "web_search",
            title: "Search the web",
            description: "Queries the configured search provider. Result URLs that the \
                          destination policy would refuse are dropped before the model sees them.",
            schema: SEARCH_SCHEMA,
            permission: PermissionDescriptor {
                capability: Capability::NetworkSearch,
                risk: RiskLevel::Medium,
                requires_approval: true,
                gateway_scope: "operator.read",
            },
        }
    }

    fn resource(
        &self,
        _arguments: &Arguments,
        _context: &ToolContext<'_>,
    ) -> Result<Resource, ToolError> {
        Ok(Resource::Host(self.provider_name.clone()))
    }

    fn invoke(
        &self,
        arguments: &Arguments,
        _context: &ToolContext<'_>,
        _authorization: &Authorization<'_>,
    ) -> Result<ToolOutput, ToolError> {
        let query = arguments.required_text("query")?;
        if query.trim().is_empty() {
            return Err(ToolError::Schema(crate::schema::SchemaError::Empty(
                "query",
            )));
        }
        let requested = arguments.count("max_results").unwrap_or(MAX_SEARCH_RESULTS);
        let limit = usize::try_from(requested.min(MAX_SEARCH_RESULTS)).unwrap_or(1);
        let hits = self.provider.borrow_mut().search(query, limit)?;

        let mut accepted = Vec::new();
        let mut rejected = 0_usize;
        for hit in hits.into_iter().take(limit) {
            if self.policy.validate(&hit.url).is_err() {
                rejected += 1;
                continue;
            }
            accepted.push(json!({
                "title": hit.title,
                "url": hit.url,
                "snippet": hit.snippet,
            }));
        }
        let rendered = accepted
            .iter()
            .filter_map(|hit| {
                let title = hit.get("title")?.as_str()?;
                let url = hit.get("url")?.as_str()?;
                Some(format!("{title}\n{url}"))
            })
            .collect::<Vec<_>>()
            .join("\n\n");
        Ok(ToolOutput::new(
            rendered,
            json!({
                "provider": self.provider_name,
                "results": accepted,
                "rejected_results": rejected,
            }),
        )
        .truncated(rejected > 0))
    }
}

/// A refused or failed network operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkError {
    /// The URL exceeded its byte bound.
    UrlTooLong,
    /// The destination policy refused the target.
    Target(TargetError),
    /// DNS revalidation refused the resolved addresses.
    Resolution(ResolutionError),
    /// The canonical host is on the denylist.
    HostDenied,
    /// The port is not on the allowlist.
    PortNotAllowed,
    /// A private-origin exception entry was malformed.
    InvalidExceptionOrigin,
    /// A redirect response carried no usable `Location`.
    MalformedRedirect,
    /// The redirect budget was exhausted.
    TooManyRedirects,
    /// No transport is configured, so the request was refused.
    TransportRefused,
    /// The transport failed to complete the request.
    TransportFailed,
}

impl Display for NetworkError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UrlTooLong => formatter.write_str("target URL is too long"),
            Self::Target(error) => write!(formatter, "target refused: {error}"),
            Self::Resolution(error) => write!(formatter, "resolution refused: {error}"),
            Self::HostDenied => formatter.write_str("target host is denied by policy"),
            Self::PortNotAllowed => formatter.write_str("target port is not allowed by policy"),
            Self::InvalidExceptionOrigin => {
                formatter.write_str("private-origin exception is malformed")
            }
            Self::MalformedRedirect => formatter.write_str("redirect carried no usable location"),
            Self::TooManyRedirects => formatter.write_str("redirect budget exhausted"),
            Self::TransportRefused => formatter.write_str("no network transport is configured"),
            Self::TransportFailed => formatter.write_str("network transport failed"),
        }
    }
}

impl Error for NetworkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Target(error) => Some(error),
            Self::Resolution(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_link_local_and_private_destinations_are_refused() {
        let policy = UrlPolicy::public_internet();
        let cases = [
            "http://127.0.0.1/",
            "http://127.1/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://10.0.0.5/",
            "http://172.16.4.4/",
            "http://192.168.1.1/",
            "http://100.64.3.3/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://[::ffff:127.0.0.1]/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://kubernetes.default.svc/api",
            "http://printer.local/",
            "http://1.2.3.4.arpa/",
        ];
        for case in cases {
            assert!(
                policy.validate(case).is_err(),
                "policy accepted {case:?}, which is not a public destination"
            );
        }
    }

    #[test]
    fn a_public_destination_is_accepted_and_canonicalized() {
        let policy = UrlPolicy::public_internet();
        let destination = policy
            .validate("https://Example.COM/path?q=1")
            .expect("public destination");
        assert_eq!(destination.host(), "example.com".to_owned());
        assert_eq!(destination.url(), "https://example.com/path?q=1");
    }

    #[test]
    fn credentials_fragments_and_odd_schemes_are_refused() {
        let policy = UrlPolicy::public_internet();
        assert_eq!(
            policy.validate("https://user:pass@example.com/"),
            Err(NetworkError::Target(TargetError::UserInfoForbidden))
        );
        assert_eq!(
            policy.validate("https://example.com/#frag"),
            Err(NetworkError::Target(TargetError::FragmentForbidden))
        );
        assert_eq!(
            policy.validate("file:///etc/passwd"),
            Err(NetworkError::Target(TargetError::UnsupportedScheme))
        );
        assert_eq!(
            policy.validate("gopher://example.com/"),
            Err(NetworkError::Target(TargetError::UnsupportedScheme))
        );
    }

    #[test]
    fn non_standard_ports_are_refused_unless_allowed() {
        let policy = UrlPolicy::public_internet();
        assert_eq!(
            policy.validate("http://example.com:8080/"),
            Err(NetworkError::PortNotAllowed)
        );
        let widened = UrlPolicy::public_internet().with_allowed_ports([80, 443, 8080]);
        assert_eq!(
            widened
                .validate("http://example.com:8080/")
                .expect("allowed port")
                .host(),
            "example.com".to_owned()
        );
    }

    #[test]
    fn exact_host_policy_does_not_imply_subdomains() {
        let policy = UrlPolicy::exact_hosts(["example.com"]).expect("valid allowlist");
        assert_eq!(
            policy
                .validate("https://example.com/")
                .expect("allowed")
                .host(),
            "example.com".to_owned()
        );
        assert_eq!(
            policy.validate("https://evil.example.com/"),
            Err(NetworkError::Target(TargetError::HostNotAllowlisted))
        );
        assert_eq!(
            policy.validate("https://example.com.evil.test/"),
            Err(NetworkError::Target(TargetError::HostNotAllowlisted))
        );
    }

    #[test]
    fn a_private_origin_exception_is_exact_and_unforgeable() {
        let mut exceptions = PrivateOriginExceptions::none();
        exceptions
            .allow_origin("http://127.0.0.1:8080")
            .expect("valid origin");
        let policy = UrlPolicy::public_internet().with_exceptions(exceptions);

        assert_eq!(
            policy
                .validate("http://127.0.0.1:8080/health")
                .expect("permitted origin")
                .host(),
            "http://127.0.0.1:8080".to_owned()
        );
        for forged in [
            "http://127.0.0.1:8080.evil.test/",
            "http://127.0.0.1:8080@evil.test/",
            "http://127.0.0.1:8081/",
            "https://127.0.0.1:8080/",
            "http://127.0.0.2:8080/",
            "http://127.0.0.1:8080\\@evil.test/",
        ] {
            assert!(
                policy.validate(forged).is_err(),
                "exception leaked to {forged:?}"
            );
        }
    }

    #[test]
    fn malformed_exception_origins_are_refused() {
        let mut exceptions = PrivateOriginExceptions::none();
        for bad in [
            "127.0.0.1:8080",
            "ftp://127.0.0.1:8080",
            "http://127.0.0.1",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:8080?x=1",
            "http://user@127.0.0.1:8080",
            "http://127.0.0.1:notaport",
            "http://127.0.0.1:99999",
            "http://LOCALHOST:8080",
        ] {
            assert_eq!(
                exceptions.allow_origin(bad),
                Err(NetworkError::InvalidExceptionOrigin),
                "accepted {bad:?}"
            );
        }
        assert!(exceptions.origins().is_empty());
    }

    #[test]
    fn the_default_transport_and_provider_refuse_everything() {
        let mut transport = DenyAllTransport;
        assert_eq!(
            transport.resolve("example.com"),
            Err(NetworkError::TransportRefused)
        );
        assert_eq!(
            transport.fetch(&HttpRequest {
                url: "https://example.com/".to_owned(),
                method: "GET".to_owned(),
                max_body_bytes: 1,
            }),
            Err(NetworkError::TransportRefused)
        );
        let mut provider = DenyAllSearchProvider;
        assert_eq!(provider.name(), "denied");
        assert_eq!(
            provider.search("anything", 1),
            Err(NetworkError::TransportRefused)
        );
    }
}
