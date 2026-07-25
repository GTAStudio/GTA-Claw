//! User-entered Gateway endpoint intake.

use std::borrow::Cow;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use url::{Host, Url};

/// Maximum accepted endpoint text, in UTF-8 bytes.
const MAX_ENDPOINT_BYTES: usize = 512;

/// A validated Gateway WebSocket endpoint that carries no credential material.
///
/// The inner [`Url`] is credential-bearing by type: a URL can hold userinfo, a
/// query string, or a bearer path segment. [`GatewayEndpoint`] therefore has a
/// hand-written [`Debug`] that prints only the scheme, host and port, and the
/// only text this type will hand to a user interface is an
/// [`EndpointSummary`], which cannot hold anything else.
#[derive(Clone, Eq, PartialEq)]
pub struct GatewayEndpoint {
    url: Url,
}

impl GatewayEndpoint {
    /// Parses endpoint text a person typed into a mobile client.
    ///
    /// Text with no `://` is interpreted as `wss://`. The default is always the
    /// secure scheme; this function will never upgrade or downgrade a scheme the
    /// caller wrote explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] when the text is empty, oversized, contains
    /// control characters, is not a URL, does not use `ws` or `wss`, has no
    /// host, carries credential material, or is a remote plaintext WebSocket.
    pub fn parse(input: &str) -> Result<Self, EndpointError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(EndpointError::Empty);
        }
        if trimmed.len() > MAX_ENDPOINT_BYTES {
            return Err(EndpointError::TooLong {
                actual: trimmed.len(),
                limit: MAX_ENDPOINT_BYTES,
            });
        }
        if trimmed.chars().any(char::is_control) {
            return Err(EndpointError::ControlCharacter);
        }
        let candidate = if trimmed.contains("://") {
            Cow::Borrowed(trimmed)
        } else {
            Cow::Owned(format!("wss://{trimmed}"))
        };
        let url = Url::parse(candidate.as_ref()).map_err(|_| EndpointError::Malformed)?;
        match url.scheme() {
            "ws" | "wss" => {}
            _ => return Err(EndpointError::UnsupportedScheme),
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(EndpointError::CredentialBearing);
        }
        if url.host().is_none() {
            return Err(EndpointError::MissingHost);
        }
        let endpoint = Self { url };
        if !endpoint.is_secure() && !endpoint.is_loopback() {
            return Err(EndpointError::InsecureRemote);
        }
        Ok(endpoint)
    }

    /// Returns whether the endpoint uses TLS.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        self.url.scheme() == "wss"
    }

    /// Returns whether the endpoint names a loopback host.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        match self.url.host() {
            Some(Host::Domain("localhost")) => true,
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            Some(Host::Domain(_)) | None => false,
        }
    }

    /// Returns display text that provably cannot carry credential material.
    #[must_use]
    pub fn summary(&self) -> EndpointSummary {
        let scheme = self.url.scheme();
        let host = self.url.host_str().unwrap_or("<unknown>");
        let text = match self.url.port() {
            Some(port) => format!("{scheme}://{host}:{port}"),
            None => format!("{scheme}://{host}"),
        };
        EndpointSummary(text)
    }

    /// Returns the validated URL for the transport layer.
    #[must_use]
    pub fn into_url(self) -> Url {
        self.url
    }

    /// Borrows the validated URL.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }
}

impl Debug for GatewayEndpoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayEndpoint")
            .field("summary", &self.summary())
            .field("secure", &self.is_secure())
            .field("loopback", &self.is_loopback())
            .finish()
    }
}

/// Redaction-safe endpoint text for display.
///
/// The only constructor is [`GatewayEndpoint::summary`], which emits scheme,
/// host and port and nothing else. The URL path is deliberately omitted: a path
/// segment can be a bearer token, and a value that reaches a log or a screen
/// must not be able to hold one.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EndpointSummary(String);

impl EndpointSummary {
    /// Returns the display text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for EndpointSummary {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Endpoint text a mobile client must refuse before any network operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointError {
    /// The field was blank.
    Empty,
    /// The text exceeded the accepted length.
    TooLong {
        /// Observed UTF-8 byte length.
        actual: usize,
        /// Accepted UTF-8 byte length.
        limit: usize,
    },
    /// The text contained a control character.
    ControlCharacter,
    /// The text is not a URL.
    Malformed,
    /// The scheme is not `ws` or `wss`.
    UnsupportedScheme,
    /// The URL carries userinfo, a query string, or a fragment.
    CredentialBearing,
    /// The URL has no host.
    MissingHost,
    /// A remote plaintext WebSocket is never accepted by this client.
    InsecureRemote,
}

impl Display for EndpointError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("enter a Gateway address"),
            Self::TooLong { actual, limit } => write!(
                formatter,
                "Gateway address is {actual} bytes, which exceeds the {limit}-byte limit"
            ),
            Self::ControlCharacter => {
                formatter.write_str("Gateway address contains a control character")
            }
            Self::Malformed => formatter.write_str("Gateway address is not a valid URL"),
            Self::UnsupportedScheme => {
                formatter.write_str("Gateway address must use ws:// or wss://")
            }
            Self::CredentialBearing => formatter
                .write_str("Gateway address must not contain a user, password, query, or fragment"),
            Self::MissingHost => formatter.write_str("Gateway address must contain a host"),
            Self::InsecureRemote => formatter
                .write_str("a remote Gateway address must use wss:// so traffic is encrypted"),
        }
    }
}

impl Error for EndpointError {}

#[cfg(test)]
mod tests {
    use super::{EndpointError, GatewayEndpoint, MAX_ENDPOINT_BYTES};

    #[test]
    fn bare_text_defaults_to_the_secure_scheme() {
        let endpoint = GatewayEndpoint::parse("gateway.example:4443").expect("bare host is valid");

        assert_eq!(endpoint.summary().as_str(), "wss://gateway.example:4443");
        assert!(
            endpoint.is_secure(),
            "expected a secure endpoint, got {endpoint:?}"
        );
    }

    #[test]
    fn an_explicit_secure_scheme_is_preserved() {
        let endpoint = GatewayEndpoint::parse("  wss://gateway.example/gateway  ")
            .expect("explicit wss is valid");

        assert_eq!(endpoint.summary().as_str(), "wss://gateway.example");
    }

    #[test]
    fn the_summary_omits_a_path_that_could_carry_a_bearer_segment() {
        let endpoint = GatewayEndpoint::parse("wss://gateway.example/ws/abcdef0123456789")
            .expect("a path is permitted on the wire");
        let summary = endpoint.summary();

        assert!(
            !summary.as_str().contains("abcdef0123456789"),
            "summary leaked the path: {summary}"
        );
        assert_eq!(summary.as_str(), "wss://gateway.example");
    }

    #[test]
    fn the_debug_representation_omits_the_path() {
        let endpoint = GatewayEndpoint::parse("wss://gateway.example/ws/abcdef0123456789")
            .expect("a path is permitted on the wire");
        let rendered = format!("{endpoint:?}");

        assert!(
            !rendered.contains("abcdef0123456789"),
            "Debug leaked the path: {rendered}"
        );
    }

    #[test]
    fn loopback_plaintext_is_accepted_and_remote_plaintext_is_not() {
        let loopback = GatewayEndpoint::parse("ws://127.0.0.1:4443").expect("loopback ws is valid");

        assert!(
            loopback.is_loopback(),
            "expected a loopback endpoint, got {loopback:?}"
        );
        assert!(
            !loopback.is_secure(),
            "expected plaintext, got {loopback:?}"
        );

        let remote = GatewayEndpoint::parse("ws://gateway.example");

        assert_eq!(remote.err(), Some(EndpointError::InsecureRemote));
    }

    #[test]
    fn localhost_and_ipv6_loopback_are_recognised() {
        for text in ["ws://localhost:4443", "ws://[::1]:4443"] {
            let endpoint = GatewayEndpoint::parse(text)
                .unwrap_or_else(|error| panic!("{text} must parse, got {error:?}"));

            assert!(
                endpoint.is_loopback(),
                "{text} must be loopback, got {endpoint:?}"
            );
        }
    }

    #[test]
    fn credential_bearing_urls_are_refused() {
        for text in [
            "wss://operator@gateway.example",
            "wss://:x@gateway.example",
            "wss://gateway.example?token=abcdef",
            "wss://gateway.example#token",
        ] {
            let error = GatewayEndpoint::parse(text)
                .err()
                .unwrap_or_else(|| panic!("{text} must be refused"));

            assert_eq!(
                error,
                EndpointError::CredentialBearing,
                "wrong refusal for {text}"
            );
        }
    }

    #[test]
    fn unsupported_schemes_are_refused() {
        for text in ["https://gateway.example", "file:///etc/passwd"] {
            let error = GatewayEndpoint::parse(text)
                .err()
                .unwrap_or_else(|| panic!("{text} must be refused"));

            assert_eq!(
                error,
                EndpointError::UnsupportedScheme,
                "wrong refusal for {text}"
            );
        }
    }

    #[test]
    fn blank_control_and_oversized_text_are_refused() {
        assert_eq!(
            GatewayEndpoint::parse("   ").err(),
            Some(EndpointError::Empty)
        );
        assert_eq!(
            GatewayEndpoint::parse("wss://gateway.example\u{7}").err(),
            Some(EndpointError::ControlCharacter)
        );

        let oversized = format!("wss://{}", "a".repeat(MAX_ENDPOINT_BYTES));
        let error = GatewayEndpoint::parse(&oversized).expect_err("oversized text is refused");

        assert_eq!(
            error,
            EndpointError::TooLong {
                actual: oversized.len(),
                limit: MAX_ENDPOINT_BYTES,
            }
        );
    }
}
