//! Closed error taxonomy for provider operations.
//!
//! Every failure surfaced by this crate is a [`ProviderError`]. The error type
//! deliberately stores only sanitized, typed data: it holds no boxed source, no
//! request URL and no header material, so an error value can never carry
//! credential bytes into a log sink.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum number of characters retained from an upstream error description.
const MAX_DETAIL_CHARS: usize = 512;

/// Closed classification of provider failures.
///
/// # Choosing a variant
///
/// Every failure in this crate lands in exactly one variant, and the variant —
/// not the HTTP status, and not the message — is what the reliability policies
/// act on. The upstream conditions map like this:
///
/// | Variant | Upstream condition | Retryable | Trips the circuit |
/// | --- | --- | --- | --- |
/// | [`Authentication`](Self::Authentication) | HTTP 401/403, a rejected or expired key, a refresh that failed | no | no |
/// | [`RateLimit`](Self::RateLimit) | HTTP 429, usually with `Retry-After` | yes | no |
/// | [`Quota`](Self::Quota) | HTTP 402, or a 403/429 whose body names an exhausted billing quota | no | no |
/// | [`Transport`](Self::Transport) | DNS, TCP, TLS or proxy failure; a body that stopped mid-response | yes | yes |
/// | [`Protocol`](Self::Protocol) | a response arrived but breaks the wire contract: unparseable HTTP, malformed JSON, an event for a block that never started | no | yes |
/// | [`Server`](Self::Server) | HTTP 5xx | yes | yes |
/// | [`InvalidRequest`](Self::InvalidRequest) | HTTP 4xx that is none of the above, and any request this crate refuses to build | no | no |
/// | [`Cancelled`](Self::Cancelled) | the caller's [`CancelToken`](crate::CancelToken) fired | no | no |
/// | [`Timeout`](Self::Timeout) | HTTP 408, or the request deadline elapsed | yes | yes |
/// | [`CircuitOpen`](Self::CircuitOpen) | the breaker refused to admit the call | no | no |
/// | [`Unsupported`](Self::Unsupported) | the provider does not implement the operation | no | no |
///
/// `Quota` is deliberately not retryable and `RateLimit` is: the first says the
/// account is out of budget, the second says the account went too fast.
/// `Protocol` is not retryable but does trip the circuit, because replaying the
/// same request gets the same broken response while a provider that is speaking
/// its own protocol wrong is unhealthy. `CircuitOpen` is not retryable because
/// the breaker owns its own recovery schedule; retrying inside a request would
/// fight it.
///
/// The two predicates are [`ErrorKind::is_retryable`] and
/// [`ErrorKind::trips_circuit`], and the table above is asserted in the tests.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorKind {
    /// Credentials are missing, malformed, expired or rejected.
    ///
    /// Retrying cannot help: the caller must supply a different credential.
    Authentication,
    /// The caller exceeded a request-rate limit and may retry later.
    ///
    /// Carries [`ProviderError::retry_after`] when the response named one.
    RateLimit,
    /// A hard billing or usage quota is exhausted; retrying will not help.
    Quota,
    /// Connection, TLS or socket-level failure before a complete response.
    ///
    /// Retryable, and counts toward opening the circuit.
    Transport,
    /// A response was received but violates the provider wire contract.
    ///
    /// Not retryable — the same request produces the same broken response — but
    /// it does count toward opening the circuit.
    Protocol,
    /// The provider reported an internal failure (HTTP 5xx).
    ///
    /// Retryable, and counts toward opening the circuit.
    Server,
    /// The request itself is invalid and must be changed before retrying.
    InvalidRequest,
    /// The caller cancelled the operation.
    ///
    /// Never retried: the caller asked to stop.
    Cancelled,
    /// The operation exceeded its deadline.
    ///
    /// Retryable, and counts toward opening the circuit.
    Timeout,
    /// The circuit breaker for this provider is open.
    ///
    /// Not retried by the request-level policy, which would only fight the
    /// breaker's own recovery schedule.
    CircuitOpen,
    /// The provider does not implement the requested operation.
    Unsupported,
}

impl ErrorKind {
    /// Every variant, in declaration order.
    pub const ALL: [Self; 11] = [
        Self::Authentication,
        Self::RateLimit,
        Self::Quota,
        Self::Transport,
        Self::Protocol,
        Self::Server,
        Self::InvalidRequest,
        Self::Cancelled,
        Self::Timeout,
        Self::CircuitOpen,
        Self::Unsupported,
    ];

    /// Returns the stable wire-safe identifier of this classification.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::RateLimit => "rate_limit",
            Self::Quota => "quota",
            Self::Transport => "transport",
            Self::Protocol => "protocol",
            Self::Server => "server",
            Self::InvalidRequest => "invalid_request",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::CircuitOpen => "circuit_open",
            Self::Unsupported => "unsupported",
        }
    }

    /// Returns `true` when re-issuing the identical request can succeed.
    ///
    /// Cancellation is never retried because the caller asked to stop, and an
    /// open circuit is not retried by the request-level policy because the
    /// breaker owns its own recovery schedule.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimit | Self::Transport | Self::Server | Self::Timeout
        )
    }

    /// Returns `true` when the failure should move the circuit breaker toward
    /// the open state.
    ///
    /// Client mistakes (`InvalidRequest`, `Unsupported`) and caller-driven
    /// cancellation say nothing about provider health, so they are excluded.
    #[must_use]
    pub const fn trips_circuit(self) -> bool {
        matches!(
            self,
            Self::Transport | Self::Server | Self::Timeout | Self::Protocol
        )
    }
}

impl Display for ErrorKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Provider operation that produced a failure.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Operation {
    /// Non-streaming chat completion.
    Complete,
    /// Streaming chat completion.
    StreamCompletion,
    /// Embedding generation.
    Embed,
    /// Model catalogue listing.
    ListModels,
    /// Credential acquisition or refresh.
    Authorize,
    /// Transport setup, outside any single provider operation.
    Transport,
}

impl Operation {
    /// Returns the stable wire-safe identifier of this operation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::StreamCompletion => "stream_completion",
            Self::Embed => "embed",
            Self::ListModels => "list_models",
            Self::Authorize => "authorize",
            Self::Transport => "transport",
        }
    }
}

impl Display for Operation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A sanitized, fully typed provider failure.
///
/// The value contains no URL, no header map and no boxed source error. Upstream
/// text is passed through [`sanitize`] before it is stored, which strips control
/// characters and bounds the length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderError {
    kind: ErrorKind,
    provider: String,
    operation: Operation,
    detail: String,
    status: Option<u16>,
    upstream_code: Option<String>,
    retry_after: Option<Duration>,
}

impl ProviderError {
    /// Builds an error for `provider` and `operation`.
    #[must_use]
    pub fn new(
        kind: ErrorKind,
        provider: impl AsRef<str>,
        operation: Operation,
        detail: impl AsRef<str>,
    ) -> Self {
        Self {
            kind,
            provider: sanitize(provider.as_ref(), 128),
            operation,
            detail: sanitize(detail.as_ref(), MAX_DETAIL_CHARS),
            status: None,
            upstream_code: None,
            retry_after: None,
        }
    }

    /// Attaches the HTTP status code that produced this error.
    #[must_use]
    pub const fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// Attaches the machine-readable error code reported by the provider.
    #[must_use]
    pub fn with_upstream_code(mut self, code: impl AsRef<str>) -> Self {
        self.upstream_code = Some(sanitize(code.as_ref(), 128));
        self
    }

    /// Attaches the server-instructed delay before the next attempt.
    #[must_use]
    pub const fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after = Some(retry_after);
        self
    }

    /// Returns the failure classification.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the provider identifier the failure belongs to.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the operation that failed.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// Returns the sanitized human-readable description.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Returns the HTTP status code, when the failure came from a response.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        self.status
    }

    /// Returns the provider-specific error code, when one was reported.
    #[must_use]
    pub fn upstream_code(&self) -> Option<&str> {
        self.upstream_code.as_deref()
    }

    /// Returns the server-instructed retry delay, when one was reported.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// Returns `true` when re-issuing the identical request can succeed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.kind.is_retryable()
    }

    /// Classifies an HTTP status code into the error taxonomy.
    ///
    /// `402`, `403` with a quota code and `429` with a zero-remaining quota
    /// header are distinguished by callers; this function applies only the
    /// status-code rules that are identical across every provider.
    #[must_use]
    pub const fn kind_for_status(status: u16) -> ErrorKind {
        match status {
            401 | 403 => ErrorKind::Authentication,
            402 => ErrorKind::Quota,
            408 => ErrorKind::Timeout,
            429 => ErrorKind::RateLimit,
            500..=599 => ErrorKind::Server,
            _ => ErrorKind::InvalidRequest,
        }
    }
}

impl Display for ProviderError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} failed ({})",
            self.provider, self.operation, self.kind
        )?;
        if let Some(status) = self.status {
            write!(formatter, " status={status}")?;
        }
        if let Some(code) = &self.upstream_code {
            write!(formatter, " code={code}")?;
        }
        if !self.detail.is_empty() {
            write!(formatter, ": {}", self.detail)?;
        }
        Ok(())
    }
}

impl Error for ProviderError {}

/// Removes control characters and bounds the length of untrusted text.
///
/// Newlines are folded into spaces so that a hostile response body cannot forge
/// additional lines in a line-oriented log.
#[must_use]
pub fn sanitize(value: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(value.len().min(max_chars));
    let mut kept = 0_usize;
    let mut truncated = false;
    for character in value.chars() {
        if kept >= max_chars {
            truncated = true;
            break;
        }
        if character.is_control() {
            if !out.ends_with(' ') && !out.is_empty() {
                out.push(' ');
                kept += 1;
            }
        } else {
            out.push(character);
            kept += 1;
        }
    }
    let mut out = out.trim().to_owned();
    if truncated {
        out.push('…');
    }
    out
}

/// Parses an HTTP `Retry-After` header value relative to `now`.
///
/// Both forms defined by RFC 9110 are accepted: a non-negative integer number of
/// seconds, and an `IMF-fixdate` timestamp. Timestamps that are already in the
/// past yield [`Duration::ZERO`]. Any other input returns [`None`].
#[must_use]
pub fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value.parse::<u64>().ok().map(Duration::from_secs);
    }
    let target = parse_imf_fixdate(value)?;
    let now_secs = now.duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(target.saturating_sub(now_secs)))
}

/// Parses an `IMF-fixdate` such as `Sun, 06 Nov 1994 08:49:37 GMT`.
///
/// Returns seconds since the Unix epoch.
fn parse_imf_fixdate(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.len() != 29 || !value.ends_with(" GMT") {
        return None;
    }
    if bytes[3] != b',' || bytes[4] != b' ' {
        return None;
    }
    let day = parse_fixed_number(&value[5..7])?;
    if bytes[7] != b' ' || bytes[11] != b' ' || bytes[16] != b' ' {
        return None;
    }
    let month = match &value[8..11] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year = parse_fixed_number(&value[12..16])?;
    if bytes[19] != b':' || bytes[22] != b':' {
        return None;
    }
    let hour = parse_fixed_number(&value[17..19])?;
    let minute = parse_fixed_number(&value[20..22])?;
    let second = parse_fixed_number(&value[23..25])?;
    if day == 0 || day > 31 || hour > 23 || minute > 59 || second > 60 || year < 1970 {
        return None;
    }
    let days = days_from_civil(i64::from(year), month, i64::from(day));
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))?;
    u64::try_from(seconds).ok()
}

fn parse_fixed_number(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u32>().ok()
}

/// Days since 1970-01-01 for a proleptic Gregorian civil date.
///
/// This is Howard Hinnant's `days_from_civil` algorithm. The caller has already
/// bounded `year`, `month` and `day` to a calendar range, so every intermediate
/// fits in `i64` without checking.
fn days_from_civil(year: i64, month: u32, day: i64) -> i64 {
    let month = i64::from(month);
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classification_covers_the_documented_ranges() {
        let cases = [
            (400_u16, ErrorKind::InvalidRequest),
            (401, ErrorKind::Authentication),
            (402, ErrorKind::Quota),
            (403, ErrorKind::Authentication),
            (404, ErrorKind::InvalidRequest),
            (408, ErrorKind::Timeout),
            (422, ErrorKind::InvalidRequest),
            (429, ErrorKind::RateLimit),
            (500, ErrorKind::Server),
            (503, ErrorKind::Server),
            (599, ErrorKind::Server),
        ];
        for (status, expected) in cases {
            assert_eq!(ProviderError::kind_for_status(status), expected, "{status}");
        }
    }

    #[test]
    fn retryable_and_circuit_classification_is_exhaustive_and_stable() {
        let retryable = ErrorKind::ALL
            .into_iter()
            .filter(|kind| kind.is_retryable())
            .collect::<Vec<_>>();
        assert_eq!(
            retryable,
            vec![
                ErrorKind::RateLimit,
                ErrorKind::Transport,
                ErrorKind::Server,
                ErrorKind::Timeout,
            ]
        );

        let tripping = ErrorKind::ALL
            .into_iter()
            .filter(|kind| kind.trips_circuit())
            .collect::<Vec<_>>();
        assert_eq!(
            tripping,
            vec![
                ErrorKind::Transport,
                ErrorKind::Protocol,
                ErrorKind::Server,
                ErrorKind::Timeout,
            ]
        );
    }

    #[test]
    fn error_kind_identifiers_are_unique_and_snake_case() {
        let mut seen = Vec::new();
        for kind in ErrorKind::ALL {
            let text = kind.as_str();
            assert!(
                text.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
            assert!(!seen.contains(&text), "duplicate identifier {text}");
            seen.push(text);
        }
        assert_eq!(seen.len(), 11);
    }

    #[test]
    fn sanitize_folds_control_characters_and_bounds_length() {
        assert_eq!(sanitize("bad\nrequest\r\nhere", 64), "bad request here");
        assert_eq!(sanitize("  padded  ", 64), "padded");
        assert_eq!(sanitize("abcdef", 3), "abc…");
        assert_eq!(sanitize("\u{0}\u{1}\u{2}", 64), "");
    }

    #[test]
    fn display_never_repeats_unsanitized_input() {
        let error = ProviderError::new(
            ErrorKind::Server,
            "openai",
            Operation::Complete,
            "upstream\nsaid\nno",
        )
        .with_status(503)
        .with_upstream_code("engine_overloaded");
        assert_eq!(
            error.to_string(),
            "openai complete failed (server) status=503 code=engine_overloaded: upstream said no"
        );
    }

    #[test]
    fn retry_after_accepts_delay_seconds() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        assert_eq!(parse_retry_after("120", now), Some(Duration::from_mins(2)));
        assert_eq!(parse_retry_after("  0 ", now), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("-5", now), None);
        assert_eq!(parse_retry_after("", now), None);
        assert_eq!(parse_retry_after("soon", now), None);
    }

    #[test]
    fn retry_after_accepts_imf_fixdate_and_clamps_the_past() {
        // 1994-11-06T08:49:37Z is 784_111_777 seconds after the Unix epoch.
        let epoch_seconds = 784_111_777_u64;
        let now = UNIX_EPOCH + Duration::from_secs(epoch_seconds - 90);
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", now),
            Some(Duration::from_secs(90))
        );

        let later = UNIX_EPOCH + Duration::from_secs(epoch_seconds + 5);
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", later),
            Some(Duration::ZERO)
        );

        for malformed in [
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun 06 Nov 1994 08:49:37 GMT",
            "Sun, 06 Xxx 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 25:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
        ] {
            assert_eq!(parse_retry_after(malformed, now), None, "{malformed}");
        }
    }

    #[test]
    fn imf_fixdate_epoch_conversion_matches_known_timestamps() {
        assert_eq!(parse_imf_fixdate("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_imf_fixdate("Tue, 19 Jan 2038 03:14:07 GMT"),
            Some(2_147_483_647)
        );
        assert_eq!(
            parse_imf_fixdate("Sat, 29 Feb 2020 12:00:00 GMT"),
            Some(1_582_977_600)
        );
    }
}
