//! Headless GTA Claw command-line adapter and bounded Gateway diagnostic.

use std::collections::BTreeSet;
use std::error::Error;
use std::ffi::OsString;
use std::future::Future;
use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use claw_application::Application;
use claw_gateway_client::{
    AuthenticationFailure, ClientMetadata, ClientTimeouts, ConfigurationError, ConnectionInfo,
    ConnectionState, GatewayClient, GatewayClientConfig, GatewayClientError, GatewayCredential,
    ProtocolFailure, ReconnectPolicy, TransportFailure,
};
use claw_platform::NativeSystemProbe;
use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, ClientId, ClientMode, Codec, ConnectErrorDetailCode,
    GatewayMethodName, Name, RequestId, resolve_core_method,
};
use claw_protocol::{ProtocolError, parse_command};
use claw_security::authorization::{Role, Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;
use rand_core::{TryCryptoRng, TryRng};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt as _;
use url::{Host, Url};
use zeroize::Zeroizing;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_TIMEOUT_MS: u64 = 250;
const MAX_TIMEOUT_MS: u64 = 120_000;
const MAX_ARGUMENTS: usize = 32;
const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_OUTPUT_TEXT_BYTES: usize = 256;
const MAX_SECRET_SOURCE_BYTES: usize = 4_096;

/// Runs the CLI using process standard streams and returns its stable exit status.
pub async fn entrypoint(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    let result = dispatch(arguments.into_iter().collect()).await;
    let exit_code = result.exit_code;
    let write_result = if result.stdout.is_empty() {
        Ok(())
    } else {
        io::stdout().lock().write_all(result.stdout.as_bytes())
    }
    .and_then(|()| {
        if result.stderr.is_empty() {
            Ok(())
        } else {
            io::stderr().lock().write_all(result.stderr.as_bytes())
        }
    });

    let exit_code = if write_result.is_err() {
        ExitCategory::Internal.code()
    } else {
        exit_code
    };
    ExitCode::from(exit_code)
}

async fn dispatch(arguments: Vec<OsString>) -> RenderedResult {
    match parse_invocation(&arguments) {
        Ok(Invocation::Version) => {
            RenderedResult::success(format!("gta-claw-cli {}\n", env!("CARGO_PKG_VERSION")))
        }
        Ok(Invocation::Help) => RenderedResult::success(format!("{USAGE}\n")),
        Ok(Invocation::Foundation) => run_foundation(arguments),
        Ok(Invocation::Gateway(options)) => {
            let interrupt = async { tokio::signal::ctrl_c().await.map_err(|_| ()) };
            run_gateway(options, interrupt).await
        }
        Err(failure) => render_parse_failure(failure),
    }
}

const USAGE: &str = "\
usage:
  gta-claw-cli --version
  gta-claw-cli health
  gta-claw-cli send <session-id> <message>
  gta-claw-cli gateway health --endpoint <ws-or-wss-url> --ephemeral-device
      [--token-stdin] [--timeout-ms <250..120000>]
      [--allow-insecure-remote-ws] [--json]";

enum Invocation {
    Version,
    Help,
    Foundation,
    Gateway(GatewayOptions),
}

#[derive(Clone, Copy)]
enum SecretSourceKind {
    None,
    Stdin,
    UnsupportedFile,
}

struct GatewayOptions {
    endpoint: String,
    ephemeral_device: bool,
    secret_source: SecretSourceKind,
    timeout: Duration,
    allow_insecure_remote_ws: bool,
    json: bool,
}

struct ParseFailure {
    message: &'static str,
    json: bool,
    endpoint: Option<String>,
}

fn parse_invocation(arguments: &[OsString]) -> Result<Invocation, ParseFailure> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(parse_failure("too many command arguments", arguments));
    }
    let Some(first) = arguments.first().and_then(|value| value.to_str()) else {
        return if arguments.is_empty() {
            Err(parse_failure("missing command", arguments))
        } else {
            Err(parse_failure("command must be valid UTF-8", arguments))
        };
    };
    match first {
        "--version" if arguments.len() == 1 => Ok(Invocation::Version),
        "--help" | "-h" if arguments.len() == 1 => Ok(Invocation::Help),
        "gateway" => parse_gateway(arguments),
        _ => Ok(Invocation::Foundation),
    }
}

fn parse_gateway(arguments: &[OsString]) -> Result<Invocation, ParseFailure> {
    if arguments.get(1).and_then(|value| value.to_str()) != Some("health") {
        return Err(parse_failure("expected `gateway health`", arguments));
    }
    let mut endpoint = None;
    let mut ephemeral_device = false;
    let mut secret_source = SecretSourceKind::None;
    let mut timeout = DEFAULT_TIMEOUT;
    let mut timeout_seen = false;
    let mut allow_insecure_remote_ws = false;
    let mut json = false;
    let mut index = 2;

    while index < arguments.len() {
        let Some(flag) = arguments[index].to_str() else {
            return Err(parse_failure("option names must be valid UTF-8", arguments));
        };
        match flag {
            "--endpoint" if endpoint.is_none() => {
                index += 1;
                let value = option_value(arguments, index, "missing endpoint value")?
                    .to_str()
                    .ok_or_else(|| parse_failure("endpoint must be valid UTF-8", arguments))?;
                if value.len() > MAX_ENDPOINT_BYTES {
                    return Err(parse_failure("invalid endpoint value", arguments));
                }
                endpoint = Some(value.to_owned());
            }
            "--ephemeral-device" if !ephemeral_device => ephemeral_device = true,
            "--token-stdin" if matches!(secret_source, SecretSourceKind::None) => {
                secret_source = SecretSourceKind::Stdin;
            }
            "--token-file" if matches!(secret_source, SecretSourceKind::None) => {
                index += 1;
                option_value(arguments, index, "missing token file path")?;
                secret_source = SecretSourceKind::UnsupportedFile;
            }
            "--timeout-ms" if !timeout_seen => {
                index += 1;
                let value = option_value(arguments, index, "missing timeout value")?
                    .to_str()
                    .ok_or_else(|| parse_failure("timeout must be valid UTF-8", arguments))?;
                let millis = value
                    .parse::<u64>()
                    .ok()
                    .filter(|value| (MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(value))
                    .ok_or_else(|| parse_failure("invalid timeout value", arguments))?;
                timeout = Duration::from_millis(millis);
                timeout_seen = true;
            }
            "--allow-insecure-remote-ws" if !allow_insecure_remote_ws => {
                allow_insecure_remote_ws = true;
            }
            "--json" if !json => json = true,
            _ => {
                return Err(parse_failure(
                    "unknown or repeated gateway option",
                    arguments,
                ));
            }
        }
        index += 1;
    }

    let endpoint =
        endpoint.ok_or_else(|| parse_failure("gateway endpoint is required", arguments))?;
    if !ephemeral_device {
        return Err(parse_failure(
            "explicit --ephemeral-device opt-in is required",
            arguments,
        ));
    }
    Ok(Invocation::Gateway(GatewayOptions {
        endpoint,
        ephemeral_device,
        secret_source,
        timeout,
        allow_insecure_remote_ws,
        json,
    }))
}

fn option_value<'a>(
    arguments: &'a [OsString],
    index: usize,
    missing: &'static str,
) -> Result<&'a OsString, ParseFailure> {
    let value = arguments
        .get(index)
        .ok_or_else(|| parse_failure(missing, arguments))?;
    if value.to_str().is_some_and(|value| value.starts_with('-')) {
        return Err(parse_failure(missing, arguments));
    }
    Ok(value)
}

fn parse_failure(message: &'static str, arguments: &[OsString]) -> ParseFailure {
    ParseFailure {
        message,
        json: arguments.iter().any(|value| value == "--json"),
        endpoint: endpoint_origin_from_arguments(arguments),
    }
}

fn endpoint_origin_from_arguments(arguments: &[OsString]) -> Option<String> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == "--endpoint")
        .and_then(|pair| pair[1].to_str())
        .and_then(sanitized_origin)
}

fn sanitized_origin(endpoint: &str) -> Option<String> {
    if endpoint.len() > MAX_ENDPOINT_BYTES || contains_forbidden_endpoint_char(endpoint) {
        return None;
    }
    let origin = Url::parse(endpoint).ok()?.origin().ascii_serialization();
    (origin.len() <= MAX_OUTPUT_TEXT_BYTES).then_some(origin)
}

struct ValidatedEndpoint {
    url: Url,
    origin: String,
}

fn validate_endpoint(
    endpoint: &str,
    allow_insecure_remote_ws: bool,
) -> Result<ValidatedEndpoint, DiagnosticFailure> {
    if endpoint.len() > MAX_ENDPOINT_BYTES
        || contains_forbidden_endpoint_char(endpoint)
        || endpoint.contains('\\')
    {
        return Err(DiagnosticFailure::usage(
            "invalid_endpoint_spelling",
            "Gateway endpoint spelling is not canonical",
        ));
    }
    let expected_scheme = if endpoint.starts_with("ws://") {
        "ws"
    } else if endpoint.starts_with("wss://") {
        "wss"
    } else {
        return Err(DiagnosticFailure::usage(
            "unsupported_scheme",
            "Gateway endpoint must use canonical ws or wss",
        ));
    };
    let url = Url::parse(endpoint)
        .map_err(|_| DiagnosticFailure::usage("invalid_endpoint", "invalid Gateway endpoint"))?;
    if url.scheme() != expected_scheme {
        return Err(DiagnosticFailure::usage(
            "invalid_endpoint_spelling",
            "Gateway endpoint spelling is not canonical",
        ));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DiagnosticFailure::usage(
            "credential_bearing_endpoint",
            "Gateway endpoint must not contain credentials, query data, or a fragment",
        ));
    }
    validate_ascii_hostname_spelling(endpoint, &url)?;
    if expected_scheme == "ws" && !allow_insecure_remote_ws && !is_loopback_host(url.host()) {
        return Err(DiagnosticFailure::usage(
            "insecure_remote_ws",
            "remote plaintext ws requires explicit diagnostic opt-in",
        ));
    }
    let origin = url.origin().ascii_serialization();
    if origin.len() > MAX_OUTPUT_TEXT_BYTES {
        return Err(DiagnosticFailure::usage(
            "invalid_endpoint",
            "Gateway endpoint origin is too long",
        ));
    }
    Ok(ValidatedEndpoint { url, origin })
}

fn validate_ascii_hostname_spelling(endpoint: &str, url: &Url) -> Result<(), DiagnosticFailure> {
    let authority = endpoint
        .split_once("://")
        .map(|(_, remainder)| remainder)
        .unwrap_or_default()
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.contains('%') {
        return Err(DiagnosticFailure::usage(
            "invalid_endpoint_spelling",
            "Gateway endpoint spelling is not canonical",
        ));
    }
    let raw_host = if authority.starts_with('[') {
        return Ok(());
    } else {
        authority
            .rsplit_once(':')
            .filter(|(_, port)| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
            .map_or(authority, |(host, _)| host)
    };
    if raw_host
        .chars()
        .any(|character| character.is_ascii_uppercase())
    {
        return Err(DiagnosticFailure::usage(
            "invalid_endpoint_spelling",
            "Gateway endpoint spelling is not canonical",
        ));
    }
    if raw_host.is_ascii() && url.host_str() != Some(raw_host) {
        return Err(DiagnosticFailure::usage(
            "invalid_endpoint_spelling",
            "Gateway endpoint spelling is not canonical",
        ));
    }
    Ok(())
}

fn is_loopback_host(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Domain("localhost")) => true,
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) | None => false,
    }
}

fn contains_forbidden_endpoint_char(value: &str) -> bool {
    value.chars().any(|character| {
        character.is_control()
            || character.is_whitespace()
            || matches!(
                character,
                '\u{00ad}'
                    | '\u{034f}'
                    | '\u{061c}'
                    | '\u{070f}'
                    | '\u{115f}'
                    | '\u{1160}'
                    | '\u{17b4}'
                    | '\u{17b5}'
                    | '\u{180b}'..='\u{180f}'
                    | '\u{200b}'..='\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2060}'..='\u{206f}'
                    | '\u{3164}'
                    | '\u{fe00}'..='\u{fe0f}'
                    | '\u{feff}'
                    | '\u{ffa0}'
                    | '\u{e0100}'..='\u{e01ef}'
            )
    })
}

fn run_foundation(arguments: Vec<OsString>) -> RenderedResult {
    let strings = match arguments
        .into_iter()
        .map(OsString::into_string)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(strings) => strings,
        Err(_) => {
            return RenderedResult::failure(
                ExitCategory::UsageConfig,
                "error: command arguments must be valid UTF-8\n".to_owned(),
            );
        }
    };
    let command = match parse_command(strings) {
        Ok(command) => command,
        Err(error) => {
            return RenderedResult::failure(
                ExitCategory::UsageConfig,
                format!("error: {}\n", safe_protocol_error(&error)),
            );
        }
    };
    let application = Application::new(NativeSystemProbe);
    match application.handle(command) {
        Ok(event) => RenderedResult::success(format!("{event}\n")),
        Err(error) => RenderedResult::failure(ExitCategory::Internal, format!("error: {error}\n")),
    }
}

fn safe_protocol_error(error: &ProtocolError) -> &'static str {
    match error {
        ProtocolError::MissingCommand => "missing command",
        ProtocolError::MissingArgument(_) => "missing command argument",
        ProtocolError::UnexpectedArgument(_) => "unexpected command argument",
        ProtocolError::UnknownCommand(_) => "unknown command",
        ProtocolError::Domain(_) => "invalid command argument",
    }
}

async fn run_gateway(
    options: GatewayOptions,
    interrupt: impl Future<Output = Result<(), ()>>,
) -> RenderedResult {
    let started = Instant::now();
    let validated = match validate_endpoint(&options.endpoint, options.allow_insecure_remote_ws) {
        Ok(validated) => validated,
        Err(failure) => {
            return render_diagnostic(
                &options,
                DiagnosticSummary::failure(
                    sanitized_origin(&options.endpoint),
                    started.elapsed(),
                    failure,
                ),
            );
        }
    };
    let endpoint = Some(validated.origin);
    tokio::pin!(interrupt);
    let deadline = tokio::time::sleep(options.timeout);
    tokio::pin!(deadline);
    let credential = tokio::select! {
        credential = read_credential(&options) => match credential {
            Ok(credential) => credential,
            Err(failure) => {
                return render_diagnostic(
                    &options,
                    DiagnosticSummary::failure(endpoint, started.elapsed(), failure),
                );
            }
        },
        signal = &mut interrupt => {
            let failure = match signal {
                Ok(()) => DiagnosticFailure::timeout(
                    "cancelled",
                    "Gateway diagnostic cancelled",
                ),
                Err(()) => DiagnosticFailure::internal(
                    "signal_error",
                    "interrupt handler failed",
                ),
            };
            return render_diagnostic(
                &options,
                DiagnosticSummary::failure(endpoint, started.elapsed(), failure),
            );
        }
        () = &mut deadline => {
            return render_diagnostic(
                &options,
                DiagnosticSummary::failure(
                    endpoint,
                    started.elapsed(),
                    DiagnosticFailure::timeout(
                        "timeout",
                        "Gateway diagnostic timed out",
                    ),
                ),
            );
        }
    };
    let identity = match generate_ephemeral_identity() {
        Ok(identity) => Arc::new(identity),
        Err(failure) => {
            return render_diagnostic(
                &options,
                DiagnosticSummary::failure(endpoint, started.elapsed(), failure),
            );
        }
    };
    let mut config = GatewayClientConfig::new(validated.url, identity);
    config.credential = credential;
    config.role = Role::Operator;
    config.scopes = ScopeSet::from_scopes([Scope::OperatorRead]);
    config.client = ClientMetadata {
        id: ClientId::Probe,
        display_name: Some(Name::new("GTA Claw Gateway diagnostic", 64).expect("static name")),
        version: Name::new(env!("CARGO_PKG_VERSION"), 64).expect("package version"),
        platform: Name::new(std::env::consts::OS, 64).expect("target OS"),
        device_family: None,
        model_identifier: None,
        mode: ClientMode::Probe,
        instance_id: None,
    };
    config.reconnect = ReconnectPolicy::Never;
    config.allow_insecure_remote_ws = options.allow_insecure_remote_ws;
    config.timeouts = ClientTimeouts {
        connect: options.timeout,
        authentication: options.timeout,
        request: options.timeout,
        shutdown: Duration::from_secs(2).min(options.timeout),
    };

    let (client, _events) = match GatewayClient::start(config) {
        Ok(client) => client,
        Err(error) => {
            return render_diagnostic(
                &options,
                DiagnosticSummary::failure(endpoint, started.elapsed(), map_client_error(&error)),
            );
        }
    };

    let attempt = execute_health(&client);
    tokio::pin!(attempt);
    let mut attempt = tokio::select! {
        result = &mut attempt => result,
        signal = &mut interrupt => {
            match signal {
                Ok(()) => DiagnosticAttempt::failure(
                    DiagnosticFailure::timeout("cancelled", "Gateway diagnostic cancelled"),
                ),
                Err(()) => DiagnosticAttempt::failure(
                    DiagnosticFailure::internal("signal_error", "interrupt handler failed"),
                ),
            }
        }
        () = &mut deadline => DiagnosticAttempt::failure(
            DiagnosticFailure::timeout("timeout", "Gateway diagnostic timed out"),
        ),
    };

    if let Err(error) = client.shutdown().await {
        attempt.failure = Some(map_client_error(&error));
    }
    let summary = attempt.into_summary(endpoint, started.elapsed());
    render_diagnostic(&options, summary)
}

async fn execute_health(client: &GatewayClient) -> DiagnosticAttempt {
    let info = match client.wait_ready().await {
        Ok(info) => match SafeConnectionInfo::try_from(info) {
            Ok(info) => info,
            Err(failure) => return DiagnosticAttempt::failure(failure),
        },
        Err(error) => {
            return DiagnosticAttempt::failure(classify_request_error(client, &error).await);
        }
    };
    let request_id = RequestId::new("gta-claw-cli-health-1", AUTHENTICATED_MAX_FRAME_BYTES)
        .expect("static request id");
    let method = GatewayMethodName::Core(
        resolve_core_method("health").expect("P02a registry contains health"),
    );
    let response = match client.request(request_id, method, &EmptyParams {}).await {
        Ok(response) => response,
        Err(error) => {
            return DiagnosticAttempt::with_info(
                classify_request_error(client, &error).await,
                info,
            );
        }
    };
    if !response.ok() {
        return DiagnosticAttempt {
            info: Some(info),
            health: Some(HealthSummary {
                ok: false,
                timestamp_ms: None,
                duration_ms: None,
            }),
            failure: Some(DiagnosticFailure::health_negative()),
        };
    }
    let Some(payload) = response.payload().value() else {
        return DiagnosticAttempt::with_info(
            DiagnosticFailure::protocol("malformed_health", "Gateway health payload is missing"),
            info,
        );
    };
    let payload: HealthPayload = match Codec::authenticated().decode_opaque(payload) {
        Ok(payload) => payload,
        Err(_) => {
            return DiagnosticAttempt::with_info(
                DiagnosticFailure::protocol(
                    "malformed_health",
                    "Gateway health payload is malformed",
                ),
                info,
            );
        }
    };
    let health = HealthSummary {
        ok: payload.ok,
        timestamp_ms: Some(payload.ts),
        duration_ms: Some(payload.duration_ms),
    };
    if !payload.ok {
        return DiagnosticAttempt {
            info: Some(info),
            health: Some(health),
            failure: Some(DiagnosticFailure::health_negative()),
        };
    }
    DiagnosticAttempt {
        info: Some(info),
        health: Some(health),
        failure: None,
    }
}

async fn classify_request_error(
    client: &GatewayClient,
    error: &GatewayClientError,
) -> DiagnosticFailure {
    if !matches!(
        error,
        GatewayClientError::DisconnectedNotReplayed
            | GatewayClientError::NotReady
            | GatewayClientError::Cancelled
    ) {
        return map_client_error(error);
    }
    let mut states = client.subscribe_state();
    loop {
        let state = states.borrow().clone();
        match state {
            ConnectionState::ProtocolFailed { .. } | ConnectionState::ResyncRequired(_) => {
                return DiagnosticFailure::protocol(
                    "protocol_error",
                    "Gateway protocol validation failed",
                );
            }
            ConnectionState::AuthenticationFailed(authentication) => {
                return map_authentication_error(authentication);
            }
            ConnectionState::ReconnectExhausted | ConnectionState::Stopped => {
                return DiagnosticFailure {
                    category: ExitCategory::TransportTransient,
                    status: "transport_failure",
                    message: "Gateway transport failed",
                };
            }
            ConnectionState::Starting
            | ConnectionState::Connecting
            | ConnectionState::Authenticating
            | ConnectionState::Ready(_)
            | ConnectionState::Reconnecting { .. } => {}
        }
        if states.changed().await.is_err() {
            return DiagnosticFailure {
                category: ExitCategory::TransportTransient,
                status: "transport_failure",
                message: "Gateway transport failed",
            };
        }
    }
}

#[derive(Serialize)]
struct EmptyParams {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HealthPayload {
    ok: bool,
    ts: u64,
    duration_ms: u64,
}

async fn read_credential(options: &GatewayOptions) -> Result<GatewayCredential, DiagnosticFailure> {
    match options.secret_source {
        SecretSourceKind::None => Ok(GatewayCredential::None),
        SecretSourceKind::Stdin => {
            let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SECRET_SOURCE_BYTES));
            tokio::io::stdin()
                .take((MAX_SECRET_SOURCE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| {
                    DiagnosticFailure::usage(
                        "secret_stdin_error",
                        "could not read token from stdin",
                    )
                })?;
            parse_secret(bytes.as_slice()).map(GatewayCredential::Token)
        }
        SecretSourceKind::UnsupportedFile => Err(DiagnosticFailure::usage(
            "token_file_unsupported",
            "token-file input is disabled because secure permissions cannot be proven portably",
        )),
    }
}

fn parse_secret(bytes: &[u8]) -> Result<SecretString, DiagnosticFailure> {
    if bytes.len() > MAX_SECRET_SOURCE_BYTES {
        return Err(DiagnosticFailure::usage(
            "secret_too_large",
            "token source exceeds 4096 bytes",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| DiagnosticFailure::usage("secret_invalid", "token must be valid UTF-8"))?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if text.is_empty()
        || text.chars().any(char::is_whitespace)
        || text.chars().any(char::is_control)
    {
        return Err(DiagnosticFailure::usage(
            "secret_invalid",
            "token must be one non-empty line without whitespace",
        ));
    }
    Ok(SecretString::from(text.to_owned()))
}

fn generate_ephemeral_identity() -> Result<DeviceIdentity, DiagnosticFailure> {
    let random = SystemRandom::new();
    generate_ephemeral_identity_with(&random)
}

fn generate_ephemeral_identity_with<R>(random: &R) -> Result<DeviceIdentity, DiagnosticFailure>
where
    R: RandomFill,
{
    let mut rng = IdentityRandom(random);
    DeviceIdentity::try_generate(&mut rng).map_err(|_| {
        DiagnosticFailure::internal("randomness_error", "secure randomness is unavailable")
    })
}

trait RandomFill {
    type Error: Error;

    fn fill(&self, destination: &mut [u8]) -> Result<(), Self::Error>;
}

impl RandomFill for SystemRandom {
    type Error = SystemRandomError;

    fn fill(&self, destination: &mut [u8]) -> Result<(), Self::Error> {
        SecureRandom::fill(self, destination).map_err(|_| SystemRandomError)
    }
}

#[derive(Clone, Copy, Debug)]
struct SystemRandomError;

impl std::fmt::Display for SystemRandomError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("system random fill failed")
    }
}

impl Error for SystemRandomError {}

struct IdentityRandom<'a, R>(&'a R);

impl<R> TryRng for IdentityRandom<'_, R>
where
    R: RandomFill,
{
    type Error = R::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.0.fill(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.0.fill(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill(destination)
    }
}

impl<R> TryCryptoRng for IdentityRandom<'_, R> where R: RandomFill {}

struct SafeConnectionInfo {
    protocol: u64,
    role: String,
    scopes: Vec<String>,
}

impl TryFrom<ConnectionInfo> for SafeConnectionInfo {
    type Error = DiagnosticFailure;

    fn try_from(info: ConnectionInfo) -> Result<Self, Self::Error> {
        validate_safe_output_text(&info.role)?;
        let mut scopes = BTreeSet::new();
        for scope in info.scopes.iter() {
            validate_safe_output_text(scope)?;
            scopes.insert(scope.clone());
        }
        Ok(Self {
            protocol: info.protocol.get(),
            role: info.role,
            scopes: scopes.into_iter().collect(),
        })
    }
}

fn validate_safe_output_text(value: &str) -> Result<(), DiagnosticFailure> {
    if value.is_empty() || value.len() > MAX_OUTPUT_TEXT_BYTES || contains_control(value) {
        Err(DiagnosticFailure::protocol(
            "unsafe_peer_text",
            "Gateway returned unsafe diagnostic text",
        ))
    } else {
        Ok(())
    }
}

fn contains_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

struct DiagnosticAttempt {
    info: Option<SafeConnectionInfo>,
    health: Option<HealthSummary>,
    failure: Option<DiagnosticFailure>,
}

impl DiagnosticAttempt {
    fn failure(failure: DiagnosticFailure) -> Self {
        Self {
            info: None,
            health: None,
            failure: Some(failure),
        }
    }

    fn with_info(failure: DiagnosticFailure, info: SafeConnectionInfo) -> Self {
        Self {
            info: Some(info),
            health: None,
            failure: Some(failure),
        }
    }

    fn into_summary(self, endpoint: Option<String>, elapsed: Duration) -> DiagnosticSummary {
        let failure = self.failure;
        let (protocol, role, scopes, server) = self.info.map_or_else(
            || (None, None, Vec::new(), None),
            |info| {
                (
                    Some(info.protocol),
                    Some(info.role),
                    info.scopes,
                    Some(ServerSummary {
                        version: None,
                        version_status: "redacted_peer_value",
                    }),
                )
            },
        );
        let (status, category, message, exit_code) = failure.map_or(
            ("healthy", "success", "Gateway health RPC succeeded", 0),
            |failure| {
                (
                    failure.status,
                    failure.category.as_str(),
                    failure.message,
                    failure.category.code(),
                )
            },
        );
        DiagnosticSummary {
            schema_version: 2,
            command: "gateway.health",
            status,
            category,
            message,
            endpoint,
            protocol,
            role,
            scopes,
            server,
            health: self.health,
            elapsed_ms: bounded_millis(elapsed),
            identity: Some("ephemeral"),
            pairing_entry_possible: true,
            exit_code,
        }
    }
}

#[derive(Serialize)]
struct DiagnosticSummary {
    schema_version: u8,
    command: &'static str,
    status: &'static str,
    category: &'static str,
    message: &'static str,
    endpoint: Option<String>,
    protocol: Option<u64>,
    role: Option<String>,
    scopes: Vec<String>,
    server: Option<ServerSummary>,
    health: Option<HealthSummary>,
    elapsed_ms: u64,
    identity: Option<&'static str>,
    pairing_entry_possible: bool,
    #[serde(skip)]
    exit_code: u8,
}

impl DiagnosticSummary {
    fn failure(endpoint: Option<String>, elapsed: Duration, failure: DiagnosticFailure) -> Self {
        DiagnosticAttempt::failure(failure).into_summary(endpoint, elapsed)
    }
}

#[derive(Serialize)]
struct ServerSummary {
    version: Option<&'static str>,
    version_status: &'static str,
}

#[derive(Serialize)]
struct HealthSummary {
    ok: bool,
    timestamp_ms: Option<u64>,
    duration_ms: Option<u64>,
}

fn bounded_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy)]
enum ExitCategory {
    UsageConfig,
    TransportTransient,
    AuthenticationPairing,
    Protocol,
    HealthNegative,
    TimeoutCancel,
    Internal,
}

impl ExitCategory {
    const fn code(self) -> u8 {
        match self {
            Self::UsageConfig => 2,
            Self::TransportTransient => 3,
            Self::AuthenticationPairing => 4,
            Self::Protocol => 5,
            Self::HealthNegative => 6,
            Self::TimeoutCancel => 7,
            Self::Internal => 8,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::UsageConfig => "usage_config",
            Self::TransportTransient => "transport_transient",
            Self::AuthenticationPairing => "authentication_pairing",
            Self::Protocol => "protocol",
            Self::HealthNegative => "health_negative",
            Self::TimeoutCancel => "timeout_cancel",
            Self::Internal => "internal",
        }
    }
}

struct DiagnosticFailure {
    category: ExitCategory,
    status: &'static str,
    message: &'static str,
}

impl DiagnosticFailure {
    const fn usage(status: &'static str, message: &'static str) -> Self {
        Self {
            category: ExitCategory::UsageConfig,
            status,
            message,
        }
    }

    const fn protocol(status: &'static str, message: &'static str) -> Self {
        Self {
            category: ExitCategory::Protocol,
            status,
            message,
        }
    }

    const fn timeout(status: &'static str, message: &'static str) -> Self {
        Self {
            category: ExitCategory::TimeoutCancel,
            status,
            message,
        }
    }

    const fn internal(status: &'static str, message: &'static str) -> Self {
        Self {
            category: ExitCategory::Internal,
            status,
            message,
        }
    }

    const fn health_negative() -> Self {
        Self {
            category: ExitCategory::HealthNegative,
            status: "unhealthy",
            message: "Gateway health RPC reported a negative result",
        }
    }
}

fn map_client_error(error: &GatewayClientError) -> DiagnosticFailure {
    match error {
        GatewayClientError::Configuration(configuration) => map_configuration_error(*configuration),
        GatewayClientError::Transport(TransportFailure::TimedOut)
        | GatewayClientError::RequestTimedOut(_)
        | GatewayClientError::ShutdownTimedOut
        | GatewayClientError::Cancelled => {
            DiagnosticFailure::timeout("timeout", "Gateway diagnostic timed out or was cancelled")
        }
        GatewayClientError::Transport(_)
        | GatewayClientError::DisconnectedNotReplayed
        | GatewayClientError::ReconnectExhausted => DiagnosticFailure {
            category: ExitCategory::TransportTransient,
            status: "transport_failure",
            message: "Gateway transport failed",
        },
        GatewayClientError::Authentication(authentication) => {
            map_authentication_error(*authentication)
        }
        GatewayClientError::Protocol(protocol) => map_protocol_error(protocol),
        GatewayClientError::Backpressure(_) | GatewayClientError::NotReady => {
            DiagnosticFailure::internal("client_state_error", "Gateway client state failed")
        }
    }
}

fn map_configuration_error(error: ConfigurationError) -> DiagnosticFailure {
    let (status, message) = match error {
        ConfigurationError::UnsupportedScheme => {
            ("unsupported_scheme", "Gateway endpoint must use ws or wss")
        }
        ConfigurationError::CredentialBearingUrl => (
            "credential_bearing_endpoint",
            "Gateway endpoint must not contain credentials, query data, or a fragment",
        ),
        ConfigurationError::InsecureRemoteWebSocket => (
            "insecure_remote_ws",
            "remote plaintext ws requires explicit diagnostic opt-in",
        ),
        ConfigurationError::WorkerProtocolUnsupported
        | ConfigurationError::InvalidProtocolRange
        | ConfigurationError::InvalidResourceLimit
        | ConfigurationError::InvalidTimeout
        | ConfigurationError::InvalidReconnectPolicy => (
            "invalid_client_config",
            "Gateway diagnostic configuration is invalid",
        ),
    };
    DiagnosticFailure::usage(status, message)
}

fn map_authentication_error(error: AuthenticationFailure) -> DiagnosticFailure {
    match error.detail_code() {
        Some(ConnectErrorDetailCode::ProtocolMismatch)
        | Some(ConnectErrorDetailCode::ClientVersionMismatch) => {
            DiagnosticFailure::protocol("version_mismatch", "Gateway version is incompatible")
        }
        Some(ConnectErrorDetailCode::PairingRequired) => DiagnosticFailure {
            category: ExitCategory::AuthenticationPairing,
            status: "pairing_required",
            message: "Gateway device pairing or approval is required",
        },
        _ => DiagnosticFailure {
            category: ExitCategory::AuthenticationPairing,
            status: "authentication_failed",
            message: "Gateway authentication was rejected",
        },
    }
}

fn map_protocol_error(error: &ProtocolFailure) -> DiagnosticFailure {
    match error {
        ProtocolFailure::HelloProtocol { .. }
        | ProtocolFailure::HandshakeRejected(ConnectErrorDetailCode::ProtocolMismatch) => {
            DiagnosticFailure::protocol(
                "version_mismatch",
                "Gateway protocol version is incompatible",
            )
        }
        _ => DiagnosticFailure::protocol("protocol_error", "Gateway protocol validation failed"),
    }
}

fn render_parse_failure(failure: ParseFailure) -> RenderedResult {
    if failure.json {
        let summary = DiagnosticSummary::failure(
            failure.endpoint,
            Duration::ZERO,
            DiagnosticFailure::usage("invalid_input", failure.message),
        );
        render_json(summary)
    } else {
        RenderedResult::failure(
            ExitCategory::UsageConfig,
            format!("error: {}\n{USAGE}\n", failure.message),
        )
    }
}

fn render_diagnostic(options: &GatewayOptions, summary: DiagnosticSummary) -> RenderedResult {
    debug_assert!(options.ephemeral_device);
    if options.json {
        render_json(summary)
    } else if summary.exit_code == 0 {
        let health = summary.health.as_ref().expect("successful health summary");
        RenderedResult::success(format!(
            "Gateway health: healthy\n\
             endpoint: {}\n\
             protocol: {}\n\
             role: {}\n\
             scopes: {}\n\
             server_version: [redacted peer value]\n\
             server_version_status: redacted_peer_value\n\
             health_ok: {}\n\
             health_timestamp_ms: {}\n\
             health_duration_ms: {}\n\
             elapsed_ms: {}\n\
             identity: ephemeral (may create a pairing/device entry; not persisted)\n",
            summary.endpoint.as_deref().unwrap_or("<invalid>"),
            summary.protocol.unwrap_or_default(),
            summary.role.as_deref().unwrap_or("<unknown>"),
            summary.scopes.join(","),
            health.ok,
            health.timestamp_ms.unwrap_or_default(),
            health.duration_ms.unwrap_or_default(),
            summary.elapsed_ms,
        ))
    } else {
        RenderedResult {
            stdout: String::new(),
            stderr: format!(
                "Gateway health failed: {} ({})\n",
                summary.message, summary.category
            ),
            exit_code: summary.exit_code,
        }
    }
}

fn render_json(summary: DiagnosticSummary) -> RenderedResult {
    let exit_code = summary.exit_code;
    match serde_json::to_string(&summary) {
        Ok(json) => RenderedResult {
            stdout: format!("{json}\n"),
            stderr: String::new(),
            exit_code,
        },
        Err(_) => RenderedResult::failure(
            ExitCategory::Internal,
            "error: could not serialize diagnostic summary\n".to_owned(),
        ),
    }
}

struct RenderedResult {
    stdout: String,
    stderr: String,
    exit_code: u8,
}

impl RenderedResult {
    fn success(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            exit_code: 0,
        }
    }

    fn failure(category: ExitCategory, stderr: String) -> Self {
        Self {
            stdout: String::new(),
            stderr,
            exit_code: category.code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fmt::{self, Display, Formatter};

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestFillError;

    impl Display for TestFillError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected random fill failure")
        }
    }

    impl Error for TestFillError {}

    struct FailingFill;

    impl RandomFill for FailingFill {
        type Error = TestFillError;

        fn fill(&self, _destination: &mut [u8]) -> Result<(), Self::Error> {
            Err(TestFillError)
        }
    }

    struct DeterministicFill {
        calls: Cell<usize>,
    }

    impl RandomFill for DeterministicFill {
        type Error = TestFillError;

        fn fill(&self, destination: &mut [u8]) -> Result<(), Self::Error> {
            self.calls.set(self.calls.get() + 1);
            destination.fill(0x5a);
            Ok(())
        }
    }

    #[test]
    fn parser_requires_explicit_identity_and_never_accepts_inline_tokens() {
        let missing_identity = vec![
            "gateway".into(),
            "health".into(),
            "--endpoint".into(),
            "ws://127.0.0.1:18789".into(),
        ];
        assert!(matches!(
            parse_invocation(&missing_identity),
            Err(ParseFailure {
                message: "explicit --ephemeral-device opt-in is required",
                ..
            })
        ));

        let inline_token = vec![
            "gateway".into(),
            "health".into(),
            "--endpoint".into(),
            "ws://127.0.0.1:18789".into(),
            "--ephemeral-device".into(),
            "--token".into(),
            "must-not-be-accepted".into(),
        ];
        assert!(matches!(
            parse_invocation(&inline_token),
            Err(ParseFailure {
                message: "unknown or repeated gateway option",
                ..
            })
        ));
    }

    #[test]
    fn parser_rejects_option_values_and_all_singleton_duplicates() {
        let base = [
            "gateway",
            "health",
            "--endpoint",
            "ws://127.0.0.1:18789",
            "--ephemeral-device",
        ];
        let cases: [(&[&str], &str); 6] = [
            (
                &["--token-file", "--token-stdin"],
                "missing token file path",
            ),
            (&["--timeout-ms", "--json"], "missing timeout value"),
            (
                &["--endpoint", "ws://127.0.0.1:9"],
                "unknown or repeated gateway option",
            ),
            (
                &["--timeout-ms", "1000", "--timeout-ms", "2000"],
                "unknown or repeated gateway option",
            ),
            (&["--json", "--json"], "unknown or repeated gateway option"),
            (
                &["--token-stdin", "--token-stdin"],
                "unknown or repeated gateway option",
            ),
        ];
        for (suffix, expected) in cases {
            let arguments = base
                .into_iter()
                .chain(suffix.iter().copied())
                .map(OsString::from)
                .collect::<Vec<_>>();
            assert!(matches!(
                parse_invocation(&arguments),
                Err(ParseFailure { message, .. }) if message == expected
            ));
        }
    }

    #[test]
    fn endpoint_validation_rejects_ambiguous_spelling_and_preserves_legal_hosts() {
        for endpoint in [
            " ws://127.0.0.1:9",
            "ws://exa\u{200b}mple.com",
            "ws://exa\u{2060}mple.com",
            "ws://exa\u{feff}mple.com",
            "WS://127.0.0.1:9",
            "ws://LOCALHOST:9",
            "wss://例え.COM/socket",
        ] {
            assert!(validate_endpoint(endpoint, false).is_err(), "{endpoint:?}");
        }
        assert!(validate_endpoint("ws://[::1]:18789/socket", false).is_ok());
        assert!(validate_endpoint("wss://例え.テスト/socket", false).is_ok());
    }

    #[test]
    fn exit_mapping_is_stable_and_non_tautological() {
        let cases = [
            (
                GatewayClientError::Transport(TransportFailure::Connect),
                3,
                "transport_transient",
            ),
            (
                GatewayClientError::Protocol(ProtocolFailure::ExpectedChallenge),
                5,
                "protocol",
            ),
            (GatewayClientError::ShutdownTimedOut, 7, "timeout_cancel"),
        ];
        for (error, expected_code, expected_category) in cases {
            let mapped = map_client_error(&error);
            assert_eq!(mapped.category.code(), expected_code);
            assert_eq!(mapped.category.as_str(), expected_category);
        }
        assert_eq!(DiagnosticFailure::health_negative().category.code(), 6);
    }

    #[test]
    fn secret_contract_is_bounded_single_line_utf8() {
        assert!(parse_secret(b"automation-token\n").is_ok());
        assert!(parse_secret(b"").is_err());
        assert!(parse_secret(b"two lines\nno").is_err());
        assert!(parse_secret(&vec![b'x'; MAX_SECRET_SOURCE_BYTES + 1]).is_err());
        assert!(parse_secret(&[0xff]).is_err());
    }

    #[test]
    fn origin_redaction_removes_credentials_query_and_fragment() {
        let origin =
            sanitized_origin("wss://operator:secret@example.test:9443/path?token=hidden#private")
                .expect("safe origin");
        assert_eq!(origin, "wss://example.test:9443");
        assert!(!origin.contains("secret"));
        assert!(!origin.contains("hidden"));
        assert!(!origin.contains("private"));
    }

    #[test]
    fn safe_output_accepts_unicode_but_rejects_controls_and_excess() {
        assert!(validate_safe_output_text("网关-v4").is_ok());
        assert!(validate_safe_output_text("gateway\nforged").is_err());
        assert!(validate_safe_output_text(&"x".repeat(MAX_OUTPUT_TEXT_BYTES + 1)).is_err());
    }

    #[test]
    fn identity_random_propagates_every_fill_failure_without_fallback() {
        let source = FailingFill;
        let mut rng = IdentityRandom(&source);
        assert_eq!(rng.try_next_u32(), Err(TestFillError));
        assert_eq!(rng.try_next_u64(), Err(TestFillError));
        assert_eq!(rng.try_fill_bytes(&mut [0_u8; 32]), Err(TestFillError));

        let failure =
            generate_ephemeral_identity_with(&source).expect_err("fill failure must propagate");
        assert_eq!(failure.category.code(), 8);
        assert_eq!(failure.status, "randomness_error");
        assert_eq!(failure.message, "secure randomness is unavailable");
    }

    #[test]
    fn identity_generation_uses_one_complete_private_fill() {
        let source = DeterministicFill {
            calls: Cell::new(0),
        };
        let identity = match generate_ephemeral_identity_with(&source) {
            Ok(identity) => identity,
            Err(_) => panic!("deterministic fill must succeed"),
        };
        assert_eq!(source.calls.get(), 1);
        assert_ne!(identity.device_id().as_bytes(), &[0_u8; 32]);
    }
}
