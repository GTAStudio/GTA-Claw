use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use claw_mcp::{
    HttpRoutePolicy,
    oauth::{
        CredentialBinding, LoopbackAuthorizationListener, NativeTokenStore, OAuthClient,
        RegisteredClient, TokenSet, TokenStore as _, authorization_server_metadata_url,
    },
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{
    ParseFailure, RenderedResult, mcp_credential::OAuthProfileLock, parse_failure,
    write_rendered_result,
};

pub(super) struct LoginCommand {
    refresh: bool,
    server: String,
    endpoint: Url,
    issuer: Url,
    authorization_endpoint: Url,
    token_endpoint: Url,
    client: RegisteredClient,
    routes: Vec<HttpRoutePolicy>,
    callback_port: u16,
    scope: Option<String>,
    timeout: Duration,
}

impl LoginCommand {
    const fn method(&self) -> &'static str {
        if self.refresh {
            "mcp.oauth.refresh"
        } else {
            "mcp.oauth.login"
        }
    }
}

pub(super) fn parse(arguments: &[OsString]) -> Result<LoginCommand, ParseFailure> {
    let refresh = arguments.get(2).and_then(|value| value.to_str()) == Some("refresh");
    let invalid = || {
        parse_failure(
            if refresh {
                "expected mcp oauth refresh with reviewed server/resource/issuer/authorization/token endpoints, public client ID and --confirm-refresh; HTTPS requires --http-proxy"
            } else {
                "expected mcp oauth login --server <id> --endpoint <url> --issuer <url> --authorization-endpoint <url> --token-endpoint <url> --client-id <id> --confirm-login; HTTPS requires --http-proxy <loopback-url>"
            },
            arguments,
        )
    };
    if arguments.get(1).and_then(|value| value.to_str()) != Some("oauth")
        || !matches!(
            arguments.get(2).and_then(|value| value.to_str()),
            Some("login" | "refresh")
        )
    {
        return Err(invalid());
    }
    let mut options = BTreeMap::new();
    let mut confirmed = false;
    let mut json_seen = false;
    let mut index = 3;
    while index < arguments.len() {
        let name = arguments[index].to_str().ok_or_else(invalid)?;
        match name {
            "--confirm-login" if !confirmed && !refresh => {
                confirmed = true;
                index += 1;
            }
            "--confirm-refresh" if !confirmed && refresh => {
                confirmed = true;
                index += 1;
            }
            "--json" if !json_seen => {
                json_seen = true;
                index += 1;
            }
            "--server"
            | "--endpoint"
            | "--issuer"
            | "--authorization-endpoint"
            | "--token-endpoint"
            | "--client-id"
            | "--http-proxy"
            | "--callback-port"
            | "--scope"
            | "--timeout-ms" => {
                let value = arguments
                    .get(index + 1)
                    .and_then(|value| value.to_str())
                    .ok_or_else(invalid)?;
                if value.starts_with("--") || options.insert(name, value).is_some() {
                    return Err(invalid());
                }
                index += 2;
            }
            _ => return Err(invalid()),
        }
    }
    if !confirmed
        || (refresh && (options.contains_key("--callback-port") || options.contains_key("--scope")))
    {
        return Err(invalid());
    }
    let server = *options.get("--server").ok_or_else(invalid)?;
    if server.is_empty()
        || server.len() > 64
        || !server
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(invalid());
    }
    let endpoint =
        parse_url(options.get("--endpoint").ok_or_else(invalid)?).map_err(|()| invalid())?;
    let issuer = parse_url(options.get("--issuer").ok_or_else(invalid)?).map_err(|()| invalid())?;
    let authorization_endpoint = parse_url(
        options
            .get("--authorization-endpoint")
            .ok_or_else(invalid)?,
    )
    .map_err(|()| invalid())?;
    let token_endpoint =
        parse_url(options.get("--token-endpoint").ok_or_else(invalid)?).map_err(|()| invalid())?;
    let proxy = options
        .get("--http-proxy")
        .map(|proxy| parse_url(proxy))
        .transpose()
        .map_err(|()| invalid())?;
    let targets = [
        endpoint.clone(),
        authorization_server_metadata_url(&issuer),
        authorization_endpoint.clone(),
        token_endpoint.clone(),
    ];
    if proxy.is_some() && targets.iter().all(|target| target.scheme() == "http") {
        return Err(invalid());
    }
    let mut routes = BTreeMap::new();
    for target in targets {
        let route = match target.scheme() {
            "http" => HttpRoutePolicy::direct_loopback(target.clone()).map_err(|_| invalid())?,
            "https" => {
                let host = target.host_str().ok_or_else(invalid)?;
                claw_tools::net::UrlPolicy::exact_hosts([host])
                    .map_err(|_| invalid())?
                    .with_allowed_ports([target.port_or_known_default().ok_or_else(invalid)?])
                    .with_max_redirects(0)
                    .validate(target.as_str())
                    .map_err(|_| invalid())?;
                HttpRoutePolicy::https_via_proxy(target.clone(), proxy.clone().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?
            }
            _ => return Err(invalid()),
        };
        routes.insert(target, route);
    }
    let callback_port = options
        .get("--callback-port")
        .map_or(Ok(0), |value| value.parse::<u16>())
        .map_err(|_| invalid())?;
    let timeout_ms = options
        .get("--timeout-ms")
        .map_or(Ok(120_000), |value| value.parse::<u64>())
        .map_err(|_| invalid())?;
    if !(250..=120_000).contains(&timeout_ms) {
        return Err(invalid());
    }
    let scope = options.get("--scope").map(|value| (*value).to_owned());
    if scope.as_ref().is_some_and(|scope| {
        scope.is_empty()
            || scope.len() > 1024
            || scope.trim() != scope
            || !scope.bytes().all(|byte| {
                byte == b' '
                    || byte == b'!'
                    || (b'#'..=b'[').contains(&byte)
                    || (b']'..=b'~').contains(&byte)
            })
    }) {
        return Err(invalid());
    }
    let client = RegisteredClient::public(*options.get("--client-id").ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    Ok(LoginCommand {
        refresh,
        server: server.to_owned(),
        endpoint,
        issuer,
        authorization_endpoint,
        token_endpoint,
        client,
        routes: routes.into_values().collect(),
        callback_port,
        scope,
        timeout: Duration::from_millis(timeout_ms),
    })
}

fn parse_url(value: &str) -> Result<Url, ()> {
    if value.len() > 2048
        || value.contains('\\')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(());
    }
    let endpoint = Url::parse(value).map_err(|_| ())?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(());
    }
    Ok(endpoint)
}

async fn login(
    command: LoginCommand,
    cancellation: &CancellationToken,
    mutation_started: &AtomicBool,
) -> Result<Value, &'static str> {
    let method = command.method();
    let binding = CredentialBinding::new(&command.server, &command.endpoint)
        .map_err(|_| "OAuth resource binding is invalid")?;
    let _profile_lock = OAuthProfileLock::acquire(&binding)?;
    let store = NativeTokenStore::new()
        .map_err(|_| "native OAuth store is unavailable; no fallback is allowed")?;
    store.status(&binding).map_err(|_| "native OAuth record is invalid or unavailable; inspect local status before authorizing")?;
    if command.refresh {
        let tokens = store
            .load(&binding)
            .map_err(|_| "OAuth record requires new authorization before refresh")?
            .ok_or("OAuth login is required before refresh")?;
        if !tokens.can_refresh() {
            return Err("OAuth record has no refresh token; new authorization is required");
        }
    }
    let oauth = OAuthClient::with_routes(Duration::from_secs(10), command.routes)
        .map_err(|_| "OAuth routes cannot be initialized")?;
    let server = oauth
        .discover_authorization_server(&command.issuer)
        .await
        .map_err(|_| "OAuth issuer discovery failed or returned unreviewed metadata")?;
    if server.authorization_endpoint() != &command.authorization_endpoint
        || server.token_endpoint() != &command.token_endpoint
        || !server
            .metadata()
            .code_challenge_methods_supported
            .iter()
            .any(|method| method == "S256")
    {
        return Err(
            "OAuth metadata must match both reviewed endpoints and explicitly support S256",
        );
    }
    if command.refresh {
        if cancellation.is_cancelled() {
            return Err("OAuth refresh cancelled before token exchange");
        }
        mutation_started.store(true, Ordering::Release);
        let tokens = oauth.refresh(&binding, &store, &server, &command.client, Some(&command.endpoint)).await
            .map_err(|_| "OAuth refresh or native persistence was not confirmed; inspect local status before new authorization")?;
        return Ok(completed(method, &binding, &tokens));
    }
    let listener =
        LoopbackAuthorizationListener::bind(([127, 0, 0, 1], command.callback_port).into())
            .await
            .map_err(|_| "the explicit loopback callback port could not be bound")?;
    let request = oauth
        .authorization_request(
            &server,
            &command.client,
            listener.redirect_uri(),
            command.scope.as_deref(),
            Some(&command.endpoint),
        )
        .map_err(|_| "OAuth authorization request was refused")?;
    if cancellation.is_cancelled() {
        return Err("OAuth login cancelled before authorization");
    }
    let pending = json!({"schema_version":1,"method":"mcp.oauth.login","stage":"authorization_required","authorizationUrl":request.url.as_str(),
        "redirectUri":listener.redirect_uri().as_str(),"automaticBrowserLaunch":false,"credentialsIncluded":false});
    if write_rendered_result(RenderedResult::success(format!("{pending}\n"))) != ExitCode::SUCCESS {
        return Err("authorization URL output was not confirmed; no token exchange was attempted");
    }
    let received = listener
        .receive(&request, cancellation)
        .await
        .map_err(|_| "OAuth callback was denied, cancelled, expired or invalid")?;
    if cancellation.is_cancelled() {
        return Err("OAuth login cancelled before token exchange");
    }
    mutation_started.store(true, Ordering::Release);
    let tokens = oauth.exchange_code(&binding, &store, &server, &command.client, received.as_callback(), Some(&command.endpoint))
        .await.map_err(|_| "OAuth exchange or native persistence was not confirmed; inspect local status before new authorization")?;
    Ok(completed(method, &binding, &tokens))
}

fn completed(method: &'static str, binding: &CredentialBinding, tokens: &TokenSet) -> Value {
    json!({"schema_version":1,"method":method,"stage":"completed","ok":true,"credentialRef":NativeTokenStore::keyring_reference(binding),
        "tokenResponseReceived":true,"nativeRecordVerified":true,"fresh":tokens.is_fresh(std::time::SystemTime::now()),"refreshAvailable":tokens.can_refresh(),
        "credentialsIncluded":false,"automaticRetry":false,"daemonNotified":false,"resourceRequestPerformed":false,"atomicCompareAndSwap":false,"cooperatingCliExclusive":true})
}

fn failed(method: &'static str, message: &'static str, may_have_changed: bool) -> RenderedResult {
    RenderedResult {
        exit_code: 2,
        stdout: format!(
            "{}\n",
            json!({"schema_version":1,"method":method,"stage":"failed","ok":false,
        "mayHaveChanged":may_have_changed,"credentialsIncluded":false,"automaticRetry":false,"daemonNotified":false,
        "error":{"code":if method == "mcp.oauth.refresh" { "oauth_refresh_refused" } else { "oauth_login_refused" },"message":message}})
        ),
        stderr: String::new(),
    }
}

pub(super) async fn run(command: LoginCommand) -> RenderedResult {
    let method = command.method();
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = cancellation.clone().drop_guard();
    let worker_cancellation = cancellation.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "OAuth worker runtime could not be initialized")?;
        let timeout = command.timeout;
        let mutation_started = AtomicBool::new(false);
        Ok::<_, &'static str>(runtime.block_on(async {
            let result = tokio::select! {
                biased;
                () = worker_cancellation.cancelled() => Err("OAuth operation cancelled; inspect local status before starting a new authorization"),
                result = tokio::time::timeout(timeout, login(command, &worker_cancellation, &mutation_started)) => {
                    result.unwrap_or(Err("OAuth operation timed out; inspect local status before starting a new authorization"))
                }
            };
            match result {
                Ok(value) => RenderedResult::success(format!("{value}\n")),
                Err(message) => failed(method, message, mutation_started.load(Ordering::Acquire)),
            }
        }))
    });
    let result = tokio::select! {
        result = &mut worker => result,
        _ = tokio::signal::ctrl_c() => { cancellation.cancel(); worker.await }
    };
    match result {
        Ok(Ok(result)) => result,
        Ok(Err(message)) => failed(method, message, false),
        Err(_) => failed(
            method,
            "OAuth worker ended without a confirmed outcome; inspect local status",
            true,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments() -> Vec<OsString> {
        [
            "mcp",
            "oauth",
            "login",
            "--server",
            "fixture",
            "--endpoint",
            "http://127.0.0.1:32109/mcp",
            "--issuer",
            "http://127.0.0.1:32109/",
            "--authorization-endpoint",
            "http://127.0.0.1:32109/authorize",
            "--token-endpoint",
            "http://127.0.0.1:32109/token",
            "--client-id",
            "fixture-client",
            "--confirm-login",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn oauth_refresh_requires_its_own_confirmation_and_cannot_change_scope_or_callback() {
        let mut refresh = arguments();
        refresh[2] = "refresh".into();
        assert!(parse(&refresh).is_err());
        *refresh.last_mut().expect("confirmation") = "--confirm-refresh".into();
        let parsed = parse(&refresh).ok().expect("confirmed refresh");
        assert!(parsed.refresh);
        assert_eq!(parsed.method(), "mcp.oauth.refresh");
        for extra in [
            vec!["--confirm-login"],
            vec!["--confirm-refresh"],
            vec!["--scope", "tools:write"],
            vec!["--callback-port", "0"],
            vec!["--token-stdin"],
        ] {
            let mut invalid = refresh.clone();
            invalid.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&invalid).is_err());
        }
        assert!(parse(&refresh[..refresh.len() - 1]).is_err());
    }

    #[test]
    fn oauth_login_requires_explicit_confirmation_endpoints_and_safe_proxy_routes() {
        let valid = arguments();
        assert!(parse(&valid).is_ok());
        assert!(parse(&valid[..valid.len() - 1]).is_err());
        for (position, value) in [
            (6, "http://remote.example/mcp"),
            (8, "http://localhost/"),
            (10, "https://auth.example/authorize"),
            (12, "http://127.0.0.1:32109/token?secret=private-token"),
            (14, "client secret"),
        ] {
            let mut invalid = valid.clone();
            invalid[position] = value.into();
            assert!(parse(&invalid).is_err());
        }
        for flag in [
            "--token",
            "--token-stdin",
            "--client-secret",
            "--confirm-login",
            "--program-sha256",
        ] {
            let mut invalid = valid.clone();
            invalid.push(flag.into());
            assert!(parse(&invalid).is_err());
        }
        let mut https = valid.clone();
        for (position, value) in [
            (6, "https://mcp.example/rpc"),
            (8, "https://auth.example/"),
            (10, "https://auth.example/authorize"),
            (12, "https://auth.example/token"),
        ] {
            https[position] = value.into();
        }
        https.extend(
            ["--http-proxy", "http://127.0.0.1:32110"]
                .into_iter()
                .map(OsString::from),
        );
        assert!(parse(&https).is_ok());
        *https.last_mut().expect("proxy") = "http://remote-proxy.example:8080".into();
        assert!(parse(&https).is_err());
        for (flag, value) in [
            ("--timeout-ms", "249"),
            ("--timeout-ms", "120001"),
            ("--callback-port", "65536"),
            ("--scope", "read\nwrite"),
        ] {
            let mut invalid = valid.clone();
            invalid.push(OsString::from(flag));
            invalid.push(OsString::from(value));
            assert!(parse(&invalid).is_err());
        }
    }
}
