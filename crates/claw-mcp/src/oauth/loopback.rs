use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{
    Method, Request, Response, StatusCode,
    header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING},
};
use http_body_util::Full;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{AuthorizationRequest, RedirectAuthorizationCallback};
use crate::error::{McpError, Result};

const MAX_CALLBACK_REQUESTS: usize = 16;
const CALLBACK_HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// An owned loopback-only receiver for one bounded OAuth redirect.
///
/// It neither opens a browser nor exchanges or persists tokens. Every response
/// closes its connection, has no cacheable content and contains no callback data.
pub struct LoopbackAuthorizationListener {
    listener: TcpListener,
    redirect_uri: Url,
}

impl LoopbackAuthorizationListener {
    /// Binds an explicit literal loopback address, optionally with an ephemeral port.
    ///
    /// # Errors
    /// Rejects non-loopback addresses or failure to bind the requested listener.
    pub async fn bind(address: SocketAddr) -> Result<Self> {
        if !address.ip().is_loopback() {
            return Err(McpError::Protocol(
                "OAuth callback listener must use a literal loopback address".into(),
            ));
        }
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let redirect_uri = Url::parse(&format!("http://{address}/oauth/callback"))?;
        Ok(Self {
            listener,
            redirect_uri,
        })
    }

    /// Returns the exact redirect URI to register and include in authorization.
    #[must_use]
    pub const fn redirect_uri(&self) -> &Url {
        &self.redirect_uri
    }

    /// Receives one valid redirect and closes this listener on every exit path.
    ///
    /// At most sixteen connections are examined, each with a five-second header
    /// budget and bounded parsing, within the authorization request's lifetime.
    /// Only origin-form, bodyless GET with the exact Host and callback path is accepted.
    ///
    /// # Errors
    /// Fails on cancellation, expiration, a mismatched request, denial, exhausted
    /// admission budget or local transport failure. Invalid redirects consume a
    /// connection slot but do not consume the authorization request itself.
    pub async fn receive<'a>(
        self,
        request: &'a AuthorizationRequest,
        cancellation: &CancellationToken,
    ) -> Result<RedirectAuthorizationCallback<'a>> {
        if request.redirect_uri != self.redirect_uri {
            return Err(McpError::Protocol(
                "OAuth listener does not match the authorized redirect".into(),
            ));
        }
        if request.attempted.load(std::sync::atomic::Ordering::Acquire)
            || request.expires_at <= std::time::Instant::now()
        {
            return Err(McpError::Protocol(
                "OAuth callback request is expired or consumed".into(),
            ));
        }
        let deadline = tokio::time::Instant::from_std(request.expires_at);
        for _ in 0..MAX_CALLBACK_REQUESTS {
            let (stream, peer) = tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(McpError::Protocol("OAuth callback wait cancelled".into())),
                () = tokio::time::sleep_until(deadline) => return Err(McpError::Protocol("OAuth callback wait expired".into())),
                accepted = self.listener.accept() => accepted?,
            };
            if !peer.ip().is_loopback() {
                continue;
            }
            let received = Arc::new(Mutex::new(None));
            let captured = Arc::clone(&received);
            let service = service_fn(move |incoming: Request<Incoming>| {
                let (status, message) = if callback_headers_match(&incoming, &request.redirect_uri)
                {
                    let callback_url = format!(
                        "{}{}",
                        request.redirect_uri.origin().ascii_serialization(),
                        incoming.uri()
                    );
                    match request.parse_redirect(&callback_url) {
                        Ok(callback) => {
                            if captured.lock().map(|mut slot| { *slot = Some(Ok(callback)); }).is_ok() {
                                (StatusCode::OK, "Authorization response received. Return to the client.\n")
                            } else {
                                (StatusCode::INTERNAL_SERVER_ERROR, "Authorization receiver failed.\n")
                            }
                        }
                        Err(error)
                            if request.attempted.load(std::sync::atomic::Ordering::Acquire) =>
                        {
                            if captured.lock().map(|mut slot| { *slot = Some(Err(error)); }).is_ok() {
                                (StatusCode::BAD_REQUEST, "Authorization was declined or already completed.\n")
                            } else {
                                (StatusCode::INTERNAL_SERVER_ERROR, "Authorization receiver failed.\n")
                            }
                        }
                        Err(_) => (
                            StatusCode::BAD_REQUEST,
                            "Authorization response was rejected.\n",
                        ),
                    }
                } else {
                    (
                        StatusCode::BAD_REQUEST,
                        "Authorization response was rejected.\n",
                    )
                };
                let response = Response::builder()
                    .status(status)
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .header("Cache-Control", "no-store")
                    .header("Pragma", "no-cache")
                    .header("Referrer-Policy", "no-referrer")
                    .header("Content-Security-Policy", "default-src 'none'")
                    .header("Connection", "close")
                    .body(Full::new(Bytes::from_static(message.as_bytes())));
                std::future::ready(response)
            });
            let mut http = http1::Builder::new();
            http.keep_alive(false)
                .max_buf_size(32 * 1024)
                .timer(TokioTimer::new())
                .header_read_timeout(CALLBACK_HEADER_TIMEOUT);
            let connection = http.serve_connection(TokioIo::new(stream), service);
            let connection_deadline =
                deadline.min(tokio::time::Instant::now() + CALLBACK_HEADER_TIMEOUT);
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(McpError::Protocol("OAuth callback wait cancelled".into())),
                result = tokio::time::timeout_at(connection_deadline, connection) => { let _ = result; }
            }
            let callback = received.lock().map_err(|_| McpError::Protocol("OAuth callback state failed".into()))?.take();
            if let Some(callback) = callback {
                return callback;
            }
        }
        Err(McpError::Protocol(
            "OAuth callback connection limit reached".into(),
        ))
    }
}

fn callback_headers_match(request: &Request<Incoming>, redirect_uri: &Url) -> bool {
    request.method() == Method::GET
        && request.uri().scheme().is_none()
        && request.uri().authority().is_none()
        && request.uri().path() == redirect_uri.path()
        && request
            .uri()
            .path_and_query()
            .is_some_and(|target| target.as_str().len() <= 16 * 1024)
        && request.headers().get_all(HOST).iter().count() == 1
        && request.headers().get(HOST).is_some_and(|host| {
            host.as_bytes()
                == redirect_uri[url::Position::BeforeHost..url::Position::AfterPort].as_bytes()
        })
        && !request.headers().contains_key(TRANSFER_ENCODING)
        && request.headers().get_all(CONTENT_LENGTH).iter().count() <= 1
        && request
            .headers()
            .get(CONTENT_LENGTH)
            .is_none_or(|length| length.as_bytes() == b"0")
}

#[cfg(test)]
mod tests {
    use super::super::{OAuthClient, RegisteredClient};
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    async fn send(
        address: SocketAddr,
        method: &str,
        target: &str,
        host: &str,
        extra: &str,
    ) -> String {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("owned callback connection");
        stream
            .write_all(
                format!(
                    "{method} {target} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("callback request");
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .await
            .expect("bounded callback response");
        String::from_utf8(bytes).expect("callback text")
    }

    #[tokio::test]
    async fn loopback_callback_admission_requires_exact_host_path_method_and_valid_state() {
        assert!(
            LoopbackAuthorizationListener::bind("0.0.0.0:0".parse().expect("address"))
                .await
                .is_err()
        );
        let listener = LoopbackAuthorizationListener::bind("127.0.0.1:0".parse().expect("address"))
            .await
            .expect("owned listener");
        let address = listener.listener.local_addr().expect("address");
        let oauth = OAuthClient::default();
        let server = super::super::tests::discovered_server(
            &Url::parse("https://auth.example/").expect("issuer"),
        );
        let client = RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: None,
        };
        let request = oauth
            .authorization_request(&server, &client, listener.redirect_uri(), None, None)
            .expect("authorization");
        let mut returned = listener.redirect_uri().clone();
        returned
            .query_pairs_mut()
            .append_pair("code", "private-loopback-code")
            .append_pair("state", &request.state);
        let target = returned[url::Position::BeforePath..].to_owned();
        let sender = tokio::spawn(async move {
            for (method, target, host, extra) in [
                ("POST", target.as_str(), address.to_string(), ""),
                ("GET", "/other", address.to_string(), ""),
                ("GET", target.as_str(), "localhost".to_owned(), ""),
                (
                    "GET",
                    "/oauth/callback?code=private-loopback-code&state=wrong",
                    address.to_string(),
                    "",
                ),
                (
                    "GET",
                    target.as_str(),
                    address.to_string(),
                    "Content-Length: 1\r\n",
                ),
            ] {
                let response = send(address, method, target, &host, extra).await;
                assert!(response.starts_with("HTTP/1.1 400"));
                assert!(!response.contains("private-loopback-code"));
            }
            let response = send(address, "GET", &target, &address.to_string(), "").await;
            assert!(response.starts_with("HTTP/1.1 200"));
            assert!(
                response
                    .to_ascii_lowercase()
                    .contains("cache-control: no-store")
            );
            assert!(!response.contains("private-loopback-code"));
        });
        let callback = listener
            .receive(&request, &CancellationToken::new())
            .await
            .expect("one valid callback");
        assert_eq!(callback.as_callback().code, "private-loopback-code");
        sender.await.expect("sender joined");
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn loopback_callback_cancellation_expiry_and_connection_budget_release_listener() {
        let oauth = OAuthClient::default();
        let server = super::super::tests::discovered_server(
            &Url::parse("https://auth.example/").expect("issuer"),
        );
        let client = RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: None,
        };
        for mode in ["cancel", "expired", "budget"] {
            let listener =
                LoopbackAuthorizationListener::bind("127.0.0.1:0".parse().expect("address"))
                    .await
                    .expect("owned listener");
            let address = listener.listener.local_addr().expect("address");
            let mut request = oauth
                .authorization_request(&server, &client, listener.redirect_uri(), None, None)
                .expect("authorization");
            let cancellation = CancellationToken::new();
            if mode == "cancel" {
                cancellation.cancel();
            }
            if mode == "expired" {
                request.expires_at = std::time::Instant::now();
            }
            let sender = if mode == "budget" {
                Some(tokio::spawn(async move {
                    for _ in 0..MAX_CALLBACK_REQUESTS {
                        assert!(
                            send(
                                address,
                                "GET",
                                "/not-the-callback",
                                &address.to_string(),
                                ""
                            )
                            .await
                            .starts_with("HTTP/1.1 400")
                        );
                    }
                }))
            } else {
                None
            };
            assert!(listener.receive(&request, &cancellation).await.is_err());
            if let Some(sender) = sender {
                sender.await.expect("sender joined");
            }
            assert!(tokio::net::TcpStream::connect(address).await.is_err());
        }
    }
}
