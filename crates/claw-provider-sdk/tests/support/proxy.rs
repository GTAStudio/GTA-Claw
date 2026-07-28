//! A loopback `CONNECT` proxy used by the proxy transport tests.
//!
//! Like [`super`], this never contacts anything off the machine. It accepts one
//! connection, records the `CONNECT` request line and headers verbatim, answers
//! with a scripted status, and then captures whatever the client writes into
//! the tunnel so a test can inspect the TLS `ClientHello` directly.

#![expect(
    unreachable_pub,
    reason = "the crate lints `unreachable_pub` at warn, but `pub` is the right visibility here: these items are the public surface a sibling test binary consumes through `mod support`"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// What a proxy observed from one client.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecordedTunnel {
    /// The full request line, e.g. `CONNECT api.example.com:443 HTTP/1.1`.
    pub request_line: String,
    /// Header names lower-cased, paired with their values.
    pub headers: Vec<(String, String)>,
    /// The first bytes the client wrote after the proxy replied.
    pub tunnelled: Vec<u8>,
}

impl RecordedTunnel {
    /// Returns the value of a header, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Returns the SNI server name from a captured TLS `ClientHello`.
    ///
    /// This walks the record and handshake headers rather than searching for
    /// the hostname as a substring, so it cannot accidentally match the same
    /// text appearing elsewhere in the bytes.
    #[must_use]
    pub fn sni_host(&self) -> Option<String> {
        let bytes = &self.tunnelled;
        // TLSPlaintext: type(1) legacy_version(2) length(2)
        if *bytes.first()? != 0x16 {
            return None;
        }
        let handshake = bytes.get(5..)?;
        // Handshake: msg_type(1) length(3)
        if *handshake.first()? != 0x01 {
            return None;
        }
        // ClientHello: version(2) random(32) then variable-length fields.
        let mut cursor = 4 + 2 + 32;
        let session_len = *handshake.get(cursor)? as usize;
        cursor += 1 + session_len;
        let cipher_len = be16(handshake, cursor)? as usize;
        cursor += 2 + cipher_len;
        let compression_len = *handshake.get(cursor)? as usize;
        cursor += 1 + compression_len;
        let extensions_len = be16(handshake, cursor)? as usize;
        cursor += 2;
        let end = cursor + extensions_len;

        while cursor + 4 <= end {
            let extension = be16(handshake, cursor)?;
            let length = be16(handshake, cursor + 2)? as usize;
            let body = handshake.get(cursor + 4..cursor + 4 + length)?;
            if extension == 0x0000 {
                // ServerNameList: list_length(2) name_type(1) name_length(2)
                let name_type = *body.get(2)?;
                if name_type != 0x00 {
                    return None;
                }
                let name_length = be16(body, 3)? as usize;
                let name = body.get(5..5 + name_length)?;
                return String::from_utf8(name.to_vec()).ok();
            }
            cursor += 4 + length;
        }
        None
    }
}

/// Reads a big-endian `u16` at `offset`.
fn be16(bytes: &[u8], offset: usize) -> Option<u16> {
    let high = u16::from(*bytes.get(offset)?);
    let low = u16::from(*bytes.get(offset + 1)?);
    Some((high << 8) | low)
}

/// A loopback proxy that answers one `CONNECT`.
pub struct TestProxy {
    address: SocketAddr,
    recorded: Arc<Mutex<Vec<RecordedTunnel>>>,
}

impl TestProxy {
    /// Starts a proxy that answers `CONNECT` with `status`.
    ///
    /// When `status` is a success the proxy then reads whatever the client
    /// writes into the tunnel, so the test can assert on the TLS handshake.
    pub async fn start(status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the proxy listener");
        let address = listener.local_addr().expect("read the proxy address");
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&recorded);

        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = Vec::new();
            let mut byte = [0_u8; 1];
            // Read exactly the request head and not one byte more, so the
            // tunnel capture below starts at the client's first tunnel byte.
            while !buffer.ends_with(b"\r\n\r\n") {
                match socket.read(&mut byte).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => buffer.push(byte[0]),
                }
            }

            let head = String::from_utf8_lossy(&buffer).into_owned();
            let mut lines = head.split("\r\n");
            let request_line = lines.next().unwrap_or_default().to_owned();
            let headers = lines
                .filter(|line| !line.is_empty())
                .filter_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
                })
                .collect();

            let reason = if (200..300).contains(&status) {
                "Connection Established"
            } else {
                "Proxy Authentication Required"
            };
            let response = format!("HTTP/1.1 {status} {reason}\r\n\r\n");
            if socket.write_all(response.as_bytes()).await.is_err() {
                return;
            }

            let mut tunnelled = Vec::new();
            if (200..300).contains(&status) {
                let mut chunk = [0_u8; 2048];
                if let Ok(Ok(read)) =
                    tokio::time::timeout(Duration::from_secs(5), socket.read(&mut chunk)).await
                    && read > 0
                {
                    tunnelled.extend_from_slice(&chunk[..read]);
                }
            }

            sink.lock().await.push(RecordedTunnel {
                request_line,
                headers,
                tunnelled,
            });
            let _ = socket.shutdown().await;
        });

        Self { address, recorded }
    }

    /// Returns the proxy URL, optionally carrying Basic credentials.
    #[must_use]
    pub fn url(&self, credentials: Option<&str>) -> String {
        credentials.map_or_else(
            || format!("http://{}", self.address),
            |credentials| format!("http://{credentials}@{}", self.address),
        )
    }

    /// Returns every tunnel the proxy recorded.
    pub async fn tunnels(&self) -> Vec<RecordedTunnel> {
        self.recorded.lock().await.clone()
    }

    /// Waits until the proxy has recorded `count` tunnels.
    pub async fn wait_for_tunnels(&self, count: usize, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if self.recorded.lock().await.len() >= count {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }
}
