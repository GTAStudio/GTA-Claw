//! Proves the configuration this crate builds is one `claw-gateway-client`
//! actually accepts, rather than one that merely looks plausible.
//!
//! Platform note: these tests have only ever been executed on Windows x86_64.
//! They exercise no Apple-specific code path, because this crate contains none.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use claw_gateway_client::{
    ConfigurationError, GatewayClient, GatewayClientError, GatewayCredential, ProtocolFailure,
    ReconnectPolicy,
};
use claw_protocol::gateway::{AUTHENTICATED_MAX_FRAME_BYTES, ClientMode, Name};
use claw_security::authorization::Scope;
use claw_security::identity::DeviceIdentity;
use gta_claw_ios::{
    GatewayEndpoint, IosClientIdentity, IosCredential, IosGatewayProfile, UnobservedDeviceProbe,
};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use serde_json::{Value, json};

fn device_identity() -> Arc<DeviceIdentity> {
    let mut rng = ChaCha20Rng::seed_from_u64(4_443);
    Arc::new(DeviceIdentity::generate(&mut rng))
}

fn profile(endpoint: &str) -> IosGatewayProfile {
    IosGatewayProfile::new(
        GatewayEndpoint::parse(endpoint)
            .unwrap_or_else(|error| panic!("{endpoint} must parse, got {error}")),
        IosCredential::token("integration-fixture").expect("the token is valid"),
        IosClientIdentity::observe(&UnobservedDeviceProbe).expect("the identity is buildable"),
        device_identity(),
    )
    .requesting([Scope::OperatorRead])
}

fn spawn_gateway_with_extra_scope() -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the test Gateway must bind");
    let address = listener
        .local_addr()
        .expect("the test Gateway must have an address");
    let gateway = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the iOS client must connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("the test Gateway read timeout must be configurable");
        complete_websocket_handshake(&mut stream);

        write_text_frame(
            &mut stream,
            br#"{"type":"event","event":"connect.challenge","payload":{"nonce":"ios-scope-pin","ts":1700000000000}}"#,
        );
        let connect: Value = serde_json::from_slice(&read_text_frame(&mut stream))
            .expect("the iOS connect request must be valid JSON");
        assert_eq!(
            connect["params"]["scopes"],
            json!(["operator.read"]),
            "the iOS profile must request the literal read-only scope set"
        );
        let request_id = connect["id"]
            .as_str()
            .expect("the connect request must carry a string id");
        let hello = json!({
            "type": "res",
            "id": request_id,
            "ok": true,
            "payload": {
                "type": "hello-ok",
                "protocol": 4,
                "server": {
                    "version": "ios-authorization-pin",
                    "connId": "read-plus-extra"
                },
                "features": {
                    "methods": ["health"],
                    "events": ["connect.challenge", "tick"]
                },
                "snapshot": {
                    "presence": [],
                    "health": {},
                    "stateVersion": {"presence": 0, "health": 0},
                    "uptimeMs": 1,
                    "authMode": "token"
                },
                "auth": {
                    "role": "operator",
                    "scopes": ["operator.read", "operator.admin"]
                },
                "policy": {
                    "maxPayload": AUTHENTICATED_MAX_FRAME_BYTES,
                    "maxBufferedBytes": AUTHENTICATED_MAX_FRAME_BYTES,
                    "tickIntervalMs": 1000
                }
            }
        });
        write_text_frame(
            &mut stream,
            &serde_json::to_vec(&hello).expect("the test hello must encode"),
        );

        let _ = read_websocket_frame(&mut stream);
    });

    (format!("ws://{address}"), gateway)
}

fn complete_websocket_handshake(stream: &mut TcpStream) {
    const HEADER_LIMIT: usize = 16 * 1024;
    const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    let mut request = Vec::with_capacity(1024);
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        assert!(
            request.len() < HEADER_LIMIT,
            "the WebSocket request headers must remain bounded"
        );
        let mut chunk = [0_u8; 1024];
        let count = stream
            .read(&mut chunk)
            .expect("the WebSocket request must be readable");
        assert!(count > 0, "the WebSocket request ended before its headers");
        request.extend_from_slice(&chunk[..count]);
    }
    let request = std::str::from_utf8(&request).expect("the WebSocket request must be UTF-8");
    let key = request
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("Sec-WebSocket-Key")
                .then(|| value.trim())
        })
        .expect("the WebSocket request must carry a key");
    let mut accept_input = Vec::with_capacity(key.len() + WEBSOCKET_GUID.len());
    accept_input.extend_from_slice(key.as_bytes());
    accept_input.extend_from_slice(WEBSOCKET_GUID);
    let accept = base64(&sha1(&accept_input));
    write!(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    )
    .expect("the WebSocket response must be writable");
    stream
        .flush()
        .expect("the WebSocket response must be flushed");
}

fn read_text_frame(stream: &mut TcpStream) -> Vec<u8> {
    loop {
        let (opcode, payload) =
            read_websocket_frame(stream).expect("the client WebSocket frame must be readable");
        match opcode {
            0x1 => return payload,
            0x8 => panic!("the client closed before sending its connect request"),
            _ => {}
        }
    }
}

fn read_websocket_frame(stream: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header)?;
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut payload_len = u64::from(header[1] & 0x7f);
    if payload_len == 126 {
        let mut extended = [0_u8; 2];
        stream.read_exact(&mut extended)?;
        payload_len = u64::from(u16::from_be_bytes(extended));
    } else if payload_len == 127 {
        let mut extended = [0_u8; 8];
        stream.read_exact(&mut extended)?;
        payload_len = u64::from_be_bytes(extended);
    }
    let mut mask = [0_u8; 4];
    if masked {
        stream.read_exact(&mut mask)?;
    }
    let mut payload =
        vec![0_u8; usize::try_from(payload_len).expect("the test frame length must fit usize")];
    stream.read_exact(&mut payload)?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % mask.len()];
        }
    }
    Ok((opcode, payload))
}

fn write_text_frame(stream: &mut TcpStream, payload: &[u8]) {
    let mut header = vec![0x81];
    if payload.len() < 126 {
        header.push(u8::try_from(payload.len()).expect("the short frame length must fit u8"));
    } else {
        header.push(126);
        header.extend_from_slice(
            &u16::try_from(payload.len())
                .expect("the test frame length must fit u16")
                .to_be_bytes(),
        );
    }
    stream
        .write_all(&header)
        .and_then(|()| stream.write_all(payload))
        .and_then(|()| stream.flush())
        .expect("the test Gateway text frame must be writable");
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or_default();
        let third = chunk.get(2).copied().unwrap_or_default();
        encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
        encoded.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        encoded.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))])
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(third & 0x3f)])
        } else {
            '='
        });
    }
    encoded
}

fn sha1(input: &[u8]) -> [u8; 20] {
    let bit_len = u64::try_from(input.len())
        .expect("the handshake input length must fit u64")
        .checked_mul(8)
        .expect("the handshake bit length must fit u64");
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = [
        0x6745_2301_u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    for block in padded.chunks_exact(64) {
        let mut words = [0_u32; 80];
        for (index, word) in words[..16].iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes(
                block[offset..offset + 4]
                    .try_into()
                    .expect("the SHA-1 word must contain four bytes"),
            );
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in words.into_iter().enumerate() {
            let (function, constant) = match index {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                60..=79 => (b ^ c ^ d, 0xca62_c1d6),
                _ => unreachable!("SHA-1 has exactly 80 rounds"),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut digest = [0_u8; 20];
    for (chunk, word) in digest.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// The client validates the configuration before it spawns anything, so this
/// case needs no async runtime.
#[test]
fn a_worker_mode_configuration_is_rejected_by_the_real_client() {
    let mut config = profile("ws://127.0.0.1:1").into_client_config();
    config.client.mode = ClientMode::Worker;

    let error = GatewayClient::start(config)
        .err()
        .expect("the client must refuse worker mode");

    assert!(
        matches!(
            error,
            GatewayClientError::Configuration(ConfigurationError::WorkerProtocolUnsupported)
        ),
        "expected a worker-protocol configuration refusal, got {error}"
    );
}

#[test]
fn a_credential_bearing_url_never_reaches_the_client() {
    let error = GatewayEndpoint::parse("wss://gateway.example?token=abcdef")
        .expect_err("a query string is refused");

    assert_eq!(
        error.to_string(),
        "Gateway address must not contain a user, password, query, or fragment"
    );
}

#[tokio::test]
async fn the_real_client_accepts_the_configuration_this_crate_builds() {
    let config = profile("ws://127.0.0.1:1").into_client_config();

    assert_eq!(config.client.mode, ClientMode::Ui);
    assert!(
        matches!(config.credential, GatewayCredential::Token(_)),
        "the fixture must carry a token, got {:?}",
        config.credential
    );

    // Port 1 on loopback refuses immediately. This proves configuration
    // admission and deterministic shutdown; it does NOT prove a handshake,
    // which no test in this crate performs.
    let (client, _events) =
        GatewayClient::start(config).expect("the client must accept this configuration");

    client
        .shutdown()
        .await
        .expect("the client must shut down deterministically");
}

#[tokio::test]
async fn a_read_only_profile_rejects_an_extra_closed_operator_scope() {
    let (endpoint, gateway) = spawn_gateway_with_extra_scope();
    let mut config = profile(&endpoint).into_client_config();
    config.reconnect = ReconnectPolicy::Never;
    let (client, _events) =
        GatewayClient::start(config).expect("the read-only iOS configuration must start");

    let readiness = tokio::time::timeout(Duration::from_secs(5), client.wait_ready())
        .await
        .expect("the authorization decision must complete");
    client
        .shutdown()
        .await
        .expect("the rejected client must shut down deterministically");
    gateway
        .join()
        .expect("the test Gateway must complete without panicking");

    assert!(
        matches!(
            readiness,
            Err(GatewayClientError::Protocol(
                ProtocolFailure::WebSocketProtocol("hello authentication mismatch")
            ))
        ),
        "an iOS profile requesting only operator.read must reject a hello that adds \
         operator.admin with the precise authorization mismatch, got {readiness:?}"
    );
}

#[tokio::test]
async fn a_declared_device_reaches_the_client_metadata_unchanged() {
    let probe = gta_claw_ios::DeclaredDeviceProbe::new()
        .with_device_family("iPad")
        .with_model_identifier("iPad14,3");
    let profile = IosGatewayProfile::new(
        GatewayEndpoint::parse("ws://127.0.0.1:1").expect("the endpoint is valid"),
        IosCredential::none(),
        IosClientIdentity::observe(&probe).expect("the identity is buildable"),
        device_identity(),
    );
    let config = profile.into_client_config();

    assert_eq!(
        config.client.device_family.as_ref().map(Name::as_str),
        Some("iPad")
    );
    assert_eq!(
        config.client.model_identifier.as_ref().map(Name::as_str),
        Some("iPad14,3")
    );

    let (client, _events) =
        GatewayClient::start(config).expect("the client must accept this configuration");

    client
        .shutdown()
        .await
        .expect("the client must shut down deterministically");
}
