//! OpenSSH `known_hosts` fail-closed verification oracles.
//!
//! The digest primitives are proved against the published RFC vectors first, so
//! the hashed-host fixtures built on top of them rest on a verified base rather
//! than on the implementation agreeing with itself.

use claw_discovery::known_hosts::digest::{base64_decode, base64_encode, hmac_sha1, sha1};
use claw_discovery::known_hosts::{HostKey, KnownHosts, KnownHostsError, Marker, RejectionCause};

fn key(seed: u8) -> HostKey {
    // A synthetic but structurally plausible blob: the SSH wire form is a
    // length-prefixed algorithm name followed by length-prefixed key material.
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0, 0, 0, 11]);
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&[0, 0, 0, 32]);
    blob.extend_from_slice(&[seed; 32]);
    HostKey::new("ssh-ed25519", blob)
}

fn encoded(key: &HostKey) -> String {
    base64_encode(&key.blob, true)
}

fn hashed_host(salt: &[u8], host: &str) -> String {
    format!(
        "|1|{}|{}",
        base64_encode(salt, true),
        base64_encode(&hmac_sha1(salt, host.as_bytes()), true)
    )
}

const HASH_SALT: &[u8; 20] = b"claw-known-host-salt";

fn fixture() -> String {
    let good1 = encoded(&key(1));
    let key_b = encoded(&key(2));
    let key_wild = encoded(&key(3));
    let key_ca = encoded(&key(4));
    let key_revoked = encoded(&key(5));
    let key_good3 = encoded(&key(6));
    let key_hidden = encoded(&key(7));
    let hidden = hashed_host(HASH_SALT, "hidden.claw.example");
    format!(
        "# gateway fleet\n\
         \n\
         gw1.claw.example,192.0.2.11 ssh-ed25519 {good1}\n\
         [gw2.claw.example]:2222 ssh-ed25519 {key_b}\n\
         *.claw.example,!admin.claw.example ssh-ed25519 {key_wild}\n\
         @cert-authority *.ca.example ssh-ed25519 {key_ca}\n\
         gw3.claw.example ssh-ed25519 {key_revoked}\n\
         gw3.claw.example ssh-ed25519 {key_good3}\n\
         @revoked gw3.claw.example ssh-ed25519 {key_revoked}\n\
         {hidden} ssh-ed25519 {key_hidden}\n"
    )
}

#[test]
fn sha1_and_hmac_sha1_match_the_published_rfc_vectors() {
    // FIPS 180-1 / RFC 3174 sample vectors.
    assert_eq!(
        hex(&sha1(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(
        hex(&sha1(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    // A message that spans several blocks and lands on the 56-byte padding
    // boundary, where a length-encoding mistake shows up.
    assert_eq!(
        hex(&sha1(&vec![b'a'; 1_000])),
        "291e9a6c66994949b57ba5e650361e98fc36b1ba"
    );

    // RFC 2202 HMAC-SHA-1 vectors 1, 2, 3 and 6.
    assert_eq!(
        hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
        "b617318655057264e28bc0b6fb378c8ef146be00"
    );
    assert_eq!(
        hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    );
    assert_eq!(
        hex(&hmac_sha1(&[0xaa; 20], &[0xdd; 50])),
        "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
    );
    assert_eq!(
        hex(&hmac_sha1(
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "aa4ae5e15272d00e95705637ce8a3b55ed402112"
    );
}

#[test]
fn base64_matches_the_rfc4648_vectors_and_rejects_malformed_input() {
    for (plain, encoded_text) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64_encode(plain.as_bytes(), true), encoded_text);
        assert_eq!(
            base64_decode(encoded_text).expect("decode"),
            plain.as_bytes()
        );
        assert_eq!(
            base64_decode(encoded_text.trim_end_matches('=')).expect("decode unpadded"),
            plain.as_bytes()
        );
    }
    assert_eq!(base64_encode(b"foob", false), "Zm9vYg");

    assert_eq!(base64_decode("Zg"), Some(b"f".to_vec()));
    // A single trailing character cannot encode a whole byte.
    assert_eq!(base64_decode("Z"), None);
    // Non-zero padding bits would let two different strings decode alike.
    assert_eq!(base64_decode("Zh"), None);
    assert_eq!(base64_decode("Zm9v*"), None);
    assert_eq!(base64_decode("Zm=9v"), None);
}

#[test]
fn host_key_fingerprint_uses_the_openssh_sha256_form() {
    let fingerprint = HostKey::new("ssh-ed25519", b"abc".to_vec()).fingerprint();
    assert_eq!(
        fingerprint, "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0",
        "the fingerprint is the unpadded base64 of the SHA-256 of the key blob"
    );
    assert!(!fingerprint.contains('='), "OpenSSH prints no padding");
    assert_ne!(key(1).fingerprint(), key(2).fingerprint());
}

#[test]
fn known_hosts_grammar_parses_every_line_form() {
    let hosts = KnownHosts::parse(&fixture()).expect("parse fixture");
    assert_eq!(
        hosts.entries().len(),
        8,
        "comments and blank lines are skipped, every other line is an entry"
    );
    assert_eq!(hosts.entries()[0].line(), 3, "line numbers count from one");
    assert_eq!(hosts.entries()[0].marker(), None);
    assert_eq!(hosts.entries()[3].marker(), Some(Marker::CertAuthority));
    assert_eq!(hosts.entries()[6].marker(), Some(Marker::Revoked));
    assert_eq!(hosts.entries()[0].key(), &key(1));

    // A comma list, an IP literal, a bracketed non-default port and a hashed
    // host all resolve to the same match key rule.
    assert!(hosts.entries()[0].matches("gw1.claw.example"));
    assert!(hosts.entries()[0].matches("192.0.2.11"));
    assert!(hosts.entries()[1].matches("[gw2.claw.example]:2222"));
    assert!(!hosts.entries()[1].matches("gw2.claw.example"));
    assert!(hosts.entries()[7].matches("hidden.claw.example"));
    assert!(!hosts.entries()[7].matches("visible.claw.example"));

    assert_eq!(
        KnownHosts::match_key("GW1.Claw.Example", 22),
        "gw1.claw.example"
    );
    assert_eq!(
        KnownHosts::match_key("GW2.claw.example", 2222),
        "[gw2.claw.example]:2222"
    );
}

#[test]
fn matching_host_and_key_is_accepted_case_insensitively() {
    let hosts = KnownHosts::parse(&fixture()).expect("parse");

    let verdict = hosts.verify("gw1.claw.example", 22, &key(1));
    assert!(
        verdict.is_accepted(),
        "expected acceptance, got {verdict:?}"
    );
    assert_eq!(
        verdict,
        claw_discovery::known_hosts::HostKeyVerdict::Accepted { line: 3 }
    );

    // DNS names are case-insensitive, so the same host in caps must not become
    // an unknown host and prompt an operator into trusting it again.
    assert!(hosts.verify("GW1.CLAW.EXAMPLE", 22, &key(1)).is_accepted());
    // The IP literal on the same line is a separate pattern for the same key.
    assert!(hosts.verify("192.0.2.11", 22, &key(1)).is_accepted());
    // The bracketed entry only applies on its own port.
    assert!(
        hosts
            .verify("gw2.claw.example", 2222, &key(2))
            .is_accepted()
    );
}

#[test]
fn revoked_key_is_refused_even_when_an_accepting_line_comes_first() {
    let hosts = KnownHosts::parse(&fixture()).expect("parse");

    // Line 7 accepts this key; line 9 revokes it. Revocation must win.
    let accepting = hosts
        .entries()
        .iter()
        .find(|entry| entry.marker().is_none() && entry.key() == &key(5))
        .expect("fixture must contain a plain accepting line for the revoked key");
    let revoking = hosts
        .entries()
        .iter()
        .find(|entry| entry.marker() == Some(Marker::Revoked))
        .expect("fixture must contain the revoking line");
    assert!(
        accepting.line() < revoking.line(),
        "the accepting line must come first, or the test proves nothing about order"
    );

    let verdict = hosts.verify("gw3.claw.example", 22, &key(5));
    assert!(!verdict.is_accepted());
    assert_eq!(verdict.cause(), Some(RejectionCause::Revoked));
    let detail = verdict.detail().expect("a refusal must state its reason");
    assert!(detail.contains("revoked"), "got {detail}");
    assert!(
        detail.contains(&key(5).fingerprint()),
        "the refusal must name the offending key, got {detail}"
    );

    // Revocation is key-specific: the other key recorded for the same host is
    // still usable, so a revocation cannot be used to lock an operator out.
    assert!(hosts.verify("gw3.claw.example", 22, &key(6)).is_accepted());
}

#[test]
fn mismatched_key_for_a_known_host_fails_closed() {
    let hosts = KnownHosts::parse(&fixture()).expect("parse");
    let verdict = hosts.verify("gw1.claw.example", 22, &key(9));

    assert!(!verdict.is_accepted());
    assert_eq!(verdict.cause(), Some(RejectionCause::Mismatch));
    let detail = verdict.detail().expect("reason");
    assert!(
        detail.contains(&key(9).fingerprint()),
        "the refusal must name the presented key, got {detail}"
    );
    assert!(
        detail.contains(&key(1).fingerprint()),
        "the refusal must name the recorded key, got {detail}"
    );
}

#[test]
fn certificate_authority_line_never_authorises_a_plain_host_key() {
    let hosts = KnownHosts::parse(&fixture()).expect("parse");

    // The CA key itself, presented as an ordinary host key, must be refused:
    // holding a CA public key is not the same as holding a certificate signed
    // by it.
    let verdict = hosts.verify("node.ca.example", 22, &key(4));
    assert!(!verdict.is_accepted());
    assert_eq!(
        verdict.cause(),
        Some(RejectionCause::CertificateAuthorityOnly)
    );
    assert!(
        verdict
            .detail()
            .expect("reason")
            .contains("@cert-authority"),
        "the refusal must name the marker it declined to honour"
    );

    // An unrelated key under the same CA-covered pattern is refused for the
    // same reason, not silently promoted to accepted.
    assert_eq!(
        hosts.verify("other.ca.example", 22, &key(9)).cause(),
        Some(RejectionCause::CertificateAuthorityOnly)
    );
}

#[test]
fn wildcards_match_and_a_negation_vetoes_the_whole_line() {
    let hosts = KnownHosts::parse(&fixture()).expect("parse");

    assert!(hosts.verify("gw9.claw.example", 22, &key(3)).is_accepted());

    // `!admin.claw.example` sits on the same line as `*.claw.example`, so the
    // negation must remove the line from consideration entirely rather than
    // being outvoted by the wildcard next to it.
    let verdict = hosts.verify("admin.claw.example", 22, &key(3));
    assert!(!verdict.is_accepted());
    assert_eq!(verdict.cause(), Some(RejectionCause::Unknown));

    // A single-character wildcard is honoured too.
    let single = KnownHosts::parse(&format!(
        "gw?.claw.example ssh-ed25519 {}\n",
        encoded(&key(1))
    ))
    .expect("parse");
    assert!(single.verify("gw7.claw.example", 22, &key(1)).is_accepted());
    assert_eq!(
        single.verify("gw77.claw.example", 22, &key(1)).cause(),
        Some(RejectionCause::Unknown)
    );

    // A wildcard must not span a label boundary implicitly, but `*` in OpenSSH
    // does match dots, so this is pinned rather than assumed.
    let broad =
        KnownHosts::parse(&format!("*.example ssh-ed25519 {}\n", encoded(&key(1)))).expect("parse");
    assert!(broad.verify("a.b.example", 22, &key(1)).is_accepted());
}

#[test]
fn hashed_host_entry_matches_only_its_own_host() {
    let hosts = KnownHosts::parse(&fixture()).expect("parse");

    assert!(
        hosts
            .verify("hidden.claw.example", 22, &key(7))
            .is_accepted()
    );
    // The hashed entry is keyed on the exact match key, so the same host on a
    // different port hashes differently and must not match.
    assert_eq!(
        hosts.verify("hidden.claw.example", 2222, &key(7)).cause(),
        Some(RejectionCause::Unknown)
    );
    assert_eq!(
        hosts.verify("hidden.claw.example", 22, &key(9)).cause(),
        Some(RejectionCause::Mismatch)
    );

    // A hashed line whose digest is the right length but the wrong value must
    // not match anything, rather than matching everything.
    let wrong = KnownHosts::parse(&format!(
        "|1|{}|{} ssh-ed25519 {}\n",
        base64_encode(HASH_SALT, true),
        base64_encode(&[0u8; 20], true),
        encoded(&key(7))
    ))
    .expect("parse");
    assert_eq!(
        wrong.verify("hidden.claw.example", 22, &key(7)).cause(),
        Some(RejectionCause::Unknown)
    );
}

#[test]
fn unknown_host_is_refused_rather_than_defaulted() {
    let hosts = KnownHosts::parse(&fixture()).expect("parse");
    let verdict = hosts.verify("brand-new.other.example", 22, &key(1));

    assert!(!verdict.is_accepted());
    assert_eq!(verdict.cause(), Some(RejectionCause::Unknown));
    assert!(
        verdict.detail().expect("reason").contains("no known_hosts"),
        "an unknown host must say so explicitly"
    );

    // An empty file accepts nothing at all.
    let empty = KnownHosts::parse("").expect("parse empty");
    assert_eq!(
        empty.verify("gw1.claw.example", 22, &key(1)).cause(),
        Some(RejectionCause::Unknown)
    );
}

#[test]
fn malformed_lines_are_errors_rather_than_silently_skipped() {
    // Silently skipping a bad line is how a revocation stops taking effect, so
    // every one of these must surface.
    let good = encoded(&key(1));
    let cases: Vec<(String, KnownHostsError)> = vec![
        (
            "gw1.claw.example ssh-ed25519\n".to_owned(),
            KnownHostsError::Malformed(1, "missing key blob".to_owned()),
        ),
        (
            "gw1.claw.example\n".to_owned(),
            KnownHostsError::Malformed(1, "missing key algorithm".to_owned()),
        ),
        (
            "gw1.claw.example ssh-ed25519 not*base64\n".to_owned(),
            KnownHostsError::Malformed(1, "key blob is not base64".to_owned()),
        ),
        (
            format!("@bogus gw1.claw.example ssh-ed25519 {good}\n"),
            KnownHostsError::UnknownMarker(1, "@bogus".to_owned()),
        ),
        (
            "@revoked\n".to_owned(),
            KnownHostsError::Malformed(1, "marker without a host field".to_owned()),
        ),
        (
            format!("gw1.claw.example,,gw2 ssh-ed25519 {good}\n"),
            KnownHostsError::Malformed(1, "empty host pattern".to_owned()),
        ),
        (
            format!("|1|bad-salt ssh-ed25519 {good}\n"),
            KnownHostsError::MalformedHashedHost(1, "missing salt separator".to_owned()),
        ),
        (
            format!("|1|**|** ssh-ed25519 {good}\n"),
            KnownHostsError::MalformedHashedHost(1, "salt is not base64".to_owned()),
        ),
        (
            format!(
                "|1|{}|{} ssh-ed25519 {good}\n",
                base64_encode(HASH_SALT, true),
                base64_encode(&[0u8; 8], true)
            ),
            KnownHostsError::MalformedHashedHost(1, "hash is 8 bytes, HMAC-SHA1 is 20".to_owned()),
        ),
    ];
    for (text, expected) in cases {
        let error = KnownHosts::parse(&text).err();
        assert_eq!(
            error,
            Some(expected.clone()),
            "parsing {text:?} must fail with {expected}"
        );
    }

    // The line number in the error is the real one, so an operator can find it.
    let text = format!("# comment\n\ngw1.claw.example ssh-ed25519 {good}\nbroken\n");
    assert_eq!(
        KnownHosts::parse(&text).err(),
        Some(KnownHostsError::Malformed(
            4,
            "missing key algorithm".to_owned()
        ))
    );

    let long = format!("{} ssh-ed25519 {good}\n", "h".repeat(9000));
    assert!(matches!(
        KnownHosts::parse(&long),
        Err(KnownHostsError::LineTooLong(1, _))
    ));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
