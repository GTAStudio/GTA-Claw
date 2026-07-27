//! DNS-SD wire-format oracles.
//!
//! Every fixture in this file is written out byte by byte, field by field, from
//! the RFC rather than captured from the encoder, so a regression in the encoder
//! cannot quietly rewrite its own expectation. The wide-area fixture is a
//! hand-assembled recursive-resolver answer, which makes the decoder the thing
//! under test rather than a mirror of the encoder.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use claw_discovery::dnssd::message::{
    CLASS_IN, FLAG_AUTHORITATIVE, FLAG_RESPONSE, Message, RecordData, TYPE_A, TYPE_AAAA, TYPE_PTR,
    TYPE_SRV, TYPE_TXT,
};
use claw_discovery::dnssd::name::Name;
use claw_discovery::dnssd::service::{
    SHARED_RECORD_TTL, ServiceAdvertisement, UNIQUE_RECORD_TTL, addresses_for, browse_query,
    resolve_instance_conflict, resolve_services,
};
use claw_discovery::dnssd::txt::TxtRecord;
use claw_discovery::dnssd::{DnsSdError, TxtValue};

fn gateway_txt() -> TxtRecord {
    let mut txt = TxtRecord::new();
    txt.push_pair("protocol", b"gta-claw/1").expect("protocol");
    txt.push_pair("deviceId", b"cell-a").expect("deviceId");
    txt
}

fn gateway_advertisement() -> ServiceAdvertisement {
    ServiceAdvertisement {
        instance: "studio".to_owned(),
        service_type: Name::parse("_openclaw-gw._tcp.local.").expect("service type"),
        host: Name::parse("studio.local.").expect("host"),
        port: 4711,
        priority: 0,
        weight: 0,
        txt: gateway_txt(),
        addresses: vec![
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x11)),
        ],
    }
}

/// The exact bytes RFC 6762 and RFC 6763 require for the announcement above.
///
/// Offsets referenced by the compression pointers, counted from the first byte
/// of the message:
///
/// * 12  — `_openclaw-gw._tcp.local.`
/// * 30  — `local.`
/// * 47  — `studio._openclaw-gw._tcp.local.`
/// * 136 — `studio.local.`
fn pinned_announcement() -> Vec<u8> {
    let mut wire = Vec::new();
    // Header: id 0, QR|AA, 0 questions, 5 answers, 0 authority, 0 additional.
    wire.extend_from_slice(&[
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
    ]);

    // Answer 1, offset 12: shared browse PTR, no cache-flush bit, TTL 4500.
    wire.extend_from_slice(b"\x0c_openclaw-gw\x04_tcp\x05local\x00");
    wire.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x09]);
    // rdata at offset 47: `studio` then a pointer back to offset 12.
    wire.extend_from_slice(b"\x06studio");
    wire.extend_from_slice(&[0xc0, 0x0c]);

    // Answer 2: unique SRV, cache-flush bit set, TTL 120, owner is offset 47.
    wire.extend_from_slice(&[0xc0, 0x2f]);
    wire.extend_from_slice(&[0x00, 0x21, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x14]);
    // priority 0, weight 0, port 4711, then an uncompressed SRV target as
    // RFC 2782 requires.
    wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x12, 0x67]);
    wire.extend_from_slice(b"\x06studio\x05local\x00");

    // Answer 3: unique TXT, cache-flush bit set, TTL 120.
    wire.extend_from_slice(&[0xc0, 0x2f]);
    wire.extend_from_slice(&[0x00, 0x10, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x24]);
    wire.push(19);
    wire.extend_from_slice(b"protocol=gta-claw/1");
    wire.push(15);
    wire.extend_from_slice(b"deviceId=cell-a");

    // Answer 4, owner recorded at offset 136: A, cache-flush bit set, TTL 120.
    wire.extend_from_slice(b"\x06studio");
    wire.extend_from_slice(&[0xc0, 0x1e]);
    wire.extend_from_slice(&[0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04]);
    wire.extend_from_slice(&[192, 0, 2, 11]);

    // Answer 5: AAAA for the same owner, now compressed to offset 136.
    wire.extend_from_slice(&[0xc0, 0x88]);
    wire.extend_from_slice(&[0x00, 0x1c, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x10]);
    wire.extend_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x11,
    ]);
    wire
}

/// A hand-assembled wide-area DNS-SD answer for the zone `claw.example.`.
///
/// Offsets referenced by the compression pointers:
///
/// * 12 — `_openclaw-gw._tcp.claw.example.`
/// * 30 — `claw.example.`
/// * 35 — `example.`
/// * 60 — `edge._openclaw-gw._tcp.claw.example.`
/// * 85 — `gw1.claw.example.`
///
/// The last additional record is a deliberately poisoned `A` for
/// `evil.example.`, which shares the parent of the queried zone but is not
/// inside it.
fn pinned_wide_area_answer() -> Vec<u8> {
    let mut wire = Vec::new();
    // Header: id 0x04d2, QR|RD|RA, 1 question, 1 answer, 0 authority,
    // 5 additional.
    wire.extend_from_slice(&[
        0x04, 0xd2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05,
    ]);

    // Question at offset 12: PTR for the browsed service type.
    wire.extend_from_slice(b"\x0c_openclaw-gw\x04_tcp\x04claw\x07example\x00");
    wire.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]);

    // Answer: PTR to the instance, rdata at offset 60.
    wire.extend_from_slice(&[0xc0, 0x0c]);
    wire.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x07]);
    wire.extend_from_slice(b"\x04edge");
    wire.extend_from_slice(&[0xc0, 0x0c]);

    // Additional 1: SRV, priority 10, weight 5, port 8443, target recorded at
    // offset 85.
    wire.extend_from_slice(&[0xc0, 0x3c]);
    wire.extend_from_slice(&[0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x0c]);
    wire.extend_from_slice(&[0x00, 0x0a, 0x00, 0x05, 0x20, 0xfb]);
    wire.extend_from_slice(b"\x03gw1");
    wire.extend_from_slice(&[0xc0, 0x1e]);

    // Additional 2: TXT.
    wire.extend_from_slice(&[0xc0, 0x3c]);
    wire.extend_from_slice(&[0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x1e]);
    wire.push(19);
    wire.extend_from_slice(b"protocol=gta-claw/1");
    wire.push(9);
    wire.extend_from_slice(b"region=eu");

    // Additional 3: A for gw1.claw.example.
    wire.extend_from_slice(&[0xc0, 0x55]);
    wire.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04]);
    wire.extend_from_slice(&[203, 0, 113, 7]);

    // Additional 4: AAAA for gw1.claw.example.
    wire.extend_from_slice(&[0xc0, 0x55]);
    wire.extend_from_slice(&[0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x10]);
    wire.extend_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07,
    ]);

    // Additional 5: the poison. `evil.example.` is outside `claw.example.`.
    wire.extend_from_slice(b"\x04evil");
    wire.extend_from_slice(&[0xc0, 0x23]);
    wire.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04]);
    wire.extend_from_slice(&[198, 51, 100, 66]);
    wire
}

#[test]
fn mdns_advertisement_matches_the_pinned_wire_bytes() {
    let announcement = gateway_advertisement()
        .announcement()
        .expect("build announcement");
    let encoded = announcement.encode().expect("encode announcement");
    assert_eq!(
        encoded,
        pinned_announcement(),
        "announcement diverged from the pinned RFC 6762 wire form"
    );

    // The pinned bytes and the structural contract must agree, so a future
    // change cannot satisfy one and quietly break the other.
    assert_eq!(announcement.flags, FLAG_RESPONSE | FLAG_AUTHORITATIVE);
    assert_eq!(announcement.answers.len(), 5);

    let ptr = &announcement.answers[0];
    assert_eq!(ptr.record_type(), TYPE_PTR);
    assert_eq!(ptr.ttl, SHARED_RECORD_TTL);
    assert!(
        !ptr.cache_flush,
        "the browse PTR is a shared record, so it must not claim the cache-flush bit"
    );
    assert_eq!(ptr.class, CLASS_IN);

    for record in &announcement.answers[1..] {
        assert!(
            record.cache_flush,
            "record type {} is unique to the instance and must set the cache-flush bit",
            record.record_type()
        );
        assert_eq!(record.ttl, UNIQUE_RECORD_TTL);
    }
    assert_eq!(announcement.answers[1].record_type(), TYPE_SRV);
    assert_eq!(announcement.answers[2].record_type(), TYPE_TXT);
    assert_eq!(announcement.answers[3].record_type(), TYPE_A);
    assert_eq!(announcement.answers[4].record_type(), TYPE_AAAA);

    // The cache-flush bit lives in the class field on the wire, so a decoder
    // that ignored it would report class 0x8001 instead of IN.
    let decoded = Message::decode(&encoded).expect("decode announcement");
    assert_eq!(decoded, announcement);
    assert!(decoded.answers[1].cache_flush);
    assert_eq!(decoded.answers[1].class, CLASS_IN);
}

#[test]
fn goodbye_announcement_zeroes_every_ttl_and_keeps_the_records() {
    let advertisement = gateway_advertisement();
    let announcement = advertisement.announcement().expect("announcement");
    let goodbye = advertisement.goodbye().expect("goodbye");

    assert_eq!(goodbye.answers.len(), announcement.answers.len());
    for (live, dead) in announcement.answers.iter().zip(goodbye.answers.iter()) {
        assert_eq!(live.name, dead.name);
        assert_eq!(live.data, dead.data);
        assert_eq!(live.cache_flush, dead.cache_flush);
        assert_eq!(dead.ttl, 0, "a goodbye record must carry TTL 0");
    }

    // A goodbye must not be readable as a live answer, or a browser would
    // resolve an instance that just withdrew itself.
    let service_type = Name::parse("_openclaw-gw._tcp.local.").expect("type");
    let zone = Name::parse("local.").expect("zone");
    let resolved = resolve_services(&goodbye, &service_type, &zone).expect("resolve goodbye");
    assert!(
        resolved.is_empty(),
        "a TTL 0 goodbye must not resolve to a live instance"
    );
}

#[test]
fn browse_query_matches_the_pinned_wire_bytes() {
    let service_type = Name::parse("_openclaw-gw._tcp.local.").expect("type");

    let multicast = browse_query(&service_type, false)
        .encode()
        .expect("encode multicast query");
    let mut expected = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    expected.extend_from_slice(b"\x0c_openclaw-gw\x04_tcp\x05local\x00");
    expected.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]);
    assert_eq!(multicast, expected);

    // The QU bit is the top bit of the question class, so only the last byte
    // pair changes.
    let unicast = browse_query(&service_type, true)
        .encode()
        .expect("encode unicast query");
    let mut expected_unicast = expected.clone();
    let last = expected_unicast.len() - 2;
    expected_unicast[last..].copy_from_slice(&[0x80, 0x01]);
    assert_eq!(unicast, expected_unicast);

    let decoded = Message::decode(&unicast).expect("decode");
    assert!(decoded.questions[0].unicast_response);
    assert_eq!(decoded.questions[0].query_class, CLASS_IN);
    assert!(!decoded.is_response());
}

#[test]
fn wide_area_answer_resolves_the_pinned_srv_txt_and_address_chain() {
    let wire = pinned_wide_area_answer();
    let message = Message::decode(&wire).expect("decode wide-area answer");
    let service_type = Name::parse("_openclaw-gw._tcp.claw.example.").expect("type");
    let zone = Name::parse("claw.example.").expect("zone");

    let resolved = resolve_services(&message, &service_type, &zone).expect("resolve");
    assert_eq!(resolved.len(), 1);
    let service = &resolved[0];
    assert_eq!(service.instance_label, "edge");
    assert_eq!(
        service.instance.to_string(),
        "edge._openclaw-gw._tcp.claw.example."
    );
    assert_eq!(service.host.to_string(), "gw1.claw.example.");
    assert_eq!(service.port, 8443);
    assert_eq!(service.priority, 10);
    assert_eq!(service.weight, 5);
    assert_eq!(
        service.addresses,
        vec![
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 7)),
        ],
        "IPv4 must precede IPv6 and the poisoned address must not appear"
    );
    assert_eq!(
        service
            .txt
            .get("protocol")
            .and_then(|value| value.as_text().map(str::to_owned)),
        Some("gta-claw/1".to_owned())
    );
    assert_eq!(
        service
            .txt
            .get("region")
            .and_then(|value| value.as_text().map(str::to_owned)),
        Some("eu".to_owned())
    );

    // Re-decoding the encoder's own output must reproduce the identical
    // message, which proves every compression pointer in the fixture was read
    // at the offset the fixture states.
    let reencoded = message.encode().expect("re-encode");
    assert_eq!(Message::decode(&reencoded).expect("re-decode"), message);

    // The fixture compresses the SRV target, as a real recursive resolver does;
    // this encoder deliberately does not, because RFC 2782 tells a sender to
    // emit the target uncompressed. Both must decode to the same name, and the
    // asymmetry is pinned here so it cannot be mistaken for a codec bug.
    assert!(
        wire.windows(6).any(|window| window == b"\x03gw1\xc0\x1e"),
        "the fixture must carry a compressed SRV target"
    );
    assert!(
        reencoded
            .windows(18)
            .any(|window| window == b"\x03gw1\x04claw\x07example\x00"),
        "this encoder must emit the SRV target uncompressed"
    );
}

#[test]
fn wide_area_poisoned_additional_record_is_never_consulted() {
    let message = Message::decode(&pinned_wide_area_answer()).expect("decode");
    let zone = Name::parse("claw.example.").expect("zone");
    let poison = Name::parse("evil.example.").expect("poison owner");

    // The record is present in the message.
    assert!(
        message.records().iter().any(|record| record.name == poison),
        "fixture must actually carry the poisoned record"
    );
    // It is never consulted, because it lives outside the queried zone.
    assert!(
        addresses_for(&message, &poison, &zone).is_empty(),
        "an out-of-bailiwick owner must resolve to no addresses"
    );

    // Reaching the same record through the parent zone would defeat the point,
    // so browsing `example.` must be refused rather than widened.
    let parent = Name::parse("example.").expect("parent");
    let service_type = Name::parse("_openclaw-gw._tcp.claw.example.").expect("type");
    let widened = resolve_services(&message, &service_type, &parent).expect("resolve in parent");
    assert_eq!(widened.len(), 1);
    assert!(
        !widened[0]
            .addresses
            .contains(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 66))),
        "the poison is owned by evil.example., never by the SRV target"
    );
}

#[test]
fn srv_target_outside_the_queried_zone_fails_closed() {
    let service_type = Name::parse("_openclaw-gw._tcp.claw.example.").expect("type");
    let zone = Name::parse("claw.example.").expect("zone");
    let instance = service_type.prepend(b"edge".to_vec()).expect("instance");
    let outside = Name::parse("gw1.evil.example.").expect("outside host");

    let message = Message {
        id: 0,
        flags: FLAG_RESPONSE,
        questions: Vec::new(),
        answers: vec![
            claw_discovery::dnssd::ResourceRecord {
                name: service_type.clone(),
                class: CLASS_IN,
                cache_flush: false,
                ttl: 3600,
                data: RecordData::Ptr(instance.clone()),
            },
            claw_discovery::dnssd::ResourceRecord {
                name: instance.clone(),
                class: CLASS_IN,
                cache_flush: false,
                ttl: 3600,
                data: RecordData::Srv {
                    priority: 0,
                    weight: 0,
                    port: 443,
                    target: outside.clone(),
                },
            },
            claw_discovery::dnssd::ResourceRecord {
                name: instance,
                class: CLASS_IN,
                cache_flush: false,
                ttl: 3600,
                data: RecordData::Txt(gateway_txt()),
            },
        ],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    let error = resolve_services(&message, &service_type, &zone).expect_err("must fail closed");
    assert_eq!(error, DnsSdError::OutOfBailiwick(outside.to_string()));
    assert!(
        error.to_string().contains("outside the queried zone"),
        "the refusal must name its reason, got {error}"
    );
}

#[test]
fn ptr_target_that_leaves_the_service_type_fails_closed() {
    let service_type = Name::parse("_openclaw-gw._tcp.claw.example.").expect("type");
    let zone = Name::parse("claw.example.").expect("zone");
    let foreign = Name::parse("edge._other._tcp.claw.example.").expect("foreign instance");

    let message = Message {
        id: 0,
        flags: FLAG_RESPONSE,
        questions: Vec::new(),
        answers: vec![claw_discovery::dnssd::ResourceRecord {
            name: service_type.clone(),
            class: CLASS_IN,
            cache_flush: false,
            ttl: 3600,
            data: RecordData::Ptr(foreign.clone()),
        }],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    assert_eq!(
        resolve_services(&message, &service_type, &zone),
        Err(DnsSdError::OutOfBailiwick(foreign.to_string()))
    );
}

#[test]
fn resolution_requires_a_response_and_a_complete_chain() {
    let service_type = Name::parse("_openclaw-gw._tcp.claw.example.").expect("type");
    let zone = Name::parse("claw.example.").expect("zone");
    let instance = service_type.prepend(b"edge".to_vec()).expect("instance");

    let mut message = Message::decode(&pinned_wide_area_answer()).expect("decode");
    message.flags &= !FLAG_RESPONSE;
    assert_eq!(
        resolve_services(&message, &service_type, &zone),
        Err(DnsSdError::NotAResponse)
    );

    // A PTR with no SRV names an instance that cannot be reached.
    let ptr_only = Message {
        id: 0,
        flags: FLAG_RESPONSE,
        questions: Vec::new(),
        answers: vec![claw_discovery::dnssd::ResourceRecord {
            name: service_type.clone(),
            class: CLASS_IN,
            cache_flush: false,
            ttl: 3600,
            data: RecordData::Ptr(instance.clone()),
        }],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    assert_eq!(
        resolve_services(&ptr_only, &service_type, &zone),
        Err(DnsSdError::MissingRecord(instance.to_string(), TYPE_SRV))
    );
}

#[test]
fn conflicting_srv_records_for_one_instance_fail_closed() {
    let service_type = Name::parse("_openclaw-gw._tcp.claw.example.").expect("type");
    let zone = Name::parse("claw.example.").expect("zone");
    let instance = service_type.prepend(b"edge".to_vec()).expect("instance");
    let host = Name::parse("gw1.claw.example.").expect("host");

    let srv = |port: u16| claw_discovery::dnssd::ResourceRecord {
        name: instance.clone(),
        class: CLASS_IN,
        cache_flush: false,
        ttl: 3600,
        data: RecordData::Srv {
            priority: 0,
            weight: 0,
            port,
            target: host.clone(),
        },
    };
    let message = Message {
        id: 0,
        flags: FLAG_RESPONSE,
        questions: Vec::new(),
        answers: vec![
            claw_discovery::dnssd::ResourceRecord {
                name: service_type.clone(),
                class: CLASS_IN,
                cache_flush: false,
                ttl: 3600,
                data: RecordData::Ptr(instance.clone()),
            },
            srv(443),
            srv(8443),
        ],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    assert_eq!(
        resolve_services(&message, &service_type, &zone),
        Err(DnsSdError::ConflictingRecords(
            instance.to_string(),
            TYPE_SRV
        ))
    );
}

#[test]
fn compression_pointer_that_does_not_point_backwards_is_refused() {
    let mut wire = vec![
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    // A name at offset 12 whose only element is a pointer to itself.
    wire.extend_from_slice(&[0xc0, 0x0c]);
    wire.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00]);
    assert_eq!(Message::decode(&wire), Err(DnsSdError::BadPointer));

    // A pointer that jumps forward is equally refused, because forward jumps are
    // what let an attacker build an unbounded expansion.
    let mut forward = vec![
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    forward.extend_from_slice(&[0xc0, 0x14]);
    forward.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00]);
    forward.extend_from_slice(b"\x05local\x00");
    assert_eq!(Message::decode(&forward), Err(DnsSdError::BadPointer));

    // A two-pointer cycle, 14 -> 12 -> 14, is refused on the forward hop.
    let mut cycle = vec![
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    cycle.extend_from_slice(&[0xc0, 0x0e, 0xc0, 0x0c]);
    cycle.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00]);
    assert_eq!(Message::decode(&cycle), Err(DnsSdError::BadPointer));
}

#[test]
fn truncated_and_overlong_wire_forms_are_refused() {
    let wire = pinned_announcement();
    for cut in [0usize, 4, 11, 20, 60, 120] {
        assert_eq!(
            Message::decode(&wire[..cut]),
            Err(DnsSdError::Truncated),
            "a {cut}-byte prefix must not decode"
        );
    }

    let mut trailing = wire.clone();
    trailing.push(0x00);
    assert_eq!(Message::decode(&trailing), Err(DnsSdError::TrailingBytes));

    // A record that claims more rdata than the buffer holds must not be read
    // past the end.
    let mut overlong = wire.clone();
    let rdlen = overlong.len() - 18;
    overlong[rdlen] = 0xff;
    assert_eq!(Message::decode(&overlong), Err(DnsSdError::Truncated));
}

#[test]
fn label_and_name_length_ceilings_are_enforced() {
    let long_label = "a".repeat(64);
    assert_eq!(Name::parse(&long_label), Err(DnsSdError::LabelTooLong(64)));
    assert!(Name::parse(&"a".repeat(63)).is_ok());

    // Three 63-byte labels encode to 193 bytes and a fourth pushes past 255.
    let label = "b".repeat(63);
    let within = [label.as_str(); 3].join(".");
    assert_eq!(Name::parse(&within).expect("within").encoded_len(), 193);
    let beyond = [label.as_str(); 4].join(".");
    assert_eq!(Name::parse(&beyond), Err(DnsSdError::NameTooLong(257)));

    // The exact 255-byte boundary is accepted, one byte past it is not.
    let exact = format!("{within}.{}", "c".repeat(61));
    assert_eq!(Name::parse(&exact).expect("exact").encoded_len(), 255);
    let over = format!("{within}.{}", "c".repeat(62));
    assert_eq!(Name::parse(&over), Err(DnsSdError::NameTooLong(256)));

    assert_eq!(Name::parse("a..b"), Err(DnsSdError::EmptyLabel));
    assert_eq!(Name::parse("a\\"), Err(DnsSdError::BadEscape));
    assert_eq!(Name::parse("a\\12"), Err(DnsSdError::BadEscape));
    assert_eq!(Name::parse("a\\1x5"), Err(DnsSdError::BadEscape));
    assert_eq!(Name::parse("a\\300"), Err(DnsSdError::BadEscape));
}

#[test]
fn instance_label_with_a_dot_is_escaped_rather_than_split() {
    let advertisement = ServiceAdvertisement {
        instance: "Jason's Mac 2.0".to_owned(),
        ..gateway_advertisement()
    };
    let instance = advertisement.instance_name().expect("instance name");

    assert_eq!(
        instance.label_count(),
        4,
        "the instance must stay a single label"
    );
    assert_eq!(instance.labels()[0], b"Jason's Mac 2.0");
    assert_eq!(
        instance.to_string(),
        "Jason's Mac 2\\.0._openclaw-gw._tcp.local."
    );

    // The presentation form must parse back to the identical labels, otherwise
    // an operator copying a name out of a log would address a different service.
    let reparsed = Name::parse(&instance.to_string()).expect("reparse");
    assert_eq!(reparsed, instance);

    // The wire form carries the dot as an ordinary byte inside one label.
    let wire = advertisement
        .announcement()
        .expect("announce")
        .encode()
        .expect("encode");
    assert!(
        wire.windows(16)
            .any(|window| window == b"\x0fJason's Mac 2.0"),
        "the instance label must appear length-prefixed and unsplit on the wire"
    );

    // Sixty-four UTF-8 bytes cannot fit one label, so the advertisement is
    // refused rather than silently truncated.
    let oversized = ServiceAdvertisement {
        instance: "é".repeat(32),
        ..gateway_advertisement()
    };
    assert_eq!(oversized.instance_name(), Err(DnsSdError::LabelTooLong(64)));
}

#[test]
fn txt_record_honours_the_rfc6763_key_value_contract() {
    let mut txt = TxtRecord::new();
    txt.push_pair("protocol", b"gta-claw/1").expect("pair");
    txt.push_flag("secure").expect("flag");
    txt.push_pair("note", b"").expect("empty");
    txt.push_pair("protocol", b"shadowed").expect("duplicate");

    assert_eq!(
        txt.get("protocol"),
        Some(TxtValue::Present(b"gta-claw/1".to_vec())),
        "the first occurrence of a key wins and a later duplicate is ignored"
    );
    // Keys are case-insensitive, values are not.
    assert_eq!(txt.get("PROTOCOL"), txt.get("protocol"));
    assert_eq!(txt.get("secure"), Some(TxtValue::Boolean));
    assert_eq!(txt.get("note"), Some(TxtValue::Empty));
    assert_eq!(txt.get("missing"), None);
    assert_eq!(txt.keys(), vec!["protocol", "secure", "note"]);

    // A boolean key and an empty-valued key are different bytes on the wire and
    // must not collapse into each other.
    let encoded = txt.encode();
    let decoded = TxtRecord::decode(&encoded).expect("decode");
    assert_eq!(decoded, txt);
    assert_ne!(decoded.get("secure"), decoded.get("note"));

    // An empty record is one zero-length string, never zero rdata bytes.
    assert_eq!(TxtRecord::new().encode(), vec![0u8]);
    assert_eq!(TxtRecord::decode(&[0]), Ok(TxtRecord::new()));
    assert_eq!(TxtRecord::decode(&[]), Err(DnsSdError::EmptyTxtRdata));
    assert_eq!(TxtRecord::decode(&[5, b'a']), Err(DnsSdError::Truncated));

    let mut oversized = TxtRecord::new();
    assert_eq!(
        oversized.push_pair("k", vec![b'v'; 255]),
        Err(DnsSdError::CharacterStringTooLong(257))
    );
    assert_eq!(
        oversized.push_pair("bad=key", b"v"),
        Err(DnsSdError::InvalidTxtKey("bad=key".to_owned()))
    );
    assert_eq!(
        oversized.push_pair("", b"v"),
        Err(DnsSdError::InvalidTxtKey(String::new()))
    );
    assert_eq!(
        oversized.push_pair("tab\there", b"v"),
        Err(DnsSdError::InvalidTxtKey("tab\there".to_owned()))
    );
    assert!(
        oversized.push_pair("k", vec![b'v'; 253]).is_ok(),
        "255 bytes exactly must be accepted"
    );
}

#[test]
fn instance_conflict_suffixes_are_deterministic_and_bounded() {
    let taken = vec!["studio".to_owned(), "studio (2)".to_owned()];
    assert_eq!(
        resolve_instance_conflict("studio", &taken, 10).expect("free name"),
        "studio (3)"
    );
    assert_eq!(
        resolve_instance_conflict("studio", &[], 10).expect("free name"),
        "studio"
    );
    // Matching is case-insensitive, as DNS-SD instance comparison is.
    assert_eq!(
        resolve_instance_conflict("Studio", &["STUDIO".to_owned()], 10).expect("free name"),
        "Studio (2)"
    );

    let all_taken: Vec<String> = core::iter::once("studio".to_owned())
        .chain((2..=4).map(|index| format!("studio ({index})")))
        .collect();
    assert_eq!(
        resolve_instance_conflict("studio", &all_taken, 4),
        Err(DnsSdError::NoFreeInstanceName("studio".to_owned()))
    );

    // A candidate that would overflow the 63-byte label is skipped rather than
    // returned, so the caller never receives a name it cannot advertise.
    let long = "c".repeat(63);
    let taken = vec![long.clone()];
    assert_eq!(
        resolve_instance_conflict(&long, &taken, 5),
        Err(DnsSdError::NoFreeInstanceName(long))
    );
}
