//! The DNS-SD service layer: advertise, goodbye, browse and resolve.
//!
//! Resolution is where a discovery client is attacked, so [`resolve_services`]
//! never trusts section placement. Every record it consumes must live inside the
//! zone the answer was solicited from, and every hop of the PTR to SRV to TXT to
//! address chain must be owned by the name the previous hop pointed at. An
//! answer that carries an address for a name outside the zone is rejected rather
//! than quietly cached, which is the difference between wide-area DNS-SD and an
//! open cache-poisoning channel.

use std::net::IpAddr;

use super::DnsSdError;
use super::message::{
    CLASS_IN, FLAG_AUTHORITATIVE, FLAG_RESPONSE, Message, Question, RecordData, ResourceRecord,
    TYPE_A, TYPE_ANY, TYPE_PTR, TYPE_SRV, TYPE_TXT,
};
use super::name::Name;
use super::txt::TxtRecord;

/// TTL RFC 6762 section 10 assigns to shared records such as the browse PTR.
pub const SHARED_RECORD_TTL: u32 = 4500;
/// TTL RFC 6762 section 10 assigns to host-name-bearing unique records.
pub const UNIQUE_RECORD_TTL: u32 = 120;

/// Everything needed to announce one service instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceAdvertisement {
    /// Human-readable instance name, unescaped, exactly one DNS label once
    /// encoded.
    pub instance: String,
    /// Service type, for example `_openclaw-gw._tcp.local.`.
    pub service_type: Name,
    /// Host name the instance runs on.
    pub host: Name,
    /// Service port.
    pub port: u16,
    /// SRV priority.
    pub priority: u16,
    /// SRV weight.
    pub weight: u16,
    /// TXT key/value set.
    pub txt: TxtRecord,
    /// Addresses to publish for [`ServiceAdvertisement::host`].
    pub addresses: Vec<IpAddr>,
}

impl ServiceAdvertisement {
    /// Returns the fully qualified service instance name.
    ///
    /// The instance is carried as one label, so a dot inside it is escaped by
    /// [`Name`] rather than splitting the label, per RFC 6763 section 4.3.
    ///
    /// # Errors
    ///
    /// Returns [`DnsSdError::EmptyLabel`] for an empty instance and
    /// [`DnsSdError::LabelTooLong`] when the UTF-8 instance exceeds 63 bytes.
    pub fn instance_name(&self) -> Result<Name, DnsSdError> {
        self.service_type.prepend(self.instance.as_bytes().to_vec())
    }

    /// Builds the authoritative announcement for this instance.
    ///
    /// The shared browse PTR carries no cache-flush bit and the long shared TTL;
    /// the SRV, TXT and address records are unique to this instance, so they
    /// carry the cache-flush bit and the short unique TTL.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`ServiceAdvertisement::instance_name`].
    pub fn announcement(&self) -> Result<Message, DnsSdError> {
        self.announcement_with_ttls(SHARED_RECORD_TTL, UNIQUE_RECORD_TTL)
    }

    /// Builds the goodbye announcement, which is the announcement at TTL zero.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`ServiceAdvertisement::instance_name`].
    pub fn goodbye(&self) -> Result<Message, DnsSdError> {
        self.announcement_with_ttls(0, 0)
    }

    fn announcement_with_ttls(&self, shared: u32, unique: u32) -> Result<Message, DnsSdError> {
        let instance = self.instance_name()?;
        let mut answers = vec![
            ResourceRecord {
                name: self.service_type.clone(),
                class: CLASS_IN,
                cache_flush: false,
                ttl: shared,
                data: RecordData::Ptr(instance.clone()),
            },
            ResourceRecord {
                name: instance.clone(),
                class: CLASS_IN,
                cache_flush: true,
                ttl: unique,
                data: RecordData::Srv {
                    priority: self.priority,
                    weight: self.weight,
                    port: self.port,
                    target: self.host.clone(),
                },
            },
            ResourceRecord {
                name: instance,
                class: CLASS_IN,
                cache_flush: true,
                ttl: unique,
                data: RecordData::Txt(self.txt.clone()),
            },
        ];
        for address in &self.addresses {
            answers.push(ResourceRecord {
                name: self.host.clone(),
                class: CLASS_IN,
                cache_flush: true,
                ttl: unique,
                data: match address {
                    IpAddr::V4(value) => RecordData::A(*value),
                    IpAddr::V6(value) => RecordData::Aaaa(*value),
                },
            });
        }
        Ok(Message {
            id: 0,
            flags: FLAG_RESPONSE | FLAG_AUTHORITATIVE,
            questions: Vec::new(),
            answers,
            authorities: Vec::new(),
            additionals: Vec::new(),
        })
    }
}

/// Builds the browse query for a service type.
///
/// `unicast_response` sets the mDNS QU bit, which a one-shot querier uses to ask
/// for a unicast reply instead of a multicast one.
#[must_use]
pub fn browse_query(service_type: &Name, unicast_response: bool) -> Message {
    Message {
        id: 0,
        flags: 0,
        questions: vec![Question {
            name: service_type.clone(),
            query_type: TYPE_PTR,
            query_class: CLASS_IN,
            unicast_response,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

/// Builds the instance resolution query, which asks for SRV and TXT at once.
#[must_use]
pub fn resolve_query(instance: &Name) -> Message {
    Message {
        id: 0,
        flags: 0,
        questions: vec![Question {
            name: instance.clone(),
            query_type: TYPE_ANY,
            query_class: CLASS_IN,
            unicast_response: false,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

/// One fully resolved service instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedService {
    /// Fully qualified instance name.
    pub instance: Name,
    /// Instance label decoded back to UTF-8 text when possible.
    pub instance_label: String,
    /// SRV target host.
    pub host: Name,
    /// SRV port.
    pub port: u16,
    /// SRV priority.
    pub priority: u16,
    /// SRV weight.
    pub weight: u16,
    /// TXT key/value set.
    pub txt: TxtRecord,
    /// Addresses of [`ResolvedService::host`], IPv4 before IPv6, deduplicated.
    pub addresses: Vec<IpAddr>,
}

/// Resolves every instance of `service_type` carried by `message`.
///
/// `zone` is the bailiwick: the zone the query was sent to. For multicast DNS
/// that is `local.`; for wide-area DNS-SD it is the browsing domain. A record
/// whose owner name is outside `zone` is never consulted, regardless of which
/// section it arrived in.
///
/// # Errors
///
/// Returns [`DnsSdError::NotAResponse`] when the QR bit is clear,
/// [`DnsSdError::OutOfBailiwick`] when the service type itself is outside the
/// zone or a chained record leaves it, [`DnsSdError::MissingRecord`] when the
/// SRV or TXT for a discovered instance is absent, and
/// [`DnsSdError::ConflictingRecords`] when two different SRV or TXT records
/// claim the same instance.
pub fn resolve_services(
    message: &Message,
    service_type: &Name,
    zone: &Name,
) -> Result<Vec<ResolvedService>, DnsSdError> {
    if !message.is_response() {
        return Err(DnsSdError::NotAResponse);
    }
    if !service_type.is_within(zone) {
        return Err(DnsSdError::OutOfBailiwick(service_type.to_string()));
    }
    // A record outside the queried zone is never consulted, whichever section
    // it arrived in, and an expiring record is never used to resolve.
    let usable: Vec<&ResourceRecord> = message
        .records()
        .into_iter()
        .filter(|record| record.name.is_within(zone) && record.ttl > 0)
        .collect();

    let mut instances: Vec<Name> = Vec::new();
    for record in usable.iter() {
        let RecordData::Ptr(target) = &record.data else {
            continue;
        };
        if record.name != *service_type {
            continue;
        }
        if !target.is_within(service_type) || target.label_count() != service_type.label_count() + 1
        {
            return Err(DnsSdError::OutOfBailiwick(target.to_string()));
        }
        if !instances.contains(target) {
            instances.push(target.clone());
        }
    }

    let mut resolved = Vec::with_capacity(instances.len());
    for instance in instances {
        let mut service: Option<(u16, u16, u16, Name)> = None;
        let mut txt: Option<TxtRecord> = None;
        for record in usable.iter() {
            if record.name != instance {
                continue;
            }
            match &record.data {
                RecordData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                } => {
                    let candidate = (*priority, *weight, *port, target.clone());
                    if service.as_ref().is_some_and(|held| *held != candidate) {
                        return Err(DnsSdError::ConflictingRecords(
                            instance.to_string(),
                            TYPE_SRV,
                        ));
                    }
                    service = Some(candidate);
                }
                RecordData::Txt(value) => {
                    if txt.as_ref().is_some_and(|held| held != value) {
                        return Err(DnsSdError::ConflictingRecords(
                            instance.to_string(),
                            TYPE_TXT,
                        ));
                    }
                    txt = Some(value.clone());
                }
                _ => {}
            }
        }
        let (priority, weight, port, host) =
            service.ok_or_else(|| DnsSdError::MissingRecord(instance.to_string(), TYPE_SRV))?;
        let txt = txt.ok_or_else(|| DnsSdError::MissingRecord(instance.to_string(), TYPE_TXT))?;
        if !host.is_within(zone) {
            return Err(DnsSdError::OutOfBailiwick(host.to_string()));
        }

        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for record in usable.iter() {
            if record.name != host {
                continue;
            }
            match &record.data {
                RecordData::A(address) => {
                    let address = IpAddr::V4(*address);
                    if !v4.contains(&address) {
                        v4.push(address);
                    }
                }
                RecordData::Aaaa(address) => {
                    let address = IpAddr::V6(*address);
                    if !v6.contains(&address) {
                        v6.push(address);
                    }
                }
                _ => {}
            }
        }
        if v4.is_empty() && v6.is_empty() {
            return Err(DnsSdError::MissingRecord(host.to_string(), TYPE_A));
        }
        v4.append(&mut v6);

        let instance_label = instance
            .labels()
            .first()
            .map(|label| String::from_utf8_lossy(label).into_owned())
            .unwrap_or_default();
        resolved.push(ResolvedService {
            instance: instance.clone(),
            instance_label,
            host,
            port,
            priority,
            weight,
            txt,
            addresses: v4,
        });
    }
    resolved.sort_by_key(|entry| entry.instance.to_string());
    Ok(resolved)
}

/// Returns the addresses `message` publishes for `host`, in bailiwick order.
///
/// Provided so a caller can prove that an out-of-zone address record was never
/// consulted, without going through a full resolution.
#[must_use]
pub fn addresses_for(message: &Message, host: &Name, zone: &Name) -> Vec<IpAddr> {
    if !host.is_within(zone) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for record in message.records() {
        if record.name != *host || record.ttl == 0 || !record.name.is_within(zone) {
            continue;
        }
        match &record.data {
            RecordData::A(address) => out.push(IpAddr::V4(*address)),
            RecordData::Aaaa(address) => out.push(IpAddr::V6(*address)),
            _ => {}
        }
    }
    out
}

/// Applies the RFC 6763 section 9 conflict suffix to an instance name.
///
/// The first taken name becomes `name (2)`, then `name (3)`, and so on. The
/// search is deterministic and bounded, and it never returns a label that would
/// exceed the 63-byte limit once appended.
///
/// # Errors
///
/// Returns [`DnsSdError::NoFreeInstanceName`] when every candidate up to
/// `limit` is taken or would overflow the label.
pub fn resolve_instance_conflict(
    desired: &str,
    taken: &[String],
    limit: u32,
) -> Result<String, DnsSdError> {
    let is_free = |candidate: &str| {
        !taken
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(candidate))
    };
    if desired.len() <= super::name::MAX_LABEL_BYTES && is_free(desired) {
        return Ok(desired.to_owned());
    }
    for index in 2..=limit {
        let candidate = format!("{desired} ({index})");
        if candidate.len() <= super::name::MAX_LABEL_BYTES && is_free(&candidate) {
            return Ok(candidate);
        }
    }
    Err(DnsSdError::NoFreeInstanceName(desired.to_owned()))
}
