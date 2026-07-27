//! Acceptance coverage for `integration.clawhub.lifecycle`.
//!
//! Upstream sources at
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`:
//! `src/plugins/clawhub.ts`, `src/skills/lifecycle/clawhub.ts` and
//! `src/infra/clawhub-install-trust.ts`.
//!
//! Every case runs against the in-memory `StaticRegistry` and
//! `PinnedTrustStore`; the crate has no transport dependency, so no case can
//! reach a real `ClawHub` endpoint.

use std::collections::BTreeSet;

use claw_clients::clawhub::{
    Attestation, ClawHub, ClawHubError, InstallRequest, InvalidPackageName, InvalidVersion,
    PackageName, PinnedTrustStore, PublisherCredentials, PublisherId, Registry, RegistryRejection,
    Release, RiskFlag, StaticRegistry, TrustError, UpdateOutcome, UpdateRequest, Version,
};

const PUBLISHER: &str = "openclaw";
const RIVAL: &str = "rival-publisher";

fn package(value: &str) -> PackageName {
    PackageName::new(value).expect("valid package name")
}

fn version(value: &str) -> Version {
    Version::parse(value).expect("valid version")
}

fn release(
    name: &str,
    version_value: &str,
    publisher: &str,
    summary: &str,
    keywords: &[&str],
    declared_risks: &[RiskFlag],
    attestation: Option<&str>,
) -> Release {
    Release {
        name: package(name),
        version: version(version_value),
        publisher: PublisherId::new(publisher),
        summary: summary.to_owned(),
        keywords: keywords
            .iter()
            .map(|keyword| (*keyword).to_owned())
            .collect(),
        risks: declared_risks.iter().copied().collect(),
        attestation: attestation.map(Attestation::new),
    }
}

fn risks(values: &[RiskFlag]) -> BTreeSet<RiskFlag> {
    values.iter().copied().collect()
}

/// `notes-sync@1.0.0`, trusted and pinned, declaring two risks.
fn notes_sync() -> Release {
    release(
        "notes-sync",
        "1.0.0",
        PUBLISHER,
        "Synchronise notes between devices",
        &["notes", "sync"],
        &[RiskFlag::FilesystemAccess, RiskFlag::NetworkAccess],
        Some("digest-notes-sync-1.0.0"),
    )
}

/// `notes-sync@1.1.0`, adding a third risk the operator has never acknowledged.
fn notes_sync_next() -> Release {
    release(
        "notes-sync",
        "1.1.0",
        PUBLISHER,
        "Synchronise notes between devices",
        &["notes", "sync"],
        &[
            RiskFlag::FilesystemAccess,
            RiskFlag::NetworkAccess,
            RiskFlag::ProcessExecution,
        ],
        Some("digest-notes-sync-1.1.0"),
    )
}

/// `camsnap@2.0.0`, trusted and pinned, declaring one risk.
fn camsnap() -> Release {
    release(
        "camsnap",
        "2.0.0",
        PUBLISHER,
        "Capture a still frame",
        &["camera"],
        &[RiskFlag::ProcessExecution],
        Some("digest-camsnap-2.0.0"),
    )
}

/// `notes-archive@0.4.0` from a publisher the operator does not trust.
fn untrusted_notes() -> Release {
    release(
        "notes-archive",
        "0.4.0",
        RIVAL,
        "Archive notes somewhere",
        &["notes"],
        &[RiskFlag::NetworkAccess],
        Some("digest-notes-archive-0.4.0"),
    )
}

fn trust_store() -> PinnedTrustStore {
    PinnedTrustStore::new()
        .trusting(PublisherId::new(PUBLISHER))
        .pinning(
            package("notes-sync"),
            version("1.0.0"),
            Attestation::new("digest-notes-sync-1.0.0"),
        )
        .pinning(
            package("notes-sync"),
            version("1.1.0"),
            Attestation::new("digest-notes-sync-1.1.0"),
        )
        .pinning(
            package("notes-sync"),
            version("2.0.0"),
            Attestation::new("digest-notes-sync-2.0.0"),
        )
        .pinning(
            package("camsnap"),
            version("2.0.0"),
            Attestation::new("digest-camsnap-2.0.0"),
        )
}

fn populated_hub() -> ClawHub<StaticRegistry, PinnedTrustStore> {
    let registry = StaticRegistry::new()
        .with_release(notes_sync())
        .with_release(camsnap())
        .with_release(untrusted_notes());
    ClawHub::new(registry, trust_store())
}

fn acknowledged_install(name: &str, values: &[RiskFlag]) -> InstallRequest {
    let mut request = InstallRequest::latest(package(name));
    request.acknowledged_risks = risks(values);
    request
}

fn acknowledged_install_exact(name: &str, at: &str, values: &[RiskFlag]) -> InstallRequest {
    let mut request = InstallRequest::exact(package(name), version(at));
    request.acknowledged_risks = risks(values);
    request
}

#[test]
fn package_names_and_versions_reject_malformed_identities() {
    assert_eq!(PackageName::new(""), Err(InvalidPackageName::Empty));
    assert_eq!(
        PackageName::new("1notes"),
        Err(InvalidPackageName::MustStartWithLetter)
    );
    assert_eq!(
        PackageName::new("notes-"),
        Err(InvalidPackageName::TrailingSeparator)
    );
    assert_eq!(
        PackageName::new("notes--sync"),
        Err(InvalidPackageName::RepeatedSeparator)
    );
    assert_eq!(
        PackageName::new("Notes"),
        Err(InvalidPackageName::MustStartWithLetter)
    );
    assert_eq!(
        PackageName::new("notes_sync"),
        Err(InvalidPackageName::UnexpectedCharacter('_'))
    );
    assert_eq!(package("notes-sync").as_str(), "notes-sync");

    assert_eq!(Version::parse("1.0"), Err(InvalidVersion::ComponentCount));
    assert_eq!(Version::parse("1.0.01"), Err(InvalidVersion::LeadingZero));
    assert_eq!(Version::parse("1.0.x"), Err(InvalidVersion::NotANumber));
    assert_eq!(Version::parse("1..0"), Err(InvalidVersion::EmptyComponent));
    assert!(version("1.10.0") > version("1.9.9"));
    assert_eq!(version("1.2.3").to_string(), "1.2.3");
    assert_eq!(Version::new(1, 2, 3), version("1.2.3"));
}

#[test]
fn search_ranks_exact_matches_first_and_never_hides_untrusted_publishers() {
    let hub = populated_hub();

    let hits = hub.search("notes");
    let names = hits
        .iter()
        .map(|hit| hit.release.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["notes-archive", "notes-sync"]);

    let untrusted = hits
        .iter()
        .find(|hit| hit.release.name.as_str() == "notes-archive")
        .expect("untrusted release is listed");
    assert!(!untrusted.is_trusted());
    assert_eq!(
        untrusted.trust,
        Some(TrustError::PublisherNotTrusted(PublisherId::new(RIVAL)))
    );

    let trusted = hits
        .iter()
        .find(|hit| hit.release.name.as_str() == "notes-sync")
        .expect("trusted release is listed");
    assert!(trusted.is_trusted());

    let exact = hub.search("camsnap");
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].release.version, version("2.0.0"));

    assert!(hub.search("no-such-package").is_empty());
    assert_eq!(hub.search("").len(), 3);
}

#[test]
fn install_records_a_trusted_release_after_exact_risk_acknowledgement() {
    let mut hub = populated_hub();
    let request = acknowledged_install(
        "notes-sync",
        &[RiskFlag::FilesystemAccess, RiskFlag::NetworkAccess],
    );

    let installed = hub.install(&request).expect("install is admitted").clone();
    assert_eq!(installed.name, package("notes-sync"));
    assert_eq!(installed.version, version("1.0.0"));
    assert_eq!(installed.publisher, PublisherId::new(PUBLISHER));
    assert_eq!(installed.attestation.as_str(), "digest-notes-sync-1.0.0");
    assert_eq!(
        installed.acknowledged_risks,
        risks(&[RiskFlag::FilesystemAccess, RiskFlag::NetworkAccess])
    );

    assert_eq!(
        hub.install(&request),
        Err(ClawHubError::AlreadyInstalled {
            name: package("notes-sync"),
            version: version("1.0.0"),
        })
    );
    assert_eq!(hub.installed_packages().len(), 1);
}

#[test]
fn install_is_fail_closed_until_the_acknowledged_risks_match_exactly() {
    let mut hub = populated_hub();

    assert_eq!(
        hub.install(&InstallRequest::latest(package("notes-sync"))),
        Err(ClawHubError::RiskNotAcknowledged {
            name: package("notes-sync"),
            version: version("1.0.0"),
            risk: RiskFlag::FilesystemAccess,
        })
    );
    assert_eq!(
        hub.install(&acknowledged_install(
            "notes-sync",
            &[RiskFlag::FilesystemAccess]
        )),
        Err(ClawHubError::RiskNotAcknowledged {
            name: package("notes-sync"),
            version: version("1.0.0"),
            risk: RiskFlag::NetworkAccess,
        })
    );
    assert_eq!(
        hub.install(&acknowledged_install(
            "notes-sync",
            &[
                RiskFlag::FilesystemAccess,
                RiskFlag::NetworkAccess,
                RiskFlag::CredentialAccess,
            ]
        )),
        Err(ClawHubError::RiskNotDeclared {
            name: package("notes-sync"),
            version: version("1.0.0"),
            risk: RiskFlag::CredentialAccess,
        })
    );

    assert_eq!(hub.installed(&package("notes-sync")), None);
    assert!(hub.installed_packages().is_empty());
}

#[test]
fn install_is_fail_closed_on_untrusted_unattested_unpinned_and_mismatched_releases() {
    let mut hub = populated_hub();
    assert_eq!(
        hub.install(&acknowledged_install(
            "notes-archive",
            &[RiskFlag::NetworkAccess]
        )),
        Err(ClawHubError::Untrusted {
            name: package("notes-archive"),
            version: version("0.4.0"),
            reason: TrustError::PublisherNotTrusted(PublisherId::new(RIVAL)),
        })
    );

    let unattested = release(
        "camsnap",
        "3.0.0",
        PUBLISHER,
        "Capture a still frame",
        &["camera"],
        &[RiskFlag::ProcessExecution],
        None,
    );
    let unpinned = release(
        "camsnap",
        "4.0.0",
        PUBLISHER,
        "Capture a still frame",
        &["camera"],
        &[RiskFlag::ProcessExecution],
        Some("digest-camsnap-4.0.0"),
    );
    let mismatched = release(
        "notes-sync",
        "2.0.0",
        PUBLISHER,
        "Synchronise notes between devices",
        &["notes"],
        &[],
        Some("digest-forged"),
    );
    let mut planted = ClawHub::new(
        StaticRegistry::new()
            .with_release(unattested)
            .with_release(unpinned)
            .with_release(mismatched),
        trust_store(),
    );

    assert_eq!(
        planted.install(
            &InstallRequest::exact(package("camsnap"), version("3.0.0"))
                .acknowledging(RiskFlag::ProcessExecution)
        ),
        Err(ClawHubError::Untrusted {
            name: package("camsnap"),
            version: version("3.0.0"),
            reason: TrustError::AttestationMissing,
        })
    );
    assert_eq!(
        planted.install(
            &InstallRequest::exact(package("camsnap"), version("4.0.0"))
                .acknowledging(RiskFlag::ProcessExecution)
        ),
        Err(ClawHubError::Untrusted {
            name: package("camsnap"),
            version: version("4.0.0"),
            reason: TrustError::AttestationUnpinned {
                name: package("camsnap"),
                version: version("4.0.0"),
            },
        })
    );
    assert_eq!(
        planted.install(&InstallRequest::latest(package("notes-sync"))),
        Err(ClawHubError::Untrusted {
            name: package("notes-sync"),
            version: version("2.0.0"),
            reason: TrustError::AttestationMismatch {
                pinned: Attestation::new("digest-notes-sync-2.0.0"),
                offered: Attestation::new("digest-forged"),
            },
        })
    );

    assert!(hub.installed_packages().is_empty());
    assert!(planted.installed_packages().is_empty());
    assert_eq!(
        hub.install(&InstallRequest::latest(package("absent-package"))),
        Err(ClawHubError::PackageNotFound {
            name: package("absent-package"),
        })
    );
    assert_eq!(
        hub.install(&InstallRequest::exact(package("camsnap"), version("9.9.9"))),
        Err(ClawHubError::VersionNotFound {
            name: package("camsnap"),
            version: version("9.9.9"),
        })
    );
}

#[test]
fn update_requires_new_risk_acknowledgement_and_refuses_a_downgrade() {
    let registry = StaticRegistry::new()
        .with_release(notes_sync())
        .with_release(notes_sync_next());
    let mut hub = ClawHub::new(registry, trust_store());
    hub.install(&acknowledged_install_exact(
        "notes-sync",
        "1.0.0",
        &[RiskFlag::FilesystemAccess, RiskFlag::NetworkAccess],
    ))
    .expect("install is admitted");

    let stale = UpdateRequest::latest(package("notes-sync"))
        .acknowledging(RiskFlag::FilesystemAccess)
        .acknowledging(RiskFlag::NetworkAccess);
    assert_eq!(
        hub.update(&stale),
        Err(ClawHubError::RiskNotAcknowledged {
            name: package("notes-sync"),
            version: version("1.1.0"),
            risk: RiskFlag::ProcessExecution,
        })
    );
    assert_eq!(
        hub.installed(&package("notes-sync"))
            .expect("still installed")
            .version,
        version("1.0.0")
    );

    let acknowledged = stale.clone().acknowledging(RiskFlag::ProcessExecution);
    assert_eq!(
        hub.update(&acknowledged),
        Ok(UpdateOutcome::Updated {
            from: version("1.0.0"),
            to: version("1.1.0"),
        })
    );
    let installed = hub
        .installed(&package("notes-sync"))
        .expect("still installed");
    assert_eq!(installed.version, version("1.1.0"));
    assert_eq!(installed.attestation.as_str(), "digest-notes-sync-1.1.0");

    assert_eq!(
        hub.update(&acknowledged),
        Ok(UpdateOutcome::AlreadyCurrent {
            version: version("1.1.0"),
        })
    );

    let downgrade = UpdateRequest::exact(package("notes-sync"), version("1.0.0"))
        .acknowledging(RiskFlag::FilesystemAccess)
        .acknowledging(RiskFlag::NetworkAccess);
    assert_eq!(
        hub.update(&downgrade),
        Err(ClawHubError::DowngradeRejected {
            name: package("notes-sync"),
            installed: version("1.1.0"),
            offered: version("1.0.0"),
        })
    );

    assert_eq!(
        hub.update(&UpdateRequest::latest(package("camsnap"))),
        Err(ClawHubError::NotInstalled {
            name: package("camsnap"),
        })
    );
}

#[test]
fn update_refuses_a_release_published_under_a_different_publisher() {
    let hijacked = release(
        "notes-sync",
        "1.1.0",
        RIVAL,
        "Synchronise notes between devices",
        &["notes"],
        &[RiskFlag::FilesystemAccess, RiskFlag::NetworkAccess],
        Some("digest-notes-sync-1.1.0"),
    );
    let registry = StaticRegistry::new()
        .with_release(notes_sync())
        .with_release(hijacked);
    let mut hub = ClawHub::new(registry, trust_store().trusting(PublisherId::new(RIVAL)));
    hub.install(&acknowledged_install_exact(
        "notes-sync",
        "1.0.0",
        &[RiskFlag::FilesystemAccess, RiskFlag::NetworkAccess],
    ))
    .expect("install is admitted");

    // The rival is trusted and correctly pinned here, so only the publisher
    // recorded at install time can stop the takeover.
    assert_eq!(
        hub.update(
            &UpdateRequest::latest(package("notes-sync"))
                .acknowledging(RiskFlag::FilesystemAccess)
                .acknowledging(RiskFlag::NetworkAccess)
        ),
        Err(ClawHubError::PublisherChanged {
            name: package("notes-sync"),
            installed: PublisherId::new(PUBLISHER),
            offered: PublisherId::new(RIVAL),
        })
    );
    assert_eq!(
        hub.installed(&package("notes-sync"))
            .expect("still installed")
            .version,
        version("1.0.0")
    );
}

#[test]
fn publish_requires_matching_credentials_an_increasing_version_and_an_attestation() {
    let mut hub = ClawHub::new(
        StaticRegistry::new().with_release(notes_sync()),
        trust_store(),
    );
    let owner = PublisherCredentials::authenticated(PublisherId::new(PUBLISHER));
    let rival = PublisherCredentials::authenticated(PublisherId::new(RIVAL));

    assert_eq!(
        hub.publish(&rival, notes_sync_next()),
        Err(ClawHubError::PublisherMismatch {
            authenticated: PublisherId::new(RIVAL),
            release: PublisherId::new(PUBLISHER),
        })
    );
    assert_eq!(
        hub.publish(&owner, notes_sync()),
        Err(ClawHubError::VersionAlreadyPublished {
            name: package("notes-sync"),
            version: version("1.0.0"),
        })
    );

    let older = release(
        "notes-sync",
        "0.9.0",
        PUBLISHER,
        "Synchronise notes between devices",
        &["notes"],
        &[],
        Some("digest-notes-sync-0.9.0"),
    );
    assert_eq!(
        hub.publish(&owner, older),
        Err(ClawHubError::VersionNotIncreasing {
            name: package("notes-sync"),
            latest: version("1.0.0"),
            offered: version("0.9.0"),
        })
    );

    let unattested = Release {
        attestation: None,
        ..notes_sync_next()
    };
    assert_eq!(
        hub.publish(&owner, unattested),
        Err(ClawHubError::Untrusted {
            name: package("notes-sync"),
            version: version("1.1.0"),
            reason: TrustError::AttestationMissing,
        })
    );
    assert_eq!(hub.registry().versions(&package("notes-sync")).len(), 1);

    assert_eq!(hub.publish(&owner, notes_sync_next()), Ok(()));
    let published = hub.registry().versions(&package("notes-sync"));
    assert_eq!(published.len(), 2);
    assert_eq!(published[1].version, version("1.1.0"));

    let mut read_only = ClawHub::new(StaticRegistry::read_only(), trust_store());
    assert_eq!(
        read_only.publish(&owner, notes_sync()),
        Err(ClawHubError::RegistryRejected {
            name: package("notes-sync"),
            reason: RegistryRejection::ReadOnly,
        })
    );
}

#[test]
fn uninstall_removes_only_the_named_package_and_forces_fresh_acknowledgement() {
    let mut hub = populated_hub();
    hub.install(&acknowledged_install(
        "notes-sync",
        &[RiskFlag::FilesystemAccess, RiskFlag::NetworkAccess],
    ))
    .expect("notes-sync install is admitted");
    hub.install(&acknowledged_install(
        "camsnap",
        &[RiskFlag::ProcessExecution],
    ))
    .expect("camsnap install is admitted");
    assert_eq!(hub.installed_packages().len(), 2);

    let removed = hub
        .uninstall(&package("notes-sync"))
        .expect("uninstall removes the package");
    assert_eq!(removed.version, version("1.0.0"));
    assert_eq!(hub.installed(&package("notes-sync")), None);
    assert!(hub.installed(&package("camsnap")).is_some());

    assert_eq!(
        hub.uninstall(&package("notes-sync")),
        Err(ClawHubError::NotInstalled {
            name: package("notes-sync"),
        })
    );

    // Reinstalling starts from zero acknowledgement, not from the removed record.
    assert_eq!(
        hub.install(&InstallRequest::latest(package("notes-sync"))),
        Err(ClawHubError::RiskNotAcknowledged {
            name: package("notes-sync"),
            version: version("1.0.0"),
            risk: RiskFlag::FilesystemAccess,
        })
    );
    hub.install(&acknowledged_install(
        "notes-sync",
        &[RiskFlag::FilesystemAccess, RiskFlag::NetworkAccess],
    ))
    .expect("reinstall with a fresh acknowledgement is admitted");
    assert_eq!(hub.installed_packages().len(), 2);
}

#[test]
fn lifecycle_runs_search_trust_risk_install_update_publish_and_uninstall_end_to_end() {
    let mut hub = ClawHub::new(
        StaticRegistry::new()
            .with_release(notes_sync())
            .with_release(untrusted_notes()),
        trust_store(),
    );
    let owner = PublisherCredentials::authenticated(PublisherId::new(PUBLISHER));

    // Search surfaces both releases and marks the untrusted one.
    let hits = hub.search("notes");
    assert_eq!(hits.len(), 2);
    assert!(hits.iter().any(|hit| !hit.is_trusted()));

    // Trust and risk both gate the install.
    assert!(matches!(
        hub.install(&acknowledged_install(
            "notes-archive",
            &[RiskFlag::NetworkAccess]
        )),
        Err(ClawHubError::Untrusted { .. })
    ));
    assert!(matches!(
        hub.install(&InstallRequest::latest(package("notes-sync"))),
        Err(ClawHubError::RiskNotAcknowledged { .. })
    ));
    hub.install(&acknowledged_install(
        "notes-sync",
        &[RiskFlag::FilesystemAccess, RiskFlag::NetworkAccess],
    ))
    .expect("install is admitted");

    // Publishing the next release makes it available to update.
    assert_eq!(hub.publish(&owner, notes_sync_next()), Ok(()));
    assert_eq!(
        hub.update(
            &UpdateRequest::latest(package("notes-sync"))
                .acknowledging(RiskFlag::FilesystemAccess)
                .acknowledging(RiskFlag::NetworkAccess)
                .acknowledging(RiskFlag::ProcessExecution)
        ),
        Ok(UpdateOutcome::Updated {
            from: version("1.0.0"),
            to: version("1.1.0"),
        })
    );

    let removed = hub
        .uninstall(&package("notes-sync"))
        .expect("uninstall removes the package");
    assert_eq!(removed.version, version("1.1.0"));
    assert!(hub.installed_packages().is_empty());
    // The registry keeps both published releases after the uninstall.
    assert_eq!(hub.registry().versions(&package("notes-sync")).len(), 2);
}
