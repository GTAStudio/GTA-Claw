//! The five dimensions of `integration.providers`, driven off the frozen data.
//!
//! `compat/upstream/inventories/providers.json` is read here at run time and
//! every assertion below iterates **its** rows, never a list restated in Rust.
//! That is deliberate: a test that walks a hand-copied list proves the list
//! agrees with itself and would pass on an inventory of one row. Iterating the
//! frozen file resists an omission (a row that gains no behaviour fails) and
//! iterating the registry in the same test resists an addition (a provider
//! GTA-Claw invented has no frozen row to match).
//!
//! | required by the ledger | covered by |
//! | --- | --- |
//! | IDs | `every_frozen_identifier_resolves_canonically_and_near_misses_do_not` |
//! | aliases | `no_frozen_identifier_may_be_registered_as_an_alias`, `the_builtin_alias_table_only_names_frozen_identifiers`, `separator_folding_would_merge_distinct_frozen_rows` |
//! | configuration | `every_frozen_provider_is_configurable_exactly_as_its_status_allows`, `every_frozen_provider_configuration_rejects_an_unknown_field`, `the_configuration_fixture_corpus_is_classified_exactly` |
//! | auth | `every_frozen_provider_accepts_exactly_its_declared_auth_modes`, `every_frozen_provider_rejects_a_blank_credential_in_every_secret_bearing_mode` |
//! | capability routing | `capability_routing_serves_every_client_bearing_frozen_provider`, `capability_routing_finds_nothing_when_no_configured_provider_qualifies`, `the_capability_catalogue_covers_the_frozen_inventory_exactly` |
//!
//! Nothing here opens a socket. Every decision under test is a pure function of
//! configuration text plus the frozen inventory.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use claw_provider_sdk::model::{AuthMode, Capability, CapabilitySet};
use claw_providers::alias::{self, AliasConflict, AliasTable, BUILTIN_ALIASES, MatchKind};
use claw_providers::auth::{self, AuthConfig};
use claw_providers::config::{ConfigError, ProviderConfig};
use claw_providers::descriptor::ImplementationStatus;
use claw_providers::registry::ProviderRegistry;
use claw_providers::routing::{self, RouteError, RouteRequest, RoutingTable};
use claw_providers::{PROVIDERS, ProviderDescriptor};
use serde_json::Value;

fn repository_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(relative)
}

fn read_json(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    serde_json::from_slice(bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

/// The frozen inventory rows, as plain string maps.
fn frozen_items() -> Vec<BTreeMap<String, String>> {
    let inventory = read_json(&repository_file(
        "compat/upstream/inventories/providers.json",
    ));
    assert_eq!(inventory["counts"]["total"], 78, "frozen row count");
    inventory["items"]
        .as_array()
        .expect("inventory items")
        .iter()
        .map(|item| {
            item.as_object()
                .expect("item object")
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        value.as_str().expect("string field").to_owned(),
                    )
                })
                .collect()
        })
        .collect()
}

fn frozen_ids() -> Vec<String> {
    frozen_items()
        .into_iter()
        .map(|item| item["id"].clone())
        .collect()
}

fn descriptor_for(id: &str) -> &'static ProviderDescriptor {
    ProviderRegistry::global()
        .get(id)
        .unwrap_or_else(|| panic!("{id} is in the frozen inventory but not in the registry"))
}

/// Renders a credential of `mode` whose every field holds `secret`.
fn credential_json(mode: AuthMode, secret: &str) -> String {
    match mode {
        AuthMode::None => r#"{"mode":"none"}"#.to_owned(),
        AuthMode::ApiKey => format!(r#"{{"mode":"api_key","key":"{secret}"}}"#),
        AuthMode::BearerToken => format!(r#"{{"mode":"bearer_token","token":"{secret}"}}"#),
        AuthMode::OAuthDeviceCode => {
            format!(r#"{{"mode":"oauth_device_code","access_token":"{secret}"}}"#)
        }
        AuthMode::OAuthAuthorizationCode => {
            format!(r#"{{"mode":"oauth_authorization_code","access_token":"{secret}"}}"#)
        }
        AuthMode::AwsSigV4 => format!(
            r#"{{"mode":"aws_sigv4","access_key_id":"{secret}","secret_access_key":"{secret}","region":"{secret}"}}"#
        ),
        AuthMode::GoogleServiceAccount => {
            format!(r#"{{"mode":"google_service_account","service_account_json":"{secret}"}}"#)
        }
        AuthMode::AzureIdentity => format!(r#"{{"mode":"azure_identity","token":"{secret}"}}"#),
    }
}

fn credential(mode: AuthMode, secret: &str) -> AuthConfig {
    serde_json::from_str(&credential_json(mode, secret))
        .unwrap_or_else(|error| panic!("{}: {error}", mode.as_str()))
}

/// A configuration for `id` using its first declared credential mode, with an
/// endpoint supplied only when the registry ships none.
fn configuration_json(descriptor: &ProviderDescriptor) -> String {
    let auth = credential_json(descriptor.auth_modes[0], "s3cret");
    let endpoint = if descriptor.base_url.is_some() {
        String::new()
    } else {
        r#","base-url":"https://endpoint.example/v1""#.to_owned()
    };
    format!(r#"{{"id":"{}","auth":{auth}{endpoint}}}"#, descriptor.id)
}

// ---------------------------------------------------------------- identifiers

#[test]
fn every_frozen_identifier_resolves_canonically_and_near_misses_do_not() {
    let ids = frozen_ids();
    assert_eq!(ids.len(), 78);

    let mut resolved = BTreeSet::new();
    for id in &ids {
        let resolution = alias::resolve(id).unwrap_or_else(|error| panic!("{id}: {error}"));
        assert_eq!(resolution.matched, MatchKind::Canonical, "{id}");
        assert_eq!(resolution.id(), id);
        assert!(!resolution.is_alias(), "{id}");
        resolved.insert(resolution.id().to_owned());

        // Case and surrounding whitespace are forgiven; nothing else is.
        for spelling in [
            id.to_uppercase(),
            format!("  {id}  "),
            format!("\t{}\n", id.to_uppercase()),
        ] {
            let loose = alias::resolve(&spelling).unwrap_or_else(|_| panic!("{spelling:?}"));
            assert_eq!(loose.id(), id, "{spelling:?}");
            assert_eq!(loose.matched, MatchKind::Canonical, "{spelling:?}");
        }

        for near in [
            format!("{id}x"),
            format!("x{id}"),
            format!("{id} {id}"),
            id.replace('-', "_"),
            id.replace('-', ""),
        ] {
            // Some transforms are the identity, and one is another real row:
            // `gmi-cloud` with its hyphen removed *is* `gmicloud`. Skip only
            // those, so the rest are genuine near misses that must not resolve.
            if alias::resolve(&near).is_ok() {
                assert!(
                    ids.contains(&near) || BUILTIN_ALIASES.iter().any(|(a, _)| *a == near),
                    "{near:?} resolves but is neither a frozen id nor a declared alias"
                );
                continue;
            }
            assert!(alias::resolve(&near).is_err(), "{near:?}");
        }
    }

    // Resists omission and addition in both directions.
    let registered: BTreeSet<String> = PROVIDERS
        .iter()
        .map(|descriptor| descriptor.id.to_owned())
        .collect();
    let frozen: BTreeSet<String> = ids.iter().cloned().collect();
    assert_eq!(resolved, frozen);
    assert_eq!(registered, frozen);
    assert_eq!(resolved.len(), 78);
}

#[test]
fn the_capability_catalogue_covers_the_frozen_inventory_exactly() {
    // Requiring nothing selects every registered provider, so this is the
    // catalogue view over the whole inventory, in frozen order.
    let catalogue: Vec<&str> = routing::registered_for(CapabilitySet::EMPTY)
        .iter()
        .map(|descriptor| descriptor.id)
        .collect();
    assert_eq!(catalogue, frozen_ids());
    assert_eq!(catalogue.len(), 78);
}

// --------------------------------------------------------------------- aliases

#[test]
fn no_frozen_identifier_may_be_registered_as_an_alias() {
    // A second name that shadows a real identifier is how a caller ends up at
    // the wrong vendor, so every one of the 78 must be refused as an alias.
    let ids = frozen_ids();
    for id in &ids {
        assert_eq!(
            AliasTable::new(&[(id.as_str(), "openai")]).expect_err(id),
            AliasConflict::ShadowsProvider { alias: id.clone() },
            "{id}"
        );
        // The same holds when the alias is added after valid entries.
        assert_eq!(
            AliasTable::new(&[("harmless-alias", "openai"), (id.as_str(), "anthropic")])
                .expect_err(id)
                .code(),
            "alias_shadows_provider",
            "{id}"
        );
    }
    assert_eq!(ids.len(), 78);
}

#[test]
fn the_builtin_alias_table_only_names_frozen_identifiers() {
    let frozen: BTreeSet<String> = frozen_ids().into_iter().collect();
    let table = AliasTable::builtin();
    assert!(!BUILTIN_ALIASES.is_empty());
    assert_eq!(table.len(), BUILTIN_ALIASES.len());

    for (name, target) in BUILTIN_ALIASES {
        assert!(
            frozen.contains(*target),
            "alias '{name}' targets '{target}', which is not in the frozen inventory"
        );
        assert!(
            !frozen.contains(*name),
            "alias '{name}' shadows a frozen identifier"
        );
        let resolution = table
            .resolve(name)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(resolution.id(), *target, "{name}");
        assert_eq!(resolution.matched, MatchKind::Alias((*name).to_owned()));
        assert!(resolution.is_alias(), "{name}");
        // Aliases are forgiven the same spellings frozen identifiers are.
        assert_eq!(
            table
                .resolve(&format!(" {} ", name.to_uppercase()))
                .unwrap_or_else(|error| panic!("{name}: {error}"))
                .id(),
            *target
        );
    }
}

#[test]
fn separator_folding_would_merge_distinct_frozen_rows() {
    // This is why `alias::normalize` stops at case. The pairs are discovered
    // from the frozen file rather than asserted from memory, so the day
    // upstream adds a third such pair, the expectation below fails loudly and
    // whoever relaxes normalisation has to look at it.
    let ids = frozen_ids();
    let mut folded: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in &ids {
        let key: String = id
            .chars()
            .filter(|character| !matches!(character, '-' | '_' | '.'))
            .collect();
        folded.entry(key).or_default().push(id.clone());
    }
    let collisions: BTreeMap<String, Vec<String>> = folded
        .into_iter()
        .filter(|(_, members)| members.len() > 1)
        .collect();
    assert_eq!(
        collisions,
        BTreeMap::from([
            (
                "gmicloud".to_owned(),
                vec!["gmi-cloud".to_owned(), "gmicloud".to_owned()]
            ),
            (
                "novitaai".to_owned(),
                vec!["novita-ai".to_owned(), "novitaai".to_owned()]
            ),
        ])
    );

    for members in collisions.values() {
        for member in members {
            assert_eq!(alias::resolve(member).expect("resolves").id(), member);
        }
        let first = descriptor_for(&members[0]);
        let second = descriptor_for(&members[1]);
        assert_ne!(first.id, second.id);
        assert_ne!(first.display_name, second.display_name);
    }
}

// --------------------------------------------------------------- configuration

#[test]
fn every_frozen_provider_is_configurable_exactly_as_its_status_allows() {
    let ids = frozen_ids();
    let mut accepted = 0_usize;
    let mut refused_for_want_of_a_client = 0_usize;
    let mut refused_for_want_of_an_endpoint = 0_usize;

    for id in &ids {
        let descriptor = descriptor_for(id);
        let config = ProviderConfig::from_json(&configuration_json(descriptor))
            .unwrap_or_else(|error| panic!("{id}: {error}"));
        assert_eq!(config.id, *id);
        assert!(config.enabled, "{id} defaults to enabled");

        match descriptor.status {
            ImplementationStatus::RegistrationOnly => {
                let error = config.resolve().expect_err(id);
                assert_eq!(error.code(), "no_client", "{id}");
                refused_for_want_of_a_client += 1;
            }
            ImplementationStatus::Implemented | ImplementationStatus::EndpointRequired => {
                let resolved = config
                    .resolve()
                    .unwrap_or_else(|error| panic!("{id}: {error}"));
                assert_eq!(resolved.id(), descriptor.id, "{id}");
                assert_eq!(resolved.via_alias, None, "{id}");
                assert_eq!(resolved.authorization.mode(), descriptor.auth_modes[0]);
                assert!(resolved.headers.is_empty(), "{id}");
                accepted += 1;

                let expected_endpoint = descriptor
                    .base_url
                    .map_or_else(|| "https://endpoint.example/v1".to_owned(), str::to_owned);
                assert_eq!(
                    resolved.base_url.as_str().trim_end_matches('/'),
                    expected_endpoint.trim_end_matches('/'),
                    "{id}"
                );

                // Dropping the endpoint is fatal for exactly the rows that ship
                // no default, and harmless for the rows that do.
                let without_endpoint = ProviderConfig::from_json(&format!(
                    r#"{{"id":"{id}","auth":{}}}"#,
                    credential_json(descriptor.auth_modes[0], "s3cret")
                ))
                .unwrap_or_else(|error| panic!("{id}: {error}"));
                if let Some(default) = descriptor.base_url {
                    assert_eq!(
                        without_endpoint
                            .resolve()
                            .unwrap_or_else(|error| panic!("{id}: {error}"))
                            .base_url
                            .as_str()
                            .trim_end_matches('/'),
                        default.trim_end_matches('/'),
                        "{id}"
                    );
                } else {
                    assert_eq!(
                        without_endpoint.resolve().expect_err(id).code(),
                        "missing_base_url",
                        "{id}"
                    );
                    refused_for_want_of_an_endpoint += 1;
                }
            }
        }
    }

    assert_eq!(accepted + refused_for_want_of_a_client, 78);
    assert_eq!(accepted, 66);
    assert_eq!(refused_for_want_of_a_client, 12);
    assert_eq!(refused_for_want_of_an_endpoint, 38);
}

#[test]
fn every_frozen_provider_configuration_rejects_an_unknown_field() {
    let ids = frozen_ids();
    for id in &ids {
        let descriptor = descriptor_for(id);
        let accepted = configuration_json(descriptor);
        // Splice one unknown key into an otherwise valid document.
        let polluted = format!(
            "{{\"unexpected-key\":true,{}",
            accepted.strip_prefix('{').expect("json object")
        );
        let error = ProviderConfig::from_json(&polluted).expect_err(id);
        assert!(
            error.to_string().contains("unexpected-key"),
            "{id}: {error}"
        );
        // And the document without it still parses, so the rejection is caused
        // by the extra key rather than by the splice.
        assert!(ProviderConfig::from_json(&accepted).is_ok(), "{id}");
    }
    assert_eq!(ids.len(), 78);
}

#[test]
fn the_configuration_fixture_corpus_is_classified_exactly() {
    let corpus = read_json(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("provider-configs.json"),
    );
    let cases = corpus["cases"].as_array().expect("cases");
    assert!(cases.len() >= 30, "the corpus must stay broad");

    let mut names = BTreeSet::new();
    let mut exercised = BTreeSet::new();
    let mut accepted = 0_usize;
    let mut parser_refusals = 0_usize;

    for case in cases {
        let name = case["name"].as_str().expect("name");
        assert!(names.insert(name.to_owned()), "duplicate case '{name}'");
        let json = case["json"].as_str().expect("json");
        let expect = case["expect"].as_str().expect("expect");

        let parsed = ProviderConfig::from_json(json);
        if expect == "rejected_by_parser" {
            assert!(
                parsed.is_err(),
                "'{name}' must not deserialise, but it did: {json}"
            );
            parser_refusals += 1;
            continue;
        }
        let parsed = parsed.unwrap_or_else(|error| panic!("'{name}' must deserialise: {error}"));

        if expect == "accepted" {
            let resolved = parsed
                .resolve()
                .unwrap_or_else(|error| panic!("'{name}' must resolve: {error}"));
            assert_eq!(
                resolved.id(),
                case["resolves_to"].as_str().expect("resolves_to"),
                "{name}"
            );
            assert_eq!(
                resolved.base_url.as_str(),
                case["base_url"].as_str().expect("base_url"),
                "{name}"
            );
            assert_eq!(
                resolved.authorization.mode().as_str(),
                case["auth_mode"].as_str().expect("auth_mode"),
                "{name}"
            );
            assert_eq!(
                resolved.via_alias.as_deref(),
                case["via_alias"].as_str(),
                "{name}"
            );
            accepted += 1;
            continue;
        }

        let error = parsed
            .resolve()
            .expect_err(&format!("'{name}' must be refused with '{expect}'"));
        assert_eq!(error.code(), expect, "{name}: {error}");
        exercised.insert(expect.to_owned());
    }

    assert!(
        accepted >= 10,
        "the corpus must contain working configurations"
    );
    assert!(parser_refusals >= 8, "strict parsing must be exercised");
    let expected: BTreeSet<String> = ConfigError::ALL_CODES
        .iter()
        .map(|code| (*code).to_owned())
        .collect();
    assert_eq!(
        exercised, expected,
        "every refusal code the production error types can return must be \
         exercised by the corpus, and no other code may appear"
    );
}

// ------------------------------------------------------------------------ auth

#[test]
fn every_frozen_provider_accepts_exactly_its_declared_auth_modes() {
    let ids = frozen_ids();
    let mut decisions = 0_usize;
    let mut acceptances = 0_usize;

    for id in &ids {
        let descriptor = descriptor_for(id);
        assert!(!descriptor.auth_modes.is_empty(), "{id}");
        for mode in AuthMode::ALL {
            decisions += 1;
            let offered = credential(mode, "s3cret");
            assert_eq!(offered.mode(), mode);
            match auth::authorize(descriptor, &offered) {
                Ok(authorized) => {
                    assert!(
                        descriptor.auth_modes.contains(&mode),
                        "{id} accepted undeclared mode {mode}"
                    );
                    assert_eq!(authorized.mode(), mode, "{id}");
                    assert_eq!(authorized.provider(), descriptor.id, "{id}");
                    acceptances += 1;
                }
                Err(error) => {
                    assert!(
                        !descriptor.auth_modes.contains(&mode),
                        "{id} refused declared mode {mode}: {error}"
                    );
                    assert_eq!(error.code(), "unsupported_auth_mode", "{id} / {mode}");
                }
            }
        }
    }

    assert_eq!(decisions, 78 * 8);
    // 78 rows declare 82 modes between them: `anthropic`, `codex`,
    // `litellm` and `microsoft-foundry` declare two each.
    assert_eq!(acceptances, 82);

    // The counts above are blind to *which* mode each row declares, so a
    // handful of rows chosen for their variety are pinned by hand. These are
    // restatements of each vendor's documented authentication, not of the
    // table under test.
    let expected: BTreeMap<&str, Vec<AuthMode>> = BTreeMap::from([
        ("openai", vec![AuthMode::BearerToken]),
        (
            "anthropic",
            vec![AuthMode::ApiKey, AuthMode::OAuthAuthorizationCode],
        ),
        ("github-copilot", vec![AuthMode::OAuthDeviceCode]),
        ("amazon-bedrock", vec![AuthMode::AwsSigV4]),
        ("amazon-bedrock-mantle", vec![AuthMode::AwsSigV4]),
        ("anthropic-vertex", vec![AuthMode::GoogleServiceAccount]),
        ("google-vertex", vec![AuthMode::GoogleServiceAccount]),
        ("google", vec![AuthMode::ApiKey]),
        ("google-gemini-cli", vec![AuthMode::OAuthAuthorizationCode]),
        (
            "microsoft-foundry",
            vec![AuthMode::AzureIdentity, AuthMode::ApiKey],
        ),
        (
            "codex",
            vec![AuthMode::OAuthAuthorizationCode, AuthMode::BearerToken],
        ),
        ("litellm", vec![AuthMode::BearerToken, AuthMode::None]),
        ("ollama", vec![AuthMode::None]),
        ("vllm", vec![AuthMode::None]),
        ("qwen-oauth", vec![AuthMode::OAuthAuthorizationCode]),
    ]);
    for (id, modes) in &expected {
        assert_eq!(descriptor_for(id).auth_modes, modes.as_slice(), "{id}");
    }
}

#[test]
fn every_frozen_provider_rejects_a_blank_credential_in_every_secret_bearing_mode() {
    let ids = frozen_ids();
    let mut checked = 0_usize;
    for id in &ids {
        let descriptor = descriptor_for(id);
        for mode in descriptor.auth_modes {
            if *mode == AuthMode::None {
                continue;
            }
            // The last spelling is a JSON escape, so the parsed secret is a
            // real tab and newline rather than the two-character text.
            for blank in ["", "   ", "\\t\\n"] {
                let error = auth::authorize(descriptor, &credential(*mode, blank))
                    .expect_err(&format!("{id} / {mode} / {blank:?}"));
                assert_eq!(error.code(), "missing_credential", "{id} / {mode}");
            }
            // The same mode with material is accepted, so the refusal above is
            // caused by the blank and not by the mode.
            assert!(
                auth::authorize(descriptor, &credential(*mode, "s3cret")).is_ok(),
                "{id} / {mode}"
            );
            checked += 1;
        }
    }
    // 82 declared modes, of which seven are `none` and carry no secret:
    // the six credential-free local runtimes plus `litellm`'s optional mode.
    assert_eq!(checked, 75);
}

// ------------------------------------------------------------ capability routing

#[test]
fn capability_routing_serves_every_client_bearing_frozen_provider() {
    let ids = frozen_ids();
    let mut routed = 0_usize;

    for id in &ids {
        let descriptor = descriptor_for(id);
        if descriptor.is_registration_only() {
            continue;
        }
        let resolved = ProviderConfig::from_json(&configuration_json(descriptor))
            .unwrap_or_else(|error| panic!("{id}: {error}"))
            .resolve()
            .unwrap_or_else(|error| panic!("{id}: {error}"));
        let table = RoutingTable::new(vec![resolved]).expect("one provider");
        assert_eq!(table.len(), 1);

        for capability in descriptor.capabilities.to_vec() {
            let route = table
                .route(&RouteRequest::for_capability(capability))
                .unwrap_or_else(|error| panic!("{id} / {capability}: {error}"));
            assert_eq!(route.id(), descriptor.id, "{id} / {capability}");
            assert_eq!(route.honoured_preference, None);

            let preferred = table
                .route(&RouteRequest::for_capability(capability).preferring(&[descriptor.id]))
                .unwrap_or_else(|error| panic!("{id} / {capability}: {error}"));
            assert_eq!(preferred.id(), descriptor.id);
            assert_eq!(
                preferred.honoured_preference.as_deref(),
                Some(descriptor.id)
            );
        }

        // Anything the descriptor does not advertise routes nowhere, even
        // though the provider is configured and enabled.
        for capability in
            CapabilitySet::from_slice(&Capability::ALL).missing_from(descriptor.capabilities)
        {
            unreachable_capability(&table, capability, descriptor.id);
        }
        routed += 1;
    }
    assert_eq!(routed, 66);
}

fn unreachable_capability(table: &RoutingTable, capability: Capability, id: &str) {
    let error = table
        .route(&RouteRequest::for_capability(capability))
        .unwrap_err();
    assert_eq!(
        error,
        RouteError::NoProviderAvailable {
            required: vec![capability],
            considered: 1,
        },
        "{id} / {capability}"
    );
    assert_eq!(
        table
            .route(&RouteRequest::for_capability(capability).preferring(&[id]))
            .unwrap_err()
            .code(),
        "preference_lacks_capability",
        "{id} / {capability}"
    );
}

#[test]
fn capability_routing_finds_nothing_when_no_configured_provider_qualifies() {
    let empty = RoutingTable::new(Vec::new()).expect("no duplicates");
    assert!(empty.is_empty());
    for capability in Capability::ALL {
        assert_eq!(
            empty
                .route(&RouteRequest::for_capability(capability))
                .unwrap_err(),
            RouteError::NoProviderAvailable {
                required: vec![capability],
                considered: 0,
            },
            "{capability}"
        );
        assert!(
            empty
                .candidates(CapabilitySet::from_slice(&[capability]))
                .is_empty()
        );
    }

    // Every registration-only row is unreachable by construction: it cannot be
    // configured at all, so it can never enter a routing table.
    let mut registration_only = 0_usize;
    for id in frozen_ids() {
        let descriptor = descriptor_for(&id);
        if !descriptor.is_registration_only() {
            continue;
        }
        assert_eq!(
            ProviderConfig::from_json(&configuration_json(descriptor))
                .unwrap_or_else(|error| panic!("{id}: {error}"))
                .resolve()
                .expect_err(&id)
                .code(),
            "no_client",
            "{id}"
        );
        assert!(
            !routing::registered_for(CapabilitySet::from_slice(&[Capability::Completion]))
                .iter()
                .any(|entry| entry.id == descriptor.id),
            "{id} is offered by the catalogue despite having no client"
        );
        registration_only += 1;
    }
    assert_eq!(registration_only, 12);
    assert_eq!(
        routing::registered_for(CapabilitySet::from_slice(&[Capability::Completion])).len(),
        66
    );
}
