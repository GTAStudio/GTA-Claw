use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};

use claw_protocol::native_accounting::AccountingRound;
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{ParseFailure, RenderedResult};

const MAX_RATE_BYTES: usize = 64 * 1024;
const MAX_RATE: u64 = 1_000_000_000_000;
const AMOUNT_SCALE: u128 = 1_000_000_000_000;

pub(super) struct EstimateCommand {
    source: PathBuf,
    rates: PathBuf,
    source_sha256: String,
    rates_sha256: String,
}

pub(super) fn parse(arguments: &[OsString]) -> Result<EstimateCommand, ParseFailure> {
    let invalid = || {
        super::parse_failure(
            "expected accounting estimate --source <local-export> --rates <local-rate-card> --expected-sha256 <source-sha256> --rates-sha256 <rate-card-sha256>",
            arguments,
        )
    };
    if arguments.get(1).and_then(|argument| argument.to_str()) != Some("estimate") {
        return Err(invalid());
    }
    let mut source = None;
    let mut rates = None;
    let mut source_sha256 = None;
    let mut rates_sha256 = None;
    let mut json_seen = false;
    let mut index = 2;
    while index < arguments.len() {
        if arguments[index] == "--json" && !json_seen {
            json_seen = true;
            index += 1;
            continue;
        }
        let value = arguments.get(index + 1).ok_or_else(invalid)?;
        match arguments[index].to_str() {
            Some("--source") if source.is_none() => source = Some(PathBuf::from(value)),
            Some("--rates") if rates.is_none() => rates = Some(PathBuf::from(value)),
            Some("--expected-sha256") if source_sha256.is_none() => {
                source_sha256 = value.to_str().map(str::to_owned);
            }
            Some("--rates-sha256") if rates_sha256.is_none() => {
                rates_sha256 = value.to_str().map(str::to_owned);
            }
            _ => return Err(invalid()),
        }
        index += 2;
    }
    let source = source
        .filter(|path| super::state_snapshot::local_absolute(path))
        .ok_or_else(invalid)?;
    let rates = rates
        .filter(|path| super::state_snapshot::local_absolute(path))
        .ok_or_else(invalid)?;
    if source == rates {
        return Err(invalid());
    }
    Ok(EstimateCommand {
        source,
        rates,
        source_sha256: source_sha256
            .filter(|value| valid_digest(value))
            .ok_or_else(invalid)?,
        rates_sha256: rates_sha256
            .filter(|value| valid_digest(value))
            .ok_or_else(invalid)?,
    })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn read_verified(
    path: &Path,
    expected: &str,
    max_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let (root, relative) = super::state_snapshot::pinned_parent(path)?;
    let resolved = root
        .resolve_file(&relative)
        .map_err(|_| "accounting input file is absent or unsafe")?;
    #[cfg(windows)]
    let file = root
        .open_read_exclusive(&resolved)
        .map_err(|_| "accounting input file is unsafe or in use")?;
    #[cfg(not(windows))]
    let file = root
        .open_no_follow(&resolved)
        .map_err(|_| "accounting input file cannot be opened safely")?;
    if file
        .metadata()
        .map_err(|_| "accounting input metadata is unavailable")?
        .len()
        > max_bytes
    {
        return Err("accounting input exceeds its byte limit");
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "accounting input read failed")?;
    if bytes.len() as u64 > max_bytes || digest(&bytes) != expected {
        return Err("accounting input size or SHA256 changed; review the input before estimating");
    }
    root.validate_root()
        .map_err(|_| "accounting input directory identity changed")?;
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountingArchive {
    schema_version: u32,
    kind: String,
    snapshot: Box<serde_json::value::RawValue>,
    plaintext: bool,
    untrusted: bool,
}

fn perform(command: &EstimateCommand) -> Result<Value, &'static str> {
    let bytes = read_verified(&command.source, &command.source_sha256, 4 * 1024 * 1024)?;
    let rates = read_verified(&command.rates, &command.rates_sha256, MAX_RATE_BYTES as u64)?;
    let archive: AccountingArchive =
        serde_json::from_slice(&bytes).map_err(|_| "input is not a closed accounting export")?;
    if archive.schema_version != 1
        || archive.kind != "gta-claw.provider-accounting"
        || !archive.plaintext
        || !archive.untrusted
    {
        return Err("input is not an untrusted schema-v1 accounting export");
    }
    let snapshot: Value = serde_json::from_str(archive.snapshot.get())
        .map_err(|_| "accounting snapshot is not valid JSON")?;
    let run = snapshot["runId"]
        .as_str()
        .filter(|value| valid_digest(value))
        .ok_or("accounting run identity is invalid")?;
    let revision = snapshot["revision"]
        .as_u64()
        .ok_or("accounting revision is invalid")?;
    claw_protocol::native_accounting::validate_snapshot(archive.snapshot.get(), run, revision)
        .map_err(|_| "accounting snapshot counters, identity or complete digest are invalid")?;
    let rounds: Vec<AccountingRound> =
        serde_json::from_value(snapshot["accounting"]["rounds"].clone())
            .map_err(|_| "accounting rounds are invalid")?;
    let prices = RateCard::parse(&rates)?;
    let estimate = prices.estimate(&rounds)?;
    Ok(
        json!({"schemaVersion":1,"operation":"accounting.estimate","ok":true,
        "sourceSha256":command.source_sha256,"ratesSha256":command.rates_sha256,"snapshotSha256":snapshot["accounting"]["sha256"],
        "runId":run,"revision":revision,"runStatus":snapshot["status"],"recordSource":snapshot["accounting"]["summary"]["recordSource"],
        "snapshotVerified":true,"sourceModified":false,"ratesModified":false,"networkContacted":false,
        "credentialsResolved":false,"automaticReplay":false,"estimate":estimate}),
    )
}

pub(super) async fn run(command: EstimateCommand) -> RenderedResult {
    match tokio::task::spawn_blocking(move || perform(&command)).await {
        Ok(Ok(receipt)) => RenderedResult::success(format!("{receipt}\n")),
        result => {
            let message = match result {
                Ok(Err(message)) => message,
                _ => "accounting estimate could not be completed",
            };
            RenderedResult {
                exit_code: super::ExitCategory::UsageConfig.code(),
                stdout: format!(
                    "{}\n",
                    json!({
                        "schemaVersion":1,"operation":"accounting.estimate","ok":false,"message":message,
                        "sourceModified":false,"ratesModified":false,"networkContacted":false,"credentialsResolved":false,
                        "automaticReplay":false,"actualCostKnown":false,"billingReconciled":false,
                    })
                ),
                stderr: String::new(),
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RateCard {
    schema_version: u32,
    kind: String,
    currency: String,
    revision: String,
    token_basis: String,
    rates: Vec<ModelRate>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelRate {
    provider: String,
    model: String,
    input_microunits_per_million: u64,
    output_microunits_per_million: u64,
}

impl RateCard {
    fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_RATE_BYTES {
            return Err("rate card exceeds 64 KiB");
        }
        let card: Self =
            serde_json::from_slice(bytes).map_err(|_| "rate card is not closed schema-v1 JSON")?;
        if card.schema_version != 1
            || card.kind != "gta-claw.token-rate-card"
            || card.token_basis != "all_reported_input_output"
            || card.currency.len() != 3
            || !card.currency.bytes().all(|byte| byte.is_ascii_uppercase())
            || card.revision.is_empty()
            || card.revision.len() > 128
            || card.revision.chars().any(char::is_control)
            || card.rates.is_empty()
            || card.rates.len() > 128
        {
            return Err("rate card identity, token basis or bounds are invalid");
        }
        let mut identities = std::collections::BTreeSet::new();
        for rate in &card.rates {
            if rate.provider.is_empty()
                || rate.provider.len() > 128
                || !rate
                    .provider
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                || rate.model.is_empty()
                || rate.model.len() > 256
                || rate
                    .model
                    .chars()
                    .any(|character| character.is_whitespace() || character.is_control())
                || rate.input_microunits_per_million > MAX_RATE
                || rate.output_microunits_per_million > MAX_RATE
                || !identities.insert((&rate.provider, &rate.model))
            {
                return Err(
                    "rate card requires unique exact provider/model pairs and bounded integer prices",
                );
            }
        }
        Ok(card)
    }

    fn estimate(&self, rounds: &[AccountingRound]) -> Result<Value, &'static str> {
        if rounds.len() > 1024 {
            return Err("accounting exceeds the bounded round count");
        }
        let rate_lookup: BTreeMap<_, _> = self
            .rates
            .iter()
            .map(|rate| ((rate.provider.as_str(), rate.model.as_str()), rate))
            .collect();
        let mut subtotal = 0_u128;
        let mut priced = 0_usize;
        let mut unreported = 0_usize;
        let mut partial = 0_usize;
        let mut missing_rate = 0_usize;
        for round in rounds {
            let Some(response) = &round.response else {
                unreported += 1;
                continue;
            };
            match response.usage_reporting.as_str() {
                "complete" => {}
                "partial" => {
                    partial += 1;
                    continue;
                }
                "unreported" => {
                    unreported += 1;
                    continue;
                }
                _ => return Err("accounting counter classification is invalid"),
            }
            let Some(rate) =
                rate_lookup.get(&(response.provider.as_str(), response.model.as_str()))
            else {
                missing_rate += 1;
                continue;
            };
            let input = u128::from(response.observed_tokens.input_tokens)
                .checked_mul(u128::from(rate.input_microunits_per_million));
            let output = u128::from(response.observed_tokens.output_tokens)
                .checked_mul(u128::from(rate.output_microunits_per_million));
            subtotal = input
                .zip(output)
                .and_then(|(input, output)| input.checked_add(output))
                .and_then(|amount| subtotal.checked_add(amount))
                .ok_or("accounting estimate exceeds its integer limit")?;
            priced += 1;
        }
        let amount = (priced > 0).then(|| {
            format!(
                "{}.{:012}",
                subtotal / AMOUNT_SCALE,
                subtotal % AMOUNT_SCALE
            )
        });
        let complete = priced > 0 && priced == rounds.len();
        Ok(json!({
            "currency":self.currency,"rateRevision":self.revision,"tokenBasis":self.token_basis,
            "recordedRounds":rounds.len(),"pricedRounds":priced,"unreportedRounds":unreported,
            "partialRounds":partial,"missingRateRounds":missing_rate,"knownSubtotal":amount,
            "totalEstimate":if complete {amount} else {None},"observedUsageEstimateComplete":complete,
            "actualCostKnown":false,"billingReconciled":false,"isInvoice":false,"source":"operator_supplied_rate_card",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claw_protocol::native_accounting::{AccountingResponse, ObservedTokens};

    #[test]
    fn estimate_command_requires_two_reviewed_local_files_without_network_options() {
        let root = std::env::temp_dir();
        let arguments = vec![
            "accounting".into(),
            "estimate".into(),
            "--source".into(),
            root.join("accounting.json").into_os_string(),
            "--rates".into(),
            root.join("rates.json").into_os_string(),
            "--expected-sha256".into(),
            "a".repeat(64).into(),
            "--rates-sha256".into(),
            "b".repeat(64).into(),
        ];
        assert!(parse(&arguments).is_ok());
        for length in [1, 2, 4, 6, 8, 9] {
            assert!(parse(&arguments[..length]).is_err());
        }
        for (offset, value) in [
            (1, "apply"),
            (3, "relative.json"),
            (5, "rates.json"),
            (7, "not-a-sha"),
            (9, "A".repeat(64).as_str()),
        ] {
            let mut invalid = arguments.clone();
            invalid[offset] = value.into();
            assert!(parse(&invalid).is_err());
        }
        for extra in [
            vec!["--rates", "duplicate.json"],
            vec!["--endpoint", "https://untrusted.invalid"],
            vec!["--overwrite"],
            vec!["--json", "--json"],
        ] {
            let mut invalid = arguments.clone();
            invalid.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&invalid).is_err());
        }
    }

    fn card() -> Value {
        json!({"schemaVersion":1,"kind":"gta-claw.token-rate-card","currency":"USD","revision":"reviewed-example",
            "tokenBasis":"all_reported_input_output","rates":[{"provider":"openai","model":"exact",
                "inputMicrounitsPerMillion":3_000_000,"outputMicrounitsPerMillion":15_000_000}]})
    }

    fn round() -> AccountingRound {
        AccountingRound {
            round: 0,
            response: Some(AccountingResponse {
                provider: "openai".to_owned(),
                model: "exact".to_owned(),
                response_id: None,
                usage_reporting: "complete".to_owned(),
                finish_reason: "stop".to_owned(),
                observed_tokens: ObservedTokens {
                    input_tokens: 1_000_000,
                    output_tokens: 100_000,
                    total_tokens: 1_100_000,
                    cached_input_tokens: 500_000,
                    reasoning_tokens: 50_000,
                },
            }),
        }
    }

    #[test]
    fn estimates_exact_flat_rates_without_double_counting_or_inventing_missing_usage() {
        let prices = RateCard::parse(card().to_string().as_bytes()).expect("rates");
        let first = round();
        let exact = prices
            .estimate(std::slice::from_ref(&first))
            .expect("exact estimate");
        assert_eq!(exact["totalEstimate"], "4.500000000000");
        assert_eq!(exact["observedUsageEstimateComplete"], true);
        assert_eq!(exact["actualCostKnown"], false);
        assert_eq!(exact["billingReconciled"], false);
        let mut missing = first.clone();
        missing.response.as_mut().expect("response").model = "alias-is-not-exact".to_owned();
        let mut partial = first.clone();
        partial.response.as_mut().expect("response").usage_reporting = "partial".to_owned();
        let mixed = prices
            .estimate(&[
                first.clone(),
                missing,
                partial,
                AccountingRound {
                    round: 3,
                    response: None,
                },
            ])
            .expect("known subtotal");
        assert_eq!(mixed["knownSubtotal"], "4.500000000000");
        assert_eq!(mixed["totalEstimate"], Value::Null);
        assert_eq!(mixed["pricedRounds"], 1);
        assert_eq!(mixed["partialRounds"], 1);
        assert_eq!(mixed["missingRateRounds"], 1);
        assert_eq!(mixed["unreportedRounds"], 1);
        let mut zero = first;
        zero.response.as_mut().expect("zero").observed_tokens = ObservedTokens {
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            cached_input_tokens: 0,
            reasoning_tokens: 0,
        };
        assert_eq!(
            prices.estimate(&[zero]).expect("explicit zero")["totalEstimate"],
            "0.000000000000"
        );
        assert_eq!(
            prices.estimate(&[]).expect("no recorded rounds")["knownSubtotal"],
            Value::Null
        );
        let mut fractional = card();
        fractional["rates"][0]["inputMicrounitsPerMillion"] = json!(1);
        fractional["rates"][0]["outputMicrounitsPerMillion"] = json!(0);
        let prices = RateCard::parse(fractional.to_string().as_bytes()).expect("submicro rate");
        let mut one = round();
        one.response.as_mut().expect("one token").observed_tokens = ObservedTokens {
            input_tokens: 1,
            output_tokens: 0,
            total_tokens: 1,
            cached_input_tokens: 0,
            reasoning_tokens: 0,
        };
        assert_eq!(
            prices.estimate(&[one]).expect("exact fraction")["totalEstimate"],
            "0.000000000001"
        );
        let mut large = card();
        large["rates"][0]["inputMicrounitsPerMillion"] = json!(MAX_RATE);
        large["rates"][0]["outputMicrounitsPerMillion"] = json!(0);
        let prices = RateCard::parse(large.to_string().as_bytes()).expect("maximum rate");
        let mut maximum = round();
        maximum
            .response
            .as_mut()
            .expect("maximum counters")
            .observed_tokens = ObservedTokens {
            input_tokens: u64::MAX,
            output_tokens: 0,
            total_tokens: u64::MAX,
            cached_input_tokens: 0,
            reasoning_tokens: 0,
        };
        assert_eq!(
            prices
                .estimate(std::slice::from_ref(&maximum))
                .expect("integer precision")["totalEstimate"],
            format!("{}.000000000000", u64::MAX)
        );
        let mut all_rounds = vec![maximum; 1024];
        assert_eq!(
            prices
                .estimate(&all_rounds)
                .expect("bounded complete round count")["totalEstimate"],
            format!("{}.000000000000", u128::from(u64::MAX) * 1024)
        );
        all_rounds.push(round());
        assert!(prices.estimate(&all_rounds).is_err());
    }

    #[test]
    fn rate_cards_reject_ambiguous_float_duplicate_or_unbounded_inputs() {
        for invalid in [
            json!(-1),
            json!(1.5),
            json!("3.0"),
            json!(true),
            json!(MAX_RATE + 1),
        ] {
            let mut value = card();
            value["rates"][0]["inputMicrounitsPerMillion"] = invalid;
            assert!(RateCard::parse(value.to_string().as_bytes()).is_err());
        }
        let mut value = card();
        value["rates"] = json!([value["rates"][0], value["rates"][0]]);
        assert!(RateCard::parse(value.to_string().as_bytes()).is_err());
        assert!(RateCard::parse(&vec![b' '; MAX_RATE_BYTES + 1]).is_err());
        let duplicate_field = card().to_string().replacen(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
            1,
        );
        assert!(RateCard::parse(duplicate_field.as_bytes()).is_err());
        let mut empty = card();
        empty["rates"] = json!([]);
        assert!(RateCard::parse(empty.to_string().as_bytes()).is_err());
        let mut many = card();
        many["rates"] = json!(
            (0..129)
                .map(|index| {
                    let mut rate = card()["rates"][0].clone();
                    rate["model"] = json!(format!("exact-{index}"));
                    rate
                })
                .collect::<Vec<_>>()
        );
        assert!(RateCard::parse(many.to_string().as_bytes()).is_err());
        for (field, invalid) in [
            ("currency", json!("usd")),
            ("revision", json!("")),
            ("tokenBasis", json!("discount-cached")),
            ("schemaVersion", json!(2)),
            ("apiKey", json!("private-fixture-secret")),
        ] {
            let mut value = card();
            value[field] = invalid;
            let error = RateCard::parse(value.to_string().as_bytes())
                .err()
                .expect("rejected");
            assert!(!error.contains("private-fixture-secret"));
        }
    }
}
