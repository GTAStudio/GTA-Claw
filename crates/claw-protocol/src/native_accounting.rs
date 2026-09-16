//! Validated, read-only accounting summaries for the native durable-run extension.

use serde::Deserialize;
use serde_json::Value;

/// How much the reported primary counters establish about a run's token use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterCoverage {
    /// An accounting record exists but contains no provider attempts.
    NoRounds,
    /// Attempts exist without any confirmed primary-counter report.
    Unreported,
    /// Some primary counters or attempts remain unreported.
    Partial,
    /// Every recorded attempt explicitly reports its primary counters.
    Complete,
    /// The checked aggregate cannot fit in the protocol's integer range.
    Overflow,
}

/// Persistence provenance, independent of request delivery or billing settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountingSource {
    /// An older peer did not identify the record source.
    Unspecified,
    /// Accounting was stored with the terminal turn.
    TerminalTurn,
    /// Accounting was recovered from the independent per-round journal.
    ProviderJournal {
        /// Monotonic journal revision, distinct from the run revision.
        revision: u64,
        /// Whether the journal was sealed with a terminal turn.
        closed: bool,
    },
}

/// Checked observed counters; cached and reasoning counters are subsets, not extra usage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservedTokens {
    /// Observed input, including the cached subset.
    pub input_tokens: u64,
    /// Observed output, including the reasoning subset.
    pub output_tokens: u64,
    /// Checked input plus output.
    pub total_tokens: u64,
    /// Subset of observed input.
    pub cached_input_tokens: u64,
    /// Subset of observed output.
    pub reasoning_tokens: u64,
}

/// Validated native accounting, with no inferred price, invoice or replay permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAccounting {
    /// Bounded number of persisted attempts, including possibly unsent intents.
    pub recorded_rounds: u16,
    /// Attempts with explicitly complete primary counters.
    pub complete_counter_rounds: u16,
    /// Attempts with explicitly partial primary counters.
    pub partial_counter_rounds: u16,
    /// Attempts without a primary-counter report.
    pub unreported_rounds: u16,
    /// Exact reporting classification, including explicit complete zeroes.
    pub coverage: CounterCoverage,
    /// Checked observed counts, absent for no rounds or aggregate overflow.
    pub observed_tokens: Option<ObservedTokens>,
    /// Validated persistence source.
    pub source: AccountingSource,
    /// Peer statement about unsent intents; absence remains unspecified.
    pub attempts_may_be_unsent: Option<bool>,
}

/// A malformed or unsupported native accounting summary, without remote content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountingError;

impl std::fmt::Display for AccountingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Provider accounting is invalid or unsupported")
    }
}

impl std::error::Error for AccountingError {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountingRunWire {
    run_id: String,
    session_id: String,
    revision: u64,
    turn: Option<u64>,
    status: String,
    accounting: AccountingPageWire,
    durable: bool,
    acknowledged: bool,
    automatic_replay: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountingPageWire {
    available: bool,
    offset: Option<usize>,
    end_offset: Option<usize>,
    next_offset: Option<usize>,
    total_rounds: Option<usize>,
    sha256: Option<String>,
    summary: Option<Value>,
    rounds: Option<Vec<AccountingRound>>,
}

/// A confirmed report or an unreported intent, in its original provider-round order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AccountingRound {
    /// Zero-based provider attempt index, not proof that a request was delivered.
    pub round: usize,
    /// Missing reports remain absent rather than becoming zero usage.
    pub response: Option<AccountingResponse>,
}

/// Stored provider-response metadata without prompts, text, tool arguments or prices.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountingResponse {
    /// Bounded, untrusted provider identity.
    pub provider: String,
    /// Bounded, untrusted model identity.
    pub model: String,
    /// Optional provider-assigned response identifier.
    pub response_id: Option<String>,
    /// Validated complete, partial or unreported primary-counter classification.
    pub usage_reporting: String,
    /// Validated provider finish reason, independent of the run outcome.
    pub finish_reason: String,
    /// Checked primary counters and their cached/reasoning subsets.
    pub observed_tokens: ObservedTokens,
}

/// Checks one native accounting page, including its whole digest when it is complete.
///
/// # Errors
/// Rejects identity changes, unsupported fields, invalid counters, bounds or digests.
pub fn validate_page(encoded: &str, parameters: &Value) -> Result<(), AccountingError> {
    validate_page_with_limit(encoded, parameters, 16)
}

/// Independently verifies a collected native accounting snapshot of at most 1024 rounds.
///
/// # Errors
/// Rejects incomplete snapshots, mismatched aggregates, identity changes or a bad full digest.
pub fn validate_snapshot(
    encoded: &str,
    run_id: &str,
    revision: u64,
) -> Result<(), AccountingError> {
    let parameters =
        serde_json::json!({"runId":run_id,"accountingPage":{"revision":revision,"offset":0}});
    validate_page_with_limit(encoded, &parameters, 1024)?;
    let reply: AccountingRunWire = serde_json::from_str(encoded).map_err(|_| AccountingError)?;
    if !reply.accounting.available || reply.accounting.next_offset.is_some() {
        return Err(AccountingError);
    }
    Ok(())
}

fn validate_page_with_limit(
    encoded: &str,
    parameters: &Value,
    max_rounds: usize,
) -> Result<(), AccountingError> {
    if encoded.len() > (max_rounds * 4096).max(64 * 1024) {
        return Err(AccountingError);
    }
    let reply: AccountingRunWire = serde_json::from_str(encoded).map_err(|_| AccountingError)?;
    if parameters["runId"].as_str() != Some(&reply.run_id)
        || parameters["accountingPage"]["revision"].as_u64() != Some(reply.revision)
        || reply.revision == 0
        || reply.session_id.is_empty()
        || reply.session_id.len() > 128
        || reply.session_id.chars().any(char::is_control)
        || !reply.durable
        || reply.acknowledged
        || reply.automatic_replay
        || !matches!(
            reply.status.as_str(),
            "completed" | "completed_with_changes" | "cancelled" | "failed" | "outcome_unknown"
        )
    {
        return Err(AccountingError);
    }
    let page = reply.accounting;
    if !page.available {
        if parameters["accountingPage"]["offset"].as_u64() != Some(0)
            || parameters["accountingPage"].get("sha256").is_some()
            || page.offset.is_some()
            || page.end_offset.is_some()
            || page.next_offset.is_some()
            || page.total_rounds.is_some()
            || page.sha256.is_some()
            || page.summary.is_some()
            || page.rounds.is_some()
        {
            return Err(AccountingError);
        }
        return Ok(());
    }
    let offset = page.offset.ok_or(AccountingError)?;
    let end = page.end_offset.ok_or(AccountingError)?;
    let total = page.total_rounds.ok_or(AccountingError)?;
    let rounds = page.rounds.ok_or(AccountingError)?;
    let digest = page.sha256.ok_or(AccountingError)?;
    let summary =
        ProviderAccounting::parse(&page.summary.ok_or(AccountingError)?)?.ok_or(AccountingError)?;
    if reply.turn.is_none()
        || parameters["accountingPage"]["offset"].as_u64() != u64::try_from(offset).ok()
        || rounds.len() > max_rounds
        || offset.checked_add(rounds.len()) != Some(end)
        || end > total
        || total != usize::from(summary.recorded_rounds)
        || (offset > 0
            && (rounds.is_empty() || parameters["accountingPage"]["sha256"].as_str().is_none()))
        || page.next_offset.map_or(end != total, |next| {
            next != end || next >= total || rounds.is_empty()
        })
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || parameters["accountingPage"]["sha256"]
            .as_str()
            .is_some_and(|expected| expected != digest)
    {
        return Err(AccountingError);
    }
    let mut counts = [0_u16; 3];
    let mut totals = [0_u128; 4];
    for (index, round) in rounds.iter().enumerate() {
        if round.round != offset + index {
            return Err(AccountingError);
        }
        let Some(response) = &round.response else {
            counts[2] += 1;
            continue;
        };
        let identity_valid = |value: &str| {
            !value.is_empty()
                && value.len() <= 512
                && !value
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
        };
        if !identity_valid(&response.provider)
            || !identity_valid(&response.model)
            || response
                .response_id
                .as_deref()
                .is_some_and(|identity| !identity_valid(identity))
            || !matches!(
                response.finish_reason.as_str(),
                "stop" | "tool_calls" | "length" | "content_filter"
            )
        {
            return Err(AccountingError);
        }
        let tokens = &response.observed_tokens;
        if tokens.input_tokens.checked_add(tokens.output_tokens) != Some(tokens.total_tokens)
            || tokens.cached_input_tokens > tokens.input_tokens
            || tokens.reasoning_tokens > tokens.output_tokens
        {
            return Err(AccountingError);
        }
        match response.usage_reporting.as_str() {
            "complete" => counts[0] += 1,
            "partial" => counts[1] += 1,
            "unreported" if tokens.total_tokens == 0 => counts[2] += 1,
            _ => return Err(AccountingError),
        }
        for (accumulated, count) in totals.iter_mut().zip([
            tokens.input_tokens,
            tokens.output_tokens,
            tokens.cached_input_tokens,
            tokens.reasoning_tokens,
        ]) {
            *accumulated += u128::from(count);
        }
    }
    let complete_page = offset == 0 && end == total;
    for (count, expected) in counts.into_iter().zip([
        summary.complete_counter_rounds,
        summary.partial_counter_rounds,
        summary.unreported_rounds,
    ]) {
        if count > expected || (complete_page && count != expected) {
            return Err(AccountingError);
        }
    }
    if let Some(observed) = summary.observed_tokens {
        for (count, expected) in totals.into_iter().zip([
            observed.input_tokens,
            observed.output_tokens,
            observed.cached_input_tokens,
            observed.reasoning_tokens,
        ]) {
            if count > u128::from(expected) || (complete_page && count != u128::from(expected)) {
                return Err(AccountingError);
            }
        }
    } else if complete_page && total > 0 && totals[0] + totals[1] <= u128::from(u64::MAX) {
        return Err(AccountingError);
    }
    if complete_page {
        use sha2::Digest as _;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let raw: Value = serde_json::from_str(encoded).map_err(|_| AccountingError)?;
        let snapshot = serde_json::json!({"summary":raw["accounting"]["summary"],"rounds":raw["accounting"]["rounds"]});
        let actual =
            sha2::Sha256::digest(serde_json::to_vec(&snapshot).map_err(|_| AccountingError)?);
        let encoded: String = actual
            .iter()
            .flat_map(|byte| {
                [
                    char::from(HEX[usize::from(byte >> 4)]),
                    char::from(HEX[usize::from(byte & 15)]),
                ]
            })
            .collect();
        if encoded != digest {
            return Err(AccountingError);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Private wire mirror; validation converts these fields to typed coverage and provenance"
)]
struct AccountingWire {
    available: bool,
    recorded_rounds: u16,
    complete_counter_rounds: u16,
    partial_counter_rounds: u16,
    unreported_rounds: u16,
    all_primary_counters_reported: bool,
    observed_tokens: Option<ObservedTokens>,
    aggregation_overflow: bool,
    cost_calculated: bool,
    billing_reconciled: bool,
    record_source: Option<SourceWire>,
    journal_revision: Option<u64>,
    journal_closed: Option<bool>,
    attempts_may_be_unsent: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceWire {
    TerminalTurn,
    ProviderJournal,
}

impl ProviderAccounting {
    /// Parses the optional `providerAccounting` field of an already-owned run.
    ///
    /// Missing/null data stays absent. The current native extension has neither
    /// computed monetary cost nor reconciled billing; future priced shapes must
    /// be implemented explicitly rather than displayed as a settled zero.
    ///
    /// # Errors
    ///
    /// Rejects unsupported fields, inconsistent counts/provenance and invalid totals.
    pub fn parse(value: &Value) -> Result<Option<Self>, AccountingError> {
        if value.is_null() {
            return Ok(None);
        }
        let wire: AccountingWire =
            serde_json::from_value(value.clone()).map_err(|_| AccountingError)?;
        if wire.recorded_rounds > 1024
            || wire.available != (wire.recorded_rounds > 0)
            || u32::from(wire.complete_counter_rounds)
                + u32::from(wire.partial_counter_rounds)
                + u32::from(wire.unreported_rounds)
                != u32::from(wire.recorded_rounds)
            || wire.cost_calculated
            || wire.billing_reconciled
            || wire.all_primary_counters_reported
                != (wire.available
                    && wire.complete_counter_rounds == wire.recorded_rounds
                    && !wire.aggregation_overflow)
            || wire.observed_tokens.is_some() != (wire.available && !wire.aggregation_overflow)
            || (!wire.available && wire.aggregation_overflow)
        {
            return Err(AccountingError);
        }
        if let Some(tokens) = &wire.observed_tokens
            && (tokens.input_tokens.checked_add(tokens.output_tokens) != Some(tokens.total_tokens)
                || tokens.cached_input_tokens > tokens.input_tokens
                || tokens.reasoning_tokens > tokens.output_tokens)
        {
            return Err(AccountingError);
        }
        let source = match wire.record_source {
            Some(SourceWire::ProviderJournal) => AccountingSource::ProviderJournal {
                revision: wire
                    .journal_revision
                    .filter(|revision| *revision > 0)
                    .ok_or(AccountingError)?,
                closed: wire.journal_closed.ok_or(AccountingError)?,
            },
            source => {
                if wire.journal_revision.is_some() || wire.journal_closed.is_some() {
                    return Err(AccountingError);
                }
                match source {
                    Some(SourceWire::TerminalTurn) => AccountingSource::TerminalTurn,
                    None => AccountingSource::Unspecified,
                    Some(SourceWire::ProviderJournal) => unreachable!(),
                }
            }
        };
        let coverage = if !wire.available {
            CounterCoverage::NoRounds
        } else if wire.aggregation_overflow {
            CounterCoverage::Overflow
        } else if wire.all_primary_counters_reported {
            CounterCoverage::Complete
        } else if wire.complete_counter_rounds == 0 && wire.partial_counter_rounds == 0 {
            CounterCoverage::Unreported
        } else {
            CounterCoverage::Partial
        };
        Ok(Some(Self {
            recorded_rounds: wire.recorded_rounds,
            complete_counter_rounds: wire.complete_counter_rounds,
            partial_counter_rounds: wire.partial_counter_rounds,
            unreported_rounds: wire.unreported_rounds,
            coverage,
            observed_tokens: wire.observed_tokens,
            source,
            attempts_may_be_unsent: wire.attempts_may_be_unsent,
        }))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{AccountingSource, CounterCoverage, ProviderAccounting};

    #[test]
    fn accounting_snapshot_preserves_the_existing_ordered_json_contract() {
        use sha2::Digest as _;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let snapshot = json!({"summary":{"available":false,"recordedRounds":0,"completeCounterRounds":0,
            "partialCounterRounds":0,"unreportedRounds":0,"allPrimaryCountersReported":false,"observedTokens":null,
            "aggregationOverflow":false,"costCalculated":false,"billingReconciled":false,"recordSource":"terminal_turn","attemptsMayBeUnsent":true},"rounds":[]});
        let digest: String =
            sha2::Sha256::digest(serde_json::to_vec(&snapshot).expect("ordered snapshot"))
                .iter()
                .flat_map(|byte| {
                    [
                        char::from(HEX[usize::from(byte >> 4)]),
                        char::from(HEX[usize::from(byte & 15)]),
                    ]
                })
                .collect();
        let mut reply = json!({"runId":"a".repeat(64),"sessionId":"owned","revision":3,"turn":0,"status":"outcome_unknown",
            "durable":true,"acknowledged":false,"automaticReplay":false,"accounting":{"available":true,"offset":0,"endOffset":0,
                "nextOffset":null,"totalRounds":0,"sha256":digest,"summary":snapshot["summary"],"rounds":snapshot["rounds"]}});
        assert!(super::validate_snapshot(&reply.to_string(), &"a".repeat(64), 3).is_ok());
        reply["accounting"]["summary"]["journalClosed"] = json!(false);
        assert!(super::validate_snapshot(&reply.to_string(), &"a".repeat(64), 3).is_err());
    }

    fn complete_zero() -> serde_json::Value {
        json!({
            "available":true,"recordedRounds":1,"completeCounterRounds":1,
            "partialCounterRounds":0,"unreportedRounds":0,"allPrimaryCountersReported":true,
            "observedTokens":{"inputTokens":0,"outputTokens":0,"totalTokens":0,"cachedInputTokens":0,"reasoningTokens":0},
            "aggregationOverflow":false,"costCalculated":false,"billingReconciled":false,
            "recordSource":"terminal_turn","attemptsMayBeUnsent":true,
        })
    }

    #[test]
    fn missing_partial_zero_and_journal_accounting_remain_distinct() {
        assert_eq!(
            ProviderAccounting::parse(&serde_json::Value::Null),
            Ok(None)
        );
        let mut value = complete_zero();
        let complete = ProviderAccounting::parse(&value)
            .expect("valid")
            .expect("present");
        assert_eq!(complete.coverage, CounterCoverage::Complete);
        assert_eq!(
            complete.observed_tokens.expect("known zero").total_tokens,
            0
        );
        value["completeCounterRounds"] = json!(0);
        value["partialCounterRounds"] = json!(1);
        value["allPrimaryCountersReported"] = json!(false);
        assert_eq!(
            ProviderAccounting::parse(&value)
                .expect("valid")
                .expect("present")
                .coverage,
            CounterCoverage::Partial
        );
        value["partialCounterRounds"] = json!(0);
        value["unreportedRounds"] = json!(1);
        value["recordSource"] = json!("provider_journal");
        value["journalRevision"] = json!(2);
        value["journalClosed"] = json!(false);
        let journal = ProviderAccounting::parse(&value)
            .expect("valid")
            .expect("present");
        assert_eq!(journal.coverage, CounterCoverage::Unreported);
        assert_eq!(
            journal.source,
            AccountingSource::ProviderJournal {
                revision: 2,
                closed: false
            }
        );
        assert_eq!(journal.attempts_may_be_unsent, Some(true));
    }

    #[test]
    fn no_rounds_overflow_and_legacy_provenance_are_not_inferred_zero_usage() {
        let mut value = complete_zero();
        value["available"] = json!(false);
        value["recordedRounds"] = json!(0);
        value["completeCounterRounds"] = json!(0);
        value["allPrimaryCountersReported"] = json!(false);
        value["observedTokens"] = serde_json::Value::Null;
        let empty = ProviderAccounting::parse(&value)
            .expect("valid")
            .expect("present");
        assert_eq!(empty.coverage, CounterCoverage::NoRounds);
        assert_eq!(empty.observed_tokens, None);
        value = complete_zero();
        value["aggregationOverflow"] = json!(true);
        value["allPrimaryCountersReported"] = json!(false);
        value["observedTokens"] = serde_json::Value::Null;
        value
            .as_object_mut()
            .expect("object")
            .remove("recordSource");
        value
            .as_object_mut()
            .expect("object")
            .remove("attemptsMayBeUnsent");
        let overflow = ProviderAccounting::parse(&value)
            .expect("valid")
            .expect("present");
        assert_eq!(overflow.coverage, CounterCoverage::Overflow);
        assert_eq!(overflow.source, AccountingSource::Unspecified);
        assert_eq!(overflow.attempts_may_be_unsent, None);
    }

    #[test]
    fn inconsistent_or_unsupported_accounting_is_rejected() {
        for (field, invalid) in [
            ("available", json!(false)),
            ("recordedRounds", json!(1025)),
            ("completeCounterRounds", json!(0)),
            ("partialCounterRounds", json!(1)),
            ("unreportedRounds", json!(-1)),
            ("allPrimaryCountersReported", json!(false)),
            ("observedTokens", serde_json::Value::Null),
            ("aggregationOverflow", json!(true)),
            ("costCalculated", json!(true)),
            ("billingReconciled", json!(true)),
            ("recordSource", json!("unknown-source")),
            ("recordSource", json!("provider_journal")),
            ("journalRevision", json!(1)),
            ("journalClosed", json!(false)),
            ("privateField", json!("remote-content")),
        ] {
            let mut value = complete_zero();
            value[field] = invalid;
            assert!(ProviderAccounting::parse(&value).is_err(), "{field}");
        }
        for (field, invalid) in [
            ("totalTokens", json!(1)),
            ("cachedInputTokens", json!(1)),
            ("reasoningTokens", json!(1)),
            ("inputTokens", json!(u64::MAX)),
            ("outputTokens", json!("0")),
            ("price", json!(0)),
        ] {
            let mut value = complete_zero();
            value["observedTokens"][field] = invalid;
            assert!(ProviderAccounting::parse(&value).is_err(), "{field}");
        }
    }
}
