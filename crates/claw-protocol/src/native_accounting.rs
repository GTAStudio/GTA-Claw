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
