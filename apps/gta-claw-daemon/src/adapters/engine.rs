//! A deterministic session engine.
//!
//! This stands in for `claw-runtime` until it lands. It is deliberately real
//! about the things the composition has to get right — it calls the provider,
//! runs whatever tools the provider asks for, calls the provider again with the
//! results, and emits a gap-free event stream — and deliberately trivial about
//! everything else.
//!
//! It holds no capability of its own. Every provider and tool call goes through
//! [`TurnCapabilities`], which re-authorizes at that moment. That is the
//! property the composition exists to guarantee, so the stand-in must not cheat
//! around it.

use claw_application::composition::{
    BoxFuture, Grant, SessionEnginePort, SubsystemError, TurnCapabilities, TurnEvent,
    TurnEventSink, TurnRequest, TurnSummary, well_known,
};

/// How many provider round trips one turn may make.
const MAX_ROUNDS: usize = 4;

/// Runs turns against whatever the capabilities allow.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeterministicEngine;

impl SessionEnginePort for DeterministicEngine {
    fn run_turn<'a>(
        &'a self,
        request: Grant<TurnRequest>,
        capabilities: &'a TurnCapabilities,
        events: &'a dyn TurnEventSink,
    ) -> BoxFuture<'a, Result<TurnSummary, SubsystemError>> {
        Box::pin(async move {
            let turn = request
                .redeem()
                .map_err(|denial| SubsystemError::denied(well_known::engine(), &denial))?;

            let mut sequence = 0;
            events.emit(TurnEvent::Started { sequence });

            let mut prompt = turn.prompt().to_owned();
            let mut tool_calls = 0_u32;
            let mut answer = String::new();

            for round in 0..MAX_ROUNDS {
                let reply = match capabilities.call_provider(&prompt, turn.context()).await {
                    Ok(reply) => reply,
                    Err(error) => {
                        sequence += 1;
                        events.emit(TurnEvent::Failed {
                            sequence,
                            reason: error.to_string(),
                        });
                        return Err(error);
                    }
                };

                answer = reply.text().to_owned();

                if reply.requested_tools().is_empty() {
                    break;
                }

                if round + 1 == MAX_ROUNDS {
                    sequence += 1;
                    events.emit(TurnEvent::Failed {
                        sequence,
                        reason: format!("the turn did not settle within {MAX_ROUNDS} rounds"),
                    });

                    return Err(SubsystemError::conflict(
                        well_known::engine(),
                        format!("the turn did not settle within {MAX_ROUNDS} rounds"),
                    ));
                }

                let mut transcript = String::new();

                for requested in reply.requested_tools() {
                    let outcome = match capabilities
                        .call_tool(requested.name(), requested.arguments().to_owned())
                        .await
                    {
                        Ok(outcome) => outcome,
                        Err(error) => {
                            sequence += 1;
                            events.emit(TurnEvent::Failed {
                                sequence,
                                reason: error.to_string(),
                            });
                            return Err(error);
                        }
                    };

                    tool_calls += 1;
                    transcript.push_str(outcome.tool().as_str());
                    transcript.push('=');
                    transcript.push_str(outcome.output());
                    transcript.push(';');

                    sequence += 1;
                    events.emit(TurnEvent::ToolCompleted { sequence, outcome });
                }

                prompt = format!("{}|{transcript}", turn.prompt());
            }

            for chunk in split_into_chunks(&answer) {
                sequence += 1;
                events.emit(TurnEvent::AssistantDelta {
                    sequence,
                    text: chunk,
                });
            }

            let summary = TurnSummary::new(
                answer,
                turn.binding().name().clone(),
                turn.model().clone(),
                tool_calls,
            );

            sequence += 1;
            events.emit(TurnEvent::Finished {
                sequence,
                summary: summary.clone(),
            });

            Ok(summary)
        })
    }
}

/// Splits an answer into the deltas a streaming client would see.
///
/// Chunking on whitespace keeps the stream deterministic, which matters because
/// the integration test asserts the exact sequence numbers.
fn split_into_chunks(answer: &str) -> Vec<String> {
    if answer.is_empty() {
        return Vec::new();
    }

    answer
        .split_inclusive(' ')
        .map(std::borrow::ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::split_into_chunks;

    #[test]
    fn an_empty_answer_produces_no_deltas() {
        assert!(split_into_chunks("").is_empty());
    }

    #[test]
    fn chunks_reassemble_into_the_original_answer() {
        let chunks = split_into_chunks("the quick brown fox");

        assert_eq!(chunks, vec!["the ", "quick ", "brown ", "fox"]);
        assert_eq!(chunks.concat(), "the quick brown fox");
    }
}
