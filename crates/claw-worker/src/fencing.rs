//! Generational fencing, the split-brain defence.
//!
//! A worker identity may have at most one live generation. Opening a new
//! generation is the *only* way a worker is admitted, and it immediately makes
//! every token minted for an earlier generation worthless — including tokens
//! held by sessions that are already running. A worker that was partitioned,
//! paused or restarted therefore cannot come back and keep acting as though it
//! still owned the identity.
//!
//! Two properties make this safe rather than merely tidy:
//!
//! * generation zero does not exist, so an unknown worker has no token that
//!   could accidentally compare equal to "not yet admitted";
//! * a token *newer* than the ledger is refused just as loudly as a stale one,
//!   because a caller presenting a generation nobody issued is forging.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::identity::WorkerId;

/// A monotonic generation number for one worker identity.
///
/// The inner value is always at least one; zero is reserved for "this identity
/// has never been admitted" and is unrepresentable.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct FencingToken(u64);

impl FencingToken {
    /// Wraps a generation number.
    ///
    /// Returns [`None`] for zero, which is reserved for "never admitted".
    #[must_use]
    pub const fn new(generation: u64) -> Option<Self> {
        if generation == 0 {
            None
        } else {
            Some(Self(generation))
        }
    }

    /// Returns the generation number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for FencingToken {
    type Error = FencingError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(FencingError::ZeroGeneration)
    }
}

impl From<FencingToken> for u64 {
    fn from(value: FencingToken) -> Self {
        value.0
    }
}

impl Display for FencingToken {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

/// A fencing verdict that is not "current".
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FencingError {
    /// Generation zero was presented; it is reserved and never valid.
    ZeroGeneration,
    /// The worker identity has no generation at all.
    NeverAdmitted {
        /// The unknown worker identity.
        worker: WorkerId,
    },
    /// A superseded generation was presented.
    Stale {
        /// Generation the caller presented.
        presented: u64,
        /// Generation the ledger currently holds.
        current: u64,
    },
    /// A generation newer than any this ledger issued was presented.
    FromFuture {
        /// Generation the caller presented.
        presented: u64,
        /// Generation the ledger currently holds.
        current: u64,
    },
    /// The generation counter for this worker cannot advance any further.
    GenerationOverflow {
        /// The worker identity whose counter is exhausted.
        worker: WorkerId,
    },
}

impl Display for FencingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroGeneration => {
                formatter.write_str("fencing generation 0 is reserved and never valid")
            }
            Self::NeverAdmitted { worker } => {
                write!(formatter, "worker `{worker}` has never been admitted")
            }
            Self::Stale { presented, current } => write!(
                formatter,
                "fencing generation {presented} was superseded by generation {current}"
            ),
            Self::FromFuture { presented, current } => write!(
                formatter,
                "fencing generation {presented} was never issued; the current generation is \
                 {current}"
            ),
            Self::GenerationOverflow { worker } => write!(
                formatter,
                "the fencing generation counter for worker `{worker}` is exhausted"
            ),
        }
    }
}

impl Error for FencingError {}

/// The per-worker generation counter.
#[derive(Clone, Debug, Default)]
pub struct GenerationLedger {
    current: BTreeMap<WorkerId, FencingToken>,
}

impl GenerationLedger {
    /// Creates an empty ledger in which no worker has ever been admitted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Advances `worker` to a fresh generation and returns its token.
    ///
    /// Every token previously issued for this worker is stale from this moment.
    ///
    /// # Errors
    ///
    /// Returns [`FencingError::GenerationOverflow`] if the counter cannot
    /// advance. It is not wrapped, because wrapping would resurrect every
    /// superseded token at once.
    pub fn open_generation(&mut self, worker: &WorkerId) -> Result<FencingToken, FencingError> {
        let next =
            match self.current.get(worker) {
                None => 1,
                Some(current) => current.get().checked_add(1).ok_or_else(|| {
                    FencingError::GenerationOverflow {
                        worker: worker.clone(),
                    }
                })?,
            };
        let token = FencingToken::new(next).ok_or(FencingError::ZeroGeneration)?;
        self.current.insert(worker.clone(), token);
        Ok(token)
    }

    /// Returns the live generation for `worker`, if it has ever been admitted.
    #[must_use]
    pub fn current(&self, worker: &WorkerId) -> Option<FencingToken> {
        self.current.get(worker).copied()
    }

    /// Accepts only the live generation for `worker`.
    ///
    /// # Errors
    ///
    /// Returns [`FencingError::NeverAdmitted`], [`FencingError::Stale`] or
    /// [`FencingError::FromFuture`]; there is no permissive branch.
    pub fn verify(&self, worker: &WorkerId, presented: FencingToken) -> Result<(), FencingError> {
        let current = self
            .current(worker)
            .ok_or_else(|| FencingError::NeverAdmitted {
                worker: worker.clone(),
            })?;
        match presented.get().cmp(&current.get()) {
            std::cmp::Ordering::Equal => Ok(()),
            std::cmp::Ordering::Less => Err(FencingError::Stale {
                presented: presented.get(),
                current: current.get(),
            }),
            std::cmp::Ordering::Greater => Err(FencingError::FromFuture {
                presented: presented.get(),
                current: current.get(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worker(name: &str) -> WorkerId {
        WorkerId::new(name).expect("test worker identity is valid")
    }

    #[test]
    fn generation_zero_is_unrepresentable() {
        assert!(FencingToken::new(0).is_none());
        assert_eq!(FencingToken::try_from(0), Err(FencingError::ZeroGeneration));
        assert_eq!(FencingToken::new(1).map(FencingToken::get), Some(1));
    }

    #[test]
    fn generations_start_at_one_and_increase_by_one() {
        let mut ledger = GenerationLedger::new();
        let worker = worker("worker-a");
        assert_eq!(ledger.current(&worker), None);
        assert_eq!(
            ledger.open_generation(&worker).map(FencingToken::get),
            Ok(1)
        );
        assert_eq!(
            ledger.open_generation(&worker).map(FencingToken::get),
            Ok(2)
        );
        assert_eq!(ledger.current(&worker).map(FencingToken::get), Some(2));
    }

    #[test]
    fn generations_are_tracked_per_worker_identity() {
        let mut ledger = GenerationLedger::new();
        let first = worker("worker-a");
        let second = worker("worker-b");
        ledger.open_generation(&first).expect("open first");
        ledger.open_generation(&first).expect("re-open first");
        ledger.open_generation(&second).expect("open second");
        assert_eq!(ledger.current(&first).map(FencingToken::get), Some(2));
        assert_eq!(ledger.current(&second).map(FencingToken::get), Some(1));
    }

    #[test]
    fn an_unknown_worker_has_no_acceptable_token() {
        let ledger = GenerationLedger::new();
        let unknown = worker("ghost");
        let token = FencingToken::new(1).expect("generation one is valid");
        assert_eq!(
            ledger.verify(&unknown, token),
            Err(FencingError::NeverAdmitted {
                worker: unknown.clone()
            })
        );
    }

    #[test]
    fn a_superseded_token_names_both_generations() {
        let mut ledger = GenerationLedger::new();
        let worker = worker("worker-a");
        let first = ledger
            .open_generation(&worker)
            .expect("open generation one");
        ledger
            .open_generation(&worker)
            .expect("open generation two");
        assert_eq!(
            ledger.verify(&worker, first),
            Err(FencingError::Stale {
                presented: 1,
                current: 2,
            })
        );
    }

    #[test]
    fn a_token_nobody_issued_is_refused_rather_than_trusted() {
        let mut ledger = GenerationLedger::new();
        let worker = worker("worker-a");
        ledger
            .open_generation(&worker)
            .expect("open generation one");
        let forged = FencingToken::new(9_999).expect("generation is non-zero");
        assert_eq!(
            ledger.verify(&worker, forged),
            Err(FencingError::FromFuture {
                presented: 9_999,
                current: 1,
            })
        );
    }

    #[test]
    fn an_exhausted_counter_refuses_to_wrap_back_to_a_live_generation() {
        let mut ledger = GenerationLedger::new();
        let worker = worker("worker-a");
        ledger.current.insert(
            worker.clone(),
            FencingToken::new(u64::MAX).expect("generation is non-zero"),
        );
        assert_eq!(
            ledger.open_generation(&worker),
            Err(FencingError::GenerationOverflow {
                worker: worker.clone()
            })
        );
        assert_eq!(
            ledger.current(&worker).map(FencingToken::get),
            Some(u64::MAX)
        );
    }
}
