use claw_application::model::goal::{GoalRecord, GoalStatus};
use claw_application::ports::{PortError, PortFuture};
use claw_domain::SessionId;
use claw_runtime::{GoalError, GoalService};

pub(crate) const MAX_CONFLICT_ATTEMPTS: usize = 3;

pub(crate) async fn retry_conflicts<'a, T>(
    mut operation: impl FnMut() -> PortFuture<'a, Result<T, GoalError>>,
) -> Result<T, GoalError> {
    for attempt in 1..=MAX_CONFLICT_ATTEMPTS {
        match operation().await {
            Err(GoalError::Port(PortError::Conflict(_))) if attempt < MAX_CONFLICT_ATTEMPTS => {}
            outcome => return outcome,
        }
    }
    unreachable!("the final retry always returns")
}

pub(crate) async fn start_with_conflict_recovery(
    service: &GoalService,
    session_id: &SessionId,
    objective: &str,
) -> Result<GoalRecord, GoalError> {
    for attempt in 1..=MAX_CONFLICT_ATTEMPTS {
        match service.start(session_id, objective).await {
            Err(error @ GoalError::Port(PortError::Conflict(_))) => {
                match service.active(session_id).await {
                    Ok(Some(committed)) if committed.objective == objective.trim() => {
                        repair_older_active_goals(service, session_id, &committed).await?;
                        return Ok(committed);
                    }
                    Ok(_) => {}
                    Err(GoalError::Port(PortError::Conflict(_)))
                        if attempt < MAX_CONFLICT_ATTEMPTS => {}
                    Err(active_error) => return Err(active_error),
                }
                if attempt == MAX_CONFLICT_ATTEMPTS {
                    return Err(error);
                }
            }
            outcome => return outcome,
        }
    }
    unreachable!("the final retry always returns")
}

async fn repair_older_active_goals(
    service: &GoalService,
    session_id: &SessionId,
    committed: &GoalRecord,
) -> Result<(), GoalError> {
    for record in service.history(session_id).await? {
        if record.goal_id == committed.goal_id || record.status != GoalStatus::Active {
            continue;
        }
        match retry_conflicts(|| Box::pin(service.close(&record.goal_id, GoalStatus::Superseded)))
            .await
        {
            Ok(_) | Err(GoalError::AlreadyClosed { .. }) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::future;

    use super::{MAX_CONFLICT_ATTEMPTS, retry_conflicts};
    use claw_application::ports::PortError;
    use claw_runtime::GoalError;

    #[test]
    fn conflicts_are_retried_to_the_fixed_ceiling() {
        let mut calls = 0;
        let outcome = crate::testing::block_on(retry_conflicts(|| {
            calls += 1;
            Box::pin(future::ready(if calls < MAX_CONFLICT_ATTEMPTS {
                Err(GoalError::Port(PortError::Conflict("injected".to_owned())))
            } else {
                Ok(calls)
            }))
        }))
        .expect("the final attempt succeeds");

        assert_eq!(outcome, MAX_CONFLICT_ATTEMPTS);
        assert_eq!(calls, MAX_CONFLICT_ATTEMPTS);
    }

    #[test]
    fn non_conflicts_are_never_retried() {
        let mut calls = 0;
        let error = crate::testing::block_on(retry_conflicts(|| {
            calls += 1;
            Box::pin(future::ready(Err::<(), _>(GoalError::Port(
                PortError::Unavailable("injected".to_owned()),
            ))))
        }))
        .expect_err("unavailable is surfaced");

        assert!(matches!(error, GoalError::Port(PortError::Unavailable(_))));
        assert_eq!(calls, 1);
    }
}
