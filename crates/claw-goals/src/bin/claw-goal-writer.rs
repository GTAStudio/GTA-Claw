//! A separate process that mutates a durable goal and exits.
//!
//! The restart test needs a restart, not a re-binding. Constructing a second
//! [`FileGoalStore`] in the same process proves the store holds no
//! cache, but it cannot prove that what reached the disk is enough to reconstruct a goal, because
//! anything the first store leaked into process memory is still there. This binary closes that
//! gap: it opens the store, applies one mutation, and exits, so the reading test observes nothing
//! but bytes on a filesystem.
//!
//! ```text
//! claw-goal-writer <root> <session> <clock-millis> set      <objective>
//! claw-goal-writer <root> <session> <clock-millis> progress <note>
//! claw-goal-writer <root> <session> <clock-millis> close    <status>
//! ```

use std::process::ExitCode;
use std::sync::Arc;

use claw_domain::SessionId;
use claw_goals::FileGoalStore;
use claw_goals::testing::{SteppingClock, block_on};
use claw_runtime::{GoalConfig, GoalService};

const USAGE: u8 = 2;
const FAILED: u8 = 3;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [root, session, clock_millis, action, value] = arguments.as_slice() else {
        eprintln!("usage: claw-goal-writer <root> <session> <clock-millis> <action> <value>");
        return ExitCode::from(USAGE);
    };

    match run(root, session, clock_millis, action, value) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("{reason}");
            ExitCode::from(FAILED)
        }
    }
}

fn run(
    root: &str,
    session: &str,
    clock_millis: &str,
    action: &str,
    value: &str,
) -> Result<String, String> {
    let session_id = SessionId::new(session).map_err(|error| error.to_string())?;
    let start: u64 = clock_millis
        .parse()
        .map_err(|_| format!("clock-millis must be a whole number, got {clock_millis}"))?;

    let store = Arc::new(FileGoalStore::open(root).map_err(|error| error.to_string())?);
    let service = GoalService::new(
        store,
        Arc::new(SteppingClock::new(start, 1_000)),
        GoalConfig::default(),
    );

    let arguments = match action {
        "set" => format!("{{\"action\":\"set\",\"objective\":{}}}", quote(value)),
        "progress" => format!("{{\"action\":\"progress\",\"note\":{}}}", quote(value)),
        "close" => format!("{{\"action\":\"close\",\"status\":{}}}", quote(value)),
        other => return Err(format!("unknown action {other}")),
    };

    let outcome = block_on(claw_goals::invoke_goal_tool(
        &service,
        &session_id,
        &arguments,
    ))
    .map_err(|error| error.to_string())?;

    Ok(outcome.summary())
}

/// Quotes a value as a JSON string so an objective containing a quote is still one argument.
fn quote(value: &str) -> String {
    serde_json::Value::String(value.to_owned()).to_string()
}
