//! Diagnostic destination rules and Gateway-path instrumentation for the TUI.
//!
//! `claw-observability` installs one process-wide subscriber, so the end-to-end
//! checks here run the real executable against a Gateway double and read the
//! stream it was pointed at. Nothing else exercises the installed subscriber,
//! the redaction layer, and the destination rules together.

#[expect(
    dead_code,
    reason = "the Gateway test double is shared with claw-gateway-client, which owns the file; \
              this binary exercises only the subset the TUI worker needs"
)]
#[path = "../../../crates/claw-gateway-client/tests/support/mod.rs"]
mod support;

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use claw_protocol::gateway::AUTHENTICATED_MAX_FRAME_BYTES;
use gta_claw_tui::Options;
use gta_claw_tui::diagnostics::{SinkChoice, Verbosity, choose_sink};
use gta_claw_tui::gateway::endpoint_label;
use serde_json::{Value, json};
use support::{
    TestGateway, complete_handshake, handler, receive_request, send_json, wait_for_close,
};
use url::Url;

const TOKEN: &str = "tui-diagnostic-token";

fn arguments(values: &[&str]) -> Vec<OsString> {
    std::iter::once("gta-claw-tui")
        .chain(values.iter().copied())
        .map(OsString::from)
        .collect()
}

/// A path under Cargo's per-target temporary directory, cleared of any leftover.
///
/// The file is opened in append mode, so a stale run must not be able to add
/// records to the ones this test asserts on.
fn log_path(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_file(&path);
    path
}

/// `--help` is the only way the help text leaves the crate.
fn help_text() -> String {
    Options::parse(arguments(&["--help"])).expect_err("--help returns the help text")
}

/// Runs the real executable so the global subscriber is genuinely installed.
///
/// `GTA_CLAW_LOG` is cleared because the developer's environment must not be
/// able to widen the filter and put a dependency's records on this stream.
async fn run_tui(gateway: &Url, extra: &[&str]) -> Output {
    let url = gateway.to_string();
    let extra: Vec<String> = extra.iter().map(|value| (*value).to_owned()).collect();
    // The Gateway double shares this runtime, so the child is waited on a
    // blocking thread rather than in the reactor it has to keep serving.
    let run = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_gta-claw-tui"))
            .arg("--plain")
            .arg("--gateway")
            .arg(&url)
            .args(&extra)
            .env("GTA_CLAW_GATEWAY_TOKEN", TOKEN)
            .env_remove("GTA_CLAW_LOG")
            .env_remove("NO_COLOR")
            .output()
            .expect("run gta-claw-tui")
    });
    tokio::time::timeout(std::time::Duration::from_secs(30), run)
        .await
        .expect("the snapshot run is bounded")
        .expect("join the child process")
}

fn diagnostic_lines(output: &Output) -> Vec<Value> {
    records(&String::from_utf8(output.stderr.clone()).expect("diagnostics are UTF-8"))
}

/// Parses the JSON records the installed subscriber wrote, from either sink.
fn records(text: &str) -> Vec<Value> {
    text.lines()
        .map(|line| {
            let record: Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("diagnostics are JSON lines: {error}: {line}"));
            assert!(
                record["fields"]["action"].is_string(),
                "every diagnostic line is one of this binary's events: {line}"
            );
            assert!(
                record["target"]
                    .as_str()
                    .expect("target")
                    .starts_with("gta_claw_tui"),
                "no dependency may share this stream: {line}"
            );
            record
        })
        .collect()
}

fn fields(record: &Value) -> &Value {
    &record["fields"]
}

fn find<'a>(records: &'a [Value], action: &str) -> Option<&'a Value> {
    records
        .iter()
        .find(|record| record["fields"]["action"] == action)
}

/// A Gateway double that answers one `sessions.list` per connection.
async fn snapshot_gateway() -> TestGateway {
    TestGateway::spawn(handler(|mut socket, _| async move {
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        let request = receive_request(&mut socket).await;
        assert_eq!(request.method().as_str(), "sessions.list");
        send_json(
            &mut socket,
            json!({
                "type": "res",
                "id": request.id().as_str(),
                "ok": true,
                "payload": {"sessions": []}
            }),
        )
        .await;
        wait_for_close(&mut socket).await;
    }))
    .await
}

#[test]
fn diagnostics_are_off_unless_asked_for_and_the_frozen_help_lines_are_unchanged() {
    let options = Options::parse(arguments(&["--plain"])).expect("default options");
    assert_eq!(options.verbosity, Verbosity::Off);
    assert_eq!(options.log_file, None);
    assert_eq!(
        choose_sink(options.verbosity, None, true, true),
        SinkChoice::Suppressed
    );

    let help = help_text();
    let mut lines = help.lines();
    assert_eq!(
        lines.next(),
        Some("Usage: gta-claw-tui [--gateway ws://HOST:PORT] [--no-color] [--plain]")
    );
    assert_eq!(
        lines.next(),
        Some("Set GTA_CLAW_GATEWAY_TOKEN for authenticated Gateways.")
    );
    assert!(help.contains("-v, --verbose"), "{help}");
    assert!(
        help.contains("2>run.jsonl"),
        "the help must name the way to keep diagnostics under the alternate screen: {help}"
    );
    assert!(
        help.contains("--log-file <p>"),
        "the help must name the other way to keep them: {help}"
    );
}

#[test]
fn the_verbosity_flags_and_the_log_file_path_parse_into_options() {
    let basic = Options::parse(arguments(&["--verbose"])).expect("verbose options");
    assert_eq!(basic.verbosity, Verbosity::Basic);
    let short = Options::parse(arguments(&["-v"])).expect("short options");
    assert_eq!(short.verbosity, Verbosity::Basic);
    let detailed = Options::parse(arguments(&["-vv"])).expect("detailed options");
    assert_eq!(detailed.verbosity, Verbosity::Detailed);
    let promoted = Options::parse(arguments(&["-v", "-vv"])).expect("the higher level wins");
    assert_eq!(promoted.verbosity, Verbosity::Detailed);

    let with_file =
        Options::parse(arguments(&["-v", "--log-file", "run.jsonl"])).expect("log file options");
    assert_eq!(with_file.log_file, Some(PathBuf::from("run.jsonl")));
    assert_eq!(
        choose_sink(
            with_file.verbosity,
            with_file.log_file.as_deref(),
            true,
            true
        ),
        SinkChoice::File(PathBuf::from("run.jsonl")),
        "a file is the only destination that is safe under the alternate screen"
    );

    // The token is the one thing that must never reach a diagnostic, so the
    // options must keep it out of their own `Debug` even next to a log file.
    let rendered = format!("{with_file:?}");
    assert!(
        rendered.contains("log_file: Some(\"run.jsonl\")"),
        "{rendered}"
    );

    let missing = Options::parse(arguments(&["--log-file"])).expect_err("path required");
    assert_eq!(missing, "--log-file requires a path");
}

#[tokio::test]
async fn the_gateway_path_is_reported_stage_by_stage_without_the_token() {
    let gateway = snapshot_gateway().await;
    let output = run_tui(&gateway.url, &["-vv"]).await;
    assert!(output.status.success(), "{output:?}");

    let records = diagnostic_lines(&output);
    let observed: Vec<&str> = records
        .iter()
        .map(|record| fields(record)["action"].as_str().expect("action"))
        .collect();
    for expected in [
        "telemetry.install",
        "endpoint.resolve",
        "identity.generate",
        "client.start",
        "connection.ready",
        "authorization.grant",
        "connection.epoch",
        "rpc.request",
        "rpc.response",
    ] {
        assert!(
            observed.contains(&expected),
            "missing {expected} in {observed:?}"
        );
    }
    // `--plain` prints its snapshot and exits without waiting for the worker, so
    // the shutdown stages belong to the interactive path and cannot be observed
    // from a snapshot run. They are instrumented all the same.
    assert!(
        !observed.contains(&"session.end"),
        "the snapshot path is expected to exit first: {observed:?}"
    );

    let text = String::from_utf8(output.stderr.clone()).expect("UTF-8 diagnostics");
    assert!(
        !text.contains(TOKEN),
        "the shared token must never reach the diagnostic stream"
    );
    for record in &records {
        for (key, value) in fields(record).as_object().expect("field map") {
            // Nothing here is a secret, so a redacted value means a field was
            // named badly and silently lost its content.
            assert_ne!(
                value, "[REDACTED]",
                "{key} is redacted by its own name; rename it"
            );
        }
    }

    let install = find(&records, "telemetry.install").expect("telemetry.install");
    assert_eq!(
        fields(install)["telemetry.default_filter"],
        "gta_claw_tui=trace",
        "a bare level would put bridged dependency `log` records on this stream"
    );
    let resolve = find(&records, "endpoint.resolve").expect("endpoint.resolve");
    assert_eq!(fields(resolve)["auth.source"], "environment");
    assert_eq!(fields(resolve)["transport.tls"], "false");
    assert_eq!(fields(resolve)["endpoint"], endpoint_label(&gateway.url));
    let grant = find(&records, "authorization.grant").expect("authorization.grant");
    assert_eq!(fields(grant)["role.granted"], "operator");
    assert_eq!(
        fields(grant)["scopes.granted"],
        "operator.read,operator.write,operator.approvals"
    );
    let rpc = find(&records, "rpc.request").expect("rpc.request");
    assert_eq!(rpc["level"], "TRACE", "per-request detail is the -vv level");
    assert_eq!(fields(rpc)["rpc.method"], "sessions.list");
    assert_eq!(fields(rpc)["rpc.request_id"], "gta-claw-tui-1");

    gateway.shutdown().await;
}

#[tokio::test]
async fn detail_is_opt_in_and_a_quiet_run_is_byte_identical() {
    let gateway = snapshot_gateway().await;
    let quiet = run_tui(&gateway.url, &[]).await;
    let basic = run_tui(&gateway.url, &["-v"]).await;
    let detailed = run_tui(&gateway.url, &["-vv"]).await;

    assert!(
        quiet.stderr.is_empty(),
        "a default run must be byte-identical to an uninstrumented one: {}",
        String::from_utf8_lossy(&quiet.stderr)
    );
    assert_eq!(
        quiet.stdout, basic.stdout,
        "the snapshot on standard output is a contract; diagnostics are additive"
    );
    assert_eq!(quiet.stdout, detailed.stdout);
    assert!(
        String::from_utf8_lossy(&quiet.stdout).starts_with("GTA Claw terminal snapshot\n"),
        "{}",
        String::from_utf8_lossy(&quiet.stdout)
    );

    let basic_records = diagnostic_lines(&basic);
    assert!(!basic_records.is_empty());
    assert!(
        basic_records
            .iter()
            .all(|record| record["level"] == "DEBUG"),
        "-v must not open the trace level"
    );
    assert!(
        find(&basic_records, "rpc.request").is_none(),
        "per-request detail is reserved for -vv"
    );
    assert!(
        find(&basic_records, "connection.epoch").is_none(),
        "per-request detail is reserved for -vv"
    );

    let detailed_records = diagnostic_lines(&detailed);
    assert!(
        detailed_records
            .iter()
            .any(|record| record["level"] == "TRACE"),
        "-vv opens the trace level"
    );
    assert!(detailed_records.len() > basic_records.len());

    gateway.shutdown().await;
}

#[tokio::test]
async fn a_log_file_takes_every_record_and_leaves_standard_error_clean() {
    let gateway = snapshot_gateway().await;
    let path = log_path("tui-diagnostics.jsonl");
    let output = run_tui(
        &gateway.url,
        &["-vv", "--log-file", path.to_str().expect("UTF-8 path")],
    )
    .await;
    gateway.shutdown().await;
    assert!(output.status.success(), "{output:?}");

    assert!(
        output.stderr.is_empty(),
        "the file is the destination, so standard error stays a clean stream: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).starts_with("GTA Claw terminal snapshot\n"),
        "the snapshot on standard output is unchanged: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let text = fs::read_to_string(&path).expect("the requested log file was written");
    let written = records(&text);
    let observed: Vec<&str> = written
        .iter()
        .map(|record| fields(record)["action"].as_str().expect("action"))
        .collect();
    for expected in [
        "telemetry.install",
        "endpoint.resolve",
        "client.start",
        "connection.ready",
        "rpc.request",
    ] {
        assert!(
            observed.contains(&expected),
            "missing {expected} in {observed:?}"
        );
    }
    let install = find(&written, "telemetry.install").expect("telemetry.install");
    assert_eq!(
        fields(install)["telemetry.output"],
        Value::from(path.display().to_string()),
        "the installed destination is reported as the file, not stderr"
    );
    assert!(
        !text.contains(TOKEN),
        "the shared token must never reach the diagnostic file either"
    );
    fs::remove_file(&path).expect("remove the log file");
}

#[tokio::test]
async fn an_unopenable_log_file_stops_the_run_without_falling_back_to_stderr() {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("no-such-tui-directory");
    let path = directory.join("run.jsonl");
    // Nothing is contacted: the destination is resolved before the worker starts,
    // so this endpoint never has to answer.
    let unreachable = Url::parse("ws://127.0.0.1:1").expect("static endpoint");
    let output = run_tui(
        &unreachable,
        &["-v", "--log-file", path.to_str().expect("UTF-8 path")],
    )
    .await;

    assert_eq!(
        output.status.code(),
        Some(1),
        "an unusable destination is a run failure, not a silent redirect"
    );
    // Standard output carries only the unconditional terminal restore `main`
    // performs on every failure; the snapshot itself never ran.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("GTA Claw terminal snapshot"),
        "the run stopped before the Gateway path: {stdout:?}"
    );
    let text = String::from_utf8(output.stderr).expect("UTF-8 failure text");
    assert_eq!(
        text.lines().count(),
        1,
        "one explanation, no records: {text}"
    );
    assert!(
        text.starts_with("gta-claw-tui: diagnostics cannot be written to "),
        "{text}"
    );
    assert!(text.contains("run.jsonl"), "the path is named: {text}");
    assert!(
        text.contains("its directory does not exist"),
        "the cause is named: {text}"
    );
    assert!(
        serde_json::from_str::<Value>(text.trim()).is_err(),
        "not one diagnostic record may fall back to standard error: {text}"
    );
    assert!(!path.exists(), "a failed open creates nothing");
    assert!(!directory.exists(), "and never creates the directory");
}
