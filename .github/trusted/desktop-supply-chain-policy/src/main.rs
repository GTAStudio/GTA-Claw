//! Strict command-line entry point for the trusted validator.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use desktop_supply_chain_policy::changes::{compute_manifest, write_manifest};
use desktop_supply_chain_policy::input::SafeRoot;
use desktop_supply_chain_policy::metadata::linux_tools;
use desktop_supply_chain_policy::policy::{
    bootstrap_archive_fingerprint, verified_bootstrap_root_fingerprint, write_bootstrap_snapshot,
    write_final_dependency_fixtures,
};
use desktop_supply_chain_policy::validation::{ValidationRequest, validate_request};
use desktop_supply_chain_policy::workflows::linux_actionlint;
use desktop_supply_chain_policy::{PolicyError, PolicyResult};

fn parse_options(
    values: impl Iterator<Item = OsString>,
) -> PolicyResult<BTreeMap<String, PathBuf>> {
    let values = values.collect::<Vec<_>>();
    if values.len() % 2 != 0 {
        return Err(PolicyError::new(
            "every command option must have one argv value",
        ));
    }
    let mut options = BTreeMap::new();
    for pair in values.chunks_exact(2) {
        let key = pair[0]
            .to_str()
            .ok_or_else(|| PolicyError::new("command option name is not UTF-8"))?;
        if !key.starts_with("--") || key.len() == 2 {
            return Err(PolicyError::new(format!(
                "invalid command option name: {key:?}"
            )));
        }
        let key = key[2..].to_owned();
        let value = PathBuf::from(&pair[1]);
        if options.insert(key.clone(), value).is_some() {
            return Err(PolicyError::new(format!(
                "duplicate command option: --{key}"
            )));
        }
    }
    Ok(options)
}

fn required(options: &mut BTreeMap<String, PathBuf>, key: &str) -> PolicyResult<PathBuf> {
    options
        .remove(key)
        .ok_or_else(|| PolicyError::new(format!("missing required option --{key}")))
}

fn required_text(options: &mut BTreeMap<String, PathBuf>, key: &str) -> PolicyResult<String> {
    let value = required(options, key)?;
    value
        .into_os_string()
        .into_string()
        .map_err(|_| PolicyError::new(format!("option --{key} is not UTF-8")))
}

fn reject_unknown(options: &BTreeMap<String, PathBuf>) -> PolicyResult<()> {
    if options.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::new(format!(
            "unknown command options: {:?}",
            options.keys().collect::<Vec<_>>()
        )))
    }
}

fn diff_manifest(values: impl Iterator<Item = OsString>) -> PolicyResult<()> {
    let mut options = parse_options(values)?;
    let git = required(&mut options, "git")?;
    let trusted = required(&mut options, "trusted-repo")?;
    let candidate = required(&mut options, "candidate-repo")?;
    let isolated_home = required(&mut options, "isolated-home")?;
    let base = required_text(&mut options, "base")?;
    let head = required_text(&mut options, "head")?;
    let output = required(&mut options, "output")?;
    reject_unknown(&options)?;
    let manifest = compute_manifest(&git, &trusted, &candidate, &isolated_home, &base, &head)?;
    write_manifest(&output, &manifest)
}

fn fingerprint(values: impl Iterator<Item = OsString>) -> PolicyResult<()> {
    let mut options = parse_options(values)?;
    let root = options.remove("root");
    let snapshot = options.remove("snapshot");
    reject_unknown(&options)?;
    match (root, snapshot) {
        (None, Some(snapshot)) => {
            let (snapshot, fingerprint) = bootstrap_archive_fingerprint(&snapshot)?;
            println!(
                "bootstrap archive {} fingerprint {fingerprint}",
                snapshot.display()
            );
            Ok(())
        }
        (Some(root), Some(snapshot)) => {
            let root = SafeRoot::new(root)?;
            let (snapshot, fingerprint) = verified_bootstrap_root_fingerprint(&root, &snapshot)?;
            println!(
                "verified materialized Bootstrap root {} against bootstrap archive {} fingerprint {fingerprint}",
                root.path().display(),
                snapshot.display()
            );
            Ok(())
        }
        (Some(_), None) => Err(PolicyError::new(
            "bootstrap fingerprint --root requires --snapshot for exact archive verification; \
             live/Final roots must not be fingerprinted directly; use \
             `bootstrap-fingerprint --snapshot <archive>`",
        )),
        (None, None) => Err(PolicyError::new(
            "bootstrap fingerprint requires --snapshot; use --root only with the same \
             --snapshot for an exact materialization check",
        )),
    }
}

fn snapshot(values: impl Iterator<Item = OsString>) -> PolicyResult<()> {
    let mut options = parse_options(values)?;
    let root = required(&mut options, "root")?;
    let output = required(&mut options, "output")?;
    reject_unknown(&options)?;
    let delta = write_bootstrap_snapshot(&SafeRoot::new(root)?, &output)?;
    println!("{delta}");
    Ok(())
}

fn final_dependency_fixtures(values: impl Iterator<Item = OsString>) -> PolicyResult<()> {
    let mut options = parse_options(values)?;
    let root = required(&mut options, "root")?;
    reject_unknown(&options)?;
    write_final_dependency_fixtures(&SafeRoot::new(root)?)
}

fn validate(values: impl Iterator<Item = OsString>) -> PolicyResult<()> {
    let mut options = parse_options(values)?;
    let trusted_root = required(&mut options, "trusted-root")?;
    let candidate_root = required(&mut options, "candidate-root")?;
    let changes = required(&mut options, "changes")?;
    let cargo = required(&mut options, "cargo")?;
    let rustc = required(&mut options, "rustc")?;
    let actionlint = required(&mut options, "actionlint")?;
    let isolation_root = required(&mut options, "isolation-root")?;
    reject_unknown(&options)?;
    let evidence = validate_request(&ValidationRequest {
        trusted_root,
        candidate_root,
        changes,
        metadata_tools: linux_tools(cargo, rustc),
        actionlint: linux_actionlint(actionlint),
        isolation_root,
    })?;
    println!(
        "desktop supply-chain policy passed: base_state={:?} relevant_change={} candidate_final={} changed_paths={} base={} head={}",
        evidence.base_state,
        evidence.relevant_change,
        evidence.candidate_final,
        evidence.changed_paths,
        evidence.base,
        evidence.head
    );
    Ok(())
}

fn run() -> PolicyResult<()> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let command = arguments
        .next()
        .ok_or_else(|| PolicyError::new("missing validator command"))?;
    match command.to_str() {
        Some("diff-manifest") => diff_manifest(arguments),
        Some("bootstrap-fingerprint") => fingerprint(arguments),
        Some("write-bootstrap-snapshot") => snapshot(arguments),
        Some("write-final-dependency-fixtures") => final_dependency_fixtures(arguments),
        Some("validate") => validate(arguments),
        Some(other) => Err(PolicyError::new(format!(
            "unknown validator command: {other}"
        ))),
        None => Err(PolicyError::new("validator command is not UTF-8")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("desktop supply-chain policy failed: {error}");
            ExitCode::FAILURE
        }
    }
}
