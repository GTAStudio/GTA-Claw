//! CI command-line entry point for the conformance harness.

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use claw_conformance::{
    ClaimFileKey, ConformanceError, Contract, DiscoveredClaimFile, Registry, discover_claim_files,
    generate_report, open_claim_file,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Human,
    Json,
    Both,
}

#[derive(Debug)]
struct Arguments {
    contract_root: PathBuf,
    claim_files: Vec<PathBuf>,
    format: OutputFormat,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("claw-conformance: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let raw_arguments = env::args().skip(1).collect::<Vec<_>>();
    if raw_arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), "--help" | "-h"))
    {
        print_usage();
        return Ok(());
    }
    let arguments = parse_arguments(raw_arguments.into_iter())?;
    let contract = Contract::load(&arguments.contract_root)
        .map_err(|error| conformance_error("contract load", &error))?;
    let repository_root = repository_root(&arguments.contract_root)?;
    let discovered_claims = discover_claim_files(&repository_root)
        .map_err(|error| conformance_error("claim discovery", &error))?;
    let mut claim_files: BTreeMap<ClaimFileKey, DiscoveredClaimFile> = BTreeMap::new();
    for claim in discovered_claims {
        claim_files.insert(claim.key().clone(), claim);
    }
    for path in arguments.claim_files {
        let claim = open_claim_file(&path)
            .map_err(|error| conformance_error("explicit claim opening", &error))?;
        claim_files.entry(claim.key().clone()).or_insert(claim);
    }

    let mut claim_files = claim_files.into_values().collect::<Vec<_>>();
    claim_files.sort_by(|left, right| left.path().cmp(right.path()));
    let mut registry = Registry::new();
    for claim in claim_files {
        registry
            .load_discovered_claim_file(claim)
            .map_err(|error| conformance_error("claim loading", &error))?;
    }
    let report = generate_report(&contract, &registry, &repository_root)
        .map_err(|error| conformance_error("report generation", &error))?;
    match arguments.format {
        OutputFormat::Human => print!("{}", report.to_human_table()),
        OutputFormat::Json => println!(
            "{}",
            report
                .to_pretty_json()
                .map_err(|error| format!("cannot serialize parity report: {error}"))?
        ),
        OutputFormat::Both => {
            print!("{}", report.to_human_table());
            println!("Machine-readable JSON:");
            println!(
                "{}",
                report
                    .to_pretty_json()
                    .map_err(|error| format!("cannot serialize parity report: {error}"))?
            );
        }
    }
    Ok(())
}

fn conformance_error(stage: &str, error: &ConformanceError) -> String {
    format!("{stage} failed [{}]: {error}", error.code().as_str())
}

fn parse_arguments(mut arguments: impl Iterator<Item = String>) -> Result<Arguments, String> {
    let mut contract_root = PathBuf::from("compat/upstream");
    let mut claim_files = Vec::new();
    let mut format = OutputFormat::Human;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--root" => {
                contract_root = PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--root requires a path".to_owned())?,
                );
            }
            "--claims" => {
                claim_files.push(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--claims requires a path".to_owned())?,
                ));
            }
            "--format" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--format requires human, json, or both".to_owned())?;
                format = match value.as_str() {
                    "human" => OutputFormat::Human,
                    "json" => OutputFormat::Json,
                    "both" => OutputFormat::Both,
                    _ => return Err(format!("unsupported output format '{value}'")),
                };
            }
            _ => return Err(format!("unknown argument '{argument}'")),
        }
    }
    Ok(Arguments {
        contract_root,
        claim_files,
        format,
    })
}

fn print_usage() {
    println!(
        "Usage: claw-conformance [--root compat/upstream] [--claims FILE]... [--format human|json|both]"
    );
}

fn repository_root(contract_root: &Path) -> Result<PathBuf, String> {
    let absolute = if contract_root.is_absolute() {
        contract_root.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| format!("cannot read current directory: {error}"))?
            .join(contract_root)
    };
    let compat = absolute
        .parent()
        .ok_or_else(|| "contract root has no compat parent".to_owned())?;
    let repository = compat
        .parent()
        .ok_or_else(|| "contract root has no repository parent".to_owned())?;
    Ok(repository.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::{OutputFormat, parse_arguments};

    #[test]
    fn arguments_accept_multiple_claim_files() {
        let parsed = parse_arguments(
            [
                "--root", "fixture", "--claims", "a.json", "--claims", "b.json", "--format", "both",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("parse arguments");
        assert_eq!(parsed.contract_root.to_string_lossy(), "fixture");
        assert_eq!(
            parsed
                .claim_files
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec!["a.json".to_owned(), "b.json".to_owned()]
        );
        assert_eq!(parsed.format, OutputFormat::Both);
    }
}
