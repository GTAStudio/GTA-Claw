//! CI command-line entry point for the conformance harness.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use claw_conformance::{
    Contract, Registry, ReportOptions, discover_claim_files, generate_report_with_options,
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
    verify_libtest_membership: bool,
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
    let contract = Contract::load(&arguments.contract_root).map_err(|error| error.to_string())?;
    let repository_root = repository_root(&arguments.contract_root)?;
    let mut claim_files =
        discover_claim_files(&repository_root).map_err(|error| error.to_string())?;
    claim_files.extend(arguments.claim_files);
    let claim_files = claim_files
        .into_iter()
        .map(|path| {
            fs::canonicalize(&path)
                .map_err(|error| format!("cannot resolve claim file '{}': {error}", path.display()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    let mut registry = Registry::new();
    for path in claim_files {
        registry
            .load_claims_file(path)
            .map_err(|error| error.to_string())?;
    }
    let mut report_options = ReportOptions::default();
    if arguments.verify_libtest_membership {
        report_options = report_options.with_libtest_membership_verification();
    }
    let report =
        generate_report_with_options(&contract, &registry, &repository_root, report_options)
            .map_err(|error| error.to_string())?;
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

fn parse_arguments(arguments: impl Iterator<Item = String>) -> Result<Arguments, String> {
    let mut arguments = arguments.peekable();
    let mut contract_root = PathBuf::from("compat/upstream");
    let mut claim_files = Vec::new();
    let mut format = OutputFormat::Human;
    let mut verify_libtest_membership = false;
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
            "--verify-libtest-membership" => verify_libtest_membership = true,
            _ => return Err(format!("unknown argument '{argument}'")),
        }
    }
    Ok(Arguments {
        contract_root,
        claim_files,
        format,
        verify_libtest_membership,
    })
}

fn print_usage() {
    println!(
        "Usage: claw-conformance [--root compat/upstream] [--claims FILE]... \
         [--format human|json|both] [--verify-libtest-membership]"
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
                "--root",
                "fixture",
                "--claims",
                "a.json",
                "--claims",
                "b.json",
                "--format",
                "both",
                "--verify-libtest-membership",
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
        assert!(parsed.verify_libtest_membership);
    }
}
