"""Command-line interface for the local performance harness."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from . import HARNESS_VERSION
from .config import (
    DEFAULT_THRESHOLDS,
    DEFAULT_WORKLOADS,
    ConfigError,
    load_catalog,
    load_thresholds,
    select_workloads,
)
from .orchestrator import LocalPerfHarness
from .storage import atomic_write_json


REPO_ROOT = Path(__file__).resolve().parents[3]


def main(arguments: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(arguments)
    try:
        catalog = load_catalog(args.catalog)
        thresholds = load_thresholds(args.thresholds)
        harness = LocalPerfHarness(REPO_ROOT, catalog, thresholds)
        if args.command == "list":
            return _list(harness, args)
        if args.command == "dry-run":
            return _dry_run(harness, catalog, args)
        if args.command == "run":
            return _run(harness, catalog, args)
        if args.command == "compare":
            return _compare(harness, args)
        parser.error("a command is required")
    except (
        ConfigError,
        FileNotFoundError,
        FileExistsError,
        json.JSONDecodeError,
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        print(f"perf: {error}", file=sys.stderr)
        return 2
    return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 tools/perf/perf.py",
        description="Retained, local-only reference/candidate performance harness.",
    )
    parser.add_argument("--version", action="version", version=HARNESS_VERSION)
    parser.add_argument(
        "--catalog",
        type=Path,
        default=DEFAULT_WORKLOADS,
        help="workload catalog JSON",
    )
    parser.add_argument(
        "--thresholds",
        type=Path,
        default=DEFAULT_THRESHOLDS,
        help="threshold configuration JSON",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    listing = commands.add_parser("list", help="list suites and host availability")
    listing.add_argument("--suite", action="append", default=[])
    listing.add_argument("--json", action="store_true", help="emit JSON")

    dry = commands.add_parser(
        "dry-run", help="resolve refs and print the exact plan without creating worktrees"
    )
    _add_plan_arguments(dry, output_required=False)

    run = commands.add_parser("run", help="execute and retain a local comparison run")
    _add_plan_arguments(run, output_required=True)
    run.add_argument(
        "--compare",
        action="store_true",
        help="evaluate the retained samples against the threshold policy",
    )
    run.add_argument(
        "--resume",
        action="store_true",
        help="recover run.partial.json and continue its unfinished slots",
    )
    run.add_argument(
        "--keep-worktrees",
        action="store_true",
        help="retain detached worktrees and build targets for local diagnosis",
    )

    compare = commands.add_parser(
        "compare", help="re-evaluate an existing retained run"
    )
    compare.add_argument("--input", type=Path, required=True, help="retained run JSON")
    compare.add_argument("--output", type=Path, required=True, help="comparison JSON")
    return parser


def _add_plan_arguments(
    parser: argparse.ArgumentParser, *, output_required: bool
) -> None:
    parser.add_argument("--reference", required=True, help="reference Git revision")
    parser.add_argument("--candidate", required=True, help="candidate Git revision")
    parser.add_argument(
        "--suite",
        action="append",
        default=[],
        help="suite id (repeat or use a comma-separated list; 'all' includes opt-in builds)",
    )
    parser.add_argument("--output", type=Path, required=output_required)
    parser.add_argument("--warmups", type=int)
    parser.add_argument("--repetitions", type=int)


def _list(harness: LocalPerfHarness, args: argparse.Namespace) -> int:
    requested = set(_suite_ids(args.suite))
    entries = [
        entry
        for entry in harness.list_workloads()
        if not requested or "all" in requested or entry["suite_id"] in requested
    ]
    known = {entry["suite_id"] for entry in harness.list_workloads()}
    unknown = sorted(requested - known - {"all"})
    if unknown:
        raise ConfigError(f"unknown suite(s): {', '.join(unknown)}")
    if args.json:
        print(json.dumps(entries, indent=2, sort_keys=True))
        return 0
    for entry in entries:
        marker = "*" if entry["default"] else " "
        print(
            f"{marker} {entry['suite_id']:<9} {entry['workload_id']:<36} "
            f"{entry['status']}"
        )
        for reason in entry["reasons"]:
            print(f"    BLOCKED: {reason}")
    return 0


def _dry_run(
    harness: LocalPerfHarness,
    catalog: dict[str, Any],
    args: argparse.Namespace,
) -> int:
    workloads = select_workloads(
        catalog,
        _suite_ids(args.suite),
        warmups=args.warmups,
        repetitions=args.repetitions,
    )
    plan = harness.dry_run(args.reference, args.candidate, workloads)
    if args.output is None:
        print(json.dumps(plan, indent=2, sort_keys=True))
    else:
        destination = _json_destination(args.output, "dry-run.json")
        atomic_write_json(destination, plan)
        print(destination)
    return 0


def _run(
    harness: LocalPerfHarness,
    catalog: dict[str, Any],
    args: argparse.Namespace,
) -> int:
    workloads = select_workloads(
        catalog,
        _suite_ids(args.suite),
        warmups=args.warmups,
        repetitions=args.repetitions,
    )
    document, exit_code = harness.run(
        reference_name=args.reference,
        candidate_name=args.candidate,
        workloads=workloads,
        output=args.output,
        compare=args.compare,
        resume=args.resume,
        keep_worktrees=args.keep_worktrees,
    )
    retained = (
        args.output.resolve() / "run.json"
        if document["status"] == "completed"
        else args.output.resolve() / "run.partial.json"
    )
    print(
        f"{document['status']} summary={document['summary']['status']} "
        f"output={retained}"
    )
    return exit_code


def _compare(harness: LocalPerfHarness, args: argparse.Namespace) -> int:
    document = json.loads(args.input.read_text(encoding="utf-8"))
    compared = harness.compare_retained(document)
    atomic_write_json(args.output, compared)
    print(f"{compared['summary']['status']} output={args.output.resolve()}")
    if compared["summary"]["status"] == "FAIL":
        return 1
    if compared["summary"]["status"] == "BLOCKED":
        return 3
    return 0


def _suite_ids(values: Sequence[str]) -> list[str]:
    return [
        suite.strip()
        for value in values
        for suite in value.split(",")
        if suite.strip()
    ]


def _json_destination(path: Path, default_name: str) -> Path:
    return path if path.suffix.lower() == ".json" else path / default_name
