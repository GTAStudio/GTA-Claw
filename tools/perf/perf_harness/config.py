"""Configuration loading and validation."""

from __future__ import annotations

import json
import math
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable


PERF_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKLOADS = PERF_ROOT / "config" / "workloads.json"
DEFAULT_THRESHOLDS = PERF_ROOT / "config" / "thresholds.json"


class ConfigError(ValueError):
    """Raised when a performance configuration is invalid."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=_reject_json_constant,
        )
    except FileNotFoundError as error:
        raise ConfigError(f"configuration does not exist: {path}") from error
    except json.JSONDecodeError as error:
        raise ConfigError(f"configuration is not valid JSON: {path}: {error}") from error
    if not isinstance(value, dict):
        raise ConfigError(f"configuration root must be an object: {path}")
    return value


def load_catalog(path: Path = DEFAULT_WORKLOADS) -> dict[str, Any]:
    catalog = load_json(path)
    validate_catalog(catalog)
    return catalog


def load_thresholds(path: Path = DEFAULT_THRESHOLDS) -> dict[str, Any]:
    thresholds = load_json(path)
    required = {
        "throughput_min_ratio",
        "median_max_ratio",
        "startup_max_ratio",
        "p95_max_ratio",
        "p99_max_ratio",
        "rss_max_ratio",
        "size_max_ratio",
        "max_errors_below_capacity",
    }
    missing = sorted(required - thresholds.keys())
    if thresholds.get("schema_version") != 1 or missing:
        raise ConfigError(
            "threshold configuration must use schema_version 1 and contain "
            + ", ".join(sorted(required))
        )
    ratio_fields = required - {"max_errors_below_capacity"}
    for field in sorted(ratio_fields):
        value = thresholds[field]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ConfigError(f"threshold {field} must be a positive number")
    maximum_errors = thresholds["max_errors_below_capacity"]
    if (
        isinstance(maximum_errors, bool)
        or not isinstance(maximum_errors, int)
        or maximum_errors < 0
    ):
        raise ConfigError(
            "threshold max_errors_below_capacity must be a non-negative integer"
        )
    return thresholds


def validate_catalog(catalog: dict[str, Any]) -> None:
    if catalog.get("definition_version") != 1:
        raise ConfigError("workload definition_version must be 1")
    defaults = catalog.get("defaults")
    suites = catalog.get("suites")
    if not isinstance(defaults, dict) or not isinstance(suites, list):
        raise ConfigError("workload catalog requires object defaults and array suites")
    _validate_counts(defaults.get("warmups"), defaults.get("repetitions"))
    _positive_number(defaults.get("timeout_seconds"), "defaults.timeout_seconds")

    suite_ids: set[str] = set()
    workload_ids: set[str] = set()
    for suite in suites:
        if not isinstance(suite, dict):
            raise ConfigError("every suite must be an object")
        suite_id = _identifier(suite.get("id"), "suite")
        if suite_id in suite_ids:
            raise ConfigError(f"duplicate suite id: {suite_id}")
        suite_ids.add(suite_id)
        workloads = suite.get("workloads")
        if not isinstance(workloads, list) or not workloads:
            raise ConfigError(f"suite {suite_id} has no workloads")
        for workload in workloads:
            if not isinstance(workload, dict):
                raise ConfigError(f"suite {suite_id} contains a non-object workload")
            workload_id = _identifier(workload.get("id"), "workload")
            if workload_id in workload_ids:
                raise ConfigError(f"duplicate workload id: {workload_id}")
            workload_ids.add(workload_id)
            command = workload.get("command")
            _validate_command(command, workload_id, "command")
            if "prepare_command" in workload:
                _validate_command(
                    workload["prepare_command"], workload_id, "prepare_command"
                )
            if workload.get("latency_class") not in {"latency", "startup"}:
                raise ConfigError(
                    f"workload {workload_id} latency_class must be latency or startup"
                )
            if workload.get("network_policy") not in {"none", "loopback-only"}:
                raise ConfigError(
                    f"workload {workload_id} network_policy must be none or loopback-only"
                )
            if workload.get("target_scope", "workload") not in {
                "workload",
                "sample",
            }:
                raise ConfigError(
                    f"workload {workload_id} target_scope must be workload or sample"
                )
            _string_mapping(
                workload.get("environment", {}),
                f"workload {workload_id} environment",
            )
            _string_list(
                workload.get("required_tools", []),
                f"workload {workload_id} required_tools",
            )
            _string_list(
                workload.get("required_paths", []),
                f"workload {workload_id} required_paths",
            )
            _string_list(
                workload.get("required_link_paths", []),
                f"workload {workload_id} required_link_paths",
            )
            if "platforms" in workload:
                _string_list(
                    workload["platforms"],
                    f"workload {workload_id} platforms",
                    non_empty=True,
                )
            capacity = workload.get("capacity")
            operations = workload.get("operations_per_sample")
            if (
                not isinstance(capacity, dict)
                or isinstance(capacity.get("value"), bool)
                or not isinstance(capacity.get("value"), int)
                or capacity["value"] <= 0
                or not isinstance(capacity.get("unit"), str)
                or not capacity["unit"]
                or isinstance(operations, bool)
                or not isinstance(operations, int)
                or operations <= 0
            ):
                raise ConfigError(f"workload {workload_id} requires a declared positive capacity")
            if operations > capacity["value"]:
                raise ConfigError(
                    f"workload {workload_id} exceeds its declared capacity "
                    f"({operations} > {capacity['value']})"
                )
            if "warmups" in workload or "repetitions" in workload:
                _validate_counts(
                    workload.get("warmups", defaults["warmups"]),
                    workload.get("repetitions", defaults["repetitions"]),
                )
            _positive_number(
                workload.get("timeout_seconds", defaults["timeout_seconds"]),
                f"workload {workload_id} timeout_seconds",
            )
            _validate_artifacts(workload.get("artifacts", []), workload_id)
            _validate_links(workload.get("links", []), workload_id)


def select_workloads(
    catalog: dict[str, Any],
    requested_suites: Iterable[str] | None,
    warmups: int | None = None,
    repetitions: int | None = None,
) -> list[dict[str, Any]]:
    requested = set(requested_suites or [])
    known = {suite["id"] for suite in catalog["suites"]}
    unknown = sorted(requested - known - {"all"})
    if unknown:
        raise ConfigError(f"unknown suite(s): {', '.join(unknown)}")
    explicit = bool(requested)
    select_all = "all" in requested
    selected: list[dict[str, Any]] = []
    defaults = catalog["defaults"]

    for suite in catalog["suites"]:
        suite_selected = (
            select_all
            or suite["id"] in requested
            or (not explicit and suite.get("enabled_by_default", False))
        )
        if not suite_selected:
            continue
        for source in suite["workloads"]:
            if (
                not explicit
                and not source.get("enabled_by_default", suite.get("enabled_by_default", False))
            ):
                continue
            workload = deepcopy(source)
            workload["suite_id"] = suite["id"]
            workload["suite_name"] = suite["name"]
            workload["warmups"] = (
                warmups
                if warmups is not None
                else workload.get("warmups", defaults["warmups"])
            )
            workload["repetitions"] = (
                repetitions
                if repetitions is not None
                else workload.get("repetitions", defaults["repetitions"])
            )
            workload["timeout_seconds"] = workload.get(
                "timeout_seconds", defaults["timeout_seconds"]
            )
            workload["target_scope"] = workload.get("target_scope", "workload")
            _validate_counts(workload["warmups"], workload["repetitions"])
            selected.append(workload)
    if not selected:
        raise ConfigError("suite selection contains no workloads")
    return selected


def _identifier(value: object, kind: str) -> str:
    if not isinstance(value, str) or not value or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in value
    ):
        raise ConfigError(f"{kind} id must be lowercase kebab-case: {value!r}")
    return value


def _validate_counts(warmups: object, repetitions: object) -> None:
    if isinstance(warmups, bool) or not isinstance(warmups, int) or warmups < 0:
        raise ConfigError("warmups must be a non-negative integer")
    if (
        isinstance(repetitions, bool)
        or not isinstance(repetitions, int)
        or repetitions < 2
        or repetitions % 2
    ):
        raise ConfigError("repetitions must be an even integer of at least 2 for exact ABBA")


def _validate_command(value: object, workload_id: str, field: str) -> None:
    if not isinstance(value, list) or not value or not all(
        isinstance(argument, str) and argument for argument in value
    ):
        raise ConfigError(
            f"workload {workload_id} requires a non-empty argv {field}"
        )


def _positive_number(value: object, field: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ConfigError(f"{field} must be a positive number")


def _string_mapping(value: object, field: str) -> None:
    if not isinstance(value, dict) or not all(
        isinstance(name, str)
        and name
        and isinstance(item, str)
        for name, item in value.items()
    ):
        raise ConfigError(f"{field} must map non-empty strings to strings")


def _string_list(value: object, field: str, *, non_empty: bool = False) -> None:
    if (
        not isinstance(value, list)
        or (non_empty and not value)
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ConfigError(f"{field} must be an array of non-empty strings")


def _validate_artifacts(value: object, workload_id: str) -> None:
    if not isinstance(value, list):
        raise ConfigError(f"workload {workload_id} artifacts must be an array")
    for artifact in value:
        if (
            not isinstance(artifact, dict)
            or not isinstance(artifact.get("path"), str)
            or not artifact["path"]
        ):
            raise ConfigError(
                f"workload {workload_id} artifacts require non-empty paths"
            )


def _validate_links(value: object, workload_id: str) -> None:
    if not isinstance(value, list):
        raise ConfigError(f"workload {workload_id} links must be an array")
    for link in value:
        if (
            not isinstance(link, dict)
            or not isinstance(link.get("source"), str)
            or not link["source"]
            or not isinstance(link.get("target"), str)
            or not link["target"]
        ):
            raise ConfigError(
                f"workload {workload_id} links require source and target strings"
            )


def _reject_json_constant(value: str) -> None:
    raise ConfigError(f"configuration contains non-finite JSON number: {value}")
