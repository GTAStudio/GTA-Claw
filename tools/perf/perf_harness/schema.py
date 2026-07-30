"""Small stdlib validator for the retained run contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import SCHEMA_VERSION


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schema" / "v1" / "perf-run.schema.json"
)
RUN_SCHEMA_URI = (
    "https://raw.githubusercontent.com/GTAStudio/GTA-Claw/main/"
    "tools/perf/schema/v1/perf-run.schema.json"
)


class SchemaError(ValueError):
    """Raised when a retained run document violates the local contract."""


def load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("x-gta-claw-schema-version") != SCHEMA_VERSION:
        raise SchemaError("schema file version does not match the harness")
    return value


def validate_run_document(document: dict[str, Any]) -> None:
    errors: list[str] = []
    if not isinstance(document, dict):
        raise SchemaError("run document must be an object")
    required_top = {
        "$schema",
        "schema_version",
        "run_id",
        "status",
        "created_at",
        "updated_at",
        "metadata",
        "workloads",
        "raw_samples",
        "summary",
    }
    missing = sorted(required_top - document.keys())
    if missing:
        errors.append(f"missing top-level fields: {', '.join(missing)}")
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    if document.get("$schema") != RUN_SCHEMA_URI:
        errors.append(f"$schema must be {RUN_SCHEMA_URI}")
    if document.get("status") not in {
        "running",
        "completed",
        "interrupted",
        "failed",
    }:
        errors.append("invalid run status")
    for field in ("workloads", "raw_samples"):
        if field in document and not isinstance(document[field], list):
            errors.append(f"{field} must be an array")
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        for field in (
            "harness",
            "repository",
            "toolchains",
            "environment",
            "configuration",
            "thresholds",
        ):
            if field not in metadata:
                errors.append(f"metadata.{field} is required")
    elif "metadata" in document:
        errors.append("metadata must be an object")
    summary = document.get("summary")
    if not isinstance(summary, dict) or "status" not in summary:
        errors.append("summary must be an object with status")
    elif summary["status"] not in {
        "NOT_COMPARED",
        "PASS",
        "FAIL",
        "BLOCKED",
        "INTERRUPTED",
    }:
        errors.append("summary.status is invalid")
    for index, sample in enumerate(document.get("raw_samples", [])):
        if not isinstance(sample, dict):
            errors.append(f"raw_samples[{index}] must be an object")
            continue
        for field in (
            "sample_id",
            "slot_id",
            "phase",
            "variant",
            "suite_id",
            "workload_id",
            "status",
            "command",
        ):
            if field not in sample:
                errors.append(f"raw_samples[{index}].{field} is required")
        if sample.get("phase") not in {"prepare", "warmup", "measure"}:
            errors.append(f"raw_samples[{index}].phase is invalid")
        if sample.get("variant") not in {"reference", "candidate"}:
            errors.append(f"raw_samples[{index}].variant is invalid")
        if sample.get("status") not in {
            "running",
            "success",
            "error",
            "timeout",
            "interrupted",
            "blocked",
        }:
            errors.append(f"raw_samples[{index}].status is invalid")
        command = sample.get("command")
        if isinstance(command, dict):
            if (
                not isinstance(command.get("argv"), list)
                or not command["argv"]
                or not all(isinstance(item, str) and item for item in command["argv"])
            ):
                errors.append(f"raw_samples[{index}].command.argv is invalid")
            if not isinstance(command.get("cwd"), str) or not command["cwd"]:
                errors.append(f"raw_samples[{index}].command.cwd is invalid")
            if not isinstance(command.get("environment"), dict):
                errors.append(
                    f"raw_samples[{index}].command.environment is invalid"
                )
        elif "command" in sample:
            errors.append(f"raw_samples[{index}].command must be an object")
    if errors:
        raise SchemaError("; ".join(errors))
