"""Build comparison summaries from retained raw samples."""

from __future__ import annotations

from typing import Any

from .stats import summarize_workload
from .thresholds import evaluate_workload


def compare_document(
    document: dict[str, Any], thresholds: dict[str, Any]
) -> dict[str, Any]:
    summaries: list[dict[str, Any]] = []
    for workload in document["workloads"]:
        availability = workload.get("availability", {})
        unavailable = [
            f"{variant}: {value.get('reason', value.get('status', 'unknown'))}"
            for variant, value in availability.items()
            if value.get("status") != "SUPPORTED"
        ]
        if unavailable:
            status = (
                "FAIL"
                if any(
                    value.get("status") == "ERROR"
                    for value in availability.values()
                )
                else "BLOCKED"
            )
            summaries.append(
                {
                    "suite_id": workload["suite_id"],
                    "workload_id": workload["id"],
                    "description": workload["description"],
                    "status": status,
                    "blocked_reasons": unavailable,
                    "checks": [],
                }
            )
            continue
        summary = summarize_workload(workload, document["raw_samples"])
        summaries.append(evaluate_workload(summary, thresholds))

    statuses = {summary["status"] for summary in summaries}
    overall = "FAIL" if "FAIL" in statuses else "BLOCKED" if "BLOCKED" in statuses else "PASS"
    return {"status": overall, "workloads": summaries}

