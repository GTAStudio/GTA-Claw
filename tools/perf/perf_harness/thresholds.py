"""Reference/candidate regression threshold evaluation."""

from __future__ import annotations

from typing import Any


def evaluate_workload(
    summary: dict[str, Any], thresholds: dict[str, Any]
) -> dict[str, Any]:
    reference = summary["variants"]["reference"]
    candidate = summary["variants"]["candidate"]
    checks: list[dict[str, Any]] = []

    within_capacity = (
        summary["operations_per_sample"] <= summary["capacity"]["value"]
    )
    if within_capacity:
        errors = reference["error_count"] + candidate["error_count"]
        limit = thresholds["max_errors_below_capacity"]
        checks.append(
            _check(
                "zero-errors-below-capacity",
                "PASS" if errors <= limit else "FAIL",
                errors,
                limit,
                "total command errors across both variants",
            )
        )
    else:
        checks.append(
            _check(
                "zero-errors-below-capacity",
                "BLOCKED",
                summary["operations_per_sample"],
                summary["capacity"]["value"],
                "workload exceeds its declared capacity",
            )
        )

    checks.append(
        _ratio_check(
            "throughput",
            reference["throughput_per_second"],
            candidate["throughput_per_second"],
            "median",
            thresholds["throughput_min_ratio"],
            minimum=True,
        )
    )
    median_limit = (
        thresholds["startup_max_ratio"]
        if summary["latency_class"] == "startup"
        else thresholds["median_max_ratio"]
    )
    checks.append(
        _ratio_check(
            "startup" if summary["latency_class"] == "startup" else "median-latency",
            reference["wall_time_seconds"],
            candidate["wall_time_seconds"],
            "median",
            median_limit,
            minimum=False,
        )
    )
    checks.append(
        _ratio_check(
            "p95-latency",
            reference["wall_time_seconds"],
            candidate["wall_time_seconds"],
            "p95",
            thresholds["p95_max_ratio"],
            minimum=False,
        )
    )
    checks.append(
        _ratio_check(
            "p99-latency",
            reference["wall_time_seconds"],
            candidate["wall_time_seconds"],
            "p99",
            thresholds["p99_max_ratio"],
            minimum=False,
        )
    )
    checks.append(
        _ratio_check(
            "max-rss",
            reference["max_rss_bytes"],
            candidate["max_rss_bytes"],
            "max",
            thresholds["rss_max_ratio"],
            minimum=False,
        )
    )
    checks.append(
        _ratio_check(
            "artifact-size",
            reference["artifact_size_bytes"],
            candidate["artifact_size_bytes"],
            "max",
            thresholds["size_max_ratio"],
            minimum=False,
        )
    )

    statuses = {check["status"] for check in checks}
    status = "FAIL" if "FAIL" in statuses else "BLOCKED" if "BLOCKED" in statuses else "PASS"
    evaluated = dict(summary)
    evaluated["status"] = status
    evaluated["checks"] = checks
    return evaluated


def _ratio_check(
    name: str,
    reference_stats: dict[str, float] | None,
    candidate_stats: dict[str, float] | None,
    statistic: str,
    limit: float,
    *,
    minimum: bool,
) -> dict[str, Any]:
    if reference_stats is None or candidate_stats is None:
        return _check(name, "BLOCKED", None, limit, f"{statistic} metric is unavailable")
    reference = reference_stats[statistic]
    candidate = candidate_stats[statistic]
    if reference == 0:
        ratio = 1.0 if candidate == 0 else None
        passed = candidate > 0 if minimum else candidate == 0
    else:
        ratio = candidate / reference
        passed = ratio >= limit if minimum else ratio <= limit
    direction = "minimum" if minimum else "maximum"
    return {
        "name": name,
        "status": "PASS" if passed else "FAIL",
        "statistic": statistic,
        "reference": reference,
        "candidate": candidate,
        "ratio": ratio,
        "limit": limit,
        "direction": direction,
    }

def _check(
    name: str, status: str, actual: Any, limit: Any, detail: str
) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "actual": actual,
        "limit": limit,
        "detail": detail,
    }
