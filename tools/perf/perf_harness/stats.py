"""Statistics over retained raw samples."""

from __future__ import annotations

import math
import statistics
from typing import Any, Iterable


def percentile(values: Iterable[float], quantile: float) -> float:
    """Compute an R7/linear percentile, including endpoints."""
    ordered = sorted(float(value) for value in values)
    if not ordered:
        raise ValueError("cannot compute a percentile of an empty sequence")
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be between zero and one")
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def metric_stats(values: Iterable[float]) -> dict[str, float] | None:
    collected = [float(value) for value in values]
    if not collected:
        return None
    return {
        "min": min(collected),
        "median": statistics.median(collected),
        "p95": percentile(collected, 0.95),
        "p99": percentile(collected, 0.99),
        "max": max(collected),
    }


def summarize_workload(
    workload: dict[str, Any], samples: Iterable[dict[str, Any]]
) -> dict[str, Any]:
    measured = [
        sample
        for sample in samples
        if sample.get("workload_id") == workload["id"]
        and sample.get("phase") == "measure"
    ]
    variants = {
        variant: _summarize_variant(
            variant,
            [sample for sample in measured if sample.get("variant") == variant],
        )
        for variant in ("reference", "candidate")
    }
    return {
        "suite_id": workload["suite_id"],
        "workload_id": workload["id"],
        "description": workload["description"],
        "latency_class": workload["latency_class"],
        "capacity": workload["capacity"],
        "operations_per_sample": workload["operations_per_sample"],
        "variants": variants,
    }


def _summarize_variant(
    variant: str, samples: list[dict[str, Any]]
) -> dict[str, Any]:
    successful = [sample for sample in samples if sample.get("status") == "success"]
    wall_times = [sample["wall_time_seconds"] for sample in successful]
    throughput = [
        sample["operations"] / sample["wall_time_seconds"]
        for sample in successful
        if sample.get("wall_time_seconds", 0) > 0
    ]
    rss = [
        sample["max_rss_bytes"]
        for sample in successful
        if sample.get("max_rss_bytes") is not None
    ]
    sizes = [
        sum(artifact["size_bytes"] for artifact in sample.get("artifacts", []))
        for sample in successful
        if sample.get("artifacts")
    ]
    return {
        "variant": variant,
        "sample_count": len(samples),
        "success_count": len(successful),
        "error_count": len(samples) - len(successful),
        "wall_time_seconds": metric_stats(wall_times),
        "throughput_per_second": metric_stats(throughput),
        "max_rss_bytes": metric_stats(rss),
        "artifact_size_bytes": metric_stats(sizes),
    }

