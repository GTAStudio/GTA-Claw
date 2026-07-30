from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from perf_harness.config import load_thresholds
from perf_harness.thresholds import evaluate_workload


class ThresholdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.thresholds = load_thresholds()

    def test_default_policy_accepts_values_at_every_boundary(self) -> None:
        summary = _summary(
            reference=_variant(throughput=100, latency=1, rss=100, size=100),
            candidate=_variant(
                throughput=95,
                latency=1.05,
                p95=1.10,
                p99=1.10,
                rss=110,
                size=105,
            ),
        )
        evaluated = evaluate_workload(summary, self.thresholds)
        self.assertEqual(evaluated["status"], "PASS")
        self.assertTrue(all(check["status"] == "PASS" for check in evaluated["checks"]))

    def test_each_regression_is_a_failure_not_a_warning(self) -> None:
        summary = _summary(
            reference=_variant(throughput=100, latency=1, rss=100, size=100),
            candidate=_variant(
                throughput=94,
                latency=1.06,
                p95=1.11,
                p99=1.12,
                rss=111,
                size=106,
            ),
        )
        evaluated = evaluate_workload(summary, self.thresholds)
        self.assertEqual(evaluated["status"], "FAIL")
        failed = {
            check["name"]
            for check in evaluated["checks"]
            if check["status"] == "FAIL"
        }
        self.assertEqual(
            failed,
            {
                "throughput",
                "median-latency",
                "p95-latency",
                "p99-latency",
                "max-rss",
                "artifact-size",
            },
        )

    def test_any_error_below_declared_capacity_fails(self) -> None:
        summary = _summary(
            reference=_variant(throughput=100, latency=1, rss=100, size=100),
            candidate=_variant(
                throughput=100,
                latency=1,
                rss=100,
                size=100,
                errors=1,
            ),
        )
        evaluated = evaluate_workload(summary, self.thresholds)
        errors = next(
            check
            for check in evaluated["checks"]
            if check["name"] == "zero-errors-below-capacity"
        )
        self.assertEqual(errors["status"], "FAIL")
        self.assertEqual(evaluated["status"], "FAIL")

    def test_unsupported_rss_is_explicitly_blocked(self) -> None:
        reference = _variant(throughput=100, latency=1, rss=100, size=100)
        candidate = _variant(throughput=100, latency=1, rss=100, size=100)
        reference["max_rss_bytes"] = None
        candidate["max_rss_bytes"] = None
        evaluated = evaluate_workload(
            _summary(reference=reference, candidate=candidate), self.thresholds
        )
        rss = next(
            check
            for check in evaluated["checks"]
            if check["name"] == "max-rss"
        )
        self.assertEqual(rss["status"], "BLOCKED")
        self.assertEqual(evaluated["status"], "BLOCKED")

    def test_zero_reference_metric_does_not_emit_non_json_infinity(self) -> None:
        reference = _variant(throughput=0, latency=1, rss=100, size=100)
        candidate = _variant(throughput=1, latency=1, rss=100, size=100)
        evaluated = evaluate_workload(
            _summary(reference=reference, candidate=candidate), self.thresholds
        )
        throughput = next(
            check
            for check in evaluated["checks"]
            if check["name"] == "throughput"
        )
        self.assertEqual(throughput["status"], "PASS")
        self.assertIsNone(throughput["ratio"])


def _summary(
    *, reference: dict[str, object], candidate: dict[str, object]
) -> dict[str, object]:
    return {
        "suite_id": "fixture",
        "workload_id": "fixture",
        "description": "fixture",
        "latency_class": "latency",
        "capacity": {"value": 10, "unit": "operations/invocation"},
        "operations_per_sample": 10,
        "variants": {"reference": reference, "candidate": candidate},
    }


def _variant(
    *,
    throughput: float,
    latency: float,
    rss: float,
    size: float,
    p95: float | None = None,
    p99: float | None = None,
    errors: int = 0,
) -> dict[str, object]:
    return {
        "sample_count": 6,
        "success_count": 6 - errors,
        "error_count": errors,
        "throughput_per_second": _metric(throughput),
        "wall_time_seconds": _metric(latency, p95=p95, p99=p99),
        "max_rss_bytes": _metric(rss),
        "artifact_size_bytes": _metric(size),
    }


def _metric(
    value: float, *, p95: float | None = None, p99: float | None = None
) -> dict[str, float]:
    return {
        "min": value,
        "median": value,
        "p95": value if p95 is None else p95,
        "p99": value if p99 is None else p99,
        "max": value,
    }


if __name__ == "__main__":
    unittest.main()
