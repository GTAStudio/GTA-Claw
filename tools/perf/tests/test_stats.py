from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from perf_harness.stats import metric_stats, percentile, summarize_workload


class StatsTests(unittest.TestCase):
    def test_percentiles_use_linear_r7_interpolation(self) -> None:
        values = [1, 2, 3, 4, 5]
        self.assertEqual(percentile(values, 0), 1)
        self.assertEqual(percentile(values, 0.5), 3)
        self.assertAlmostEqual(percentile(values, 0.95), 4.8)
        self.assertAlmostEqual(percentile(values, 0.99), 4.96)
        self.assertEqual(percentile(values, 1), 5)

    def test_metric_stats_reports_all_retained_latency_points(self) -> None:
        summary = metric_stats([0.4, 0.1, 0.3, 0.2])
        assert summary is not None
        self.assertEqual(summary["min"], 0.1)
        self.assertEqual(summary["median"], 0.25)
        self.assertEqual(summary["max"], 0.4)

    def test_workload_summary_excludes_warmups_and_derives_throughput(self) -> None:
        workload = {
            "suite_id": "fixture",
            "id": "deterministic",
            "description": "fixture",
            "latency_class": "latency",
            "capacity": {"value": 10, "unit": "operations/invocation"},
            "operations_per_sample": 10,
        }
        samples = [
            _sample("warmup", "reference", "success", 100.0, 100, 10),
            _sample("measure", "reference", "success", 2.0, 200, 10),
            _sample("measure", "reference", "error", 3.0, None, 10),
            _sample("measure", "candidate", "success", 1.0, 220, 11),
        ]
        summary = summarize_workload(workload, samples)

        reference = summary["variants"]["reference"]
        candidate = summary["variants"]["candidate"]
        self.assertEqual(reference["sample_count"], 2)
        self.assertEqual(reference["success_count"], 1)
        self.assertEqual(reference["error_count"], 1)
        self.assertEqual(reference["throughput_per_second"]["median"], 5.0)
        self.assertEqual(candidate["throughput_per_second"]["median"], 10.0)
        self.assertEqual(candidate["artifact_size_bytes"]["max"], 11.0)


def _sample(
    phase: str,
    variant: str,
    status: str,
    wall: float,
    rss: int | None,
    artifact_size: int,
) -> dict[str, object]:
    return {
        "workload_id": "deterministic",
        "phase": phase,
        "variant": variant,
        "status": status,
        "wall_time_seconds": wall,
        "max_rss_bytes": rss,
        "operations": 10,
        "artifacts": [{"size_bytes": artifact_size}],
    }


if __name__ == "__main__":
    unittest.main()

