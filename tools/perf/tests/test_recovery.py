from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from perf_harness.schedule import abba_variants, build_schedule, remaining_slots
from perf_harness.schema import RUN_SCHEMA_URI
from perf_harness.storage import recover_interrupted_document, sha256_json


class RecoveryTests(unittest.TestCase):
    def test_abba_schedule_is_exact_and_balanced(self) -> None:
        self.assertEqual(
            abba_variants(4),
            [
                "reference",
                "candidate",
                "candidate",
                "reference",
                "reference",
                "candidate",
                "candidate",
                "reference",
            ],
        )

    def test_recovery_marks_inflight_attempt_and_reschedules_its_slot(self) -> None:
        workload = {
            "id": "fixture",
            "suite_id": "fixture-suite",
            "warmups": 0,
            "repetitions": 2,
        }
        schedule = build_schedule([workload])
        first = schedule[0]
        second = schedule[1]
        document = _document(
            [
                _sample(first, "running"),
                _sample(second, "success"),
            ]
        )

        recovered = recover_interrupted_document(document)
        self.assertEqual(recovered["status"], "running")
        self.assertEqual(recovered["raw_samples"][0]["status"], "interrupted")
        slots = [slot["slot_id"] for slot in remaining_slots(schedule, recovered["raw_samples"])]
        self.assertIn(first["slot_id"], slots)
        self.assertNotIn(second["slot_id"], slots)

    def test_terminal_errors_are_retained_instead_of_retried(self) -> None:
        workload = {
            "id": "fixture",
            "suite_id": "fixture-suite",
            "warmups": 0,
            "repetitions": 2,
        }
        schedule = build_schedule([workload])
        failed = schedule[0]
        slots = remaining_slots(schedule, [_sample(failed, "error")])
        self.assertNotIn(failed["slot_id"], {slot["slot_id"] for slot in slots})

    def test_retained_json_hash_rejects_nonfinite_numbers(self) -> None:
        with self.assertRaises(ValueError):
            sha256_json({"invalid": float("nan")})


def _document(samples: list[dict[str, object]]) -> dict[str, object]:
    return {
        "$schema": RUN_SCHEMA_URI,
        "schema_version": 1,
        "run_id": "fixture",
        "status": "running",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "metadata": {
            "harness": {},
            "repository": {},
            "toolchains": [],
            "environment": {},
            "configuration": {},
            "thresholds": {},
        },
        "workloads": [],
        "raw_samples": samples,
        "summary": {"status": "NOT_COMPARED", "workloads": []},
    }


def _sample(slot: dict[str, object], status: str) -> dict[str, object]:
    return {
        "sample_id": f"{slot['slot_id']}:attempt-1",
        **slot,
        "status": status,
        "command": {"argv": ["fixture"], "cwd": ".", "environment": {}},
    }


if __name__ == "__main__":
    unittest.main()
