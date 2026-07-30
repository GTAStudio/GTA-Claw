from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from perf_harness.orchestrator import _summary_exit_code, _uncompared_summary


class RunStateTests(unittest.TestCase):
    def test_uncompared_supported_run_is_not_misreported_as_passed(self) -> None:
        summary = _uncompared_summary(
            _document("SUPPORTED", sample_status="success")
        )
        self.assertEqual(summary["status"], "NOT_COMPARED")
        self.assertEqual(_summary_exit_code(summary["status"]), 0)

    def test_uncompared_unsupported_run_is_blocked(self) -> None:
        summary = _uncompared_summary(
            _document("BLOCKED", sample_status="blocked")
        )
        self.assertEqual(summary["status"], "BLOCKED")
        self.assertEqual(_summary_exit_code(summary["status"]), 3)

    def test_uncompared_execution_error_fails(self) -> None:
        summary = _uncompared_summary(
            _document("SUPPORTED", sample_status="error")
        )
        self.assertEqual(summary["status"], "FAIL")
        self.assertEqual(_summary_exit_code(summary["status"]), 1)


def _document(
    availability: str, *, sample_status: str
) -> dict[str, object]:
    return {
        "workloads": [
            {
                "availability": {
                    "reference": {"status": availability},
                    "candidate": {"status": availability},
                }
            }
        ],
        "raw_samples": [
            {
                "phase": "measure",
                "status": sample_status,
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()
