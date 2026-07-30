from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from perf_harness.inventory import child_environment
from perf_harness.runner import CommandRunner


class CommandCaptureTests(unittest.TestCase):
    def test_stdout_stderr_exit_status_and_command_are_retained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            result = CommandRunner(output).run(
                sample_id="capture",
                argv=[
                    sys.executable,
                    "-c",
                    "import sys; print('captured'); print('warning', file=sys.stderr)",
                ],
                cwd=output,
                environment=child_environment(),
                timeout_seconds=5,
            )

            self.assertEqual(result["status"], "success")
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["command"]["argv"][0], sys.executable)
            self.assertFalse(result["command"]["shell"])
            self.assertIsNotNone(result["stdout"]["sha256"])
            self.assertIsNotNone(result["stderr"]["sha256"])
            self.assertEqual(
                (output / result["stdout"]["path"]).read_text(encoding="utf-8"),
                "captured\n",
            )
            self.assertEqual(
                (output / result["stderr"]["path"]).read_text(encoding="utf-8"),
                "warning\n",
            )

    def test_nonzero_exit_is_an_error_with_exact_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            result = CommandRunner(output).run(
                sample_id="failure",
                argv=[sys.executable, "-c", "raise SystemExit(7)"],
                cwd=output,
                environment=child_environment(),
                timeout_seconds=5,
            )
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["exit_code"], 7)


if __name__ == "__main__":
    unittest.main()

