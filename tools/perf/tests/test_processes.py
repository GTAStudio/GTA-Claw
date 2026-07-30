from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from perf_harness.processes import process_exists


class ProcessTests(unittest.TestCase):
    def test_current_process_exists(self) -> None:
        self.assertTrue(process_exists(os.getpid()))

    def test_nonpositive_process_ids_do_not_exist(self) -> None:
        self.assertFalse(process_exists(0))
        self.assertFalse(process_exists(-1))


if __name__ == "__main__":
    unittest.main()
