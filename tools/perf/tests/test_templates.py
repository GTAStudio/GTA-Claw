from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from perf_harness.templates import render_template


class TemplateTests(unittest.TestCase):
    def test_named_tokens_render_without_touching_javascript_braces(self) -> None:
        source = (
            "import { pathToFileURL } from 'node:url'; "
            "const { splitMessage } = module; "
            "const output = '{target_dir}/fixture.js';"
        )
        self.assertEqual(
            render_template(source, {"target_dir": "/tmp/target"}),
            (
                "import { pathToFileURL } from 'node:url'; "
                "const { splitMessage } = module; "
                "const output = '/tmp/target/fixture.js';"
            ),
        )

    def test_unknown_named_token_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing_path"):
            render_template("{missing_path}/fixture", {"target_dir": "/tmp"})


if __name__ == "__main__":
    unittest.main()
