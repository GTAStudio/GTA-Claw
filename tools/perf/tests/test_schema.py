from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from perf_harness.config import load_catalog
from perf_harness.schema import (
    RUN_SCHEMA_URI,
    SchemaError,
    load_schema,
    validate_run_document,
)


class SchemaTests(unittest.TestCase):
    def test_versioned_schema_and_catalog_are_loadable(self) -> None:
        schema = load_schema()
        catalog = load_catalog()
        self.assertEqual(schema["x-gta-claw-schema-version"], 1)
        self.assertEqual(catalog["definition_version"], 1)
        self.assertTrue(catalog["suites"])

    def test_minimal_run_document_satisfies_the_local_validator(self) -> None:
        validate_run_document(_document())

    def test_missing_raw_sample_command_is_rejected(self) -> None:
        document = _document()
        del document["raw_samples"][0]["command"]
        with self.assertRaisesRegex(SchemaError, r"raw_samples\[0\]\.command"):
            validate_run_document(document)

    def test_wrong_schema_version_is_rejected(self) -> None:
        document = copy.deepcopy(_document())
        document["schema_version"] = 2
        with self.assertRaisesRegex(SchemaError, "schema_version"):
            validate_run_document(document)

    def test_wrong_schema_uri_is_rejected(self) -> None:
        document = copy.deepcopy(_document())
        document["$schema"] = "schema/v1/perf-run.schema.json"
        with self.assertRaisesRegex(SchemaError, r"\$schema"):
            validate_run_document(document)


def _document() -> dict[str, object]:
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
        "raw_samples": [
            {
                "sample_id": "sample-1",
                "slot_id": "slot-1",
                "phase": "measure",
                "variant": "reference",
                "suite_id": "fixture",
                "workload_id": "fixture",
                "status": "running",
                "command": {"argv": ["true"], "cwd": ".", "environment": {}},
            }
        ],
        "summary": {"status": "NOT_COMPARED", "workloads": []},
    }


if __name__ == "__main__":
    unittest.main()
