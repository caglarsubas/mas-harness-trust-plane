from __future__ import annotations

import hashlib
import json
import platform
import unittest
from pathlib import Path

import planeon_harness.attributes
import planeon_harness.context
import planeon_harness.decorators

from planeon_trust.usage.config import load_usage_config
from planeon_trust.usage.dimensions import DIMENSIONS, PUBLIC_MAXIMA

from .support import ROOT


class UsageContractTests(unittest.TestCase):
    def test_upstream_lock_and_dependency_closure_are_exact(self) -> None:
        lock = json.loads((ROOT / "services/usage-ledger/contracts/upstream.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock["contracts"]["commit"], "2146278a95344cd2a8e22596b2f315b46edffc88")
        self.assertEqual(lock["sdkTelemetry"]["commit"], "92a8ebf8e705eb2bf7a4e5be89edc5e8aa062c08")
        expected = {
            planeon_harness.context: lock["sdkTelemetry"]["contextSha256"],
            planeon_harness.attributes: lock["sdkTelemetry"]["attributesSha256"],
            planeon_harness.decorators: lock["sdkTelemetry"]["decoratorsSha256"],
        }
        for module, digest in expected.items():
            self.assertEqual(hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest(), digest)
            self.assertIn("/opt/planeon/toolchains/trust-002/", str(Path(module.__file__).resolve()))
        self.assertEqual(hashlib.sha256((ROOT / "pyproject.toml").read_bytes()).hexdigest(), "9d5cab5e815621d362fd4d6fd3b1a632d2c1bf06f1db8338ebb50dd5d2eda266")
        self.assertEqual(hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest(), "7b96ed608236c1fb1ceedf61d4ed94de68d6d518cbc9a4da4162a2d93b974502")
        self.assertEqual(platform.python_version(), "3.12.14")

    def test_public_dimension_names_and_limits_are_preserved(self) -> None:
        self.assertEqual(DIMENSIONS[:5], ("concurrentTasks", "taskSeconds", "retries", "toolCalls", "modelTokens"))
        self.assertEqual(dict(PUBLIC_MAXIMA), {"concurrentTasks": 1024, "taskSeconds": 86400, "retries": 100, "toolCalls": 10000, "modelTokens": 10000000})
        contract = json.loads((ROOT / "services/usage-ledger/contracts/usage-api.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(tuple(contract["properties"]["dimensions"]["const"]), DIMENSIONS)

    def test_local_config_is_closed_and_complete(self) -> None:
        budgets, buffer = load_usage_config(ROOT / "fixtures/usage/config.json")
        self.assertEqual(len(budgets), 2)
        self.assertEqual({item.enforcement for item in budgets}, {"HARD", "ADVISORY"})
        self.assertEqual(buffer, {"maximumRecords": 128, "maximumBytes": 1048576, "maximumAgeSeconds": 300})
        vectors = json.loads((ROOT / "fixtures/usage/usage-vectors.json").read_text(encoding="utf-8"))
        self.assertEqual(vectors["source"], "INDEPENDENT_CLEAN_ROOM")
        self.assertEqual(len(vectors["cases"]), 18)


if __name__ == "__main__":
    unittest.main()
