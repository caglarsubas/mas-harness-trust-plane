from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from planeon_trust.common.json_io import JsonContractError
from planeon_trust.usage.module_contracts import validate_backend_contract, validate_collector_contract

from .support import ROOT


class ModuleContractTests(unittest.TestCase):
    def test_collector_and_external_backends_are_closed_and_inert(self) -> None:
        collector = validate_collector_contract(ROOT / "modules/otel-collector/module.json")
        metrics = validate_backend_contract(ROOT / "modules/prometheus/backend-contract.json", signal="METRICS")
        traces = validate_backend_contract(ROOT / "modules/jaeger/backend-contract.json", signal="TRACES")
        self.assertFalse(collector["enabled"])
        self.assertEqual(collector["artifactState"], "SOURCE_CONTRACT_ONLY")
        for backend in (metrics, traces):
            self.assertEqual(backend["ownership"], "TENANT_SUPPLIED_EXTERNAL")
            self.assertFalse(backend["builtByRepository"])
            self.assertTrue(backend["tenantAttestationRequired"])

    def test_collector_rejects_literal_network_authority(self) -> None:
        source = json.loads((ROOT / "modules/otel-collector/module.json").read_text(encoding="utf-8"))
        source["network"]["urlLiteralsAllowed"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "collector.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaises(JsonContractError):
                validate_collector_contract(path)

    def test_backend_rejects_product_ownership_or_direct_network_configuration(self) -> None:
        source = json.loads((ROOT / "modules/prometheus/backend-contract.json").read_text(encoding="utf-8"))
        source["builtByRepository"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backend.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaises(JsonContractError):
                validate_backend_contract(path, signal="METRICS")

    def test_module_sources_contain_no_url_or_public_host(self) -> None:
        for path in sorted((ROOT / "modules").rglob("*.json")):
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("http" + "://", raw)
            self.assertNotIn("https" + "://", raw)
            document = json.loads(raw)
            self.assertNotIn("host", document.get("network", {}))


if __name__ == "__main__":
    unittest.main()
