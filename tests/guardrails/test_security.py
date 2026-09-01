from __future__ import annotations

import ast
import contextlib
import io
import json
import unittest
from pathlib import Path

from planeon_harness.guardrail import (
    API_VERSION,
    PROFILE_KIND,
    DetectorAction,
    DetectorFinding,
    FailMode,
    GuardrailClient,
    GuardrailProfile,
    GuardrailStage,
)

from planeon_trust.guardrails.detectors import build_detectors, parse_specs


ROOT = Path(__file__).resolve().parents[2]


class _ThrowingDetector:
    detector_id = "detector.failure"

    def evaluate(self, request):
        raise RuntimeError("PRIVATE_DETECTOR_EXCEPTION_SENTINEL")


class _MalformedDetector:
    detector_id = "detector.malformed"

    def evaluate(self, request):
        return {"raw": "PRIVATE_MALFORMED_SENTINEL"}


class _AllowDetector:
    detector_id = "detector.allow"

    def evaluate(self, request):
        return DetectorFinding(self.detector_id, DetectorAction.ALLOW, "NO_MATCH")


def profile(detectors: tuple[str, ...], fail_mode: FailMode) -> GuardrailProfile:
    return GuardrailProfile(API_VERSION, PROFILE_KIND, "profile.failure", "1.0.0", GuardrailStage.OUTPUT, fail_mode, 1024, detectors)


class SecurityTests(unittest.TestCase):
    def test_throwing_and_malformed_detectors_never_leak_details(self) -> None:
        cases = (
            (profile(("detector.failure",), FailMode.FAIL_CLOSED), (_ThrowingDetector(),), "ERROR_FAIL_CLOSED"),
            (profile(("detector.failure", "detector.allow"), FailMode.FAIL_OPEN), (_ThrowingDetector(), _AllowDetector()), "ERROR_FAIL_OPEN"),
            (profile(("detector.malformed",), FailMode.FAIL_CLOSED), (_MalformedDetector(),), "ERROR_FAIL_CLOSED"),
        )
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            results = [GuardrailClient(item, detectors).evaluate("PRIVATE_REQUEST_SENTINEL") for item, detectors, _ in cases]
        for result, (_, _, outcome) in zip(results, cases, strict=True):
            self.assertEqual(result.outcome.value, outcome)
            serialized = result.canonical_json()
            self.assertNotIn("PRIVATE_", serialized)
            self.assertNotIn("RuntimeError", serialized)
        self.assertEqual(captured.getvalue(), "")

    def test_closed_redactor_uses_unicode_scalar_ranges_and_fixed_token(self) -> None:
        sdk_profile = GuardrailProfile(
            API_VERSION,
            PROFILE_KIND,
            "profile.unicode",
            "1.0.0",
            GuardrailStage.OUTPUT,
            FailMode.FAIL_CLOSED,
            1024,
            ("detector.secret",),
        )
        specs = parse_specs([{"detectorId": "detector.secret", "implementation": "SECRET_PATTERN_V1"}])
        result = GuardrailClient(sdk_profile, build_detectors(sdk_profile.detector_ids, specs)).evaluate("🔒 password=PRIVATE_UNICODE_VALUE end")
        self.assertEqual(result.outcome.value, "REDACT")
        self.assertEqual(result.redacted_content, "🔒 [REDACTED] end")
        self.assertNotIn("PRIVATE_UNICODE_VALUE", result.canonical_json())

    def test_guardrail_runtime_has_no_network_subprocess_or_dynamic_plugin_import(self) -> None:
        forbidden_modules = {"httpx", "requests", "socket", "subprocess", "urllib", "importlib"}
        files = list((ROOT / "src/planeon_trust/guardrails").glob("*.py")) + [ROOT / "services/guardrail-service/app.py"]
        for path in files:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imported = {
                node.names[0].name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import) and node.names
            } | {
                str(node.module).split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            }
            self.assertFalse(imported & forbidden_modules, f"{path}: {imported & forbidden_modules}")
            self.assertNotIn("__import__(", path.read_text(encoding="utf-8"))

    def test_packet_descriptor_is_cumulative_direct_argv_and_porting_stays_closed(self) -> None:
        descriptor = json.loads((ROOT / "ci/targets/trust-002.json").read_text(encoding="utf-8"))
        self.assertEqual(descriptor["packetId"], "TRUST-002")
        self.assertEqual(
            {target["name"] for target in descriptor["targets"]},
            {"prefetch", "guardrail-vectors", "streaming-failure-matrix", "security", "zero-bill"},
        )
        for target in descriptor["targets"]:
            self.assertEqual(target["acceptedVariables"], {})
            for command in target["argvTemplate"]:
                self.assertIsInstance(command, list)
                self.assertNotIn(Path(command[0]).name, {"sh", "bash", "zsh", "env"})
        porting = (ROOT / "PORTING.yaml").read_text(encoding="utf-8")
        self.assertIn("NO_AUTHORIZATION", porting)
        self.assertNotIn("COPY_AUTHORIZED", porting)

    def test_toolchain_and_contract_locks_are_local_exact_and_non_networked(self) -> None:
        lock = json.loads((ROOT / "ci/toolchains/trust-002.lock.json").read_text(encoding="utf-8"))
        upstream = json.loads((ROOT / "services/guardrail-service/contracts/upstream.lock.json").read_text(encoding="utf-8"))
        self.assertFalse(lock["networkRequired"])
        self.assertEqual(lock["wheelhouse"], "/opt/planeon/wheelhouse/trust-002")
        self.assertEqual(len(lock["packages"]), 4)
        self.assertEqual(upstream["sdk"]["commit"], "a181302f81bf6a83760cfae3890551ace89f51e4")
        self.assertEqual(upstream["contracts"]["entries"]["EvidenceRecord"], "sha256:05ea50ee0ad9fb74414871c8c3fa572e9f1a22bbc667194f911834f26b829674")
        self.assertFalse(upstream["contracts"]["guardrailCloudEventPresent"])


if __name__ == "__main__":
    unittest.main()
