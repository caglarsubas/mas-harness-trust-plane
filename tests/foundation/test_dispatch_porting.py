from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci.run_make_target import TargetDescriptorError, dispatch, load_rules
from ci.validate_porting import main as validate_porting

from tests.foundation.support import ROOT


def descriptor(packet, targets):
    return {"schemaVersion": "harness.planeon.ai/make-target-descriptor/v1alpha1", "packetId": packet, "targets": targets}


def target(name="security", variables=None, argv=None):
    return {"name": name, "acceptedVariables": variables or {}, "argvTemplate": argv or [["python3", "check.py"]]}


class DispatchPortingTests(unittest.TestCase):
    def write(self, root: Path, packet: str, targets):
        (root / f"{packet.lower()}.json").write_text(json.dumps(descriptor(packet, targets)), encoding="utf-8")

    def test_current_descriptor_inventory_and_unknown_target(self):
        rules = load_rules(ROOT / "ci/targets")
        self.assertEqual(
            {rule.name for rule in rules},
            {"help", "prefetch", "policy-vectors", "guardrail-vectors", "streaming-failure-matrix", "usage-vectors", "observability-smoke", "authority-boundary", "security", "zero-bill"},
        )
        owners = {
            name: [rule.packet_id for rule in rules if rule.name == name]
            for name in {rule.name for rule in rules}
        }
        self.assertEqual(owners["prefetch"], ["TRUST-001", "TRUST-002"])
        self.assertEqual(owners["security"], ["TRUST-001", "TRUST-002", "TRUST-FIX-001", "TRUST-OBS-001"])
        self.assertEqual(owners["zero-bill"], ["TRUST-001", "TRUST-002", "TRUST-OBS-001"])
        self.assertEqual(owners["guardrail-vectors"], ["TRUST-002"])
        self.assertEqual(owners["streaming-failure-matrix"], ["TRUST-002"])
        self.assertEqual(owners["usage-vectors"], ["TRUST-OBS-001"])
        self.assertEqual(owners["observability-smoke"], ["TRUST-OBS-001"])
        self.assertEqual(owners["authority-boundary"], ["TRUST-FIX-001"])
        with self.assertRaisesRegex(TargetDescriptorError, "zero applicable handlers"):
            dispatch("missing", {}, ROOT / "ci/targets")

    def test_cumulative_handlers_execute_in_lexical_packet_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, "B-001", [target(argv=[["python3", "b.py"]])])
            self.write(root, "A-001", [target(argv=[["python3", "a.py"]])])
            completed = type("Completed", (), {"returncode": 0})()
            with mock.patch("ci.run_make_target.subprocess.run", return_value=completed) as run:
                self.assertEqual(dispatch("security", {}, root), 0)
            self.assertEqual([call.args[0] for call in run.call_args_list], [("python3", "a.py"), ("python3", "b.py")])

    def test_duplicate_ambiguous_owner_filename_variable_and_shell_rejected(self):
        cases = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a-001.json").write_text('{"schemaVersion":"x","schemaVersion":"x"}', encoding="utf-8")
            with self.assertRaisesRegex(TargetDescriptorError, "duplicate JSON member"):
                load_rules(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, "A-001", [target(), target()])
            with self.assertRaisesRegex(TargetDescriptorError, "duplicate or overlapping"):
                load_rules(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "wrong.json").write_text(json.dumps(descriptor("A-001", [target()])), encoding="utf-8")
            with self.assertRaisesRegex(TargetDescriptorError, "owner or filename mismatch"):
                load_rules(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, "A-001", [target(variables={"SECRET": {"const": "x"}})])
            with self.assertRaisesRegex(TargetDescriptorError, "undeclared Make variable"):
                load_rules(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, "A-001", [target(argv=[["sh", "-c", "true"]])])
            with self.assertRaisesRegex(TargetDescriptorError, "shell transport"):
                load_rules(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, "A-001", [target(variables={"MODULE": {"const": "x"}}), target(variables={"MODULE": {"enum": ["x", "y"]}})])
            with self.assertRaisesRegex(TargetDescriptorError, "multiple applicable handlers from one packet"):
                dispatch("security", {"MODULE": "x"}, root)

    def test_porting_is_exact_no_authorization_sentinel(self):
        with mock.patch("sys.argv", ["validate_porting.py", "PORTING.yaml"]):
            self.assertEqual(validate_porting(), 0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PORTING.yaml"
            path.write_text((ROOT / "PORTING.yaml").read_text() + "sourcePath: forbidden\n", encoding="utf-8")
            with mock.patch("sys.argv", ["validate_porting.py", str(path)]):
                self.assertEqual(validate_porting(), 2)


if __name__ == "__main__":
    unittest.main()
