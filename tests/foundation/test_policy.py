from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from planeon_trust.common.policy import PolicyDenied, PolicyManager, verify_policy_artifact

from tests.foundation.support import FIXTURES, NOW, document


class PolicyTests(unittest.TestCase):
    def test_signed_activation_rotation_and_atomic_state(self):
        changes: list[str] = []
        manager = PolicyManager(lambda: changes.append("changed"))
        first = manager.activate(FIXTURES / "v1" / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW)
        second = manager.activate(FIXTURES / "v2" / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW)
        state = manager.state("acme.one")
        self.assertEqual(state.active, second)
        self.assertEqual(state.last_known_good, first)
        self.assertEqual(changes, ["changed", "changed"])

    def test_tampered_module_rejected_without_pointer_change(self):
        manager = PolicyManager()
        first = manager.activate(FIXTURES / "v1" / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "v2"
            shutil.copytree(FIXTURES / "v2", root)
            (root / "policy.rego").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(PolicyDenied, "MODULE_DIGEST_MISMATCH"):
                manager.activate(root / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW)
        self.assertEqual(manager.state("acme.one").active, first)

    def test_key_state_purpose_and_signature_fail_closed(self):
        for field, value, reason in [("state", "REVOKED", "SIGNER_REVOKED"), ("state", "PENDING", "SIGNER_NOT_ACTIVE"), ("purposes", ["RUNTIME_ADMISSION"], "KEY_PURPOSE_MISMATCH")]:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "keyset.json"
                keyset = document(FIXTURES / "policy-keyset.json")
                keyset["keys"][0][field] = value
                path.write_text(json.dumps(keyset), encoding="utf-8")
                with self.subTest(reason=reason), self.assertRaisesRegex(PolicyDenied, reason):
                    verify_policy_artifact(FIXTURES / "v1" / "policy-artifact.json", path, now=NOW)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "v1"
            shutil.copytree(FIXTURES / "v1", root)
            artifact = document(root / "policy-artifact.json")
            original = artifact["signature"]["value"]
            artifact["signature"]["value"] = ("A" if original[0] != "A" else "B") + original[1:]
            (root / "policy-artifact.json").write_text(json.dumps(artifact), encoding="utf-8")
            with self.assertRaisesRegex(PolicyDenied, "SIGNATURE_INVALID"):
                verify_policy_artifact(root / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW)

    def test_version_predecessor_expiry_revocation_and_rollback(self):
        with self.assertRaisesRegex(PolicyDenied, "VERSION_INVALID"):
            PolicyManager().activate(FIXTURES / "v2" / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW)
        manager = PolicyManager()
        first = manager.activate(FIXTURES / "v1" / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW)
        second = manager.activate(FIXTURES / "v2" / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW)
        manager.revoke("acme.one", second.policy_digest)
        with self.assertRaisesRegex(PolicyDenied, "POLICY_UNAVAILABLE"):
            manager.active("acme.one", now=NOW)
        self.assertEqual(manager.rollback("acme.one", now=NOW), first)
        manager.revoke("acme.one", first.policy_digest)
        with self.assertRaisesRegex(PolicyDenied, "LAST_KNOWN_GOOD_UNAVAILABLE"):
            manager.rollback("acme.one", now=NOW)
        with self.assertRaisesRegex(PolicyDenied, "POLICY_EXPIRED"):
            verify_policy_artifact(FIXTURES / "v1" / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW + timedelta(days=600))

    def test_active_policy_expiry_clears_cache_hook(self):
        changes: list[str] = []
        manager = PolicyManager(lambda: changes.append("changed"))
        manager.activate(FIXTURES / "v1" / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW)
        with self.assertRaisesRegex(PolicyDenied, "POLICY_EXPIRED"):
            manager.active("acme.one", now=NOW + timedelta(days=600))
        self.assertEqual(changes, ["changed", "changed"])

    def test_path_and_data_tampering_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "v1"
            shutil.copytree(FIXTURES / "v1", root)
            (root / "data.json").write_text('{"version":9}\n', encoding="utf-8")
            with self.assertRaisesRegex(PolicyDenied, "DATA_DIGEST_MISMATCH"):
                verify_policy_artifact(root / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW)


if __name__ == "__main__":
    unittest.main()
