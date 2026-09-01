from __future__ import annotations

import unittest

from planeon_trust.guardrails.profiles import GuardrailProfileManager, ProfileDenied

from .support import NOW, ProfileAuthority


class SignedProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = ProfileAuthority()

    def tearDown(self) -> None:
        self.authority.close()

    def test_signed_profile_activates_with_closed_detector_registry(self) -> None:
        artifact, digest = self.authority.artifact(
            profile_id="profile.output",
            stage="OUTPUT",
            detectors=[{"detectorId": "detector.secret", "implementation": "SECRET_PATTERN_V1"}],
        )
        manager = GuardrailProfileManager()
        verified = manager.activate(artifact, self.authority.keyset_path, now=NOW)
        self.assertEqual(verified.profile_digest, digest)
        self.assertEqual(verified.profile.profile_id, "profile.output")
        self.assertEqual(verified.client().evaluate("ordinary").outcome.value, "ALLOW")

    def test_input_and_runtime_cannot_activate_fail_open(self) -> None:
        for stage in ("INPUT", "RUNTIME"):
            artifact, _ = self.authority.artifact(profile_id=f"profile.{stage.lower()}", stage=stage, fail_mode="FAIL_OPEN")
            with self.subTest(stage=stage), self.assertRaisesRegex(ProfileDenied, "FAIL_MODE_DENIED"):
                GuardrailProfileManager().activate(artifact, self.authority.keyset_path, now=NOW)

    def test_wrong_purpose_tenant_and_tamper_fail_content_free(self) -> None:
        wrong_purpose, _ = self.authority.artifact(profile_id="profile.output", stage="OUTPUT", purpose="POLICY_BUNDLE")
        wrong_tenant, _ = self.authority.artifact(profile_id="profile.other", stage="OUTPUT", organization_id="acme.two")
        valid, _ = self.authority.artifact(profile_id="profile.valid", stage="OUTPUT")
        tampered = self.authority.mutate(valid, lambda item: item["payload"]["profile"].__setitem__("maximumContentBytes", 64))
        cases = ((wrong_purpose, "KEY_PURPOSE_MISMATCH"), (wrong_tenant, "TENANT_MISMATCH"), (tampered, "PROFILE_DIGEST_MISMATCH"))
        for path, reason in cases:
            with self.subTest(reason=reason), self.assertRaises(ProfileDenied) as captured:
                GuardrailProfileManager().activate(path, self.authority.keyset_path, now=NOW)
            self.assertEqual(captured.exception.reason_code, reason)
            self.assertNotIn("maximumContentBytes", str(captured.exception))

    def test_version_predecessor_rollback_and_revocation_are_atomic(self) -> None:
        first, digest_one = self.authority.artifact(profile_id="profile.output", stage="OUTPUT", version="1.0.0")
        second, digest_two = self.authority.artifact(
            profile_id="profile.output", stage="OUTPUT", version="1.1.0", supersedes=digest_one
        )
        manager = GuardrailProfileManager()
        manager.activate(first, self.authority.keyset_path, now=NOW)
        manager.activate(second, self.authority.keyset_path, now=NOW)
        self.assertEqual(manager.active("acme.one", "profile.output", now=NOW).profile_digest, digest_two)
        rolled_back = manager.rollback("acme.one", "profile.output", now=NOW)
        self.assertEqual(rolled_back.profile_digest, digest_one)
        manager.revoke("acme.one", "profile.output", digest_one)
        with self.assertRaises(ProfileDenied) as captured:
            manager.active("acme.one", "profile.output", now=NOW)
        self.assertEqual(captured.exception.reason_code, "PROFILE_UNAVAILABLE")

    def test_rejected_successor_does_not_change_active_profile(self) -> None:
        first, digest = self.authority.artifact(profile_id="profile.output", stage="OUTPUT", version="1.0.0")
        duplicate, _ = self.authority.artifact(
            profile_id="profile.output", stage="OUTPUT", version="1.0.0", supersedes=digest
        )
        manager = GuardrailProfileManager()
        manager.activate(first, self.authority.keyset_path, now=NOW)
        with self.assertRaises(ProfileDenied) as captured:
            manager.activate(duplicate, self.authority.keyset_path, now=NOW)
        self.assertEqual(captured.exception.reason_code, "VERSION_INVALID")
        self.assertEqual(manager.active("acme.one", "profile.output", now=NOW).profile_digest, digest)


if __name__ == "__main__":
    unittest.main()
