from __future__ import annotations

import json
import unittest

from planeon_trust.guardrails.service import GuardrailServiceDenied

from .support import FIXTURES, NOW, TOKEN_ONE, service_bundle


class GuardrailServiceTests(unittest.TestCase):
    def test_independent_service_vectors_cover_all_unary_stages(self) -> None:
        document = json.loads((FIXTURES / "service-vectors.json").read_text(encoding="utf-8"))
        self.assertEqual(document["schemaVersion"], "harness.planeon.ai/guardrail-service-vectors/v1alpha1")
        for vector in document["vectors"]:
            profile = vector["profile"]
            bundle = service_bundle(
                profile_id=profile["profileId"],
                stage=profile["stage"],
                fail_mode=profile["failMode"],
                maximum_content_bytes=profile["maximumContentBytes"],
                detectors=vector["detectors"],
            )
            try:
                result = bundle.service.evaluate(
                    TOKEN_ONE,
                    {"profileId": profile["profileId"], "content": vector["content"]},
                    now=NOW,
                )
                with self.subTest(vector=vector["id"]):
                    self.assertEqual(result["outcome"], vector["expected"]["outcome"])
                    self.assertEqual(result["reasonCode"], vector["expected"]["reasonCode"])
                    self.assertEqual(result["released"], vector["expected"]["released"])
                    self.assertEqual(result["redactedContent"], vector["expected"]["redactedContent"])
                    self.assertEqual(result["stage"], profile["stage"])
                    self.assertEqual(result["evidenceRecord"]["spec"]["recordState"], "RECEIVED")
            finally:
                bundle.close()

    def test_exact_request_rejects_caller_tenant_and_unknown_fields(self) -> None:
        bundle = service_bundle()
        try:
            cases = (
                ({"profileId": "profile.output", "content": "safe", "organizationId": "acme.two"}, "CALLER_TENANT_FORBIDDEN"),
                ({"profileId": "profile.output", "content": "safe", "extra": False}, "REQUEST_MALFORMED"),
                ({"profileId": "profile.output"}, "REQUEST_MALFORMED"),
            )
            for request, reason in cases:
                with self.subTest(reason=reason), self.assertRaises(GuardrailServiceDenied) as captured:
                    bundle.service.evaluate(TOKEN_ONE, request, now=NOW)
                self.assertEqual(captured.exception.reason_code, reason)
        finally:
            bundle.close()

    def test_utf8_limit_denies_before_release(self) -> None:
        bundle = service_bundle(maximum_content_bytes=4)
        try:
            result = bundle.service.evaluate(TOKEN_ONE, {"profileId": "profile.output", "content": "ééé"}, now=NOW)
            self.assertEqual(result["contentBytes"], 6)
            self.assertEqual(result["outcome"], "DENY")
            self.assertEqual(result["reasonCode"], "PAYLOAD_TOO_LARGE")
            self.assertFalse(result["released"])
        finally:
            bundle.close()

    def test_streaming_profile_requires_stream_route(self) -> None:
        bundle = service_bundle(profile_id="profile.stream", stage="STREAMING")
        try:
            with self.assertRaises(GuardrailServiceDenied) as captured:
                bundle.service.evaluate(TOKEN_ONE, {"profileId": "profile.stream", "content": "safe"}, now=NOW)
            self.assertEqual(captured.exception.reason_code, "STREAM_ROUTE_REQUIRED")
        finally:
            bundle.close()

    def test_atomic_commit_failure_returns_no_success_and_no_partial_state(self) -> None:
        bundle = service_bundle()
        try:
            bundle.store.fail_next_commit = True
            with self.assertRaises(GuardrailServiceDenied) as captured:
                bundle.service.evaluate(TOKEN_ONE, {"profileId": "profile.output", "content": "private-value-never-stored"}, now=NOW)
            self.assertEqual(captured.exception.reason_code, "AUDIT_COMMIT_FAILED")
            snapshot = bundle.store.snapshot()
            self.assertEqual((snapshot.decisions, snapshot.audits, snapshot.evidence, snapshot.outbox), ((), (), (), ()))
        finally:
            bundle.close()

    def test_response_shape_is_closed_and_sdk_result_is_not_reinterpreted(self) -> None:
        bundle = service_bundle()
        try:
            result = bundle.service.evaluate(TOKEN_ONE, {"profileId": "profile.output", "content": "ordinary"}, now=NOW)
            self.assertEqual(
                set(result),
                {
                    "schemaVersion", "decisionId", "profileDigest", "contentDigest", "contentBytes",
                    "evaluatedAt", "released", "profileId", "profileVersion", "stage", "outcome",
                    "reasonCode", "detectorFindings", "failedDetectorIds", "degraded",
                    "redactedContent", "evidenceRecord",
                },
            )
            self.assertEqual(result["outcome"], "ALLOW")
            self.assertTrue(result["released"])
        finally:
            bundle.close()


if __name__ == "__main__":
    unittest.main()
