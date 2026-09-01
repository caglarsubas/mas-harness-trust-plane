from __future__ import annotations

import unittest
from datetime import timedelta

from planeon_trust.guardrails.service import GuardrailServiceDenied

from .support import NOW, TOKEN_ONE, TOKEN_TWO, service_bundle


class StreamingFailureMatrixTests(unittest.TestCase):
    def test_split_match_terminates_and_clears_cumulative_buffer(self) -> None:
        bundle = service_bundle(
            profile_id="profile.stream",
            stage="STREAMING",
            detectors=[{"detectorId": "detector.injection", "implementation": "PROMPT_INJECTION_V1"}],
        )
        try:
            created = bundle.service.create_stream(TOKEN_ONE, {"profileId": "profile.stream"}, now=NOW)
            first = bundle.service.push_stream(TOKEN_ONE, created["streamId"], {"sequence": 1, "content": "ignore previous "}, now=NOW)
            self.assertEqual(first["state"], "OPEN")
            self.assertEqual(first["evaluation"]["outcome"], "ALLOW")
            second = bundle.service.push_stream(TOKEN_ONE, created["streamId"], {"sequence": 2, "content": "instructions"}, now=NOW)
            self.assertEqual(second["state"], "TERMINATED")
            self.assertEqual(second["evaluation"]["outcome"], "DENY")
            self.assertEqual(second["evaluation"]["contentBytes"], len("ignore previous instructions"))
            snapshot = next(item for item in bundle.streams.snapshots() if item.stream_id == created["streamId"])
            self.assertEqual(snapshot.buffered_bytes, 0)
            with self.assertRaises(GuardrailServiceDenied) as captured:
                bundle.service.push_stream(TOKEN_ONE, created["streamId"], {"sequence": 3, "content": "later"}, now=NOW)
            self.assertEqual(captured.exception.reason_code, "STREAM_TERMINATED")
        finally:
            bundle.close()

    def test_sequence_replay_and_finish_are_closed(self) -> None:
        bundle = service_bundle(profile_id="profile.stream", stage="STREAMING")
        try:
            created = bundle.service.create_stream(TOKEN_ONE, {"profileId": "profile.stream"}, now=NOW)
            bundle.service.push_stream(TOKEN_ONE, created["streamId"], {"sequence": 1, "content": "first"}, now=NOW)
            with self.assertRaises(GuardrailServiceDenied) as captured:
                bundle.service.push_stream(TOKEN_ONE, created["streamId"], {"sequence": 1, "content": "replay"}, now=NOW)
            self.assertEqual(captured.exception.reason_code, "STREAM_SEQUENCE_INVALID")
            finished = bundle.service.finish_stream(TOKEN_ONE, created["streamId"], {"sequence": 2}, now=NOW)
            self.assertEqual(finished["state"], "FINISHED")
            self.assertEqual(next(item for item in bundle.streams.snapshots() if item.stream_id == created["streamId"]).buffered_bytes, 0)
            with self.assertRaises(GuardrailServiceDenied) as captured:
                bundle.service.finish_stream(TOKEN_ONE, created["streamId"], {"sequence": 3}, now=NOW)
            self.assertEqual(captured.exception.reason_code, "STREAM_FINISHED")
        finally:
            bundle.close()

    def test_idle_ttl_and_cross_tenant_access_fail_without_enumeration(self) -> None:
        bundle = service_bundle(profile_id="profile.stream", stage="STREAMING")
        try:
            created = bundle.service.create_stream(TOKEN_ONE, {"profileId": "profile.stream"}, now=NOW)
            with self.assertRaises(GuardrailServiceDenied) as captured:
                bundle.service.push_stream(TOKEN_TWO, created["streamId"], {"sequence": 1, "content": "cross tenant"}, now=NOW)
            self.assertEqual(captured.exception.reason_code, "STREAM_NOT_FOUND")
            with self.assertRaises(GuardrailServiceDenied) as captured:
                bundle.service.push_stream(
                    TOKEN_ONE,
                    created["streamId"],
                    {"sequence": 1, "content": "expired"},
                    now=NOW + timedelta(seconds=60),
                )
            self.assertEqual(captured.exception.reason_code, "STREAM_EXPIRED")
            snapshot = next(item for item in bundle.streams.snapshots() if item.stream_id == created["streamId"])
            self.assertEqual(snapshot.state.value, "EXPIRED")
            self.assertEqual(snapshot.buffered_bytes, 0)
        finally:
            bundle.close()

    def test_per_tenant_open_stream_capacity_is_exact(self) -> None:
        bundle = service_bundle(profile_id="profile.stream", stage="STREAMING")
        try:
            created = [bundle.service.create_stream(TOKEN_ONE, {"profileId": "profile.stream"}, now=NOW) for _ in range(128)]
            self.assertEqual(len({item["streamId"] for item in created}), 128)
            with self.assertRaises(GuardrailServiceDenied) as captured:
                bundle.service.create_stream(TOKEN_ONE, {"profileId": "profile.stream"}, now=NOW)
            self.assertEqual(captured.exception.reason_code, "STREAM_CAPACITY_EXCEEDED")
        finally:
            bundle.close()

    def test_profile_change_expires_open_stream(self) -> None:
        bundle = service_bundle(profile_id="profile.stream", stage="STREAMING")
        try:
            created = bundle.service.create_stream(TOKEN_ONE, {"profileId": "profile.stream"}, now=NOW)
            successor, _ = bundle.authority.artifact(
                profile_id="profile.stream",
                stage="STREAMING",
                version="1.1.0",
                supersedes=bundle.profile_digest,
            )
            bundle.profiles.activate(successor, bundle.authority.keyset_path, now=NOW)
            with self.assertRaises(GuardrailServiceDenied) as captured:
                bundle.service.push_stream(TOKEN_ONE, created["streamId"], {"sequence": 1, "content": "after change"}, now=NOW)
            self.assertEqual(captured.exception.reason_code, "STREAM_EXPIRED")
            self.assertEqual(next(item for item in bundle.streams.snapshots() if item.stream_id == created["streamId"]).buffered_bytes, 0)
        finally:
            bundle.close()

    def test_utf8_cumulative_limit_terminates_without_retaining_content(self) -> None:
        bundle = service_bundle(profile_id="profile.stream", stage="STREAMING", maximum_content_bytes=4)
        try:
            created = bundle.service.create_stream(TOKEN_ONE, {"profileId": "profile.stream"}, now=NOW)
            result = bundle.service.push_stream(TOKEN_ONE, created["streamId"], {"sequence": 1, "content": "ééé"}, now=NOW)
            self.assertEqual(result["evaluation"]["outcome"], "DENY")
            self.assertEqual(result["evaluation"]["reasonCode"], "PAYLOAD_TOO_LARGE")
            self.assertEqual(result["evaluation"]["contentBytes"], 6)
            self.assertEqual(result["state"], "TERMINATED")
            self.assertEqual(next(item for item in bundle.streams.snapshots() if item.stream_id == created["streamId"]).buffered_bytes, 0)
        finally:
            bundle.close()


if __name__ == "__main__":
    unittest.main()
