from __future__ import annotations

import json
import unittest
from datetime import timedelta

from planeon_trust.common.cache import CacheKey, DecisionCache
from planeon_trust.common.decision import DecisionDenied

from tests.foundation.support import FIXTURES, NOW, REQUEST, FakeOpa, document, service, tokens


class BrokenCache(DecisionCache):
    def get(self, key, *, now):
        raise RuntimeError("cache failed")


class DecisionTests(unittest.TestCase):
    def test_allow_is_tenant_derived_atomic_and_redacted(self):
        core, _, _, store, fake = service()
        result = core.decide(tokens()["RS256"], REQUEST, now=NOW)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["organizationId"], "acme.one")
        self.assertEqual(result["reasonCode"], None)
        snapshot = store.snapshot()
        self.assertEqual((len(snapshot.decisions), len(snapshot.audits), len(snapshot.outbox)), (1, 1, 1))
        with self.assertRaises(TypeError):
            snapshot.decisions[0]["allowed"] = False
        self.assertIsInstance(snapshot.decisions[0]["obligationIds"], tuple)
        serialized = json.dumps([dict(item) for group in (snapshot.decisions, snapshot.audits, snapshot.outbox) for item in group])
        for secret_marker in (tokens()["RS256"], "attributes", "authorization", "businessPayload", "policySource"):
            self.assertNotIn(secret_marker, serialized)
        opa_input = json.loads(fake.inputs[0])["input"]
        self.assertEqual(opa_input["organizationId"], "acme.one")
        self.assertNotIn("token", opa_input)

    def test_caller_tenant_and_unknown_fields_are_denied(self):
        core, *_ = service()
        for request, reason in [({**REQUEST, "organizationId": "acme.two"}, "REQUEST_MALFORMED"), ({**REQUEST, "attributes": {"tenantId": "acme.two"}}, "CALLER_TENANT_FORBIDDEN")]:
            with self.subTest(reason=reason), self.assertRaisesRegex(DecisionDenied, reason):
                core.decide(tokens()["RS256"], request, now=NOW)

    def test_cache_is_allow_only_nonmutation_bounded_and_tenant_keyed(self):
        core, _, cache, store, fake = service()
        core.decide(tokens()["RS256"], REQUEST, now=NOW)
        core.decide(tokens()["RS256"], REQUEST, now=NOW + timedelta(seconds=1))
        self.assertEqual(fake.calls, 1)
        self.assertEqual(len(store.snapshot().decisions), 2)
        mutation = {**REQUEST, "mutation": True}
        core.decide(tokens()["RS256"], mutation, now=NOW)
        core.decide(tokens()["RS256"], mutation, now=NOW)
        self.assertEqual(fake.calls, 3)
        small = DecisionCache(maximum_entries=1, maximum_ttl_seconds=2)
        one = CacheKey("acme.one", "s1", "r1", "p1")
        two = CacheKey("acme.two", "s1", "r1", "p1")
        small.put(one, reason_code="ALLOW", obligations=(), now=NOW, ttl_seconds=2)
        small.put(two, reason_code="ALLOW", obligations=(), now=NOW, ttl_seconds=2)
        self.assertIsNone(small.get(one, now=NOW))
        self.assertIsNone(small.get(two, now=NOW + timedelta(seconds=2)))
        self.assertLessEqual(len(cache.snapshot()), 1024)

    def test_explicit_deny_and_opa_failures_never_allow(self):
        denial = document(FIXTURES / "opa-results.json")["deny"]
        cases = [
            (FakeOpa(body=denial), "ACTION_DENIED"),
            (FakeOpa(status=500), "OPA_NON_SUCCESS"),
            (FakeOpa(body=b"{"), "OPA_UNAVAILABLE"),
            (FakeOpa(body=b"x" * 65537), "OPA_RESPONSE_INVALID"),
            (FakeOpa(failure=TimeoutError()), "OPA_UNAVAILABLE"),
            (FakeOpa(body={"result": {"allowed": True}}), "OPA_UNAVAILABLE"),
        ]
        for fake, reason in cases:
            core, *_ = service(fake)
            with self.subTest(reason=reason):
                result = core.decide(tokens()["RS256"], REQUEST, now=NOW)
                self.assertFalse(result["allowed"])
                self.assertEqual(result["reasonCode"], reason)

    def test_cache_and_atomic_store_failures_fail_closed(self):
        core, policies, _, store, fake = service()
        core.cache = BrokenCache()
        denied = core.decide(tokens()["RS256"], REQUEST, now=NOW)
        self.assertFalse(denied["allowed"])
        self.assertEqual(denied["reasonCode"], "CACHE_FAILURE")
        store.fail_next_commit = True
        with self.assertRaisesRegex(DecisionDenied, "AUDIT_COMMIT_FAILED"):
            core.decide(tokens()["RS256"], {**REQUEST, "mutation": True}, now=NOW)
        snapshot = store.snapshot()
        self.assertEqual((len(snapshot.decisions), len(snapshot.audits), len(snapshot.outbox)), (1, 1, 1))

    def test_policy_rotation_clears_cache_and_revocation_denies(self):
        core, policies, cache, _, _ = service()
        core.decide(tokens()["RS256"], REQUEST, now=NOW)
        self.assertTrue(cache.snapshot())
        second = policies.activate(FIXTURES / "v2" / "policy-artifact.json", FIXTURES / "policy-keyset.json", now=NOW)
        self.assertFalse(cache.snapshot())
        policies.revoke("acme.one", second.policy_digest)
        with self.assertRaisesRegex(DecisionDenied, "POLICY_UNAVAILABLE"):
            core.decide(tokens()["RS256"], REQUEST, now=NOW)


if __name__ == "__main__":
    unittest.main()
