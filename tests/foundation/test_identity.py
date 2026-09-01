from __future__ import annotations

import base64
import copy
import json
import unittest
from datetime import timedelta

from planeon_trust.common.identity import IdentityDenied, IdentityVerifier, TokenIdentityTracker, load_registry

from tests.foundation.support import FIXTURES, NOW, document, registry, tokens


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class IdentityTests(unittest.TestCase):
    def test_rs_es_and_ed_vectors_derive_server_identity(self):
        verifier = IdentityVerifier(registry())
        for algorithm, token in tokens().items():
            with self.subTest(algorithm=algorithm):
                identity = verifier.verify(token, now=NOW)
                self.assertEqual(identity.organization_id, "acme.one")
                self.assertEqual(identity.subject_id, "subject.alice")
                self.assertTrue(identity.token_identity_digest.startswith("sha256:"))
                self.assertNotIn(token, repr(identity))

    def test_tampered_signature_denied(self):
        token = tokens()["EdDSA"]
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        with self.assertRaisesRegex(IdentityDenied, "SIGNATURE_INVALID"):
            IdentityVerifier(registry()).verify(tampered, now=NOW)

    def test_unknown_issuer_key_and_algorithm_precedence(self):
        original = tokens()["RS256"]
        header, payload, signature = original.split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        claims["iss"] = "https://unknown.example.test"
        with self.assertRaisesRegex(IdentityDenied, "ISSUER_UNKNOWN"):
            IdentityVerifier(registry()).verify(f"{header}.{encode(json.dumps(claims, separators=(',', ':')).encode())}.{signature}", now=NOW)
        parsed_header = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
        parsed_header["kid"] = "missing"
        with self.assertRaisesRegex(IdentityDenied, "SIGNER_UNKNOWN"):
            IdentityVerifier(registry()).verify(f"{encode(json.dumps(parsed_header, separators=(',', ':')).encode())}.{payload}.{signature}", now=NOW)
        parsed_header["alg"] = "HS256"
        with self.assertRaisesRegex(IdentityDenied, "ALGORITHM_DENIED"):
            IdentityVerifier(registry()).verify(f"{encode(json.dumps(parsed_header, separators=(',', ':')).encode())}.{payload}.{signature}", now=NOW)

    def test_registry_binding_denies_audience_tenant_and_lifetime(self):
        source = document(FIXTURES / "oidc-registry.json")
        cases = [("audiences", ["other"], "AUDIENCE_MISMATCH"), ("tenantValue", "other", "TENANT_MISMATCH"), ("maximumTokenLifetimeSeconds", 599, "TOKEN_LIFETIME_INVALID")]
        for field, value, reason in cases:
            altered = copy.deepcopy(source)
            altered["issuers"][0][field] = value
            with self.subTest(reason=reason), self.assertRaisesRegex(IdentityDenied, reason):
                IdentityVerifier(load_registry(altered)).verify(tokens()["RS256"], now=NOW)

    def test_time_and_duplicate_json_fail_closed(self):
        verifier = IdentityVerifier(registry())
        with self.assertRaisesRegex(IdentityDenied, "TOKEN_NOT_YET_VALID"):
            verifier.verify(tokens()["RS256"], now=NOW - timedelta(minutes=6))
        with self.assertRaisesRegex(IdentityDenied, "TOKEN_EXPIRED"):
            verifier.verify(tokens()["RS256"], now=NOW + timedelta(minutes=6))
        header, _, signature = tokens()["RS256"].split(".")
        duplicate_payload = b'{"iss":"https://issuer-rs.example.test","iss":"https://issuer-rs.example.test"}'
        with self.assertRaisesRegex(IdentityDenied, "TOKEN_MALFORMED"):
            verifier.verify(f"{header}.{encode(duplicate_payload)}.{signature}", now=NOW)

    def test_jti_identity_conflict_is_bounded_and_denied(self):
        tracker = TokenIdentityTracker(maximum_entries=2)
        tracker.bind("sha256:" + "1" * 64, "acme.one", "subject.alice")
        tracker.bind("sha256:" + "1" * 64, "acme.one", "subject.alice")
        with self.assertRaisesRegex(IdentityDenied, "TOKEN_IDENTITY_CONFLICT"):
            tracker.bind("sha256:" + "1" * 64, "acme.two", "subject.mallory")


if __name__ == "__main__":
    unittest.main()
