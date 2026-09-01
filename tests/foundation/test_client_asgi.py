from __future__ import annotations

import asyncio
import json
import unittest
from unittest import mock

from planeon_trust.common.asgi import PolicyAsgiApp
from planeon_trust.common.client import PolicyClient, PolicyDenied

from tests.foundation.support import NOW, REQUEST, service, tokens


class ClientAsgiTests(unittest.TestCase):
    def setUp(self):
        self.core, *_ = service()
        self.token = tokens()["RS256"]

    def direct_transport(self, token, request, timeout):
        del timeout
        result = self.core.decide(token, request, now=NOW)
        return 200, json.dumps(result, sort_keys=True, separators=(",", ":")).encode()

    def test_client_accepts_only_exact_unexpired_allow(self):
        client = PolicyClient(transport=self.direct_transport, organization_id="acme.one")
        result = client.authorize(self.token, REQUEST, now=NOW)
        self.assertTrue(result["allowed"])
        for field, value, reason in [
            ("organizationId", "acme.two", "TENANT_MISMATCH"),
            ("requestDigest", "sha256:" + "0" * 64, "REQUEST_DIGEST_MISMATCH"),
            ("policyDigest", "sha256:" + "0" * 64, "POLICY_DIGEST_MISMATCH"),
        ]:
            def altered(token, request, timeout, *, field=field, value=value):
                status, raw = self.direct_transport(token, request, timeout)
                document = json.loads(raw)
                document[field] = value
                return status, json.dumps(document).encode()
            expected = result["policyDigest"] if field == "policyDigest" else None
            with self.subTest(reason=reason), self.assertRaisesRegex(PolicyDenied, reason):
                PolicyClient(transport=altered, organization_id="acme.one", expected_policy_digest=expected).authorize(self.token, REQUEST, now=NOW)

    def test_client_timeout_non_success_malformed_deny_and_expiry(self):
        with self.assertRaisesRegex(PolicyDenied, "TOKEN_MISSING"):
            PolicyClient(transport=self.direct_transport, organization_id="acme.one").authorize("", REQUEST, now=NOW)
        transports = [
            (lambda *_: (_ for _ in ()).throw(TimeoutError()), "TRANSPORT_FAILURE"),
            (lambda *_: (503, b"{}"), "TRANSPORT_DENIED"),
            (lambda *_: (200, b"{}"), "RESPONSE_MALFORMED"),
        ]
        for transport, reason in transports:
            with self.subTest(reason=reason), self.assertRaisesRegex(PolicyDenied, reason):
                PolicyClient(transport=transport, organization_id="acme.one").authorize(self.token, REQUEST, now=NOW)
        def denied(token, request, timeout):
            status, raw = self.direct_transport(token, request, timeout)
            value = json.loads(raw)
            value["allowed"] = False
            value["reasonCode"] = "ACTION_DENIED"
            return status, json.dumps(value).encode()
        with self.assertRaisesRegex(PolicyDenied, "ACTION_DENIED"):
            PolicyClient(transport=denied, organization_id="acme.one").authorize(self.token, REQUEST, now=NOW)
        def expired(token, request, timeout):
            status, raw = self.direct_transport(token, request, timeout)
            value = json.loads(raw)
            value["expiresAt"] = value["evaluatedAt"]
            return status, json.dumps(value).encode()
        with self.assertRaisesRegex(PolicyDenied, "DECISION_EXPIRED"):
            PolicyClient(transport=expired, organization_id="acme.one").authorize(self.token, REQUEST, now=NOW)

    def test_asgi_route_auth_body_and_no_store_headers(self):
        app = PolicyAsgiApp(self.core, readiness_organization_id="acme.one")
        with mock.patch("planeon_trust.common.asgi._now", return_value=NOW):
            status, body, headers = asyncio.run(call_app(app, "POST", "/trust/v1/policy:decide", REQUEST, self.token))
            self.assertEqual(status, 200)
            self.assertTrue(body["allowed"])
            self.assertIn((b"cache-control", b"no-store"), headers)
            status, body, _ = asyncio.run(call_app(app, "POST", "/trust/v1/policy:decide", {**REQUEST, "attributes": {"organizationId": "acme.two"}}, self.token))
            self.assertEqual((status, body["reasonCode"]), (403, "CALLER_TENANT_FORBIDDEN"))
            status, body, _ = asyncio.run(call_app(app, "POST", "/trust/v1/policy:decide", REQUEST, None))
            self.assertEqual((status, body["reasonCode"]), (401, "TOKEN_MISSING"))
            status, body, _ = asyncio.run(call_app(app, "GET", "/health/ready", None, None))
            self.assertEqual((status, body["status"]), (200, "READY"))
            status, body, _ = asyncio.run(call_app(app, "GET", "/missing", None, None))
            self.assertEqual((status, body["reasonCode"]), (404, "ROUTE_NOT_FOUND"))

    def test_readiness_requires_active_policy_and_reachable_backend(self):
        unreachable, *_ = service(ready=False)
        app = PolicyAsgiApp(unreachable, readiness_organization_id="acme.one")
        with mock.patch("planeon_trust.common.asgi._now", return_value=NOW):
            status, body, _ = asyncio.run(call_app(app, "GET", "/health/ready", None, None))
        self.assertEqual((status, body["status"]), (503, "NOT_READY"))


async def call_app(app, method, path, body, token):
    encoded = b"" if body is None else json.dumps(body).encode()
    headers = [(b"content-type", b"application/json")]
    if token:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    events = [{"type": "http.request", "body": encoded, "more_body": False}]
    sent = []
    async def receive():
        return events.pop(0)
    async def send(event):
        sent.append(event)
    await app({"type": "http", "method": method, "path": path, "headers": headers}, receive, send)
    start, response = sent
    return start["status"], json.loads(response["body"]), start["headers"]


if __name__ == "__main__":
    unittest.main()
