from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from planeon_trust.usage import UsageAsgiApp

from .support import NOW, TOKEN_ONE, TOKEN_TWO, reserve_request, service_bundle


async def invoke(
    app: UsageAsgiApp,
    method: str,
    path: str,
    *,
    body: object | None = None,
    raw_body: bytes | None = None,
    token: str | None = TOKEN_ONE,
) -> tuple[int, dict[str, str], dict[str, object]]:
    headers: list[tuple[bytes, bytes]] = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode("ascii")))
    if body is not None or raw_body is not None:
        headers.append((b"content-type", b"application/json"))
    encoded = raw_body if raw_body is not None else json.dumps(body).encode("utf-8") if body is not None else b""
    events = [{"type": "http.request", "body": encoded, "more_body": False}]
    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return events.pop(0)

    async def send(event: dict[str, object]) -> None:
        sent.append(event)

    with patch("planeon_trust.usage.asgi._now", return_value=NOW):
        await app(
            {"type": "http", "method": method, "path": path, "headers": headers},
            receive,
            send,
        )
    start, response = sent
    response_headers = {
        name.decode("ascii"): value.decode("latin-1")
        for name, value in start["headers"]
    }
    return int(start["status"]), response_headers, json.loads(response["body"])


class UsageApiTests(unittest.TestCase):
    def setUp(self) -> None:
        service, self.ledger, _ = service_bundle()
        self.app = UsageAsgiApp(service, readiness_organization_id="acme.one")

    def call(self, method: str, path: str, **kwargs):
        return asyncio.run(invoke(self.app, method, path, **kwargs))

    def test_reserve_commit_and_tenant_queries(self) -> None:
        status, headers, reserved = self.call(
            "POST",
            "/observability/v1/usage:reserve",
            body=reserve_request(),
        )
        self.assertEqual(status, 201)
        self.assertEqual(headers["cache-control"], "no-store")
        status, _, committed = self.call(
            "POST",
            "/observability/v1/usage:commit",
            body={
                "schemaVersion": "harness.planeon.ai/usage-ledger/v1alpha1",
                "reservationId": reserved["reservationId"],
                "idempotencyKey": "commit.one",
                "observed": {"concurrentTasks": 1, "modelTokens": 80},
            },
        )
        self.assertEqual((status, committed["state"]), (200, "COMMITTED"))
        status, _, usage = self.call("GET", "/observability/v1/usage")
        self.assertEqual(status, 200)
        self.assertEqual(len(usage["items"]), 1)
        status, _, slos = self.call("GET", "/observability/v1/slos")
        self.assertEqual((status, slos["budgetCount"]), (200, 1))

    def test_health_routes_are_nonauthenticated_but_readiness_is_evidence_based(self) -> None:
        status, _, body = self.call("GET", "/health/live", token=None)
        self.assertEqual((status, body["status"]), (200, "LIVE"))
        status, _, body = self.call("GET", "/health/ready", token=None)
        self.assertEqual((status, body["status"]), (200, "READY"))

    def test_missing_token_and_cross_tenant_access_fail_closed(self) -> None:
        status, _, body = self.call("GET", "/observability/v1/budgets", token=None)
        self.assertEqual((status, body["reasonCode"]), (401, "TOKEN_MISSING"))
        status, _, body = self.call(
            "POST",
            "/observability/v1/usage:reserve",
            body=reserve_request(),
            token=TOKEN_TWO,
        )
        self.assertEqual((status, body["reasonCode"]), (404, "BUDGET_NOT_FOUND"))

    def test_caller_tenant_and_content_fields_are_rejected_without_echo(self) -> None:
        tenant_body = reserve_request()
        tenant_body["organizationId"] = "acme.two"
        status, _, body = self.call("POST", "/observability/v1/usage:reserve", body=tenant_body)
        self.assertEqual((status, body["reasonCode"]), (403, "CALLER_TENANT_FORBIDDEN"))

        sentinel = "private-value-never-return"
        content_body = reserve_request()
        content_body["requested"] = {"modelTokens": 1, "nested": {"prompt": sentinel}}
        status, _, body = self.call("POST", "/observability/v1/usage:reserve", body=content_body)
        self.assertEqual((status, body["reasonCode"]), (400, "CONTENT_FIELD_FORBIDDEN"))
        self.assertNotIn(sentinel, json.dumps(body))

    def test_oversized_body_is_rejected_before_parsing(self) -> None:
        status, _, body = self.call(
            "POST",
            "/observability/v1/usage:reserve",
            raw_body=b"{" + b"x" * 65_536,
        )
        self.assertEqual((status, body["reasonCode"]), (400, "REQUEST_MALFORMED"))


if __name__ == "__main__":
    unittest.main()
