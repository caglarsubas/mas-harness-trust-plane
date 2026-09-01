from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from planeon_trust.guardrails.asgi import GuardrailAsgiApp

from .support import NOW, TOKEN_ONE, service_bundle


async def invoke(app: GuardrailAsgiApp, path: str, body: object, *, token: str | None = TOKEN_ONE):
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    events = [{"type": "http.request", "body": encoded, "more_body": False}]
    output: list[dict[str, object]] = []

    async def receive():
        return events.pop(0)

    async def send(event):
        output.append(event)

    headers = [(b"content-type", b"application/json")]
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode("ascii")))
    await app({"type": "http", "method": "POST", "path": path, "headers": headers}, receive, send)
    status = output[0]["status"]
    response = json.loads(output[1]["body"])
    return status, response, output[0]["headers"]


class GuardrailAsgiTests(unittest.TestCase):
    def test_unary_and_stream_routes_use_exact_transport(self) -> None:
        unary = service_bundle()
        streaming = service_bundle(profile_id="profile.stream", stage="STREAMING")
        try:
            with patch("planeon_trust.guardrails.asgi._now", return_value=NOW):
                status, response, headers = asyncio.run(
                    invoke(GuardrailAsgiApp(unary.service, readiness_organization_id="acme.one"), "/trust/v1/guardrails:evaluate", {"profileId": "profile.output", "content": "ordinary"})
                )
                self.assertEqual(status, 200)
                self.assertEqual(response["outcome"], "ALLOW")
                self.assertIn((b"cache-control", b"no-store"), headers)
                app = GuardrailAsgiApp(streaming.service, readiness_organization_id="acme.one")
                status, created, _ = asyncio.run(invoke(app, "/trust/v1/guardrails/streams", {"profileId": "profile.stream"}))
                self.assertEqual(status, 201)
                status, pushed, _ = asyncio.run(
                    invoke(app, f"/trust/v1/guardrails/streams/{created['streamId']}:push", {"sequence": 1, "content": "chunk"})
                )
                self.assertEqual((status, pushed["state"], pushed["nextSequence"]), (200, "OPEN", 2))
                status, finished, _ = asyncio.run(
                    invoke(app, f"/trust/v1/guardrails/streams/{created['streamId']}:finish", {"sequence": 2})
                )
                self.assertEqual((status, finished["state"]), (200, "FINISHED"))
        finally:
            unary.close()
            streaming.close()

    def test_auth_schema_and_route_failures_are_content_free(self) -> None:
        bundle = service_bundle()
        try:
            app = GuardrailAsgiApp(bundle.service, readiness_organization_id="acme.one")
            with patch("planeon_trust.guardrails.asgi._now", return_value=NOW):
                status, response, _ = asyncio.run(
                    invoke(app, "/trust/v1/guardrails:evaluate", {"profileId": "profile.output", "content": "PRIVATE_HTTP_SENTINEL"}, token=None)
                )
                self.assertEqual((status, response["reasonCode"]), (401, "TOKEN_MISSING"))
                self.assertNotIn("PRIVATE_HTTP_SENTINEL", repr(response))
                status, response, _ = asyncio.run(
                    invoke(app, "/trust/v1/guardrails:evaluate", {"profileId": "profile.output", "content": "safe", "organizationId": "acme.two"})
                )
                self.assertEqual((status, response["reasonCode"]), (403, "CALLER_TENANT_FORBIDDEN"))
                status, response, _ = asyncio.run(invoke(app, "/trust/v1/not-a-route", {}))
                self.assertEqual((status, response["reasonCode"]), (404, "ROUTE_NOT_FOUND"))
        finally:
            bundle.close()

    def test_stream_conflict_is_409_and_does_not_reflect_chunk(self) -> None:
        bundle = service_bundle(profile_id="profile.stream", stage="STREAMING")
        try:
            app = GuardrailAsgiApp(bundle.service, readiness_organization_id="acme.one")
            with patch("planeon_trust.guardrails.asgi._now", return_value=NOW):
                _, created, _ = asyncio.run(invoke(app, "/trust/v1/guardrails/streams", {"profileId": "profile.stream"}))
                status, response, _ = asyncio.run(
                    invoke(app, f"/trust/v1/guardrails/streams/{created['streamId']}:push", {"sequence": 2, "content": "PRIVATE_SEQUENCE_SENTINEL"})
                )
                self.assertEqual((status, response["reasonCode"]), (409, "STREAM_SEQUENCE_INVALID"))
                self.assertNotIn("PRIVATE_SEQUENCE_SENTINEL", repr(response))
        finally:
            bundle.close()


if __name__ == "__main__":
    unittest.main()
