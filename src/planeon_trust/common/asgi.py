"""Minimal dependency-free ASGI adapter for the TRUST-001 service core."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Awaitable, Callable

from .decision import DecisionDenied, DecisionService
from .json_io import JsonContractError, load_json_bytes


ERROR_SCHEMA = "harness.planeon.ai/policy-error/v1alpha1"
MAXIMUM_BODY_BYTES = 65536


class PolicyAsgiApp:
    def __init__(self, service: DecisionService, *, readiness_organization_id: str) -> None:
        self.service = service
        self.readiness_organization_id = readiness_organization_id

    async def __call__(self, scope: dict[str, object], receive: Callable[[], Awaitable[dict[str, object]]], send: Callable[[dict[str, object]], Awaitable[None]]) -> None:
        if scope.get("type") != "http":
            raise RuntimeError("only HTTP ASGI scope is supported")
        path, method = scope.get("path"), scope.get("method")
        if method == "GET" and path == "/health/live":
            await self._send(send, 200, {"status": "LIVE"})
            return
        if method == "GET" and path == "/health/ready":
            ready = self.service.ready(organization_id=self.readiness_organization_id, now=_now())
            await self._send(send, 200 if ready else 503, {"status": "READY" if ready else "NOT_READY"})
            return
        if method != "POST" or path != "/trust/v1/policy:decide":
            await self._send_error(send, 404, "ROUTE_NOT_FOUND")
            return
        headers = _headers(scope.get("headers"))
        if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            await self._send_error(send, 415, "CONTENT_TYPE_DENIED")
            return
        authorization = headers.get("authorization", "")
        if not authorization.startswith("Bearer ") or len(authorization) <= 7:
            await self._send_error(send, 401, "TOKEN_MISSING")
            return
        token = authorization[7:]
        try:
            body = await _body(receive)
            request = load_json_bytes(body, maximum=MAXIMUM_BODY_BYTES)
            response = self.service.decide(token, request, now=_now())
        except DecisionDenied as exc:
            await self._send_error(send, 403, exc.reason_code)
            return
        except JsonContractError:
            await self._send_error(send, 400, "REQUEST_MALFORMED")
            return
        except ValueError:
            await self._send_error(send, 400, "REQUEST_MALFORMED")
            return
        await self._send(send, 200, response)

    async def _send_error(self, send: Callable[[dict[str, object]], Awaitable[None]], status: int, reason: str) -> None:
        await self._send(send, status, {"schemaVersion": ERROR_SCHEMA, "allowed": False, "reasonCode": reason})

    @staticmethod
    async def _send(send: Callable[[dict[str, object]], Awaitable[None]], status: int, body: dict[str, object]) -> None:
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(encoded)).encode("ascii")), (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": encoded, "more_body": False})


def _headers(value: object) -> dict[str, str]:
    if not isinstance(value, list):
        return {}
    result: dict[str, str] = {}
    for item in value:
        if not isinstance(item, tuple) or len(item) != 2 or not all(isinstance(part, bytes) for part in item):
            return {}
        try:
            name, content = item[0].decode("ascii").lower(), item[1].decode("latin-1")
        except UnicodeError:
            return {}
        if name in result:
            return {}
        result[name] = content
    return result


async def _body(receive: Callable[[], Awaitable[dict[str, object]]]) -> bytes:
    data = bytearray()
    while True:
        event = await receive()
        if event.get("type") != "http.request" or not isinstance(event.get("body", b""), bytes):
            raise JsonContractError("invalid ASGI request body")
        data.extend(event.get("body", b""))
        if len(data) > MAXIMUM_BODY_BYTES:
            raise JsonContractError("request body is oversized")
        if not event.get("more_body", False):
            break
    return bytes(data)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)
