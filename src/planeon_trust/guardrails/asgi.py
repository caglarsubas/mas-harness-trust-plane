"""Dependency-free ASGI transport for the closed TRUST-002 HTTP routes."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Awaitable, Callable

from planeon_trust.common.json_io import JsonContractError, load_json_bytes

from .service import GuardrailService, GuardrailServiceDenied


ERROR_SCHEMA = "harness.planeon.ai/guardrail-error/v1alpha1"
MAXIMUM_BODY_BYTES = 1_100_000
STREAM_PREFIX = "/trust/v1/guardrails/streams/"


class GuardrailAsgiApp:
    def __init__(self, service: GuardrailService, *, readiness_organization_id: str) -> None:
        self.service = service
        self.readiness_organization_id = readiness_organization_id

    async def __call__(
        self,
        scope: dict[str, object],
        receive: Callable[[], Awaitable[dict[str, object]]],
        send: Callable[[dict[str, object]], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            raise RuntimeError("only HTTP ASGI scope is supported")
        path, method = scope.get("path"), scope.get("method")
        if method == "GET" and path == "/health/live":
            await self._send(send, 200, {"status": "LIVE"})
            return
        if method == "GET" and path == "/health/ready":
            ready = self.service.ready(self.readiness_organization_id, now=_now())
            await self._send(send, 200 if ready else 503, {"status": "READY" if ready else "NOT_READY"})
            return
        route = self._route(method, path)
        if route is None:
            await self._error(send, 404, "ROUTE_NOT_FOUND")
            return
        headers = _headers(scope.get("headers"))
        if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            await self._error(send, 415, "CONTENT_TYPE_DENIED")
            return
        authorization = headers.get("authorization", "")
        if not authorization.startswith("Bearer ") or len(authorization) <= 7:
            await self._error(send, 401, "TOKEN_MISSING")
            return
        try:
            body = load_json_bytes(await _body(receive), maximum=MAXIMUM_BODY_BYTES)
            token = authorization[7:]
            operation, stream_id = route
            if operation == "evaluate":
                response = self.service.evaluate(token, body, now=_now())
            elif operation == "create":
                response = self.service.create_stream(token, body, now=_now())
            elif operation == "push":
                response = self.service.push_stream(token, stream_id, body, now=_now())
            else:
                response = self.service.finish_stream(token, stream_id, body, now=_now())
        except GuardrailServiceDenied as exc:
            await self._error(send, _status(exc.reason_code), exc.reason_code)
            return
        except (JsonContractError, UnicodeError, ValueError):
            await self._error(send, 400, "REQUEST_MALFORMED")
            return
        await self._send(send, 200 if route[0] != "create" else 201, response)

    @staticmethod
    def _route(method: object, path: object) -> tuple[str, str | None] | None:
        if method != "POST" or not isinstance(path, str):
            return None
        if path == "/trust/v1/guardrails:evaluate":
            return "evaluate", None
        if path == "/trust/v1/guardrails/streams":
            return "create", None
        if not path.startswith(STREAM_PREFIX):
            return None
        tail = path[len(STREAM_PREFIX) :]
        if tail.endswith(":push"):
            stream_id = tail[:-5]
            return ("push", stream_id) if stream_id and "/" not in stream_id else None
        if tail.endswith(":finish"):
            stream_id = tail[:-7]
            return ("finish", stream_id) if stream_id and "/" not in stream_id else None
        return None

    async def _error(
        self,
        send: Callable[[dict[str, object]], Awaitable[None]],
        status: int,
        reason: str,
    ) -> None:
        await self._send(send, status, {"schemaVersion": ERROR_SCHEMA, "allowed": False, "reasonCode": reason})

    @staticmethod
    async def _send(
        send: Callable[[dict[str, object]], Awaitable[None]],
        status: int,
        body: dict[str, object],
    ) -> None:
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(encoded)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": encoded, "more_body": False})


def _status(reason: str) -> int:
    if reason in {"TOKEN_MALFORMED", "TOKEN_MISSING", "TOKEN_EXPIRED", "TOKEN_NOT_YET_VALID", "SIGNATURE_INVALID"}:
        return 401
    if reason in {"ISSUER_UNKNOWN", "AUDIENCE_MISMATCH", "TENANT_MISMATCH", "CALLER_TENANT_FORBIDDEN"}:
        return 403
    if reason in {"PROFILE_UNAVAILABLE", "PROFILE_EXPIRED", "AUDIT_COMMIT_FAILED", "STREAM_CLEAR_FAILED"}:
        return 503
    if reason == "STREAM_NOT_FOUND":
        return 404
    if reason.startswith("STREAM_") and reason not in {"STREAM_ROUTE_REQUIRED", "STREAM_REQUEST_MALFORMED"}:
        return 409
    return 400


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
