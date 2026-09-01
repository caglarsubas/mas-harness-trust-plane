"""Dependency-free ASGI adapter for TRUST-OBS-001 routes."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Awaitable, Callable

from planeon_trust.common.json_io import JsonContractError, load_json_bytes

from .errors import UsageDenied
from .service import UsageService


ERROR_SCHEMA = "harness.planeon.ai/usage-error/v1alpha1"
MAXIMUM_BODY_BYTES = 65_536


class UsageAsgiApp:
    def __init__(self, service: UsageService, *, readiness_organization_id: str) -> None:
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
        method, path = scope.get("method"), scope.get("path")
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
        authorization = headers.get("authorization", "")
        if not authorization.startswith("Bearer ") or len(authorization) <= 7:
            await self._error(send, 401, "TOKEN_MISSING")
            return
        try:
            token = authorization[7:]
            if method == "POST":
                if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                    await self._error(send, 415, "CONTENT_TYPE_DENIED")
                    return
                body = load_json_bytes(await _body(receive), maximum=MAXIMUM_BODY_BYTES)
                response = getattr(self.service, route)(token, body, now=_now())
            else:
                response = getattr(self.service, route)(token, now=_now())
        except UsageDenied as exc:
            await self._error(send, _status(exc.reason_code), exc.reason_code)
            return
        except (JsonContractError, UnicodeError, ValueError):
            await self._error(send, 400, "REQUEST_MALFORMED")
            return
        await self._send(send, 201 if route == "reserve" else 200, dict(response))

    @staticmethod
    def _route(method: object, path: object) -> str | None:
        routes = {
            ("POST", "/observability/v1/usage:reserve"): "reserve",
            ("POST", "/observability/v1/usage:commit"): "commit",
            ("POST", "/observability/v1/usage:release"): "release",
            ("POST", "/observability/v1/budgets:evaluate"): "evaluate",
            ("GET", "/observability/v1/usage"): "usage",
            ("GET", "/observability/v1/budgets"): "budgets",
            ("GET", "/observability/v1/slos"): "slos",
            ("GET", "/observability/v1/health/dependencies"): "dependencies",
        }
        return routes.get((method, path))

    async def _error(self, send: Callable[[dict[str, object]], Awaitable[None]], status: int, reason: str) -> None:
        await self._send(send, status, {"schemaVersion": ERROR_SCHEMA, "allowed": False, "reasonCode": reason})

    @staticmethod
    async def _send(send: Callable[[dict[str, object]], Awaitable[None]], status: int, body: dict[str, object]) -> None:
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
    if reason in {"STORE_COMMIT_FAILED", "DEPENDENCY_UNAVAILABLE", "RECONCILIATION_STALE"}:
        return 503
    if reason in {"BUDGET_NOT_FOUND", "RESERVATION_NOT_FOUND"}:
        return 404
    if reason in {"BUDGET_EXCEEDED", "BUDGET_SUSPENDED", "IDEMPOTENCY_CONFLICT", "RESERVATION_TERMINAL", "RESERVATION_EXPIRED", "COMMIT_EXCEEDS_RESERVATION", "CLOCK_REGRESSION"}:
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
            return bytes(data)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)
