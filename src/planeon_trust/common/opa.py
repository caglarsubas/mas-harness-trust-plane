"""Loopback-only OPA decision transport with a closed response contract."""

from __future__ import annotations

import ipaddress
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

from .canonical import canonical_json
from .json_io import JsonContractError, load_json_bytes, require_object


DEFAULT_ENDPOINT = "http://127.0.0.1:8181/v1/data/planeon/authz/decision"
OPA_PATH = "/v1/data/planeon/authz/decision"
MAXIMUM_RESPONSE_BYTES = 65536


class OpaDenied(PermissionError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(f"OPA decision denied: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class OpaDecision:
    allowed: bool
    reason_code: str
    obligations: tuple[str, ...]
    ttl_seconds: int


Transport = Callable[[bytes, float], tuple[int, bytes]]
ReadinessProbe = Callable[[float], bool]


def validate_endpoint(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname
        loopback = host == "localhost" or (host is not None and ipaddress.ip_address(host).is_loopback)
    except (ValueError, TypeError):
        loopback = False
        parsed = urllib.parse.SplitResult("", "", "", "", "")
    if (
        parsed.scheme != "http"
        or not loopback
        or parsed.path != OPA_PATH
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port != 8181
    ):
        raise ValueError("OPA endpoint must be the fixed loopback HTTP decision path")
    return value


def _urllib_transport(endpoint: str) -> Transport:
    def send(body: bytes, timeout: float) -> tuple[int, bytes]:
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read(MAXIMUM_RESPONSE_BYTES + 1)
                return int(response.status), data
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read(MAXIMUM_RESPONSE_BYTES + 1)
    return send


def _urllib_readiness_probe(endpoint: str) -> ReadinessProbe:
    parsed = urllib.parse.urlsplit(endpoint)
    health_endpoint = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/health", "bundles", ""))

    def probe(timeout: float) -> bool:
        request = urllib.request.Request(health_endpoint, headers={"Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                response.read(MAXIMUM_RESPONSE_BYTES + 1)
                return 200 <= int(response.status) < 300
        except urllib.error.HTTPError as exc:
            exc.read(MAXIMUM_RESPONSE_BYTES + 1)
            return False

    return probe


class OpaClient:
    def __init__(
        self,
        endpoint: str = DEFAULT_ENDPOINT,
        *,
        timeout_seconds: float = 1.0,
        transport: Transport | None = None,
        readiness_probe: ReadinessProbe | None = None,
    ) -> None:
        self.endpoint = validate_endpoint(endpoint)
        if not 0.05 <= timeout_seconds <= 5.0:
            raise ValueError("OPA timeout is outside the closed bound")
        self.timeout_seconds = timeout_seconds
        self._transport = transport or _urllib_transport(self.endpoint)
        self._readiness_probe = readiness_probe or _urllib_readiness_probe(self.endpoint)

    def ready(self) -> bool:
        try:
            return self._readiness_probe(self.timeout_seconds) is True
        except (OSError, TimeoutError, urllib.error.URLError, ValueError, TypeError):
            return False

    def evaluate(self, input_document: dict[str, object]) -> OpaDecision:
        try:
            status, body = self._transport(canonical_json({"input": input_document}), self.timeout_seconds)
            if status < 200 or status >= 300:
                raise OpaDenied("OPA_NON_SUCCESS")
            if not isinstance(body, bytes) or not body or len(body) > MAXIMUM_RESPONSE_BYTES:
                raise OpaDenied("OPA_RESPONSE_INVALID")
            envelope = require_object(load_json_bytes(body, maximum=MAXIMUM_RESPONSE_BYTES), fields={"result"}, label="OPA envelope")
            result = require_object(envelope["result"], fields={"allowed", "reasonCode", "obligations", "ttlSeconds"}, label="OPA result")
            allowed, reason, obligations, ttl = result["allowed"], result["reasonCode"], result["obligations"], result["ttlSeconds"]
            if not isinstance(allowed, bool):
                raise OpaDenied("OPA_RESPONSE_INVALID")
            if not isinstance(reason, str) or not reason or len(reason) > 128:
                raise OpaDenied("OPA_RESPONSE_INVALID")
            if not isinstance(obligations, list) or len(obligations) > 32 or not all(isinstance(item, str) and item and len(item) <= 128 for item in obligations):
                raise OpaDenied("OPA_RESPONSE_INVALID")
            if len(obligations) != len(set(obligations)) or obligations != sorted(obligations):
                raise OpaDenied("OPA_RESPONSE_INVALID")
            if not isinstance(ttl, int) or isinstance(ttl, bool) or not 0 <= ttl <= 30:
                raise OpaDenied("OPA_RESPONSE_INVALID")
            if allowed and reason != "ALLOW":
                raise OpaDenied("OPA_RESPONSE_INVALID")
            if not allowed and reason == "ALLOW":
                raise OpaDenied("OPA_RESPONSE_INVALID")
            return OpaDecision(allowed, reason, tuple(obligations), ttl)
        except OpaDenied:
            raise
        except (JsonContractError, OSError, TimeoutError, urllib.error.URLError, ValueError, TypeError) as exc:
            raise OpaDenied("OPA_UNAVAILABLE") from exc
