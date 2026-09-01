"""Injected-transport fail-closed policy decision client."""

from __future__ import annotations

from datetime import datetime
from typing import Callable

from .canonical import digest_json, require_digest
from .decision import DECISION_SCHEMA, validate_request
from .json_io import JsonContractError, load_json_bytes
from .time import require_now, utc_timestamp


class PolicyDenied(PermissionError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(f"policy client denied: {reason_code}")
        self.reason_code = reason_code


ClientTransport = Callable[[str, dict[str, object], float], tuple[int, bytes]]


class PolicyClient:
    def __init__(
        self,
        *,
        transport: ClientTransport,
        organization_id: str,
        timeout_seconds: float = 1.0,
        expected_policy_digest: str | None = None,
    ) -> None:
        if not callable(transport) or not organization_id:
            raise ValueError("client transport and organization are required")
        if not 0.05 <= timeout_seconds <= 5.0:
            raise ValueError("client timeout is outside the closed bound")
        self._transport = transport
        self.organization_id = organization_id
        self.timeout_seconds = timeout_seconds
        self.expected_policy_digest = require_digest(expected_policy_digest, "expectedPolicyDigest") if expected_policy_digest else None

    def authorize(self, token: str, raw_request: object, *, now: datetime) -> dict[str, object]:
        current = require_now(now)
        if not isinstance(token, str) or not token or len(token) > 16384:
            raise PolicyDenied("TOKEN_MISSING")
        request = validate_request(raw_request)
        try:
            status, raw = self._transport(token, request, self.timeout_seconds)
            if status < 200 or status >= 300:
                raise PolicyDenied("TRANSPORT_DENIED")
            if not isinstance(raw, bytes) or not raw or len(raw) > 65536:
                raise PolicyDenied("RESPONSE_MALFORMED")
            response = load_json_bytes(raw, maximum=65536)
            expected_fields = {
                "schemaVersion", "decisionId", "organizationId", "subjectId", "requestDigest",
                "policyDigest", "allowed", "reasonCode", "obligations", "evaluatedAt", "expiresAt",
            }
            if not isinstance(response, dict) or set(response) != expected_fields or response["schemaVersion"] != DECISION_SCHEMA:
                raise PolicyDenied("RESPONSE_MALFORMED")
            if response["organizationId"] != self.organization_id:
                raise PolicyDenied("TENANT_MISMATCH")
            if response["requestDigest"] != digest_json(request):
                raise PolicyDenied("REQUEST_DIGEST_MISMATCH")
            policy_digest = require_digest(response["policyDigest"], "policyDigest")
            if self.expected_policy_digest and policy_digest != self.expected_policy_digest:
                raise PolicyDenied("POLICY_DIGEST_MISMATCH")
            decision_id = response["decisionId"]
            if (
                not isinstance(decision_id, str)
                or len(decision_id) != 41
                or not decision_id.startswith("decision.")
                or any(character not in "0123456789abcdef" for character in decision_id[9:])
            ):
                raise PolicyDenied("RESPONSE_MALFORMED")
            if not isinstance(response["subjectId"], str) or not 1 <= len(response["subjectId"]) <= 200:
                raise PolicyDenied("RESPONSE_MALFORMED")
            if response["allowed"] is not True or response["reasonCode"] is not None:
                reason = response["reasonCode"] if isinstance(response["reasonCode"], str) else "POLICY_DENIED"
                raise PolicyDenied(reason)
            obligations = response["obligations"]
            if (
                not isinstance(obligations, list)
                or len(obligations) > 32
                or obligations != sorted(set(obligations))
                or not all(isinstance(item, str) and 1 <= len(item) <= 128 for item in obligations)
            ):
                raise PolicyDenied("RESPONSE_MALFORMED")
            evaluated = utc_timestamp(response["evaluatedAt"], "evaluatedAt")
            expires = utc_timestamp(response["expiresAt"], "expiresAt")
            if evaluated > current or current >= expires or evaluated >= expires:
                raise PolicyDenied("DECISION_EXPIRED")
            return response
        except PolicyDenied:
            raise
        except (JsonContractError, OSError, TimeoutError, ValueError, TypeError, KeyError) as exc:
            raise PolicyDenied("TRANSPORT_FAILURE") from exc
