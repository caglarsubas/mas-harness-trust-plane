"""Authenticated transport-neutral usage-ledger service."""

from __future__ import annotations

from datetime import datetime
from typing import Mapping

from planeon_trust.common.identity import IdentityDenied, IdentityVerifier, TenantIdentity, contains_tenant_identity
from planeon_trust.common.json_io import JsonContractError, require_object

from .errors import UsageDenied
from .ledger import UsageLedger
from .models import DependencyHealth, USAGE_SCHEMA
from .telemetry import BoundedTelemetryBuffer


FORBIDDEN_CONTENT_KEYS = frozenset(
    {
        "authorization",
        "body",
        "completion",
        "content",
        "cookie",
        "credential",
        "currency",
        "endpoint",
        "invoice",
        "memory",
        "message",
        "output",
        "password",
        "payload",
        "pricing",
        "prompt",
        "secret",
        "source",
        "tenantId",
        "token",
        "toolPayload",
    }
)


class UsageService:
    def __init__(
        self,
        *,
        identity: IdentityVerifier,
        ledger: UsageLedger,
        buffer: BoundedTelemetryBuffer,
        health: DependencyHealth | None = None,
    ) -> None:
        self.identity = identity
        self.ledger = ledger
        self.buffer = buffer
        self.health = health or DependencyHealth()

    def reserve(self, token: object, body: object, *, now: datetime) -> Mapping[str, object]:
        identity = self._admit(token, body, now)
        request = require_object(
            body,
            fields={"schemaVersion", "budgetId", "budgetDigest", "scopeType", "scopeId", "operationId", "idempotencyKey", "requested", "reservationTtlSeconds"},
            label="usage reserve request",
        )
        self._schema(request)
        return self.ledger.reserve(
            identity,
            budget_id=request["budgetId"],
            budget_digest=request["budgetDigest"],
            scope_type=request["scopeType"],
            scope_id=request["scopeId"],
            operation_id=request["operationId"],
            idempotency_key=request["idempotencyKey"],
            requested=request["requested"],
            reservation_ttl_seconds=request["reservationTtlSeconds"],
            now=now,
        )

    def commit(self, token: object, body: object, *, now: datetime) -> Mapping[str, object]:
        identity = self._admit(token, body, now)
        request = require_object(body, fields={"schemaVersion", "reservationId", "idempotencyKey", "observed"}, label="usage commit request")
        self._schema(request)
        return self.ledger.commit(
            identity,
            reservation_id=request["reservationId"],
            idempotency_key=request["idempotencyKey"],
            observed=request["observed"],
            now=now,
        )

    def release(self, token: object, body: object, *, now: datetime) -> Mapping[str, object]:
        identity = self._admit(token, body, now)
        request = require_object(body, fields={"schemaVersion", "reservationId", "idempotencyKey", "reasonCode"}, label="usage release request")
        self._schema(request)
        return self.ledger.release(
            identity,
            reservation_id=request["reservationId"],
            idempotency_key=request["idempotencyKey"],
            reason=request["reasonCode"],
            now=now,
        )

    def evaluate(self, token: object, body: object, *, now: datetime) -> Mapping[str, object]:
        identity = self._admit(token, body, now)
        request = require_object(body, fields={"schemaVersion", "budgetId", "budgetDigest", "scopeType", "scopeId", "requested"}, label="budget evaluate request")
        self._schema(request)
        return self.ledger.evaluate(
            identity,
            budget_id=request["budgetId"],
            budget_digest=request["budgetDigest"],
            scope_type=request["scopeType"],
            scope_id=request["scopeId"],
            requested=request["requested"],
            now=now,
        )

    def usage(self, token: object, *, now: datetime) -> Mapping[str, object]:
        identity = self._admit(token, None, now)
        return {"schemaVersion": USAGE_SCHEMA, "items": [dict(item) for item in self.ledger.list_usage(identity, now=now)]}

    def budgets(self, token: object, *, now: datetime) -> Mapping[str, object]:
        identity = self._admit(token, None, now)
        return {"schemaVersion": USAGE_SCHEMA, "items": [dict(item) for item in self.ledger.list_budgets(identity, now=now)]}

    def slos(self, token: object, *, now: datetime) -> Mapping[str, object]:
        identity = self._admit(token, None, now)
        budgets = self.ledger.list_budgets(identity, now=now)
        states: dict[str, int] = {}
        for item in budgets:
            state = str(item["state"])
            states[state] = states.get(state, 0) + 1
        return {
            "schemaVersion": USAGE_SCHEMA,
            "budgetCount": len(budgets),
            "budgetStates": dict(sorted(states.items())),
            "hardBudgetProtection": "ACTIVE" if all(item["state"] != "RESET_PENDING" for item in budgets if item["enforcement"] == "HARD") else "DEGRADED",
        }

    def dependencies(self, token: object, *, now: datetime) -> Mapping[str, object]:
        identity = self._admit(token, None, now)
        return self.health.to_dict(
            reconciliation_current=self.ledger.reconciliation_current(identity.organization_id, now=now),
            audit_buffer_saturated=self.buffer.audit_saturated,
        )

    def ready(self, organization_id: str, *, now: datetime) -> bool:
        projection = self.health.to_dict(
            reconciliation_current=self.ledger.reconciliation_current(organization_id, now=now),
            audit_buffer_saturated=self.buffer.audit_saturated,
        )
        return projection["status"] == "READY"

    def _admit(self, token: object, body: object | None, now: datetime) -> TenantIdentity:
        try:
            if body is not None:
                if contains_tenant_identity(body):
                    raise UsageDenied("CALLER_TENANT_FORBIDDEN")
                if _contains_forbidden_content(body):
                    raise UsageDenied("CONTENT_FIELD_FORBIDDEN")
            return self.identity.verify(token, now=now)
        except IdentityDenied as exc:
            raise UsageDenied(exc.reason_code) from exc
        except JsonContractError as exc:
            raise UsageDenied("REQUEST_MALFORMED") from exc

    @staticmethod
    def _schema(request: Mapping[str, object]) -> None:
        if request.get("schemaVersion") != USAGE_SCHEMA:
            raise UsageDenied("SCHEMA_VERSION_INVALID")


def _contains_forbidden_content(value: object) -> bool:
    if isinstance(value, dict):
        return any(key in FORBIDDEN_CONTENT_KEYS or _contains_forbidden_content(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_forbidden_content(item) for item in value)
    return False
