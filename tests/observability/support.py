from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from planeon_trust.common.identity import IdentityDenied, TenantIdentity
from planeon_trust.usage import BoundedTelemetryBuffer, BudgetDefinition, UsageLedger, UsageService


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 9, 1, 16, 10, 0, tzinfo=timezone.utc)
TOKEN_ONE = "usage-test-token-one"
TOKEN_TWO = "usage-test-token-two"
BUDGET_DIGEST = "sha256:" + "1" * 64
ADVISORY_DIGEST = "sha256:" + "2" * 64


class FakeIdentity:
    def verify(self, token: object, *, now: datetime) -> TenantIdentity:
        del now
        if token == TOKEN_ONE:
            return identity_one()
        if token == TOKEN_TWO:
            return identity_two()
        raise IdentityDenied("TOKEN_MALFORMED")


def identity_one() -> TenantIdentity:
    return TenantIdentity("acme.one", "user.one", "https://issuer.example.test", "sha256:" + "a" * 64)


def identity_two() -> TenantIdentity:
    return TenantIdentity("acme.two", "user.two", "https://issuer.example.test", "sha256:" + "b" * 64)


def budget(
    *,
    organization_id: str = "acme.one",
    budget_id: str = "budget.foundation",
    budget_digest: str = BUDGET_DIGEST,
    scope_type: str = "TENANT",
    scope_id: str = "acme.one",
    enforcement: str = "HARD",
    enabled: bool = True,
    limits: dict[str, int] | None = None,
    window_seconds: int = 3600,
    reservation_ttl_seconds: int = 300,
    retention_windows: int = 24,
) -> BudgetDefinition:
    return BudgetDefinition(
        organization_id=organization_id,
        budget_id=budget_id,
        budget_digest=budget_digest,
        scope_type=scope_type,
        scope_id=scope_id,
        limits=limits
        or {
            "concurrentTasks": 4,
            "taskSeconds": 300,
            "retries": 2,
            "toolCalls": 20,
            "modelTokens": 4096,
            "modelCalls": 8,
            "inputTokens": 2048,
            "outputTokens": 2048,
            "cpuSeconds": 600,
            "gpuSeconds": 0,
            "storageBytes": 1048576,
        },
        enforcement=enforcement,
        window_epoch=datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc),
        window_seconds=window_seconds,
        warning_threshold_basis_points=8000,
        reservation_ttl_seconds=reservation_ttl_seconds,
        retention_windows=retention_windows,
        enabled=enabled,
    )


def ledger_with_budget(definition: BudgetDefinition | None = None) -> UsageLedger:
    ledger = UsageLedger()
    ledger.add_budget(definition or budget())
    return ledger


def service_bundle() -> tuple[UsageService, UsageLedger, BoundedTelemetryBuffer]:
    ledger = ledger_with_budget()
    ledger.reconcile(identity_one(), budget_id="budget.foundation", now=NOW)
    buffer = BoundedTelemetryBuffer(maximum_records=16, maximum_bytes=65536, maximum_age_seconds=300)
    return UsageService(identity=FakeIdentity(), ledger=ledger, buffer=buffer), ledger, buffer


def reserve_request(*, key: str = "reserve.one", requested: dict[str, int] | None = None) -> dict[str, object]:
    return {
        "schemaVersion": "harness.planeon.ai/usage-ledger/v1alpha1",
        "budgetId": "budget.foundation",
        "budgetDigest": BUDGET_DIGEST,
        "scopeType": "TENANT",
        "scopeId": "acme.one",
        "operationId": "operation.one",
        "idempotencyKey": key,
        "requested": requested or {"concurrentTasks": 1, "modelTokens": 100},
        "reservationTtlSeconds": 60,
    }
