"""Immutable packet-local usage and observability records."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Mapping

from planeon_trust.common.canonical import require_digest
from planeon_trust.common.time import require_now

from .dimensions import DIMENSIONS, PUBLIC_MAXIMA, normalize_dimensions
from .errors import UsageDenied


USAGE_SCHEMA = "harness.planeon.ai/usage-ledger/v1alpha1"
SCOPES = frozenset({"TENANT", "PROFILE", "ROUTE", "WORKFLOW"})
ENFORCEMENTS = frozenset({"HARD", "ADVISORY"})
RESERVATION_STATES = frozenset({"RESERVED", "COMMITTED", "RELEASED", "EXPIRED"})
BUDGET_STATES = frozenset({"AVAILABLE", "WARNING", "EXHAUSTED", "SUSPENDED", "RESET_PENDING"})
_STABLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def stable_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _STABLE_ID.fullmatch(value) is None:
        raise UsageDenied(f"{field.upper()}_INVALID")
    return value


def reason_code(value: object) -> str:
    if not isinstance(value, str) or _REASON.fullmatch(value) is None:
        raise UsageDenied("REASON_CODE_INVALID")
    return value


def timestamp(value: datetime) -> str:
    return require_now(value).astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class Window:
    index: int
    start: datetime
    end: datetime

    def to_dict(self) -> dict[str, object]:
        return {"index": self.index, "start": timestamp(self.start), "end": timestamp(self.end)}


@dataclass(frozen=True, slots=True)
class BudgetDefinition:
    organization_id: str
    budget_id: str
    budget_digest: str
    scope_type: str
    scope_id: str
    limits: Mapping[str, int]
    enforcement: str
    window_epoch: datetime
    window_seconds: int
    warning_threshold_basis_points: int
    reservation_ttl_seconds: int
    retention_windows: int
    enabled: bool = True

    def __post_init__(self) -> None:
        stable_id(self.organization_id, "organization_id")
        stable_id(self.budget_id, "budget_id")
        stable_id(self.scope_id, "scope_id")
        require_digest(self.budget_digest, "budgetDigest")
        if self.scope_type not in SCOPES:
            raise UsageDenied("SCOPE_TYPE_INVALID")
        if self.enforcement not in ENFORCEMENTS:
            raise UsageDenied("ENFORCEMENT_INVALID")
        if isinstance(self.enabled, bool) is False:
            raise UsageDenied("BUDGET_ENABLED_INVALID")
        if not 60 <= self.window_seconds <= 31_536_000:
            raise UsageDenied("WINDOW_SECONDS_INVALID")
        if not 1 <= self.warning_threshold_basis_points <= 9999:
            raise UsageDenied("WARNING_THRESHOLD_INVALID")
        if not 1 <= self.reservation_ttl_seconds <= 3600:
            raise UsageDenied("RESERVATION_TTL_INVALID")
        if not 1 <= self.retention_windows <= 366:
            raise UsageDenied("RETENTION_WINDOWS_INVALID")
        epoch = require_now(self.window_epoch).astimezone(timezone.utc)
        if epoch.microsecond:
            raise UsageDenied("WINDOW_EPOCH_INVALID")
        normalized = normalize_dimensions(
            dict(self.limits),
            label="LIMITS",
            require_nonzero=True,
            enforce_public_maxima=True,
        )
        if normalized["concurrentTasks"] and normalized["concurrentTasks"] < 1:
            raise UsageDenied("LIMITS_INVALID")
        for name, maximum in PUBLIC_MAXIMA.items():
            if normalized[name] > maximum:
                raise UsageDenied("LIMITS_INVALID")
        object.__setattr__(self, "window_epoch", epoch)
        object.__setattr__(self, "limits", normalized)

    def window_at(self, now: datetime) -> Window:
        current = require_now(now).astimezone(timezone.utc)
        if current < self.window_epoch:
            raise UsageDenied("WINDOW_NOT_STARTED")
        index = int((current - self.window_epoch).total_seconds()) // self.window_seconds
        start = self.window_epoch + timedelta(seconds=index * self.window_seconds)
        return Window(index=index, start=start, end=start + timedelta(seconds=self.window_seconds))

    def to_dict(self, *, state: str, window: Window, committed: Mapping[str, int], reserved: Mapping[str, int]) -> dict[str, object]:
        return {
            "schemaVersion": USAGE_SCHEMA,
            "budgetId": self.budget_id,
            "budgetDigest": self.budget_digest,
            "scopeType": self.scope_type,
            "scopeId": self.scope_id,
            "limits": dict(self.limits),
            "enforcement": self.enforcement,
            "state": state,
            "window": window.to_dict(),
            "committed": dict(committed),
            "reserved": dict(reserved),
            "warningThresholdBasisPoints": self.warning_threshold_basis_points,
        }


@dataclass(frozen=True, slots=True)
class Reservation:
    reservation_id: str
    organization_id: str
    subject_digest: str
    budget_id: str
    budget_digest: str
    scope_type: str
    scope_id: str
    operation_id: str
    request_digest: str
    idempotency_key_digest: str
    requested: Mapping[str, int]
    window: Window
    created_at: datetime
    expires_at: datetime
    enforcement: str
    exceeded_dimensions: tuple[str, ...]
    state: str = "RESERVED"

    def to_dict(self, *, budget_state: str) -> dict[str, object]:
        return {
            "schemaVersion": USAGE_SCHEMA,
            "reservationId": self.reservation_id,
            "budgetId": self.budget_id,
            "budgetDigest": self.budget_digest,
            "scopeType": self.scope_type,
            "scopeId": self.scope_id,
            "operationId": self.operation_id,
            "requested": dict(self.requested),
            "state": self.state,
            "budgetState": budget_state,
            "enforcement": self.enforcement,
            "exceededDimensions": list(self.exceeded_dimensions),
            "window": self.window.to_dict(),
            "createdAt": timestamp(self.created_at),
            "expiresAt": timestamp(self.expires_at),
        }


@dataclass(frozen=True, slots=True)
class ReservationTransition:
    transition_id: str
    reservation_id: str
    organization_id: str
    state: str
    idempotency_key_digest: str
    request_digest: str
    observed: Mapping[str, int]
    reason_code: str
    occurred_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": USAGE_SCHEMA,
            "transitionId": self.transition_id,
            "reservationId": self.reservation_id,
            "state": self.state,
            "observed": dict(self.observed),
            "reasonCode": self.reason_code,
            "occurredAt": timestamp(self.occurred_at),
        }


@dataclass(frozen=True, slots=True)
class UsageEntry:
    usage_entry_id: str
    organization_id: str
    reservation_id: str
    budget_id: str
    budget_digest: str
    scope_type: str
    scope_id: str
    operation_id: str
    dimensions: Mapping[str, int]
    window_index: int
    recorded_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": USAGE_SCHEMA,
            "usageEntryId": self.usage_entry_id,
            "reservationId": self.reservation_id,
            "budgetId": self.budget_id,
            "budgetDigest": self.budget_digest,
            "scopeType": self.scope_type,
            "scopeId": self.scope_id,
            "operationId": self.operation_id,
            "dimensions": dict(self.dimensions),
            "windowIndex": self.window_index,
            "recordedAt": timestamp(self.recorded_at),
        }


@dataclass(frozen=True, slots=True)
class Aggregate:
    organization_id: str
    budget_id: str
    window_index: int
    committed: Mapping[str, int]
    reserved: Mapping[str, int]
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ReconciliationFinding:
    finding_id: str
    organization_id: str
    budget_id: str
    window_index: int
    expected_digest: str
    observed_digest: str
    status: str
    recorded_at: datetime


@dataclass(frozen=True, slots=True)
class RetentionFinding:
    finding_id: str
    organization_id: str
    budget_id: str
    cutoff_window_index: int
    history_digest: str
    status: str
    recorded_at: datetime


@dataclass(frozen=True, slots=True)
class DependencyHealth:
    durable_store_ready: bool = True
    collector_contract_valid: bool = True
    collector_ready: bool = True
    backend_ready: bool = True

    def __post_init__(self) -> None:
        if not all(isinstance(value, bool) for value in (self.durable_store_ready, self.collector_contract_valid, self.collector_ready, self.backend_ready)):
            raise UsageDenied("DEPENDENCY_HEALTH_INVALID")

    def to_dict(self, *, reconciliation_current: bool, audit_buffer_saturated: bool) -> dict[str, object]:
        ready = self.durable_store_ready and self.collector_contract_valid and reconciliation_current and not audit_buffer_saturated
        degraded = not self.collector_ready or not self.backend_ready or audit_buffer_saturated
        return {
            "schemaVersion": USAGE_SCHEMA,
            "status": "READY" if ready else "NOT_READY",
            "degraded": degraded,
            "dependencies": {
                "durableStore": "READY" if self.durable_store_ready else "UNAVAILABLE",
                "collectorContract": "VALID" if self.collector_contract_valid else "INVALID",
                "collector": "READY" if self.collector_ready else "UNAVAILABLE",
                "backend": "READY" if self.backend_ready else "UNAVAILABLE",
                "reconciliation": "CURRENT" if reconciliation_current else "STALE",
                "auditBuffer": "SATURATED" if audit_buffer_saturated else "AVAILABLE",
            },
        }


def frozen_dimensions(value: Mapping[str, int]) -> Mapping[str, int]:
    return MappingProxyType({name: value[name] for name in DIMENSIONS})
