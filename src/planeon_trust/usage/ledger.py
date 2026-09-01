"""Atomic tenant-scoped reference usage ledger."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Callable, Mapping

from planeon_trust.common.canonical import digest_json, opaque_digest, require_digest
from planeon_trust.common.identity import TenantIdentity
from planeon_trust.common.time import require_now

from .dimensions import (
    DIMENSIONS,
    add_dimensions,
    exceeded_dimensions,
    normalize_dimensions,
    reached_dimensions,
    subtract_dimensions,
    within_reservation,
    zero_dimensions,
)
from .errors import UsageDenied
from .models import (
    Aggregate,
    BudgetDefinition,
    ReconciliationFinding,
    Reservation,
    ReservationTransition,
    RetentionFinding,
    UsageEntry,
    Window,
    frozen_dimensions,
    reason_code,
    stable_id,
    timestamp,
)


@dataclass(slots=True)
class LedgerState:
    budgets: dict[tuple[str, str], BudgetDefinition] = field(default_factory=dict)
    reservations: dict[str, Reservation] = field(default_factory=dict)
    transitions: list[ReservationTransition] = field(default_factory=list)
    usage_entries: list[UsageEntry] = field(default_factory=list)
    aggregates: dict[tuple[str, str, int], Aggregate] = field(default_factory=dict)
    idempotency: dict[tuple[str, str, str], tuple[str, str]] = field(default_factory=dict)
    audit_records: list[Mapping[str, object]] = field(default_factory=list)
    outbox_records: list[Mapping[str, object]] = field(default_factory=list)
    reconciliation_findings: list[ReconciliationFinding] = field(default_factory=list)
    retention_findings: list[RetentionFinding] = field(default_factory=list)
    last_clock: dict[str, datetime] = field(default_factory=dict)
    reconciled: dict[tuple[str, str, int], str] = field(default_factory=dict)

    def copy(self) -> LedgerState:
        return LedgerState(
            budgets=dict(self.budgets),
            reservations=dict(self.reservations),
            transitions=list(self.transitions),
            usage_entries=list(self.usage_entries),
            aggregates=dict(self.aggregates),
            idempotency=dict(self.idempotency),
            audit_records=list(self.audit_records),
            outbox_records=list(self.outbox_records),
            reconciliation_findings=list(self.reconciliation_findings),
            retention_findings=list(self.retention_findings),
            last_clock=dict(self.last_clock),
            reconciled=dict(self.reconciled),
        )


class UsageLedger:
    """Locked copy-on-commit ledger used for deterministic offline acceptance."""

    def __init__(self, *, failure_injector: Callable[[str], None] | None = None) -> None:
        self._state = LedgerState()
        self._lock = threading.RLock()
        self._failure_injector = failure_injector

    def add_budget(self, budget: BudgetDefinition) -> None:
        key = (budget.organization_id, budget.budget_id)
        with self._lock:
            candidate = self._state.copy()
            existing = candidate.budgets.get(key)
            if existing is not None:
                if existing == budget:
                    return
                raise UsageDenied("BUDGET_CONFLICT")
            candidate.budgets[key] = budget
            self._commit(candidate, "ADD_BUDGET")

    def reserve(
        self,
        identity: TenantIdentity,
        *,
        budget_id: object,
        budget_digest: object,
        scope_type: object,
        scope_id: object,
        operation_id: object,
        idempotency_key: object,
        requested: object,
        reservation_ttl_seconds: object,
        now: datetime,
    ) -> Mapping[str, object]:
        current = require_now(now)
        organization_id = stable_id(identity.organization_id, "organization_id")
        budget_name = stable_id(budget_id, "budget_id")
        supplied_digest = require_digest(budget_digest, "budgetDigest")
        scope = stable_id(scope_id, "scope_id")
        operation = stable_id(operation_id, "operation_id")
        if not isinstance(scope_type, str):
            raise UsageDenied("SCOPE_TYPE_INVALID")
        key_digest = self._key_digest(idempotency_key)
        amounts = normalize_dimensions(
            requested,
            label="REQUESTED",
            require_nonzero=True,
            enforce_public_maxima=True,
        )
        if isinstance(reservation_ttl_seconds, bool) or not isinstance(reservation_ttl_seconds, int):
            raise UsageDenied("RESERVATION_TTL_INVALID")
        request = {
            "organizationId": organization_id,
            "budgetId": budget_name,
            "budgetDigest": supplied_digest,
            "scopeType": scope_type,
            "scopeId": scope,
            "operationId": operation,
            "idempotencyKeyDigest": key_digest,
            "requested": dict(amounts),
            "reservationTtlSeconds": reservation_ttl_seconds,
        }
        request_digest = digest_json(request)
        with self._lock:
            candidate = self._state.copy()
            self._advance_clock(candidate, organization_id, current)
            self._expire_due(candidate, organization_id, current)
            replay = candidate.idempotency.get((organization_id, "RESERVE", key_digest))
            if replay is not None:
                if replay[0] != request_digest:
                    raise UsageDenied("IDEMPOTENCY_CONFLICT")
                reservation = candidate.reservations[replay[1]]
                budget = candidate.budgets[(organization_id, reservation.budget_id)]
                return MappingProxyType(reservation.to_dict(budget_state=self._budget_state(candidate, budget, reservation.window)))
            budget = self._budget(candidate, organization_id, budget_name, supplied_digest, scope_type, scope)
            if not budget.enabled:
                self._append_denial(candidate, identity, request_digest, "BUDGET_SUSPENDED", current)
                self._commit(candidate, "RESERVE_DENIED")
                raise UsageDenied("BUDGET_SUSPENDED")
            if not 1 <= reservation_ttl_seconds <= min(3600, budget.reservation_ttl_seconds):
                raise UsageDenied("RESERVATION_TTL_INVALID")
            window = budget.window_at(current)
            aggregate = self._aggregate(candidate, budget, window, current)
            projected = add_dimensions(aggregate.committed, aggregate.reserved, amounts)
            exceeded = exceeded_dimensions(projected, budget.limits)
            if exceeded and budget.enforcement == "HARD":
                self._append_denial(candidate, identity, request_digest, "BUDGET_EXCEEDED", current)
                self._commit(candidate, "RESERVE_DENIED")
                raise UsageDenied("BUDGET_EXCEEDED")
            reservation_id = "res." + request_digest[7:47]
            expires_at = min(current + timedelta(seconds=reservation_ttl_seconds), window.end)
            reservation = Reservation(
                reservation_id=reservation_id,
                organization_id=organization_id,
                subject_digest=identity.token_identity_digest,
                budget_id=budget.budget_id,
                budget_digest=budget.budget_digest,
                scope_type=budget.scope_type,
                scope_id=budget.scope_id,
                operation_id=operation,
                request_digest=request_digest,
                idempotency_key_digest=key_digest,
                requested=amounts,
                window=window,
                created_at=current,
                expires_at=expires_at,
                enforcement=budget.enforcement,
                exceeded_dimensions=exceeded,
            )
            candidate.reservations[reservation_id] = reservation
            candidate.idempotency[(organization_id, "RESERVE", key_digest)] = (request_digest, reservation_id)
            candidate.aggregates[self._aggregate_key(budget, window)] = replace(
                aggregate,
                reserved=add_dimensions(aggregate.reserved, amounts),
                updated_at=current,
            )
            self._append_event(candidate, identity, "usage.reserved.v1", reservation_id, request_digest, current)
            self._mark_reconciled(candidate, budget, window)
            self._commit(candidate, "RESERVE")
            return MappingProxyType(reservation.to_dict(budget_state=self._budget_state(candidate, budget, window)))

    def commit(
        self,
        identity: TenantIdentity,
        *,
        reservation_id: object,
        idempotency_key: object,
        observed: object,
        now: datetime,
    ) -> Mapping[str, object]:
        amounts = normalize_dimensions(
            observed,
            label="OBSERVED",
            require_nonzero=False,
            enforce_public_maxima=True,
        )
        return self._transition(
            identity,
            reservation_id=reservation_id,
            idempotency_key=idempotency_key,
            observed=amounts,
            target="COMMITTED",
            reason="USAGE_COMMITTED",
            now=now,
        )

    def release(
        self,
        identity: TenantIdentity,
        *,
        reservation_id: object,
        idempotency_key: object,
        reason: object,
        now: datetime,
    ) -> Mapping[str, object]:
        return self._transition(
            identity,
            reservation_id=reservation_id,
            idempotency_key=idempotency_key,
            observed=MappingProxyType(zero_dimensions()),
            target="RELEASED",
            reason=reason_code(reason),
            now=now,
        )

    def evaluate(
        self,
        identity: TenantIdentity,
        *,
        budget_id: object,
        budget_digest: object,
        scope_type: object,
        scope_id: object,
        requested: object,
        now: datetime,
    ) -> Mapping[str, object]:
        amounts = normalize_dimensions(requested, label="REQUESTED", require_nonzero=True, enforce_public_maxima=True)
        current = require_now(now)
        organization_id = stable_id(identity.organization_id, "organization_id")
        with self._lock:
            candidate = self._state.copy()
            self._advance_clock(candidate, organization_id, current)
            self._expire_due(candidate, organization_id, current)
            budget = self._budget(
                candidate,
                organization_id,
                stable_id(budget_id, "budget_id"),
                require_digest(budget_digest, "budgetDigest"),
                scope_type,
                stable_id(scope_id, "scope_id"),
            )
            window = budget.window_at(current)
            aggregate = self._aggregate(candidate, budget, window, current)
            projected = add_dimensions(aggregate.committed, aggregate.reserved, amounts)
            exceeded = exceeded_dimensions(projected, budget.limits)
            state = self._budget_state(candidate, budget, window)
            if candidate != self._state:
                self._mark_reconciled(candidate, budget, window)
                self._commit(candidate, "EVALUATE_EXPIRY")
            return MappingProxyType(
                {
                    "schemaVersion": "harness.planeon.ai/usage-ledger/v1alpha1",
                    "budgetId": budget.budget_id,
                    "budgetDigest": budget.budget_digest,
                    "scopeType": budget.scope_type,
                    "scopeId": budget.scope_id,
                    "state": state,
                    "enforcement": budget.enforcement,
                    "allowed": budget.enabled and (not exceeded or budget.enforcement == "ADVISORY"),
                    "exceededDimensions": list(exceeded),
                    "projected": dict(projected),
                    "window": window.to_dict(),
                }
            )

    def list_usage(self, identity: TenantIdentity, *, now: datetime) -> tuple[Mapping[str, object], ...]:
        organization_id = stable_id(identity.organization_id, "organization_id")
        with self._lock:
            self._require_clock_not_regressed(self._state, organization_id, require_now(now))
            return tuple(MappingProxyType(entry.to_dict()) for entry in self._state.usage_entries if entry.organization_id == organization_id)

    def list_budgets(self, identity: TenantIdentity, *, now: datetime) -> tuple[Mapping[str, object], ...]:
        current = require_now(now)
        organization_id = stable_id(identity.organization_id, "organization_id")
        with self._lock:
            self._require_clock_not_regressed(self._state, organization_id, current)
            result: list[Mapping[str, object]] = []
            for key, budget in sorted(self._state.budgets.items()):
                if key[0] != organization_id:
                    continue
                window = budget.window_at(current)
                aggregate = self._aggregate(self._state, budget, window, current)
                result.append(MappingProxyType(budget.to_dict(state=self._budget_state(self._state, budget, window), window=window, committed=aggregate.committed, reserved=aggregate.reserved)))
            return tuple(result)

    def reconcile(self, identity: TenantIdentity, *, budget_id: object, now: datetime) -> ReconciliationFinding:
        current = require_now(now)
        organization_id = stable_id(identity.organization_id, "organization_id")
        budget_name = stable_id(budget_id, "budget_id")
        with self._lock:
            candidate = self._state.copy()
            self._advance_clock(candidate, organization_id, current)
            self._expire_due(candidate, organization_id, current)
            budget = candidate.budgets.get((organization_id, budget_name))
            if budget is None:
                raise UsageDenied("BUDGET_NOT_FOUND")
            window = budget.window_at(current)
            observed = self._aggregate(candidate, budget, window, current)
            expected = self._recomputed(candidate, budget, window, current)
            expected_digest = self._aggregate_digest(expected)
            observed_digest = self._aggregate_digest(observed)
            status = "MATCH" if expected_digest == observed_digest else "MISMATCH"
            finding = ReconciliationFinding(
                finding_id="recon." + digest_json({"organizationId": organization_id, "budgetId": budget_name, "window": window.index, "expected": expected_digest, "observed": observed_digest})[7:47],
                organization_id=organization_id,
                budget_id=budget_name,
                window_index=window.index,
                expected_digest=expected_digest,
                observed_digest=observed_digest,
                status=status,
                recorded_at=current,
            )
            candidate.reconciliation_findings.append(finding)
            candidate.reconciled[self._aggregate_key(budget, window)] = status
            self._commit(candidate, "RECONCILE")
            return finding

    def retention_due(self, identity: TenantIdentity, *, budget_id: object, now: datetime) -> RetentionFinding:
        current = require_now(now)
        organization_id = stable_id(identity.organization_id, "organization_id")
        budget_name = stable_id(budget_id, "budget_id")
        with self._lock:
            candidate = self._state.copy()
            self._advance_clock(candidate, organization_id, current)
            budget = candidate.budgets.get((organization_id, budget_name))
            if budget is None:
                raise UsageDenied("BUDGET_NOT_FOUND")
            window = budget.window_at(current)
            cutoff = window.index - budget.retention_windows
            history = [
                entry.to_dict()
                for entry in candidate.usage_entries
                if entry.organization_id == organization_id and entry.budget_id == budget_name and entry.window_index <= cutoff
            ]
            history_digest = digest_json(history)
            finding = RetentionFinding(
                finding_id="retain." + digest_json({"organizationId": organization_id, "budgetId": budget_name, "cutoff": cutoff, "historyDigest": history_digest})[7:47],
                organization_id=organization_id,
                budget_id=budget_name,
                cutoff_window_index=cutoff,
                history_digest=history_digest,
                status="RETENTION_DUE" if history else "NOT_DUE",
                recorded_at=current,
            )
            candidate.retention_findings.append(finding)
            self._commit(candidate, "RETENTION_FINDING")
            return finding

    def reconciliation_current(self, organization_id: str, *, now: datetime) -> bool:
        with self._lock:
            for key, budget in self._state.budgets.items():
                if key[0] != organization_id:
                    continue
                window = budget.window_at(now)
                if self._state.reconciled.get(self._aggregate_key(budget, window)) != "MATCH":
                    return False
            return True

    def snapshot(self) -> Mapping[str, object]:
        with self._lock:
            state = self._state
            return MappingProxyType(
                {
                    "budgets": len(state.budgets),
                    "reservations": tuple(state.reservations.values()),
                    "transitions": tuple(state.transitions),
                    "usageEntries": tuple(state.usage_entries),
                    "aggregates": tuple(state.aggregates.values()),
                    "auditRecords": tuple(state.audit_records),
                    "outboxRecords": tuple(state.outbox_records),
                    "reconciliationFindings": tuple(state.reconciliation_findings),
                    "retentionFindings": tuple(state.retention_findings),
                }
            )

    def _transition(
        self,
        identity: TenantIdentity,
        *,
        reservation_id: object,
        idempotency_key: object,
        observed: Mapping[str, int],
        target: str,
        reason: str,
        now: datetime,
    ) -> Mapping[str, object]:
        current = require_now(now)
        organization_id = stable_id(identity.organization_id, "organization_id")
        reservation_name = stable_id(reservation_id, "reservation_id")
        key_digest = self._key_digest(idempotency_key)
        request_digest = digest_json(
            {
                "organizationId": organization_id,
                "reservationId": reservation_name,
                "transition": target,
                "idempotencyKeyDigest": key_digest,
                "observed": dict(observed),
                "reasonCode": reason,
            }
        )
        with self._lock:
            candidate = self._state.copy()
            self._advance_clock(candidate, organization_id, current)
            self._expire_due(candidate, organization_id, current)
            replay = candidate.idempotency.get((organization_id, target, key_digest))
            if replay is not None:
                if replay[0] != request_digest:
                    raise UsageDenied("IDEMPOTENCY_CONFLICT")
                transition = next(item for item in candidate.transitions if item.transition_id == replay[1])
                return MappingProxyType(transition.to_dict())
            reservation = candidate.reservations.get(reservation_name)
            if reservation is None or reservation.organization_id != organization_id:
                raise UsageDenied("RESERVATION_NOT_FOUND")
            if reservation.state == "EXPIRED":
                raise UsageDenied("RESERVATION_EXPIRED")
            if reservation.state != "RESERVED":
                raise UsageDenied("RESERVATION_TERMINAL")
            if target == "COMMITTED" and not within_reservation(observed, reservation.requested):
                raise UsageDenied("COMMIT_EXCEEDS_RESERVATION")
            budget = candidate.budgets[(organization_id, reservation.budget_id)]
            aggregate = self._aggregate(candidate, budget, reservation.window, current)
            committed = add_dimensions(aggregate.committed, observed) if target == "COMMITTED" else aggregate.committed
            reserved = subtract_dimensions(aggregate.reserved, reservation.requested)
            candidate.aggregates[self._aggregate_key(budget, reservation.window)] = replace(aggregate, committed=committed, reserved=reserved, updated_at=current)
            transition_id = "transition." + request_digest[7:47]
            transition = ReservationTransition(
                transition_id=transition_id,
                reservation_id=reservation_name,
                organization_id=organization_id,
                state=target,
                idempotency_key_digest=key_digest,
                request_digest=request_digest,
                observed=observed,
                reason_code=reason,
                occurred_at=current,
            )
            candidate.transitions.append(transition)
            candidate.reservations[reservation_name] = replace(reservation, state=target)
            candidate.idempotency[(organization_id, target, key_digest)] = (request_digest, transition_id)
            if target == "COMMITTED":
                usage_id = "usage." + digest_json({"reservationId": reservation_name, "transitionId": transition_id, "dimensions": dict(observed)})[7:47]
                candidate.usage_entries.append(
                    UsageEntry(
                        usage_entry_id=usage_id,
                        organization_id=organization_id,
                        reservation_id=reservation_name,
                        budget_id=reservation.budget_id,
                        budget_digest=reservation.budget_digest,
                        scope_type=reservation.scope_type,
                        scope_id=reservation.scope_id,
                        operation_id=reservation.operation_id,
                        dimensions=observed,
                        window_index=reservation.window.index,
                        recorded_at=current,
                    )
                )
                self._append_event(candidate, identity, "usage.committed.v1", usage_id, request_digest, current)
            else:
                self._append_event(candidate, identity, "usage.released.v1", transition_id, request_digest, current)
            self._mark_reconciled(candidate, budget, reservation.window)
            self._commit(candidate, target)
            return MappingProxyType(transition.to_dict())

    def _expire_due(self, candidate: LedgerState, organization_id: str, now: datetime) -> None:
        for reservation_id, reservation in tuple(candidate.reservations.items()):
            if reservation.organization_id != organization_id or reservation.state != "RESERVED" or reservation.expires_at > now:
                continue
            budget = candidate.budgets[(organization_id, reservation.budget_id)]
            aggregate = self._aggregate(candidate, budget, reservation.window, now)
            candidate.aggregates[self._aggregate_key(budget, reservation.window)] = replace(
                aggregate,
                reserved=subtract_dimensions(aggregate.reserved, reservation.requested),
                updated_at=now,
            )
            request_digest = digest_json({"reservationId": reservation_id, "state": "EXPIRED", "expiredAt": timestamp(now)})
            transition = ReservationTransition(
                transition_id="transition." + request_digest[7:47],
                reservation_id=reservation_id,
                organization_id=organization_id,
                state="EXPIRED",
                idempotency_key_digest=opaque_digest("system-expiry:" + reservation_id),
                request_digest=request_digest,
                observed=MappingProxyType(zero_dimensions()),
                reason_code="RESERVATION_EXPIRED",
                occurred_at=now,
            )
            candidate.transitions.append(transition)
            candidate.reservations[reservation_id] = replace(reservation, state="EXPIRED")
            self._append_system_event(candidate, organization_id, "usage.expired.v1", transition.transition_id, request_digest, now)
            self._mark_reconciled(candidate, budget, reservation.window)

    @staticmethod
    def _budget(
        candidate: LedgerState,
        organization_id: str,
        budget_id: str,
        budget_digest: str,
        scope_type: object,
        scope_id: str,
    ) -> BudgetDefinition:
        budget = candidate.budgets.get((organization_id, budget_id))
        if budget is None:
            raise UsageDenied("BUDGET_NOT_FOUND")
        if budget.budget_digest != budget_digest:
            raise UsageDenied("BUDGET_DIGEST_MISMATCH")
        if scope_type != budget.scope_type or scope_id != budget.scope_id:
            raise UsageDenied("BUDGET_SCOPE_MISMATCH")
        return budget

    @staticmethod
    def _aggregate_key(budget: BudgetDefinition, window: Window) -> tuple[str, str, int]:
        return budget.organization_id, budget.budget_id, window.index

    @classmethod
    def _aggregate(cls, state: LedgerState, budget: BudgetDefinition, window: Window, now: datetime) -> Aggregate:
        return state.aggregates.get(
            cls._aggregate_key(budget, window),
            Aggregate(
                organization_id=budget.organization_id,
                budget_id=budget.budget_id,
                window_index=window.index,
                committed=MappingProxyType(zero_dimensions()),
                reserved=MappingProxyType(zero_dimensions()),
                updated_at=now,
            ),
        )

    @classmethod
    def _recomputed(cls, state: LedgerState, budget: BudgetDefinition, window: Window, now: datetime) -> Aggregate:
        committed = zero_dimensions()
        reserved = zero_dimensions()
        for entry in state.usage_entries:
            if (entry.organization_id, entry.budget_id, entry.window_index) == cls._aggregate_key(budget, window):
                committed = dict(add_dimensions(committed, entry.dimensions))
        for reservation in state.reservations.values():
            if (
                reservation.organization_id == budget.organization_id
                and reservation.budget_id == budget.budget_id
                and reservation.window.index == window.index
                and reservation.state == "RESERVED"
            ):
                reserved = dict(add_dimensions(reserved, reservation.requested))
        return Aggregate(budget.organization_id, budget.budget_id, window.index, frozen_dimensions(committed), frozen_dimensions(reserved), now)

    @staticmethod
    def _aggregate_digest(aggregate: Aggregate) -> str:
        return digest_json(
            {
                "organizationId": aggregate.organization_id,
                "budgetId": aggregate.budget_id,
                "windowIndex": aggregate.window_index,
                "committed": dict(aggregate.committed),
                "reserved": dict(aggregate.reserved),
            }
        )

    @classmethod
    def _mark_reconciled(cls, state: LedgerState, budget: BudgetDefinition, window: Window) -> None:
        observed = cls._aggregate(state, budget, window, window.start)
        expected = cls._recomputed(state, budget, window, window.start)
        state.reconciled[cls._aggregate_key(budget, window)] = "MATCH" if cls._aggregate_digest(observed) == cls._aggregate_digest(expected) else "MISMATCH"

    @classmethod
    def _budget_state(cls, state: LedgerState, budget: BudgetDefinition, window: Window) -> str:
        if not budget.enabled:
            return "SUSPENDED"
        aggregate = cls._aggregate(state, budget, window, window.start)
        total = add_dimensions(aggregate.committed, aggregate.reserved)
        previous_keys = [key for key, status in state.reconciled.items() if key[:2] == (budget.organization_id, budget.budget_id) and key[2] < window.index and status != "MATCH"]
        if previous_keys:
            return "RESET_PENDING"
        if reached_dimensions(total, budget.limits):
            return "EXHAUSTED"
        for name in DIMENSIONS:
            limit = budget.limits[name]
            if limit > 0 and total[name] * 10_000 >= limit * budget.warning_threshold_basis_points:
                return "WARNING"
        return "AVAILABLE"

    @staticmethod
    def _key_digest(value: object) -> str:
        stable = stable_id(value, "idempotency_key")
        return opaque_digest(stable)

    @staticmethod
    def _advance_clock(state: LedgerState, organization_id: str, now: datetime) -> None:
        UsageLedger._require_clock_not_regressed(state, organization_id, now)
        state.last_clock[organization_id] = now

    @staticmethod
    def _require_clock_not_regressed(state: LedgerState, organization_id: str, now: datetime) -> None:
        previous = state.last_clock.get(organization_id)
        if previous is not None and now < previous:
            raise UsageDenied("CLOCK_REGRESSION")

    def _commit(self, candidate: LedgerState, operation: str) -> None:
        try:
            if self._failure_injector is not None:
                self._failure_injector(operation)
        except Exception as exc:
            raise UsageDenied("STORE_COMMIT_FAILED") from exc
        self._state = candidate

    @staticmethod
    def _append_denial(state: LedgerState, identity: TenantIdentity, request_digest: str, reason: str, now: datetime) -> None:
        record = MappingProxyType(
            {
                "organizationId": identity.organization_id,
                "subjectDigest": opaque_digest(identity.subject_id),
                "requestDigest": request_digest,
                "reasonCode": reason,
                "recordedAt": timestamp(now),
            }
        )
        state.audit_records.append(record)

    @staticmethod
    def _append_event(state: LedgerState, identity: TenantIdentity, event_type: str, subject_id: str, request_digest: str, now: datetime) -> None:
        UsageLedger._append_system_event(state, identity.organization_id, event_type, subject_id, request_digest, now, opaque_digest(identity.subject_id))

    @staticmethod
    def _append_system_event(
        state: LedgerState,
        organization_id: str,
        event_type: str,
        subject_id: str,
        request_digest: str,
        now: datetime,
        subject_digest: str = "sha256:" + "0" * 64,
    ) -> None:
        envelope = MappingProxyType(
            {
                "organizationId": organization_id,
                "subjectDigest": subject_digest,
                "type": event_type,
                "aggregateId": subject_id,
                "requestDigest": request_digest,
                "recordedAt": timestamp(now),
            }
        )
        state.audit_records.append(envelope)
        state.outbox_records.append(envelope)
