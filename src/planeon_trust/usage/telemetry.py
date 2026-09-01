"""Content-free telemetry admission and bounded local buffering."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Mapping

from planeon_harness.attributes import context_attributes, sanitize_attributes
from planeon_harness.context import HarnessContext
from planeon_trust.common.canonical import digest_json
from planeon_trust.common.time import require_now

from .errors import TelemetrySaturated, UsageDenied
from .models import timestamp


PRIORITIES = frozenset({"LOW", "NORMAL", "AUDIT"})


@dataclass(frozen=True, slots=True)
class TelemetryRecord:
    record_id: str
    organization_id: str
    trace_id: str
    span_id: str
    operation_name: str
    operation_kind: str
    outcome: str
    attributes: Mapping[str, object]
    dropped_attribute_count: int
    priority: str
    audit_required: bool
    recorded_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": "harness.planeon.ai/content-free-telemetry/v1alpha1",
            "recordId": self.record_id,
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "operationName": self.operation_name,
            "operationKind": self.operation_kind,
            "outcome": self.outcome,
            "attributes": dict(self.attributes),
            "droppedAttributeCount": self.dropped_attribute_count,
            "priority": self.priority,
            "auditRequired": self.audit_required,
            "recordedAt": timestamp(self.recorded_at),
        }

    def size_bytes(self) -> int:
        return len(json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


class CardinalityGuard:
    def __init__(self, maximum_values_per_key: int) -> None:
        if not 1 <= maximum_values_per_key <= 10_000:
            raise UsageDenied("CARDINALITY_LIMIT_INVALID")
        self.maximum = maximum_values_per_key
        self._values: dict[tuple[str, str], set[str]] = {}

    def admit(self, organization_id: str, attributes: Mapping[str, object]) -> tuple[Mapping[str, object], int]:
        accepted: dict[str, object] = {}
        dropped = 0
        for key, value in sorted(attributes.items()):
            marker = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            bucket = self._values.setdefault((organization_id, key), set())
            if marker not in bucket and len(bucket) >= self.maximum:
                dropped += 1
                continue
            bucket.add(marker)
            accepted[key] = value
        return MappingProxyType(accepted), dropped


class ContentFreeTelemetry:
    def __init__(self, *, maximum_values_per_key: int = 128) -> None:
        self.cardinality = CardinalityGuard(maximum_values_per_key)

    def admit(
        self,
        context: HarnessContext,
        *,
        operation_name: str,
        operation_kind: str,
        outcome: str,
        attributes: Mapping[str, object] | None,
        priority: str,
        audit_required: bool,
        now: datetime,
    ) -> TelemetryRecord:
        current = require_now(now)
        if context.organization_id is None:
            raise UsageDenied("TELEMETRY_TENANT_REQUIRED")
        if priority not in PRIORITIES or (priority == "AUDIT") != audit_required:
            raise UsageDenied("TELEMETRY_PRIORITY_INVALID")
        base = context_attributes(context, operation_name=operation_name, operation_kind=operation_kind, outcome=outcome)
        sanitized = sanitize_attributes(attributes)
        base.update(sanitized.values)
        cardinality_safe, cardinality_dropped = self.cardinality.admit(context.organization_id, base)
        identity = {
            "organizationId": context.organization_id,
            "traceId": context.trace_id,
            "spanId": context.span_id,
            "operationName": operation_name,
            "operationKind": operation_kind,
            "outcome": outcome,
            "attributes": dict(cardinality_safe),
            "recordedAt": timestamp(current),
        }
        return TelemetryRecord(
            record_id="telemetry." + digest_json(identity)[7:47],
            organization_id=context.organization_id,
            trace_id=context.trace_id,
            span_id=context.span_id,
            operation_name=operation_name,
            operation_kind=operation_kind,
            outcome=outcome,
            attributes=cardinality_safe,
            dropped_attribute_count=sanitized.dropped_count + cardinality_dropped,
            priority=priority,
            audit_required=audit_required,
            recorded_at=current,
        )


class BoundedTelemetryBuffer:
    def __init__(self, *, maximum_records: int, maximum_bytes: int, maximum_age_seconds: int) -> None:
        if not 1 <= maximum_records <= 100_000:
            raise UsageDenied("BUFFER_RECORD_LIMIT_INVALID")
        if not 1024 <= maximum_bytes <= 1_073_741_824:
            raise UsageDenied("BUFFER_BYTE_LIMIT_INVALID")
        if not 1 <= maximum_age_seconds <= 86_400:
            raise UsageDenied("BUFFER_AGE_LIMIT_INVALID")
        self.maximum_records = maximum_records
        self.maximum_bytes = maximum_bytes
        self.maximum_age_seconds = maximum_age_seconds
        self._records: list[TelemetryRecord] = []
        self._bytes = 0
        self._audit_saturated = False
        self._lock = threading.RLock()

    @property
    def audit_saturated(self) -> bool:
        with self._lock:
            return self._audit_saturated

    def append(self, record: TelemetryRecord, *, now: datetime) -> str:
        current = require_now(now)
        encoded_size = record.size_bytes()
        if encoded_size > self.maximum_bytes:
            if record.audit_required:
                with self._lock:
                    self._audit_saturated = True
                raise TelemetrySaturated("audit record exceeds the bounded telemetry buffer")
            return "DROPPED"
        with self._lock:
            self._expire_nonaudit(current)
            while len(self._records) + 1 > self.maximum_records or self._bytes + encoded_size > self.maximum_bytes:
                index = self._drop_candidate()
                if index is None:
                    if record.audit_required:
                        self._audit_saturated = True
                        raise TelemetrySaturated("audit-required telemetry cannot be preserved")
                    return "DROPPED"
                removed = self._records.pop(index)
                self._bytes -= removed.size_bytes()
            self._records.append(record)
            self._bytes += encoded_size
            return "BUFFERED"

    def records(self, organization_id: str) -> tuple[TelemetryRecord, ...]:
        with self._lock:
            return tuple(record for record in self._records if record.organization_id == organization_id)

    def _expire_nonaudit(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.maximum_age_seconds)
        retained: list[TelemetryRecord] = []
        total = 0
        for record in self._records:
            if not record.audit_required and record.recorded_at < cutoff:
                continue
            retained.append(record)
            total += record.size_bytes()
        self._records = retained
        self._bytes = total

    def _drop_candidate(self) -> int | None:
        for priority in ("LOW", "NORMAL"):
            for index, record in enumerate(self._records):
                if not record.audit_required and record.priority == priority:
                    return index
        return None
