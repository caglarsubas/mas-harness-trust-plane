from __future__ import annotations

import json
import unittest
from datetime import timedelta

from planeon_harness.context import HarnessContext
from planeon_trust.usage import BoundedTelemetryBuffer, ContentFreeTelemetry, TelemetrySaturated

from .support import NOW


def context(*, span: str = "2" * 16) -> HarnessContext:
    return HarnessContext.create(
        trace_id="1" * 32,
        span_id=span,
        tenant_id="tenant.one",
        organization_id="acme.one",
        harness_id="harness.observability",
        plane_id="plane.trust",
        operation_id="operation.one",
        correlation_id="correlation.one",
    )


def record(
    telemetry: ContentFreeTelemetry,
    *,
    span: str,
    priority: str = "NORMAL",
    audit_required: bool = False,
    now=NOW,
):
    return telemetry.admit(
        context(span=span),
        operation_name="usage.reserve",
        operation_kind="SERVER",
        outcome="success",
        attributes={"harness.label.route": "usage.reserve"},
        priority=priority,
        audit_required=audit_required,
        now=now,
    )


class TelemetryTests(unittest.TestCase):
    def test_content_and_unknown_attributes_are_dropped_without_value_echo(self) -> None:
        sentinel = "private-value-never-export"
        accepted = ContentFreeTelemetry().admit(
            context(),
            operation_name="usage.reserve",
            operation_kind="SERVER",
            outcome="success",
            attributes={
                "harness.label.route": "usage.reserve",
                "harness.label.prompt": sentinel,
                "arbitrary.attribute": sentinel,
            },
            priority="NORMAL",
            audit_required=False,
            now=NOW,
        )
        encoded = json.dumps(accepted.to_dict(), sort_keys=True)
        self.assertNotIn(sentinel, encoded)
        self.assertEqual(accepted.attributes["harness.label.route"], "usage.reserve")
        self.assertEqual(accepted.dropped_attribute_count, 2)

    def test_cardinality_is_bounded_per_tenant_and_key(self) -> None:
        telemetry = ContentFreeTelemetry(maximum_values_per_key=1)
        first = telemetry.admit(
            context(),
            operation_name="usage.reserve",
            operation_kind="SERVER",
            outcome="success",
            attributes={"harness.label.route": "route.one"},
            priority="NORMAL",
            audit_required=False,
            now=NOW,
        )
        second = telemetry.admit(
            context(span="3" * 16),
            operation_name="usage.reserve",
            operation_kind="SERVER",
            outcome="success",
            attributes={"harness.label.route": "route.two"},
            priority="NORMAL",
            audit_required=False,
            now=NOW,
        )
        self.assertIn("harness.label.route", first.attributes)
        self.assertNotIn("harness.label.route", second.attributes)
        self.assertEqual(second.dropped_attribute_count, 1)

    def test_buffer_drops_low_priority_first_and_expires_nonaudit(self) -> None:
        telemetry = ContentFreeTelemetry()
        buffer = BoundedTelemetryBuffer(maximum_records=2, maximum_bytes=65536, maximum_age_seconds=10)
        low = record(telemetry, span="2" * 16, priority="LOW")
        normal = record(telemetry, span="3" * 16)
        newest = record(telemetry, span="4" * 16)
        self.assertEqual(buffer.append(low, now=NOW), "BUFFERED")
        self.assertEqual(buffer.append(normal, now=NOW), "BUFFERED")
        self.assertEqual(buffer.append(newest, now=NOW), "BUFFERED")
        self.assertEqual([item.span_id for item in buffer.records("acme.one")], ["3" * 16, "4" * 16])

        later = record(telemetry, span="5" * 16, now=NOW + timedelta(seconds=11))
        buffer.append(later, now=NOW + timedelta(seconds=11))
        self.assertEqual([item.span_id for item in buffer.records("acme.one")], ["5" * 16])

    def test_audit_saturation_fails_closed(self) -> None:
        telemetry = ContentFreeTelemetry()
        buffer = BoundedTelemetryBuffer(maximum_records=1, maximum_bytes=65536, maximum_age_seconds=300)
        first = record(telemetry, span="2" * 16, priority="AUDIT", audit_required=True)
        second = record(telemetry, span="3" * 16, priority="AUDIT", audit_required=True)
        self.assertEqual(buffer.append(first, now=NOW), "BUFFERED")
        with self.assertRaises(TelemetrySaturated):
            buffer.append(second, now=NOW)
        self.assertTrue(buffer.audit_saturated)
        self.assertEqual(buffer.records("acme.one"), (first,))


if __name__ == "__main__":
    unittest.main()
