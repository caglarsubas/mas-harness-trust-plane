from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import timedelta
from types import MappingProxyType

from planeon_trust.usage.dimensions import zero_dimensions

from .support import BUDGET_DIGEST, NOW, budget, identity_one, ledger_with_budget


class RetentionAndReconciliationTests(unittest.TestCase):
    def test_expiry_releases_reserved_capacity_and_is_audited(self) -> None:
        ledger = ledger_with_budget()
        ledger.reserve(
            identity_one(),
            budget_id="budget.foundation",
            budget_digest=BUDGET_DIGEST,
            scope_type="TENANT",
            scope_id="acme.one",
            operation_id="operation.expiry",
            idempotency_key="reserve.expiry",
            requested={"concurrentTasks": 1},
            reservation_ttl_seconds=60,
            now=NOW,
        )
        ledger.evaluate(
            identity_one(),
            budget_id="budget.foundation",
            budget_digest=BUDGET_DIGEST,
            scope_type="TENANT",
            scope_id="acme.one",
            requested={"concurrentTasks": 1},
            now=NOW + timedelta(seconds=61),
        )
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot["reservations"][0].state, "EXPIRED")
        self.assertEqual(snapshot["transitions"][0].state, "EXPIRED")
        self.assertEqual(snapshot["aggregates"][0].reserved["concurrentTasks"], 0)
        self.assertEqual(snapshot["outboxRecords"][-1]["type"], "usage.expired.v1")

    def test_reconciliation_detects_but_does_not_repair_mismatch(self) -> None:
        ledger = ledger_with_budget()
        ledger.reserve(
            identity_one(),
            budget_id="budget.foundation",
            budget_digest=BUDGET_DIGEST,
            scope_type="TENANT",
            scope_id="acme.one",
            operation_id="operation.reconcile",
            idempotency_key="reserve.reconcile",
            requested={"concurrentTasks": 1},
            reservation_ttl_seconds=60,
            now=NOW,
        )
        key = next(iter(ledger._state.aggregates))
        corrupt = zero_dimensions()
        corrupt["concurrentTasks"] = 3
        ledger._state.aggregates[key] = replace(
            ledger._state.aggregates[key],
            reserved=MappingProxyType(corrupt),
        )

        finding = ledger.reconcile(identity_one(), budget_id="budget.foundation", now=NOW)
        self.assertEqual(finding.status, "MISMATCH")
        self.assertEqual(ledger._state.aggregates[key].reserved["concurrentTasks"], 3)
        self.assertFalse(ledger.reconciliation_current("acme.one", now=NOW))

    def test_retention_is_findings_only_and_preserves_history(self) -> None:
        definition = budget(window_seconds=60, reservation_ttl_seconds=60, retention_windows=1)
        ledger = ledger_with_budget(definition)
        reservation = ledger.reserve(
            identity_one(),
            budget_id="budget.foundation",
            budget_digest=BUDGET_DIGEST,
            scope_type="TENANT",
            scope_id="acme.one",
            operation_id="operation.retention",
            idempotency_key="reserve.retention",
            requested={"modelTokens": 10},
            reservation_ttl_seconds=30,
            now=NOW,
        )
        ledger.commit(
            identity_one(),
            reservation_id=reservation["reservationId"],
            idempotency_key="commit.retention",
            observed={"modelTokens": 8},
            now=NOW,
        )
        count_before = len(ledger.snapshot()["usageEntries"])
        finding = ledger.retention_due(
            identity_one(),
            budget_id="budget.foundation",
            now=NOW + timedelta(seconds=121),
        )
        self.assertEqual(finding.status, "RETENTION_DUE")
        self.assertEqual(len(ledger.snapshot()["usageEntries"]), count_before)
        self.assertEqual(len(ledger.snapshot()["retentionFindings"]), 1)

    def test_prior_window_mismatch_sets_reset_pending(self) -> None:
        definition = budget(window_seconds=60, reservation_ttl_seconds=60)
        ledger = ledger_with_budget(definition)
        current_window = definition.window_at(NOW)
        ledger._state.reconciled[("acme.one", "budget.foundation", current_window.index)] = "MISMATCH"
        projection = ledger.list_budgets(identity_one(), now=NOW + timedelta(seconds=61))[0]
        self.assertEqual(projection["state"], "RESET_PENDING")


if __name__ == "__main__":
    unittest.main()
