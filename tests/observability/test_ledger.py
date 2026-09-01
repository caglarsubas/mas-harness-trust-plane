from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from planeon_trust.usage import UsageDenied, UsageLedger

from .support import ADVISORY_DIGEST, BUDGET_DIGEST, NOW, budget, identity_one, ledger_with_budget


class UsageLedgerTests(unittest.TestCase):
    def test_hard_reservations_are_atomic_under_concurrency(self) -> None:
        ledger = ledger_with_budget(budget(limits={"concurrentTasks": 4}))

        def reserve(index: int) -> str:
            try:
                result = ledger.reserve(
                    identity_one(),
                    budget_id="budget.foundation",
                    budget_digest=BUDGET_DIGEST,
                    scope_type="TENANT",
                    scope_id="acme.one",
                    operation_id=f"operation.{index}",
                    idempotency_key=f"reserve.{index}",
                    requested={"concurrentTasks": 1},
                    reservation_ttl_seconds=60,
                    now=NOW,
                )
                return str(result["state"])
            except UsageDenied as exc:
                return exc.reason_code

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(reserve, range(8)))

        self.assertEqual(results.count("RESERVED"), 4)
        self.assertEqual(results.count("BUDGET_EXCEEDED"), 4)
        projection = ledger.list_budgets(identity_one(), now=NOW)[0]
        self.assertEqual(projection["reserved"]["concurrentTasks"], 4)
        self.assertEqual(projection["state"], "EXHAUSTED")

    def test_reserve_commit_and_release_are_idempotent_and_terminal(self) -> None:
        ledger = ledger_with_budget()
        arguments = {
            "budget_id": "budget.foundation",
            "budget_digest": BUDGET_DIGEST,
            "scope_type": "TENANT",
            "scope_id": "acme.one",
            "operation_id": "operation.one",
            "idempotency_key": "reserve.one",
            "requested": {"modelTokens": 100},
            "reservation_ttl_seconds": 60,
            "now": NOW,
        }
        first = ledger.reserve(identity_one(), **arguments)
        replay = ledger.reserve(identity_one(), **arguments)
        self.assertEqual(dict(first), dict(replay))

        conflicting = dict(arguments)
        conflicting["requested"] = {"modelTokens": 101}
        with self.assertRaisesRegex(UsageDenied, "IDEMPOTENCY_CONFLICT"):
            ledger.reserve(identity_one(), **conflicting)

        committed = ledger.commit(
            identity_one(),
            reservation_id=first["reservationId"],
            idempotency_key="commit.one",
            observed={"modelTokens": 80},
            now=NOW,
        )
        replayed_commit = ledger.commit(
            identity_one(),
            reservation_id=first["reservationId"],
            idempotency_key="commit.one",
            observed={"modelTokens": 80},
            now=NOW,
        )
        self.assertEqual(dict(committed), dict(replayed_commit))
        self.assertEqual(committed["state"], "COMMITTED")
        with self.assertRaisesRegex(UsageDenied, "RESERVATION_TERMINAL"):
            ledger.release(
                identity_one(),
                reservation_id=first["reservationId"],
                idempotency_key="release.one",
                reason="CALLER_CANCELLED",
                now=NOW,
            )

    def test_commit_cannot_exceed_the_reservation(self) -> None:
        ledger = ledger_with_budget()
        reservation = ledger.reserve(
            identity_one(),
            budget_id="budget.foundation",
            budget_digest=BUDGET_DIGEST,
            scope_type="TENANT",
            scope_id="acme.one",
            operation_id="operation.one",
            idempotency_key="reserve.one",
            requested={"modelTokens": 100},
            reservation_ttl_seconds=60,
            now=NOW,
        )
        with self.assertRaisesRegex(UsageDenied, "COMMIT_EXCEEDS_RESERVATION"):
            ledger.commit(
                identity_one(),
                reservation_id=reservation["reservationId"],
                idempotency_key="commit.one",
                observed={"modelTokens": 101},
                now=NOW,
            )

    def test_advisory_budget_reports_excess_without_blocking(self) -> None:
        definition = budget(
            budget_id="budget.advisory",
            budget_digest=ADVISORY_DIGEST,
            enforcement="ADVISORY",
            limits={"toolCalls": 1},
        )
        ledger = ledger_with_budget(definition)
        reservation = ledger.reserve(
            identity_one(),
            budget_id="budget.advisory",
            budget_digest=ADVISORY_DIGEST,
            scope_type="TENANT",
            scope_id="acme.one",
            operation_id="operation.advisory",
            idempotency_key="reserve.advisory",
            requested={"toolCalls": 2},
            reservation_ttl_seconds=60,
            now=NOW,
        )
        self.assertEqual(reservation["state"], "RESERVED")
        self.assertEqual(reservation["exceededDimensions"], ["toolCalls"])
        evaluation = ledger.evaluate(
            identity_one(),
            budget_id="budget.advisory",
            budget_digest=ADVISORY_DIGEST,
            scope_type="TENANT",
            scope_id="acme.one",
            requested={"toolCalls": 1},
            now=NOW,
        )
        self.assertTrue(evaluation["allowed"])
        self.assertEqual(evaluation["enforcement"], "ADVISORY")

    def test_suspension_clock_and_store_failure_are_fail_closed(self) -> None:
        suspended = ledger_with_budget(budget(enabled=False))
        with self.assertRaisesRegex(UsageDenied, "BUDGET_SUSPENDED"):
            suspended.reserve(
                identity_one(),
                budget_id="budget.foundation",
                budget_digest=BUDGET_DIGEST,
                scope_type="TENANT",
                scope_id="acme.one",
                operation_id="operation.one",
                idempotency_key="reserve.one",
                requested={"modelTokens": 1},
                reservation_ttl_seconds=60,
                now=NOW,
            )
        self.assertEqual(suspended.list_budgets(identity_one(), now=NOW)[0]["state"], "SUSPENDED")
        with self.assertRaisesRegex(UsageDenied, "CLOCK_REGRESSION"):
            suspended.list_budgets(identity_one(), now=NOW - timedelta(seconds=1))

        def fail_reserve(operation: str) -> None:
            if operation == "RESERVE":
                raise RuntimeError("injected durable-store failure")

        failing = UsageLedger(failure_injector=fail_reserve)
        failing.add_budget(budget())
        before = dict(failing.snapshot())
        with self.assertRaisesRegex(UsageDenied, "STORE_COMMIT_FAILED"):
            failing.reserve(
                identity_one(),
                budget_id="budget.foundation",
                budget_digest=BUDGET_DIGEST,
                scope_type="TENANT",
                scope_id="acme.one",
                operation_id="operation.one",
                idempotency_key="reserve.failure",
                requested={"modelTokens": 1},
                reservation_ttl_seconds=60,
                now=NOW,
            )
        self.assertEqual(before, dict(failing.snapshot()))


if __name__ == "__main__":
    unittest.main()
