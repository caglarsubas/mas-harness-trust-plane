from __future__ import annotations

import json
import unittest
from pathlib import Path

from planeon_trust.usage import UsageDenied

from .support import NOW, TOKEN_ONE, identity_one, reserve_request, service_bundle


class UsageSecurityTests(unittest.TestCase):
    def test_idempotency_and_identity_material_are_stored_only_as_digests(self) -> None:
        service, ledger, _ = service_bundle()
        sentinel = "private-idempotency-material"
        request = reserve_request(key=sentinel)
        reservation = service.reserve(TOKEN_ONE, request, now=NOW)
        service.commit(
            TOKEN_ONE,
            {
                "schemaVersion": "harness.planeon.ai/usage-ledger/v1alpha1",
                "reservationId": reservation["reservationId"],
                "idempotencyKey": "private-commit-material",
                "observed": {"concurrentTasks": 1},
            },
            now=NOW,
        )
        persisted = repr(dict(ledger.snapshot()))
        self.assertNotIn(sentinel, persisted)
        self.assertNotIn(TOKEN_ONE, persisted)
        self.assertNotIn("private-commit-material", persisted)
        self.assertIn("sha256:", persisted)

    def test_recursive_content_key_rejection_never_echoes_value(self) -> None:
        service, _, _ = service_bundle()
        sentinel = "confidential-workload-content"
        body = reserve_request()
        body["unexpected"] = [{"toolPayload": sentinel}]
        with self.assertRaises(UsageDenied) as raised:
            service.reserve(TOKEN_ONE, body, now=NOW)
        self.assertEqual(raised.exception.reason_code, "CONTENT_FIELD_FORBIDDEN")
        self.assertNotIn(sentinel, str(raised.exception))

    def test_ledger_queries_are_strictly_tenant_scoped(self) -> None:
        service, ledger, _ = service_bundle()
        service.reserve(TOKEN_ONE, reserve_request(), now=NOW)
        self.assertEqual(len(ledger.list_budgets(identity_one(), now=NOW)), 1)
        from .support import identity_two

        self.assertEqual(ledger.list_budgets(identity_two(), now=NOW), ())
        self.assertEqual(ledger.list_usage(identity_two(), now=NOW), ())

    def test_public_error_contract_is_content_free(self) -> None:
        schema = json.loads(
            (Path(__file__).resolve().parents[2] / "services/usage-ledger/contracts/usage-error.schema.json").read_text(
                encoding="utf-8"
            )
        )
        properties = set(schema["properties"])
        self.assertEqual(properties, {"schemaVersion", "allowed", "reasonCode"})
        self.assertFalse(schema["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
