from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class MigrationAndHelmTests(unittest.TestCase):
    def test_sql_forces_tenant_rls_and_metadata_only_append_permissions(self) -> None:
        sql = (ROOT / "migrations/guardrails/001_guardrails.sql").read_text(encoding="utf-8")
        for role in ("owner", "migrator", "runtime", "evidence_writer"):
            self.assertIn(f"planeon_guardrail_{role}", sql)
        for table in ("profile_versions", "profile_state_events", "decisions", "evidence_outbox"):
            self.assertIn(f"ALTER TABLE guardrails.{table} ENABLE ROW LEVEL SECURITY", sql)
            self.assertIn(f"ALTER TABLE guardrails.{table} FORCE ROW LEVEL SECURITY", sql)
            self.assertRegex(sql, rf"CREATE POLICY {table}_tenant")
        self.assertIn("current_setting('planeon.organization_id', true)", sql)
        self.assertIn("REVOKE UPDATE, DELETE, TRUNCATE", sql)
        self.assertNotRegex(sql.casefold(), r"\b(?:raw_content|redacted_content|prompt|model_output|token|claims|private_key)\b")
        self.assertNotRegex(sql.casefold(), r"\bpayload\s+(?:text|json|jsonb|bytea)\b")

    def test_chart_is_digest_only_existing_secret_and_openshift_safe(self) -> None:
        chart = ROOT / "deploy/helm/guardrail-service"
        values = (chart / "values.yaml").read_text(encoding="utf-8")
        schema = json.loads((chart / "values.schema.json").read_text(encoding="utf-8"))
        deployment = (chart / "templates/deployment.yaml").read_text(encoding="utf-8")
        network = (chart / "templates/networkpolicy.yaml").read_text(encoding="utf-8")
        rendered_sources = "\n".join(path.read_text(encoding="utf-8") for path in (chart / "templates").glob("*"))
        self.assertIn('repository: ""', values)
        self.assertIn('digest: ""', values)
        self.assertNotRegex(rendered_sources, r"image:\s+[^\n]+:[a-zA-Z]")
        self.assertIn('printf "%s@%s"', rendered_sources)
        self.assertEqual(schema["properties"]["networkPolicy"]["properties"]["enabled"], {"const": True})
        for secret in ("oidcRegistry", "profileKeyset", "activeProfiles", "database"):
            self.assertIn(secret, schema["properties"]["existingSecrets"]["required"])
        for marker in (
            "automountServiceAccountToken: false",
            "runAsNonRoot: true",
            "allowPrivilegeEscalation: false",
            "readOnlyRootFilesystem: true",
            'capabilities: {drop: ["ALL"]}',
            "seccompProfile: {type: RuntimeDefault}",
        ):
            self.assertIn(marker, deployment)
        self.assertIn("ingress: []", network)
        self.assertIn("egress: []", network)
        self.assertIsNone(re.search(r"\bkind:\s*(?:Secret|Namespace|PersistentVolume|PersistentVolumeClaim)\b", rendered_sources))

    def test_service_contracts_are_closed_json_and_pin_absent_upstream_surface(self) -> None:
        contracts = ROOT / "services/guardrail-service/contracts"
        documents = {path.name: json.loads(path.read_text(encoding="utf-8")) for path in contracts.glob("*.json")}
        self.assertEqual(len(documents), 10)
        identifiers = [item["$id"] for item in documents.values() if "$id" in item]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        for name, document in documents.items():
            if name != "upstream.lock.json":
                self.assertFalse(document["additionalProperties"], name)
        upstream = documents["upstream.lock.json"]
        self.assertFalse(upstream["contracts"]["guardrailRoutePresent"])
        self.assertFalse(upstream["contracts"]["guardrailCloudEventPresent"])
        self.assertEqual(upstream["sdk"]["wheelSha256"], "9b85d01b7079fe27c189d70b7fba46614c3df647d6f44e9270fe4683d7337fa4")
        response = documents["guardrail-evaluate-response.schema.json"]
        self.assertIn("evidenceRecord", response["required"])
        self.assertIn("redactedContent", response["required"])


if __name__ == "__main__":
    unittest.main()
