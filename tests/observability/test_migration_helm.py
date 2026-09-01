from __future__ import annotations

import json
import re
import unittest

from .support import ROOT


class MigrationAndHelmTests(unittest.TestCase):
    def test_migration_has_separated_roles_rls_and_append_only_authority(self) -> None:
        sql = (ROOT / "migrations/usage/001_usage.sql").read_text(encoding="utf-8")
        for role in ("owner", "migrator", "runtime", "audit_reader"):
            self.assertIn(f"CREATE ROLE planeon_usage_{role}", sql)
        tables = re.findall(r"CREATE TABLE usage\.([a-z_]+)", sql)
        self.assertEqual(len(tables), 9)
        self.assertEqual(sql.count("ENABLE ROW LEVEL SECURITY"), 9)
        self.assertEqual(sql.count("FORCE ROW LEVEL SECURITY"), 9)
        self.assertEqual(sql.count("_append_only BEFORE UPDATE OR DELETE"), 9)
        self.assertEqual(sql.count("CREATE POLICY "), 9)
        self.assertIn("current_setting('planeon.organization_id', true)", sql)
        self.assertIn("set_config('planeon.organization_id', validated_organization_id, true)", sql)
        runtime_grant = next(line for line in sql.splitlines() if line.startswith("GRANT SELECT, INSERT"))
        self.assertNotIn("UPDATE", runtime_grant)
        self.assertNotIn("DELETE", runtime_grant)
        self.assertNotIn("TRUNCATE", runtime_grant)
        self.assertNotIn("DROP ", sql.upper())

    def test_chart_is_disabled_digest_pinned_and_uses_existing_authority(self) -> None:
        chart = ROOT / "deploy/helm/usage-ledger"
        values = (chart / "values.yaml").read_text(encoding="utf-8")
        deployment = (chart / "templates/deployment.yaml").read_text(encoding="utf-8")
        service = (chart / "templates/service.yaml").read_text(encoding="utf-8")
        network = (chart / "templates/networkpolicy.yaml").read_text(encoding="utf-8")
        self.assertTrue(values.startswith("enabled: false\n"))
        self.assertIn('repository: ""', values)
        self.assertIn('digest: ""', values)
        self.assertIn('image: "{{ .Values.image.repository }}@{{ .Values.image.digest }}"', deployment)
        self.assertIn("automountServiceAccountToken: false", deployment)
        self.assertIn("runAsNonRoot: true", deployment)
        self.assertIn("allowPrivilegeEscalation: false", deployment)
        self.assertIn("readOnlyRootFilesystem: true", deployment)
        self.assertIn('capabilities: {drop: ["ALL"]}', deployment)
        self.assertIn("existingSecrets.oidcRegistry", deployment)
        self.assertIn("existingSecrets.database", deployment)
        self.assertNotIn("kind: Secret", deployment + service + network)
        self.assertNotIn("kind: Namespace", deployment + service + network)
        self.assertIn("policyTypes:", network)
        self.assertIn("Ingress", network)
        self.assertIn("Egress", network)

    def test_values_schema_is_closed_and_requires_immutable_image_fields(self) -> None:
        schema = json.loads((ROOT / "deploy/helm/usage-ledger/values.schema.json").read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("image", schema["required"])
        self.assertEqual(set(schema["properties"]["image"]["required"]), {"repository", "digest", "pullPolicy"})
        self.assertFalse(schema["properties"]["image"]["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
