from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from tests.foundation.support import ROOT


class MigrationHelmTests(unittest.TestCase):
    def test_postgres_roles_rls_least_privilege_and_append_only(self):
        sql = (ROOT / "migrations/policy/001_foundation.sql").read_text(encoding="utf-8")
        for role in ("owner", "migrator", "runtime", "audit_writer"):
            self.assertRegex(sql, rf"CREATE ROLE planeon_trust_{role} NOLOGIN .*NOBYPASSRLS")
        for table in ("policy_bundle", "policy_decision", "audit_record", "outbox_event"):
            self.assertIn(f"ALTER TABLE policy.{table} ENABLE ROW LEVEL SECURITY", sql)
            self.assertIn(f"ALTER TABLE policy.{table} FORCE ROW LEVEL SECURITY", sql)
            self.assertIn(f"CREATE POLICY {table}_tenant ON policy.{table}", sql)
            self.assertIn(f"ALTER TABLE policy.{table} OWNER TO planeon_trust_owner", sql)
        self.assertEqual(sql.count("NULLIF(current_setting('planeon.organization_id', true), '')"), 8)
        self.assertIn("set_config('planeon.organization_id', $1, true)", sql)
        self.assertNotRegex(sql, r"GRANT .*\b(?:DELETE|TRUNCATE|CREATE|DROP)\b.*planeon_trust_runtime")
        self.assertNotRegex(sql, r"(?im)^\s*(?:DROP|TRUNCATE|DELETE FROM)\b")
        self.assertIn("audit_record_append_only BEFORE UPDATE OR DELETE", sql)
        self.assertIn("outbox_event_append_only BEFORE UPDATE OR DELETE", sql)
        self.assertIn("ALTER FUNCTION policy.reject_append_only_change() OWNER TO planeon_trust_owner", sql)

    def test_chart_is_digest_only_inert_and_secret_referencing(self):
        chart = ROOT / "deploy/helm/policy-decision"
        values = (chart / "values.yaml").read_text(encoding="utf-8")
        schema = json.loads((chart / "values.schema.json").read_text(encoding="utf-8"))
        deployment = (chart / "templates/deployment.yaml").read_text(encoding="utf-8")
        helpers = (chart / "templates/_helpers.tpl").read_text(encoding="utf-8")
        network = (chart / "templates/networkpolicy.yaml").read_text(encoding="utf-8")
        self.assertGreaterEqual(values.count('repository: ""'), 2)
        self.assertGreaterEqual(values.count('digest: ""'), 2)
        self.assertIn("enabled: false", values)
        self.assertEqual(schema["$defs"]["digest"]["pattern"], "^sha256:[a-f0-9]{64}$")
        self.assertIn('printf "%s@%s"', helpers)
        self.assertNotRegex(deployment, r"image:\s*[^\n]+:[a-zA-Z]")
        for marker in ("runAsNonRoot: true", "readOnlyRootFilesystem: true", "allowPrivilegeEscalation: false", 'drop: ["ALL"]', "seccompProfile", "automountServiceAccountToken: false", "resources:", "livenessProbe", "readinessProbe"):
            self.assertIn(marker, deployment)
        self.assertIn("secretName:", deployment)
        self.assertNotIn("kind: Secret", deployment)
        self.assertIn("policyTypes: [Ingress, Egress]", network)
        self.assertIn("ingress: []", network)
        self.assertIn("egress: []", network)
        self.assertIn("if and .Values.networkPolicy.databaseNamespaceLabels .Values.networkPolicy.databasePodLabels", network)
        self.assertNotIn("port: 53", network)
        for path in chart.rglob("*.yaml"):
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"\bkind:\s*(?:Namespace|PersistentVolume|PersistentVolumeClaim|Secret)\b")


if __name__ == "__main__":
    unittest.main()
