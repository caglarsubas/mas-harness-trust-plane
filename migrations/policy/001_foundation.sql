-- TRUST-001 additive PostgreSQL authority. No destructive/down migration exists.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'planeon_trust_owner') THEN
    CREATE ROLE planeon_trust_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'planeon_trust_migrator') THEN
    CREATE ROLE planeon_trust_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'planeon_trust_runtime') THEN
    CREATE ROLE planeon_trust_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'planeon_trust_audit_writer') THEN
    CREATE ROLE planeon_trust_audit_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS policy AUTHORIZATION planeon_trust_owner;
GRANT USAGE ON SCHEMA policy TO planeon_trust_migrator, planeon_trust_runtime, planeon_trust_audit_writer;

CREATE TABLE policy.policy_bundle (
  organization_id text NOT NULL,
  policy_digest text NOT NULL,
  policy_id text NOT NULL,
  bundle_version bigint NOT NULL CHECK (bundle_version > 0),
  state text NOT NULL CHECK (state IN ('ACTIVE', 'RETIRED', 'REVOKED')),
  signer_key_id text NOT NULL,
  effective_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  supersedes_policy_digest text,
  recorded_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, policy_digest),
  CHECK (effective_at < expires_at)
);

CREATE TABLE policy.policy_decision (
  organization_id text NOT NULL,
  decision_id text NOT NULL,
  subject_digest text NOT NULL,
  request_digest text NOT NULL,
  policy_digest text NOT NULL,
  allowed boolean NOT NULL,
  reason_code text NOT NULL,
  obligation_ids jsonb NOT NULL,
  evaluated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, decision_id),
  FOREIGN KEY (organization_id, policy_digest) REFERENCES policy.policy_bundle (organization_id, policy_digest),
  CHECK (evaluated_at < expires_at)
);

CREATE TABLE policy.audit_record (
  organization_id text NOT NULL,
  audit_id text NOT NULL,
  decision_id text NOT NULL,
  subject_digest text NOT NULL,
  request_digest text NOT NULL,
  policy_digest text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('ALLOW', 'DENY')),
  reason_code text NOT NULL,
  obligation_ids jsonb NOT NULL,
  cache_hit boolean NOT NULL,
  recorded_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, audit_id)
);

CREATE TABLE policy.outbox_event (
  organization_id text NOT NULL,
  event_id text NOT NULL,
  event_type text NOT NULL,
  classification text NOT NULL,
  aggregate_id text NOT NULL,
  aggregate_digest text NOT NULL,
  recorded_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, event_id)
);

ALTER TABLE policy.policy_bundle OWNER TO planeon_trust_owner;
ALTER TABLE policy.policy_decision OWNER TO planeon_trust_owner;
ALTER TABLE policy.audit_record OWNER TO planeon_trust_owner;
ALTER TABLE policy.outbox_event OWNER TO planeon_trust_owner;

ALTER TABLE policy.policy_bundle ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy.policy_bundle FORCE ROW LEVEL SECURITY;
ALTER TABLE policy.policy_decision ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy.policy_decision FORCE ROW LEVEL SECURITY;
ALTER TABLE policy.audit_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy.audit_record FORCE ROW LEVEL SECURITY;
ALTER TABLE policy.outbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy.outbox_event FORCE ROW LEVEL SECURITY;

CREATE POLICY policy_bundle_tenant ON policy.policy_bundle
  USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));
CREATE POLICY policy_decision_tenant ON policy.policy_decision
  USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));
CREATE POLICY audit_record_tenant ON policy.audit_record
  USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));
CREATE POLICY outbox_event_tenant ON policy.outbox_event
  USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));

CREATE FUNCTION policy.reject_append_only_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'append-only relation cannot be changed';
END
$$;

ALTER FUNCTION policy.reject_append_only_change() OWNER TO planeon_trust_owner;

CREATE TRIGGER audit_record_append_only BEFORE UPDATE OR DELETE ON policy.audit_record
  FOR EACH ROW EXECUTE FUNCTION policy.reject_append_only_change();
CREATE TRIGGER outbox_event_append_only BEFORE UPDATE OR DELETE ON policy.outbox_event
  FOR EACH ROW EXECUTE FUNCTION policy.reject_append_only_change();

REVOKE ALL ON SCHEMA policy FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA policy FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA policy FROM PUBLIC;

GRANT SELECT ON policy.policy_bundle TO planeon_trust_runtime;
GRANT SELECT, INSERT ON policy.policy_decision TO planeon_trust_runtime;
GRANT SELECT, INSERT ON policy.audit_record, policy.outbox_event TO planeon_trust_audit_writer;
GRANT SELECT, INSERT, UPDATE ON policy.policy_bundle TO planeon_trust_migrator;

-- After validating an admitted organization id, each application transaction
-- must execute: SELECT set_config('planeon.organization_id', $1, true);
