BEGIN;

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'planeon_guardrail_owner') THEN
    CREATE ROLE planeon_guardrail_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'planeon_guardrail_migrator') THEN
    CREATE ROLE planeon_guardrail_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'planeon_guardrail_runtime') THEN
    CREATE ROLE planeon_guardrail_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'planeon_guardrail_evidence_writer') THEN
    CREATE ROLE planeon_guardrail_evidence_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

CREATE SCHEMA IF NOT EXISTS guardrails AUTHORIZATION planeon_guardrail_owner;
REVOKE ALL ON SCHEMA guardrails FROM PUBLIC;
GRANT USAGE ON SCHEMA guardrails TO planeon_guardrail_migrator, planeon_guardrail_runtime, planeon_guardrail_evidence_writer;

CREATE OR REPLACE FUNCTION guardrails.current_organization_id()
RETURNS text
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
  SELECT NULLIF(current_setting('planeon.organization_id', true), '')
$$;
ALTER FUNCTION guardrails.current_organization_id() OWNER TO planeon_guardrail_owner;
REVOKE ALL ON FUNCTION guardrails.current_organization_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION guardrails.current_organization_id() TO planeon_guardrail_runtime, planeon_guardrail_evidence_writer;

CREATE TABLE IF NOT EXISTS guardrails.profile_versions (
  organization_id text NOT NULL,
  profile_id text NOT NULL,
  profile_version text NOT NULL,
  profile_digest text NOT NULL CHECK (profile_digest ~ '^sha256:[0-9a-f]{64}$'),
  signer_key_id text NOT NULL,
  stage text NOT NULL CHECK (stage IN ('INPUT', 'OUTPUT', 'RUNTIME', 'STREAMING')),
  fail_mode text NOT NULL CHECK (fail_mode IN ('FAIL_CLOSED', 'FAIL_OPEN')),
  effective_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  supersedes_profile_digest text CHECK (supersedes_profile_digest IS NULL OR supersedes_profile_digest ~ '^sha256:[0-9a-f]{64}$'),
  recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (organization_id, profile_id, profile_digest),
  CHECK (effective_at < expires_at),
  CHECK (fail_mode = 'FAIL_CLOSED' OR stage IN ('OUTPUT', 'STREAMING'))
);
ALTER TABLE guardrails.profile_versions OWNER TO planeon_guardrail_owner;

CREATE TABLE IF NOT EXISTS guardrails.profile_state_events (
  event_id text PRIMARY KEY,
  organization_id text NOT NULL,
  profile_id text NOT NULL,
  profile_digest text NOT NULL CHECK (profile_digest ~ '^sha256:[0-9a-f]{64}$'),
  state text NOT NULL CHECK (state IN ('ACTIVE', 'SUPERSEDED', 'REVOKED', 'ROLLED_BACK')),
  reason_code text NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);
ALTER TABLE guardrails.profile_state_events OWNER TO planeon_guardrail_owner;

CREATE TABLE IF NOT EXISTS guardrails.decisions (
  decision_id text PRIMARY KEY,
  organization_id text NOT NULL,
  profile_id text NOT NULL,
  profile_version text NOT NULL,
  profile_digest text NOT NULL CHECK (profile_digest ~ '^sha256:[0-9a-f]{64}$'),
  stage text NOT NULL CHECK (stage IN ('INPUT', 'OUTPUT', 'RUNTIME', 'STREAMING')),
  content_digest text NOT NULL CHECK (content_digest ~ '^sha256:[0-9a-f]{64}$'),
  content_bytes bigint NOT NULL CHECK (content_bytes BETWEEN 0 AND 1048576),
  outcome text NOT NULL CHECK (outcome IN ('ALLOW', 'DENY', 'REDACT', 'QUARANTINE', 'ERROR_FAIL_CLOSED', 'ERROR_FAIL_OPEN')),
  reason_code text NOT NULL,
  degraded boolean NOT NULL,
  released boolean NOT NULL,
  evidence_id text NOT NULL UNIQUE,
  evaluated_at timestamptz NOT NULL,
  CHECK (released = (outcome IN ('ALLOW', 'REDACT')))
);
ALTER TABLE guardrails.decisions OWNER TO planeon_guardrail_owner;

CREATE TABLE IF NOT EXISTS guardrails.evidence_outbox (
  evidence_id text PRIMARY KEY,
  organization_id text NOT NULL,
  decision_id text NOT NULL UNIQUE REFERENCES guardrails.decisions(decision_id),
  record_state text NOT NULL CHECK (record_state = 'RECEIVED'),
  axis text NOT NULL CHECK (axis = 'SECURITY'),
  result text NOT NULL CHECK (result IN ('PASS', 'WARN', 'FAIL')),
  evidence_digest text NOT NULL CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
  provenance_digest text NOT NULL CHECK (provenance_digest ~ '^sha256:[0-9a-f]{64}$'),
  campaign_generated boolean NOT NULL CHECK (campaign_generated = false),
  collected_at timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  dispatched_at timestamptz
);
ALTER TABLE guardrails.evidence_outbox OWNER TO planeon_guardrail_owner;

ALTER TABLE guardrails.profile_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE guardrails.profile_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE guardrails.profile_state_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE guardrails.profile_state_events FORCE ROW LEVEL SECURITY;
ALTER TABLE guardrails.decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE guardrails.decisions FORCE ROW LEVEL SECURITY;
ALTER TABLE guardrails.evidence_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE guardrails.evidence_outbox FORCE ROW LEVEL SECURITY;

CREATE POLICY profile_versions_tenant ON guardrails.profile_versions
  USING (organization_id = guardrails.current_organization_id())
  WITH CHECK (organization_id = guardrails.current_organization_id());
CREATE POLICY profile_state_events_tenant ON guardrails.profile_state_events
  USING (organization_id = guardrails.current_organization_id())
  WITH CHECK (organization_id = guardrails.current_organization_id());
CREATE POLICY decisions_tenant ON guardrails.decisions
  USING (organization_id = guardrails.current_organization_id())
  WITH CHECK (organization_id = guardrails.current_organization_id());
CREATE POLICY evidence_outbox_tenant ON guardrails.evidence_outbox
  USING (organization_id = guardrails.current_organization_id())
  WITH CHECK (organization_id = guardrails.current_organization_id());

REVOKE ALL ON ALL TABLES IN SCHEMA guardrails FROM PUBLIC;
GRANT SELECT, INSERT ON guardrails.profile_versions, guardrails.profile_state_events TO planeon_guardrail_migrator;
GRANT SELECT, INSERT ON guardrails.decisions TO planeon_guardrail_runtime;
GRANT SELECT, INSERT ON guardrails.evidence_outbox TO planeon_guardrail_evidence_writer;
REVOKE UPDATE, DELETE, TRUNCATE ON guardrails.profile_versions, guardrails.profile_state_events, guardrails.decisions, guardrails.evidence_outbox FROM planeon_guardrail_migrator, planeon_guardrail_runtime, planeon_guardrail_evidence_writer;

COMMIT;
