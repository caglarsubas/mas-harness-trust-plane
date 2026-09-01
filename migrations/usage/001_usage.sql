-- TRUST-OBS-001 additive PostgreSQL contract. No destructive rollback exists.
CREATE ROLE planeon_usage_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE planeon_usage_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE planeon_usage_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE planeon_usage_audit_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;

CREATE SCHEMA usage AUTHORIZATION planeon_usage_owner;
GRANT USAGE ON SCHEMA usage TO planeon_usage_migrator, planeon_usage_runtime, planeon_usage_audit_reader;

CREATE TABLE usage.budget_definition (
    organization_id text NOT NULL,
    budget_id text NOT NULL,
    budget_digest text NOT NULL CHECK (budget_digest ~ '^sha256:[0-9a-f]{64}$'),
    scope_type text NOT NULL CHECK (scope_type IN ('TENANT', 'PROFILE', 'ROUTE', 'WORKFLOW')),
    scope_id text NOT NULL,
    enforcement text NOT NULL CHECK (enforcement IN ('HARD', 'ADVISORY')),
    limits_json jsonb NOT NULL,
    window_epoch timestamptz NOT NULL,
    window_seconds integer NOT NULL CHECK (window_seconds BETWEEN 60 AND 31536000),
    warning_threshold_basis_points integer NOT NULL CHECK (warning_threshold_basis_points BETWEEN 1 AND 9999),
    reservation_ttl_seconds integer NOT NULL CHECK (reservation_ttl_seconds BETWEEN 1 AND 3600),
    retention_windows integer NOT NULL CHECK (retention_windows BETWEEN 1 AND 366),
    enabled boolean NOT NULL,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, budget_id),
    UNIQUE (organization_id, budget_digest)
);

CREATE TABLE usage.reservation (
    organization_id text NOT NULL,
    reservation_id text NOT NULL,
    budget_id text NOT NULL,
    budget_digest text NOT NULL CHECK (budget_digest ~ '^sha256:[0-9a-f]{64}$'),
    subject_digest text NOT NULL CHECK (subject_digest ~ '^sha256:[0-9a-f]{64}$'),
    operation_id text NOT NULL,
    scope_type text NOT NULL CHECK (scope_type IN ('TENANT', 'PROFILE', 'ROUTE', 'WORKFLOW')),
    scope_id text NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    idempotency_key_digest text NOT NULL CHECK (idempotency_key_digest ~ '^sha256:[0-9a-f]{64}$'),
    requested_json jsonb NOT NULL,
    window_index bigint NOT NULL CHECK (window_index >= 0),
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, reservation_id),
    UNIQUE (organization_id, idempotency_key_digest),
    FOREIGN KEY (organization_id, budget_id) REFERENCES usage.budget_definition (organization_id, budget_id)
);

CREATE TABLE usage.reservation_transition (
    organization_id text NOT NULL,
    transition_id text NOT NULL,
    reservation_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('COMMITTED', 'RELEASED', 'EXPIRED')),
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    idempotency_key_digest text NOT NULL CHECK (idempotency_key_digest ~ '^sha256:[0-9a-f]{64}$'),
    observed_json jsonb NOT NULL,
    reason_code text NOT NULL,
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, transition_id),
    UNIQUE (organization_id, reservation_id),
    UNIQUE (organization_id, state, idempotency_key_digest),
    FOREIGN KEY (organization_id, reservation_id) REFERENCES usage.reservation (organization_id, reservation_id)
);

CREATE TABLE usage.usage_entry (
    organization_id text NOT NULL,
    usage_entry_id text NOT NULL,
    reservation_id text NOT NULL,
    budget_id text NOT NULL,
    budget_digest text NOT NULL CHECK (budget_digest ~ '^sha256:[0-9a-f]{64}$'),
    scope_type text NOT NULL CHECK (scope_type IN ('TENANT', 'PROFILE', 'ROUTE', 'WORKFLOW')),
    scope_id text NOT NULL,
    operation_id text NOT NULL,
    dimensions_json jsonb NOT NULL,
    window_index bigint NOT NULL CHECK (window_index >= 0),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, usage_entry_id),
    UNIQUE (organization_id, reservation_id),
    FOREIGN KEY (organization_id, reservation_id) REFERENCES usage.reservation (organization_id, reservation_id)
);

CREATE TABLE usage.aggregate_snapshot (
    organization_id text NOT NULL,
    aggregate_id text NOT NULL,
    budget_id text NOT NULL,
    window_index bigint NOT NULL CHECK (window_index >= 0),
    revision bigint NOT NULL CHECK (revision >= 1),
    committed_json jsonb NOT NULL,
    reserved_json jsonb NOT NULL,
    aggregate_digest text NOT NULL CHECK (aggregate_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, aggregate_id),
    UNIQUE (organization_id, budget_id, window_index, revision)
);

CREATE TABLE usage.reconciliation_finding (
    organization_id text NOT NULL,
    finding_id text NOT NULL,
    budget_id text NOT NULL,
    window_index bigint NOT NULL CHECK (window_index >= 0),
    expected_digest text NOT NULL CHECK (expected_digest ~ '^sha256:[0-9a-f]{64}$'),
    observed_digest text NOT NULL CHECK (observed_digest ~ '^sha256:[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status IN ('MATCH', 'MISMATCH')),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, finding_id)
);

CREATE TABLE usage.retention_finding (
    organization_id text NOT NULL,
    finding_id text NOT NULL,
    budget_id text NOT NULL,
    cutoff_window_index bigint NOT NULL,
    history_digest text NOT NULL CHECK (history_digest ~ '^sha256:[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status IN ('RETENTION_DUE', 'NOT_DUE')),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, finding_id)
);

CREATE TABLE usage.audit_record (
    organization_id text NOT NULL,
    audit_id text NOT NULL,
    subject_digest text NOT NULL CHECK (subject_digest ~ '^sha256:[0-9a-f]{64}$'),
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    reason_code text NOT NULL,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, audit_id)
);

CREATE TABLE usage.outbox_event (
    organization_id text NOT NULL,
    event_id text NOT NULL,
    event_type text NOT NULL,
    aggregate_id text NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, event_id)
);

CREATE FUNCTION usage.reject_authoritative_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'usage authoritative records are append-only';
END;
$$;

CREATE TRIGGER budget_definition_append_only BEFORE UPDATE OR DELETE ON usage.budget_definition FOR EACH ROW EXECUTE FUNCTION usage.reject_authoritative_mutation();
CREATE TRIGGER reservation_append_only BEFORE UPDATE OR DELETE ON usage.reservation FOR EACH ROW EXECUTE FUNCTION usage.reject_authoritative_mutation();
CREATE TRIGGER reservation_transition_append_only BEFORE UPDATE OR DELETE ON usage.reservation_transition FOR EACH ROW EXECUTE FUNCTION usage.reject_authoritative_mutation();
CREATE TRIGGER usage_entry_append_only BEFORE UPDATE OR DELETE ON usage.usage_entry FOR EACH ROW EXECUTE FUNCTION usage.reject_authoritative_mutation();
CREATE TRIGGER aggregate_snapshot_append_only BEFORE UPDATE OR DELETE ON usage.aggregate_snapshot FOR EACH ROW EXECUTE FUNCTION usage.reject_authoritative_mutation();
CREATE TRIGGER reconciliation_finding_append_only BEFORE UPDATE OR DELETE ON usage.reconciliation_finding FOR EACH ROW EXECUTE FUNCTION usage.reject_authoritative_mutation();
CREATE TRIGGER retention_finding_append_only BEFORE UPDATE OR DELETE ON usage.retention_finding FOR EACH ROW EXECUTE FUNCTION usage.reject_authoritative_mutation();
CREATE TRIGGER audit_record_append_only BEFORE UPDATE OR DELETE ON usage.audit_record FOR EACH ROW EXECUTE FUNCTION usage.reject_authoritative_mutation();
CREATE TRIGGER outbox_event_append_only BEFORE UPDATE OR DELETE ON usage.outbox_event FOR EACH ROW EXECUTE FUNCTION usage.reject_authoritative_mutation();

ALTER TABLE usage.budget_definition ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage.budget_definition FORCE ROW LEVEL SECURITY;
ALTER TABLE usage.reservation ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage.reservation FORCE ROW LEVEL SECURITY;
ALTER TABLE usage.reservation_transition ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage.reservation_transition FORCE ROW LEVEL SECURITY;
ALTER TABLE usage.usage_entry ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage.usage_entry FORCE ROW LEVEL SECURITY;
ALTER TABLE usage.aggregate_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage.aggregate_snapshot FORCE ROW LEVEL SECURITY;
ALTER TABLE usage.reconciliation_finding ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage.reconciliation_finding FORCE ROW LEVEL SECURITY;
ALTER TABLE usage.retention_finding ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage.retention_finding FORCE ROW LEVEL SECURITY;
ALTER TABLE usage.audit_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage.audit_record FORCE ROW LEVEL SECURITY;
ALTER TABLE usage.outbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage.outbox_event FORCE ROW LEVEL SECURITY;

CREATE POLICY budget_tenant ON usage.budget_definition USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));
CREATE POLICY reservation_tenant ON usage.reservation USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));
CREATE POLICY transition_tenant ON usage.reservation_transition USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));
CREATE POLICY usage_entry_tenant ON usage.usage_entry USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));
CREATE POLICY aggregate_tenant ON usage.aggregate_snapshot USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));
CREATE POLICY reconciliation_tenant ON usage.reconciliation_finding USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));
CREATE POLICY retention_tenant ON usage.retention_finding USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));
CREATE POLICY audit_tenant ON usage.audit_record USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));
CREATE POLICY outbox_tenant ON usage.outbox_event USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), ''));

-- The application begins every transaction with:
-- SELECT set_config('planeon.organization_id', validated_organization_id, true);
GRANT SELECT, INSERT ON usage.budget_definition, usage.reservation, usage.reservation_transition, usage.usage_entry, usage.aggregate_snapshot, usage.reconciliation_finding, usage.retention_finding, usage.audit_record, usage.outbox_event TO planeon_usage_runtime;
GRANT SELECT ON usage.audit_record, usage.outbox_event, usage.reconciliation_finding, usage.retention_finding TO planeon_usage_audit_reader;
