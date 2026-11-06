-- Audit evidence for qualified fresh-install schema snapshots.  This table does
-- not make a snapshot qualified: the migration runner records a row only after
-- validating the snapshot, its manifest and its independently reviewed schema
-- fingerprint.  Ordinary migration-chain installs do not create a row.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=163) THEN
    RAISE EXCEPTION 'MIGRATION_0164_REQUIRES_0163';
  END IF;
END $$;

CREATE TABLE epm.schema_baseline_materialization (
    baseline_id text PRIMARY KEY CHECK (baseline_id ~ '^[a-z0-9][a-z0-9._-]{7,127}$'),
    target_version integer NOT NULL CHECK (target_version > 0),
    canonical_chain_digest text NOT NULL CHECK (canonical_chain_digest ~ '^[0-9a-f]{64}$'),
    execution_artifact_digest text NOT NULL CHECK (execution_artifact_digest ~ '^[0-9a-f]{64}$'),
    equivalence_evidence_digest text NOT NULL CHECK (equivalence_evidence_digest ~ '^[0-9a-f]{64}$'),
    schema_fingerprint text NOT NULL CHECK (schema_fingerprint ~ '^[0-9a-f]{64}$'),
    reviewer_identity text NOT NULL CHECK (length(reviewer_identity) BETWEEN 1 AND 300),
    source_commit text NOT NULL CHECK (length(source_commit) BETWEEN 1 AND 200),
    build_id text NOT NULL CHECK (length(build_id) BETWEEN 1 AND 200),
    postgres_profile text NOT NULL CHECK (length(postgres_profile) BETWEEN 1 AND 500),
    extension_profile text NOT NULL CHECK (length(extension_profile) BETWEEN 1 AND 1000),
    artifact_format text NOT NULL CHECK (artifact_format = 'openepm-sql-statements-v1'),
    materialization_method text NOT NULL CHECK (materialization_method = 'qualified-fresh-snapshot'),
    materialized_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CHECK (target_version < 164)
);

REVOKE ALL ON epm.schema_baseline_materialization FROM PUBLIC;
GRANT SELECT ON epm.schema_baseline_materialization TO epm_lifecycle;
