-- Immutable, application-scoped saved-grid definitions for the human UI and
-- MCP clients.  Definitions are presentation/query plans only: they contain
-- stable metadata IDs and never SQL, credentials, calculated values or facts.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=203) THEN
        RAISE EXCEPTION 'MIGRATION_0204_PREDECESSOR_0203_REQUIRED';
    END IF;
END $migration$;

CREATE TABLE epm.saved_grid_definition (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    grid_id text NOT NULL
      CHECK(grid_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$'),
    version bigint NOT NULL CHECK(version > 0),
    name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200
      AND name=btrim(name) AND name !~ '[[:cntrl:]]'),
    definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
      AND octet_length(definition::text) <= 1048576),
    canonical_digest text NOT NULL CHECK(canonical_digest ~ '^[0-9a-f]{64}$'),
    metadata_revision bigint NOT NULL CHECK(metadata_revision > 0),
    creator_issuer text NOT NULL CHECK(length(creator_issuer) BETWEEN 1 AND 300
      AND creator_issuer !~ '[[:cntrl:]]'),
    creator_subject_id text NOT NULL CHECK(length(creator_subject_id) BETWEEN 1 AND 300
      AND creator_subject_id !~ '[[:cntrl:]]'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,grid_id,version),
    UNIQUE(workspace_id,application_id,grid_id,version,canonical_digest),
    FOREIGN KEY(workspace_id,application_id)
      REFERENCES epm.application_state(workspace_id,application_id)
      ON DELETE RESTRICT
);

CREATE INDEX saved_grid_definition_latest
  ON epm.saved_grid_definition(workspace_id,application_id,grid_id,version DESC);

ALTER TABLE epm.saved_grid_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY saved_grid_definition_runtime_scope
    ON epm.saved_grid_definition TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY saved_grid_definition_lifecycle_scope
    ON epm.saved_grid_definition TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.saved_grid_definition
    FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT ON epm.saved_grid_definition TO epm_runtime;
GRANT SELECT ON epm.saved_grid_definition TO epm_lifecycle;

-- Extend exact owner-reset inventory in child-first order.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_pair text :=
  $pattern$'dimensional_security_policy_version','application_access_grant',$pattern$;
DECLARE new_pair text :=
  $pattern$'saved_grid_definition','dimensional_security_policy_version','application_access_grant',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0204_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0204_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  'd3f570714c551d1f47e2498f74db7ee66b49197071bd0186ffbc60ab3a668e21';
DECLARE new_fingerprint constant text :=
  '68c2dc7e39200d93437d551a1696e6ff5741789a889c41b5e969b62add77d983';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0204_FINGERPRINT_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0204_FINGERPRINT_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;
