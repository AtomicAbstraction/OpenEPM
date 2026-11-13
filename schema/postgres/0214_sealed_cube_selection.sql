-- Durable subject-bound technical artifacts for exact generic cube selections.
-- Sealing changes no business facts or metadata.  It preserves the authorized
-- resolution needed by grids, rules and jobs after a lost client response.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=213) THEN
    RAISE EXCEPTION 'MIGRATION_0214_PREDECESSOR_0213_REQUIRED';
  END IF;
END $migration$;

CREATE TABLE epm.sealed_cube_selection (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  selection_id text NOT NULL
    CHECK(selection_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,199}$'),
  issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 300
    AND issuer !~ '[[:cntrl:]]'),
  subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 300
    AND subject_id !~ '[[:cntrl:]]'),
  request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
  selection jsonb NOT NULL CHECK(jsonb_typeof(selection)='object'
    AND octet_length(selection::text) <= 4194304),
  resolved_selection jsonb NOT NULL CHECK(jsonb_typeof(resolved_selection)='object'
    AND octet_length(resolved_selection::text) <= 8388608),
  selection_digest text NOT NULL CHECK(selection_digest ~ '^[0-9a-f]{64}$'),
  resolution_digest text NOT NULL CHECK(resolution_digest ~ '^[0-9a-f]{64}$'),
  metadata_revision bigint NOT NULL CHECK(metadata_revision > 0),
  policy_revision bigint NOT NULL CHECK(policy_revision >= 0),
  commit_revision bigint NOT NULL CHECK(commit_revision >= 0),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,issuer,subject_id,selection_id),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id)
    ON DELETE RESTRICT,
  CHECK(expires_at > created_at)
);

CREATE INDEX sealed_cube_selection_expiry
  ON epm.sealed_cube_selection(expires_at,workspace_id,application_id);

ALTER TABLE epm.sealed_cube_selection ENABLE ROW LEVEL SECURITY;

CREATE POLICY sealed_cube_selection_runtime_scope
  ON epm.sealed_cube_selection TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY sealed_cube_selection_lifecycle_scope
  ON epm.sealed_cube_selection TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.sealed_cube_selection
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT ON epm.sealed_cube_selection TO epm_runtime;
GRANT SELECT,DELETE ON epm.sealed_cube_selection TO epm_lifecycle;

DO $migration$
DECLARE definition text; revised text;
DECLARE old_pair text :=
  $pattern$'member_list_publication','member_list_version','saved_grid_definition',$pattern$;
DECLARE new_pair text :=
  $pattern$'sealed_cube_selection','member_list_publication','member_list_version','saved_grid_definition',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0214_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0214_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  'e8784f95bdd1e7b081607497eb2d402405239a57f97af17bb023ec891cb9d166';
DECLARE new_fingerprint constant text :=
  'ef10c6ad1b520b8ab5c1cbdfba7da632ed06fdf7dbc7e491a06c6e44b50742da';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0214_FINGERPRINT_PREDECESSOR_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0214_FINGERPRINT_UPDATE_FAILED';
  END IF;
  EXECUTE revised;
END $migration$;
