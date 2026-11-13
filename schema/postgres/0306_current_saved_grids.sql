BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=305) THEN
    RAISE EXCEPTION 'MIGRATION_0306_REQUIRES_0305';
  END IF;
END $migration$;

CREATE TABLE epm.saved_grid_current (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  grid_id text NOT NULL CHECK(grid_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$'),
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200
    AND name=btrim(name) AND name !~ '[[:cntrl:]]'),
  definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
    AND octet_length(definition::text)<=1048576),
  canonical_digest text NOT NULL CHECK(canonical_digest ~ '^[0-9a-f]{64}$'),
  state_token text NOT NULL CHECK(state_token ~ '^[0-9a-f]{64}$'),
  metadata_revision bigint NOT NULL CHECK(metadata_revision>0),
  creator_issuer text NOT NULL CHECK(length(creator_issuer) BETWEEN 1 AND 300
    AND creator_issuer !~ '[[:cntrl:]]'),
  creator_subject_id text NOT NULL CHECK(length(creator_subject_id) BETWEEN 1 AND 300
    AND creator_subject_id !~ '[[:cntrl:]]'),
  updated_operation_id text,
  updated_revision bigint NOT NULL CHECK(updated_revision>=0),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,grid_id),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,updated_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id) ON DELETE RESTRICT
);

-- Carry forward only the latest current definition for each stable grid ID.
INSERT INTO epm.saved_grid_current(workspace_id,application_id,grid_id,name,
  definition,canonical_digest,state_token,metadata_revision,creator_issuer,
  creator_subject_id,updated_operation_id,updated_revision,updated_at)
SELECT DISTINCT ON(workspace_id,application_id,grid_id)
  workspace_id,application_id,grid_id,name,definition,canonical_digest,
  encode(sha256(convert_to(workspace_id||E'\n'||application_id||E'\n'||
    grid_id||E'\n'||version::text||E'\n'||canonical_digest,'UTF8')),'hex'),
  metadata_revision,creator_issuer,creator_subject_id,NULL,0,created_at
FROM epm.saved_grid_definition
ORDER BY workspace_id,application_id,grid_id,version DESC;

DROP TABLE epm.saved_grid_definition;
ALTER TABLE epm.saved_grid_current RENAME TO saved_grid_definition;

ALTER TABLE epm.saved_grid_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY saved_grid_definition_runtime_scope
  ON epm.saved_grid_definition TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY saved_grid_definition_lifecycle_scope
  ON epm.saved_grid_definition TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.saved_grid_definition
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT ON epm.saved_grid_definition TO epm_runtime;
GRANT UPDATE(name,definition,canonical_digest,state_token,metadata_revision,
  creator_issuer,creator_subject_id,updated_operation_id,updated_revision,
  updated_at) ON epm.saved_grid_definition TO epm_runtime;
GRANT SELECT ON epm.saved_grid_definition TO epm_lifecycle;

DO $migration$
DECLARE definition text;
DECLARE previous constant text := '94d2bca8ca4c1326f81af73f9c1b34200750567ebf2de9aac743f4bf74d4b301';
DECLARE current_graph constant text := '192a4db51119418273db23abfcd23a453234b54dff4ff9c457b9dc590884cc2c';
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0306_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
  SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0306_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
