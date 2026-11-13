-- Immutable reusable member-list versions and one explicit publication state.
-- Definitions contain canonical fixed-core IR only: never SQL or executable
-- Python.  Publication is separately fenced so authoring cannot silently
-- change an admitted selection or calculation.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=212) THEN
    RAISE EXCEPTION 'MIGRATION_0213_PREDECESSOR_0212_REQUIRED';
  END IF;
END $migration$;

CREATE TABLE epm.member_list_version (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  list_id text NOT NULL
    CHECK(list_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  version bigint NOT NULL CHECK(version > 0),
  dimension_id text NOT NULL,
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200
    AND name=btrim(name) AND name !~ '[[:cntrl:]]'),
  definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
    AND octet_length(definition::text) <= 4194304),
  canonical_digest text NOT NULL CHECK(canonical_digest ~ '^[0-9a-f]{64}$'),
  metadata_revision bigint NOT NULL CHECK(metadata_revision > 0),
  created_operation_id text NOT NULL,
  created_revision bigint NOT NULL CHECK(created_revision > 0),
  creator_issuer text NOT NULL CHECK(length(creator_issuer) BETWEEN 1 AND 300
    AND creator_issuer !~ '[[:cntrl:]]'),
  creator_subject_id text NOT NULL CHECK(length(creator_subject_id) BETWEEN 1 AND 300
    AND creator_subject_id !~ '[[:cntrl:]]'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,list_id,version),
  UNIQUE(workspace_id,application_id,list_id,version,canonical_digest),
  FOREIGN KEY(workspace_id,application_id,dimension_id)
    REFERENCES epm.dimension(workspace_id,application_id,dimension_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,created_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT
);

CREATE INDEX member_list_version_latest
  ON epm.member_list_version(
    workspace_id,application_id,list_id,version DESC);

CREATE TABLE epm.member_list_publication (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  list_id text NOT NULL,
  version bigint,
  status text NOT NULL CHECK(status IN ('Published','Inactive')),
  state_revision bigint NOT NULL CHECK(state_revision > 0),
  operation_id text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,list_id),
  FOREIGN KEY(workspace_id,application_id,list_id,version)
    REFERENCES epm.member_list_version(
      workspace_id,application_id,list_id,version) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.operation_receipt(
      workspace_id,application_id,operation_id) ON DELETE RESTRICT,
  CHECK((status='Published' AND version IS NOT NULL)
     OR (status='Inactive' AND version IS NULL))
);

ALTER TABLE epm.member_list_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.member_list_publication ENABLE ROW LEVEL SECURITY;

CREATE POLICY member_list_version_runtime_scope
  ON epm.member_list_version TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY member_list_version_lifecycle_scope
  ON epm.member_list_version TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY member_list_publication_runtime_scope
  ON epm.member_list_publication TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY member_list_publication_lifecycle_scope
  ON epm.member_list_publication TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.member_list_version,epm.member_list_publication
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT ON epm.member_list_version TO epm_runtime;
GRANT SELECT,INSERT,UPDATE ON epm.member_list_publication TO epm_runtime;
GRANT SELECT ON epm.member_list_version,epm.member_list_publication
  TO epm_lifecycle;

-- Extend exact owner-reset inventory in child-first order.  The reviewed
-- structural fingerprint is advanced below after applying this candidate to
-- an isolated schema and inspecting the canonical FK graph.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_pair text :=
  $pattern$'saved_grid_definition','dimensional_security_policy_version',$pattern$;
DECLARE new_pair text :=
  $pattern$'member_list_publication','member_list_version','saved_grid_definition','dimensional_security_policy_version',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0213_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0213_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '4c976e4afb5c84849ee580683808d0371b3cf4d969fc2f22266524246e93451c';
DECLARE new_fingerprint constant text :=
  'e8784f95bdd1e7b081607497eb2d402405239a57f97af17bb023ec891cb9d166';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0213_FINGERPRINT_PREDECESSOR_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0213_FINGERPRINT_UPDATE_FAILED';
  END IF;
  EXECUTE revised;
END $migration$;
