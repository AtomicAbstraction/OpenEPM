-- Relationally retain the exact authoritative receipt observed by a generic
-- workflow completion. Fixed core still supplies the function-specific
-- verifier and normalized evidence envelope; callers cannot declare receipt
-- provenance, function identity or currentness.

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=229) THEN
    RAISE EXCEPTION 'MIGRATION_0230_PREDECESSOR_0229_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.operation_receipt
  ADD CONSTRAINT operation_receipt_identity_revision_unique
  UNIQUE(workspace_id,application_id,operation_id,committed_revision);

CREATE TABLE epm.application_workflow_evidence_link (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  occurrence_id text NOT NULL,
  activity_id text NOT NULL,
  completion_operation_id text NOT NULL,
  event_type text NOT NULL DEFAULT 'ActivityCompleted'
    CHECK(event_type='ActivityCompleted'),
  evidence_operation_id text NOT NULL,
  evidence_committed_revision bigint NOT NULL
    CHECK(evidence_committed_revision>0),
  validator_id text NOT NULL CHECK(length(validator_id) BETWEEN 1 AND 200
    AND validator_id ~ '^[a-z][a-z0-9_.-]*$'),
  validator_version bigint NOT NULL CHECK(validator_version>0),
  evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,occurrence_id,
    completion_operation_id),
  FOREIGN KEY(workspace_id,application_id,occurrence_id,activity_id)
    REFERENCES epm.application_workflow_activity(
      workspace_id,application_id,occurrence_id,activity_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,occurrence_id,
      completion_operation_id,event_type)
    REFERENCES epm.application_workflow_event(
      workspace_id,application_id,occurrence_id,operation_id,event_type)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,evidence_operation_id,
      evidence_committed_revision)
    REFERENCES epm.operation_receipt(
      workspace_id,application_id,operation_id,committed_revision)
    ON DELETE RESTRICT,
  CHECK(completion_operation_id<>evidence_operation_id)
);

CREATE INDEX application_workflow_evidence_source
  ON epm.application_workflow_evidence_link(
    workspace_id,application_id,evidence_operation_id,
    evidence_committed_revision,occurrence_id,activity_id);

CREATE FUNCTION epm.application_workflow_evidence_link_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN
  RAISE EXCEPTION 'APPLICATION_WORKFLOW_EVIDENCE_LINK_IMMUTABLE'
    USING ERRCODE='23514';
END$$;
CREATE TRIGGER application_workflow_evidence_link_immutable
  BEFORE UPDATE OR DELETE ON epm.application_workflow_evidence_link
  FOR EACH ROW EXECUTE FUNCTION epm.application_workflow_evidence_link_immutable();
REVOKE ALL ON FUNCTION epm.application_workflow_evidence_link_immutable()
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;

ALTER TABLE epm.application_workflow_evidence_link ENABLE ROW LEVEL SECURITY;
CREATE POLICY application_workflow_evidence_link_runtime_scope
  ON epm.application_workflow_evidence_link TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY application_workflow_evidence_link_lifecycle_scope
  ON epm.application_workflow_evidence_link FOR SELECT TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.application_workflow_evidence_link
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT ON epm.application_workflow_evidence_link TO epm_runtime;
GRANT SELECT(workspace_id,application_id,occurrence_id,activity_id,
  completion_operation_id,evidence_operation_id,evidence_committed_revision,
  validator_id,validator_version,evidence_digest)
  ON epm.application_workflow_evidence_link TO epm_lifecycle;

-- Evidence links are children of both immutable workflow events and operation
-- receipts, so reset deletes them before either parent.
DO $migration$ DECLARE definition text;DECLARE revised text;
DECLARE old_group text:=$pattern$'application_workflow_event','application_workflow_activity','application_workflow_occurrence',$pattern$;
DECLARE new_group text:=$pattern$'application_workflow_evidence_link','application_workflow_event','application_workflow_activity','application_workflow_occurrence',$pattern$;
BEGIN
  definition:=pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_group IN definition)=0 OR position(new_group IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0230_DEFINITION_MISMATCH';END IF;
  revised:=replace(definition,old_group,new_group);
  IF revised=definition OR position(new_group IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0230_UPDATE_FAILED';END IF;
  EXECUTE revised;
END $migration$;

-- Placeholder is replaced with the independently observed canonical graph
-- fingerprint after a clean disposable 0001--0230 construction.
DO $migration$
DECLARE definition text;DECLARE revised text;
DECLARE old_fingerprint constant text:=
  'a4d91cdb7da6fc922d0de3dfddc4bf3d55b5cd41946aacd5a5ab08b8945b6f75';
DECLARE new_fingerprint constant text:=
  '29e581d280aed9d5452a756fcf1dff6a21d8f2fe9fae81e929eaf391e132c75e';
BEGIN
  definition:=pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0
     OR position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0230_FINGERPRINT_PREDECESSOR_MISMATCH';END IF;
  revised:=replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0230_FINGERPRINT_UPDATE_FAILED';END IF;
  EXECUTE revised;
END $migration$;

DO $migration$ DECLARE role_name text;BEGIN
  FOREACH role_name IN ARRAY ARRAY['epm_lifecycle','epm_lifecycle_login'] LOOP
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name)
       AND has_table_privilege(role_name,
         'epm.application_workflow_evidence_link','DELETE') THEN
      RAISE EXCEPTION 'MIGRATION_0230_LIFECYCLE_DELETE_REMAINS:%',role_name;
    END IF;
  END LOOP;
END $migration$;

