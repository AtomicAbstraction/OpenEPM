-- Strengthen the generic workflow occurrence boundary before transitions are
-- exposed. An activity must belong to the same immutable flow identity as
-- its occurrence, and one receipt-backed terminal command may append both the
-- activity event and the explicit occurrence-terminal event.

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=228) THEN
    RAISE EXCEPTION 'MIGRATION_0229_PREDECESSOR_0228_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.application_workflow_occurrence
  ADD CONSTRAINT application_workflow_occurrence_flow_identity
  UNIQUE(workspace_id,application_id,occurrence_id,flow_id,flow_version);

ALTER TABLE epm.application_workflow_activity
  ADD CONSTRAINT application_workflow_activity_occurrence_flow_fkey
  FOREIGN KEY(workspace_id,application_id,occurrence_id,flow_id,flow_version)
  REFERENCES epm.application_workflow_occurrence(
    workspace_id,application_id,occurrence_id,flow_id,flow_version)
  ON DELETE RESTRICT;

DO $migration$
DECLARE constraint_name text;
BEGIN
  SELECT con.conname INTO constraint_name
  FROM pg_constraint con
  WHERE con.conrelid='epm.application_workflow_event'::regclass
    AND con.contype='u'
    AND ARRAY(SELECT att.attname::text FROM unnest(con.conkey)
      WITH ORDINALITY AS key(attnum,ordinal)
      JOIN pg_attribute att ON att.attrelid=con.conrelid
       AND att.attnum=key.attnum ORDER BY key.ordinal)
      =ARRAY['workspace_id','application_id','occurrence_id','operation_id'];
  IF constraint_name IS NULL THEN
    RAISE EXCEPTION 'APPLICATION_WORKFLOW_EVENT_OPERATION_UNIQUE_MISSING';
  END IF;
  EXECUTE format('ALTER TABLE epm.application_workflow_event '
    'DROP CONSTRAINT %I',constraint_name);
END $migration$;

ALTER TABLE epm.application_workflow_event
  ADD CONSTRAINT application_workflow_event_operation_type_unique
  UNIQUE(workspace_id,application_id,occurrence_id,operation_id,event_type);

-- Placeholder is replaced with the independently observed canonical graph
-- fingerprint after a clean disposable 0001--0229 construction.
DO $migration$
DECLARE definition text;DECLARE revised text;
DECLARE old_fingerprint constant text:=
  'c8e9df021f82a1d473cf1066aeeb38495c112cfa36c7b7685f7eabfb67fa316a';
DECLARE new_fingerprint constant text:=
  'a4d91cdb7da6fc922d0de3dfddc4bf3d55b5cd41946aacd5a5ab08b8945b6f75';
BEGIN
  definition:=pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0
     OR position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0229_FINGERPRINT_PREDECESSOR_MISMATCH';END IF;
  revised:=replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0229_FINGERPRINT_UPDATE_FAILED';END IF;
  EXECUTE revised;
END $migration$;

