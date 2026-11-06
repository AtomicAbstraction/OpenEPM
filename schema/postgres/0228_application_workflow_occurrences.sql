-- Durable domain-neutral workflow occurrences, activity state and immutable
-- audit events.  These records observe authoritative evidence; they neither
-- execute a destination nor grant cube access.

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=227) THEN
    RAISE EXCEPTION 'MIGRATION_0228_PREDECESSOR_0227_REQUIRED';
  END IF;
END $migration$;

CREATE TABLE epm.application_workflow_occurrence (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  occurrence_id text NOT NULL CHECK(occurrence_id ~ '^[0-9a-f]{32}$'),
  flow_id text NOT NULL,
  flow_version bigint NOT NULL CHECK(flow_version>0),
  flow_digest text NOT NULL CHECK(flow_digest ~ '^[0-9a-f]{64}$'),
  status text NOT NULL CHECK(status IN ('Active','Completed','Cancelled')),
  occurrence_version bigint NOT NULL CHECK(occurrence_version>0),
  started_revision bigint NOT NULL CHECK(started_revision>0),
  started_operation_id text NOT NULL,
  last_operation_id text NOT NULL,
  started_by_issuer text NOT NULL CHECK(length(started_by_issuer) BETWEEN 1 AND 300
    AND started_by_issuer !~ '[[:cntrl:]]'),
  started_by_subject_id text NOT NULL CHECK(length(started_by_subject_id)
    BETWEEN 1 AND 300 AND started_by_subject_id !~ '[[:cntrl:]]'),
  started_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  completed_at timestamptz,
  cancelled_at timestamptz,
  PRIMARY KEY(workspace_id,application_id,occurrence_id),
  FOREIGN KEY(workspace_id,application_id,flow_id,flow_version,flow_digest)
    REFERENCES epm.application_workflow_version(
      workspace_id,application_id,flow_id,version,definition_digest)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,started_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,last_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT,
  CHECK((status='Completed')=(completed_at IS NOT NULL)),
  CHECK((status='Cancelled')=(cancelled_at IS NOT NULL)),
  CHECK(NOT(completed_at IS NOT NULL AND cancelled_at IS NOT NULL))
);

CREATE TABLE epm.application_workflow_activity (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  occurrence_id text NOT NULL,
  flow_id text NOT NULL,
  flow_version bigint NOT NULL CHECK(flow_version>0),
  activity_id text NOT NULL CHECK(length(activity_id) BETWEEN 1 AND 300
    AND activity_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'),
  kind text NOT NULL CHECK(kind IN ('Action','Review')),
  status text NOT NULL CHECK(status IN (
    'Blocked','Ready','Completed','Returned','Cancelled')),
  activity_version bigint NOT NULL CHECK(activity_version>0),
  operation_id text,
  completed_by_issuer text,
  completed_by_subject_id text,
  completed_at timestamptz,
  returned_to_activity_id text,
  PRIMARY KEY(workspace_id,application_id,occurrence_id,activity_id),
  FOREIGN KEY(workspace_id,application_id,occurrence_id)
    REFERENCES epm.application_workflow_occurrence(
      workspace_id,application_id,occurrence_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,flow_id,flow_version,activity_id)
    REFERENCES epm.application_workflow_assignment_pin(
      workspace_id,application_id,flow_id,flow_version,activity_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,occurrence_id,
      returned_to_activity_id)
    REFERENCES epm.application_workflow_activity(
      workspace_id,application_id,occurrence_id,activity_id)
    ON DELETE RESTRICT,
  CHECK((status='Completed')=(completed_at IS NOT NULL)),
  CHECK((completed_at IS NULL)=(completed_by_issuer IS NULL)),
  CHECK((completed_at IS NULL)=(completed_by_subject_id IS NULL)),
  CHECK((status='Returned')=(returned_to_activity_id IS NOT NULL)),
  CHECK(status<>'Returned' OR kind='Review')
);

CREATE TABLE epm.application_workflow_event (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  occurrence_id text NOT NULL,
  event_ordinal bigint NOT NULL CHECK(event_ordinal>0),
  event_type text NOT NULL CHECK(event_type IN (
    'OccurrenceStarted','ActivityCompleted','ActivityReturned',
    'OccurrenceCompleted','OccurrenceCancelled')),
  activity_id text,
  operation_id text NOT NULL,
  actor_issuer text NOT NULL CHECK(length(actor_issuer) BETWEEN 1 AND 300
    AND actor_issuer !~ '[[:cntrl:]]'),
  actor_subject_id text NOT NULL CHECK(length(actor_subject_id) BETWEEN 1 AND 300
    AND actor_subject_id !~ '[[:cntrl:]]'),
  command_digest text NOT NULL CHECK(command_digest ~ '^[0-9a-f]{64}$'),
  evidence jsonb,
  evidence_digest text CHECK(evidence_digest IS NULL
    OR evidence_digest ~ '^[0-9a-f]{64}$'),
  committed_revision bigint NOT NULL CHECK(committed_revision>0),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,occurrence_id,event_ordinal),
  UNIQUE(workspace_id,application_id,occurrence_id,operation_id),
  FOREIGN KEY(workspace_id,application_id,occurrence_id)
    REFERENCES epm.application_workflow_occurrence(
      workspace_id,application_id,occurrence_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,occurrence_id,activity_id)
    REFERENCES epm.application_workflow_activity(
      workspace_id,application_id,occurrence_id,activity_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT,
  CHECK((event_type IN ('ActivityCompleted','ActivityReturned'))=
    (activity_id IS NOT NULL)),
  CHECK((evidence IS NULL)=(evidence_digest IS NULL)),
  CHECK((event_type IN ('ActivityCompleted','ActivityReturned'))=
    (evidence IS NOT NULL)),
  CHECK(evidence IS NULL OR (jsonb_typeof(evidence)='object'
    AND octet_length(evidence::text)<=1048576))
);

CREATE INDEX application_workflow_occurrence_status
  ON epm.application_workflow_occurrence(
    workspace_id,application_id,status,started_at,occurrence_id);
CREATE INDEX application_workflow_activity_worklist
  ON epm.application_workflow_activity(
    workspace_id,application_id,status,flow_id,flow_version,
    occurrence_id,activity_id);

CREATE FUNCTION epm.application_workflow_event_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN
  RAISE EXCEPTION 'APPLICATION_WORKFLOW_EVENT_IMMUTABLE' USING ERRCODE='23514';
END$$;
CREATE TRIGGER application_workflow_event_immutable
  BEFORE UPDATE OR DELETE ON epm.application_workflow_event
  FOR EACH ROW EXECUTE FUNCTION epm.application_workflow_event_immutable();
REVOKE ALL ON FUNCTION epm.application_workflow_event_immutable()
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;

DO $migration$ DECLARE relation_name text;BEGIN
  FOREACH relation_name IN ARRAY ARRAY['application_workflow_occurrence',
    'application_workflow_activity','application_workflow_event'] LOOP
    EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',relation_name);
    EXECUTE format('CREATE POLICY %I ON epm.%I TO epm_runtime USING '
      '(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true)) WITH CHECK '
      '(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true))',
      relation_name||'_runtime_scope',relation_name);
    EXECUTE format('CREATE POLICY %I ON epm.%I FOR SELECT TO epm_lifecycle '
      'USING(workspace_id=current_setting(''epm.workspace_id'',true))',
      relation_name||'_lifecycle_scope',relation_name);
  END LOOP;
END $migration$;

REVOKE ALL ON epm.application_workflow_occurrence,
  epm.application_workflow_activity,epm.application_workflow_event
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT ON epm.application_workflow_occurrence TO epm_runtime;
GRANT UPDATE(status,occurrence_version,last_operation_id,completed_at,cancelled_at)
  ON epm.application_workflow_occurrence TO epm_runtime;
GRANT SELECT,INSERT ON epm.application_workflow_activity TO epm_runtime;
GRANT UPDATE(status,activity_version,operation_id,completed_by_issuer,
  completed_by_subject_id,completed_at,returned_to_activity_id)
  ON epm.application_workflow_activity TO epm_runtime;
GRANT SELECT,INSERT ON epm.application_workflow_event TO epm_runtime;
GRANT SELECT(workspace_id,application_id,occurrence_id,flow_id,flow_version,
  status,occurrence_version) ON epm.application_workflow_occurrence
  TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,occurrence_id,activity_id,status,
  activity_version) ON epm.application_workflow_activity TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,occurrence_id,event_ordinal,event_type,
  activity_id,committed_revision) ON epm.application_workflow_event
  TO epm_lifecycle;

-- Extend owner reset inventory in child-first order.  The canonical schema
-- fingerprint is pinned after a clean disposable 0001--0228 inspection.
DO $migration$ DECLARE definition text;DECLARE revised text;
DECLARE old_group text:=$pattern$'application_workflow_assignment_pin','application_workflow_state','application_workflow_version',$pattern$;
DECLARE new_group text:=$pattern$'application_workflow_event','application_workflow_activity','application_workflow_occurrence','application_workflow_assignment_pin','application_workflow_state','application_workflow_version',$pattern$;
BEGIN
  definition:=pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_group IN definition)=0 OR position(new_group IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0228_DEFINITION_MISMATCH';END IF;
  revised:=replace(definition,old_group,new_group);
  IF revised=definition OR position(new_group IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0228_UPDATE_FAILED';END IF;
  EXECUTE revised;
END $migration$;

-- Active human work blocks destructive reset; completed/cancelled history is
-- removable only through the existing exact owner workflow.
DO $migration$ DECLARE definition text;DECLARE revised text;
DECLARE marker text:=$pattern$    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),$pattern$;
DECLARE guard text:=$pattern$    IF EXISTS (SELECT 1 FROM epm.application_workflow_occurrence
        WHERE workspace_id=p_workspace_id AND status='Active') THEN
        RAISE EXCEPTION 'UNSETTLED_APPLICATION_WORKFLOW_OCCURRENCES';
    END IF;

$pattern$;
BEGIN
  definition:=pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(marker IN definition)=0 OR position(guard IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0228_ACTIVE_GUARD_MISMATCH';END IF;
  revised:=replace(definition,marker,guard||marker);
  IF revised=definition THEN RAISE EXCEPTION 'RESET_0228_ACTIVE_GUARD_MISMATCH';END IF;
  EXECUTE revised;
END $migration$;

DO $migration$
DECLARE definition text;DECLARE revised text;
DECLARE old_fingerprint constant text:=
  'c422e1cb28cfcb0de4c1993f44f95ad1fc7c802f516c05eaa1f21bef6b01aec3';
DECLARE new_fingerprint constant text:=
  'c8e9df021f82a1d473cf1066aeeb38495c112cfa36c7b7685f7eabfb67fa316a';
BEGIN
  definition:=pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0
     OR position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0228_FINGERPRINT_PREDECESSOR_MISMATCH';END IF;
  revised:=replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0228_FINGERPRINT_UPDATE_FAILED';END IF;
  EXECUTE revised;
END $migration$;

DO $migration$ DECLARE role_name text;DECLARE relation_name text;BEGIN
  FOREACH role_name IN ARRAY ARRAY['epm_lifecycle','epm_lifecycle_login'] LOOP
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
      FOREACH relation_name IN ARRAY ARRAY[
        'epm.application_workflow_occurrence',
        'epm.application_workflow_activity',
        'epm.application_workflow_event'] LOOP
        IF has_table_privilege(role_name,relation_name,'DELETE') THEN
          RAISE EXCEPTION 'MIGRATION_0228_LIFECYCLE_DELETE_REMAINS:%:%',
            role_name,relation_name;
        END IF;
      END LOOP;
    END IF;
  END LOOP;
END $migration$;
