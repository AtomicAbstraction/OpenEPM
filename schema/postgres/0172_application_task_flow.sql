-- Domain-neutral, human-oriented application task flows.  Definitions refer
-- to existing planning assignments and authoritative application artifacts;
-- this storage does not create another identity/group model and does not
-- execute the referenced business operation.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=171) THEN
    RAISE EXCEPTION 'MIGRATION_0172_PREDECESSOR_0171_REQUIRED';
  END IF;
END $migration$;

CREATE TABLE epm.application_task_flow_version (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    flow_id text NOT NULL
      CHECK(flow_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
        AND length(flow_id) <= 300),
    version bigint NOT NULL CHECK(version > 0),
    definition jsonb NOT NULL
      CHECK(jsonb_typeof(definition)='object'
        AND octet_length(definition::text) <= 4194304),
    canonical_digest text NOT NULL CHECK(canonical_digest ~ '^[0-9a-f]{64}$'),
    operation_id text NOT NULL,
    created_revision bigint NOT NULL CHECK(created_revision > 0),
    creator_issuer text NOT NULL
      CHECK(length(creator_issuer) BETWEEN 1 AND 300
        AND creator_issuer !~ '[[:cntrl:]]'),
    creator_subject_id text NOT NULL
      CHECK(length(creator_subject_id) BETWEEN 1 AND 300
        AND creator_subject_id !~ '[[:cntrl:]]'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,flow_id,version),
    UNIQUE(workspace_id,application_id,flow_id,version,canonical_digest),
    FOREIGN KEY(workspace_id,application_id)
      REFERENCES epm.application_state(workspace_id,application_id)
      ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE epm.application_task_flow_state (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    flow_id text NOT NULL,
    latest_version bigint NOT NULL CHECK(latest_version > 0),
    published_version bigint,
    state_revision bigint NOT NULL CHECK(state_revision > 0),
    last_operation_id text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,flow_id),
    FOREIGN KEY(workspace_id,application_id,flow_id,latest_version)
      REFERENCES epm.application_task_flow_version
        (workspace_id,application_id,flow_id,version) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,flow_id,published_version)
      REFERENCES epm.application_task_flow_version
        (workspace_id,application_id,flow_id,version) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,last_operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE epm.application_task_flow_occurrence (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    occurrence_id text NOT NULL CHECK(occurrence_id ~ '^[0-9a-f]{32}$'),
    flow_id text NOT NULL,
    flow_version bigint NOT NULL,
    flow_digest text NOT NULL CHECK(flow_digest ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CHECK(status IN ('Active','Completed','Cancelled')),
    occurrence_version bigint NOT NULL CHECK(occurrence_version > 0),
    started_revision bigint NOT NULL CHECK(started_revision > 0),
    started_operation_id text NOT NULL,
    last_operation_id text NOT NULL,
    started_by_issuer text NOT NULL CHECK(length(started_by_issuer) BETWEEN 1 AND 300),
    started_by_subject_id text NOT NULL CHECK(length(started_by_subject_id) BETWEEN 1 AND 300),
    started_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    completed_at timestamptz,
    cancelled_at timestamptz,
    PRIMARY KEY(workspace_id,application_id,occurrence_id),
    FOREIGN KEY(workspace_id,application_id,flow_id,flow_version,flow_digest)
      REFERENCES epm.application_task_flow_version
        (workspace_id,application_id,flow_id,version,canonical_digest)
      ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,started_operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(workspace_id,application_id,last_operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK((status='Completed')=(completed_at IS NOT NULL)),
    CHECK((status='Cancelled')=(cancelled_at IS NOT NULL)),
    CHECK(NOT (completed_at IS NOT NULL AND cancelled_at IS NOT NULL))
);

ALTER TABLE epm.planning_assignment_version
  ADD CONSTRAINT planning_assignment_version_taskflow_digest_key
  UNIQUE(workspace_id,application_id,assignment_set_id,version,canonical_digest);

CREATE TABLE epm.application_task_flow_activity (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    occurrence_id text NOT NULL,
    activity_id text NOT NULL
      CHECK(activity_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
        AND length(activity_id) <= 300),
    kind text NOT NULL CHECK(kind IN (
      'ManualConfirmation','PlanningSliceOpen','PlanningSubmission',
      'PlanningApproval','CalculationPublication')),
    status text NOT NULL CHECK(status IN ('Blocked','Ready','Completed','Cancelled')),
    activity_version bigint NOT NULL CHECK(activity_version > 0),
    assignment_set_id text NOT NULL,
    assignment_version bigint NOT NULL CHECK(assignment_version > 0),
    assignment_digest text NOT NULL CHECK(assignment_digest ~ '^[0-9a-f]{64}$'),
    assignment_id text NOT NULL,
    operation_id text,
    completed_by_issuer text,
    completed_by_subject_id text,
    completed_at timestamptz,
    PRIMARY KEY(workspace_id,application_id,occurrence_id,activity_id),
    FOREIGN KEY(workspace_id,application_id,occurrence_id)
      REFERENCES epm.application_task_flow_occurrence
        (workspace_id,application_id,occurrence_id) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,assignment_set_id,
                assignment_version,assignment_digest)
      REFERENCES epm.planning_assignment_version
        (workspace_id,application_id,assignment_set_id,version,canonical_digest)
      ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK((status='Completed')=(completed_at IS NOT NULL)),
    CHECK((status='Completed')=(operation_id IS NOT NULL)),
    CHECK((completed_at IS NULL)=(completed_by_issuer IS NULL)),
    CHECK((completed_at IS NULL)=(completed_by_subject_id IS NULL))
);

CREATE TABLE epm.application_task_flow_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    occurrence_id text NOT NULL,
    event_ordinal bigint NOT NULL CHECK(event_ordinal > 0),
    event_type text NOT NULL CHECK(event_type IN (
      'OccurrenceStarted','ActivityCompleted','OccurrenceCompleted',
      'OccurrenceCancelled')),
    activity_id text,
    operation_id text NOT NULL,
    actor_issuer text NOT NULL CHECK(length(actor_issuer) BETWEEN 1 AND 300),
    actor_subject_id text NOT NULL CHECK(length(actor_subject_id) BETWEEN 1 AND 300),
    command_digest text NOT NULL CHECK(command_digest ~ '^[0-9a-f]{64}$'),
    evidence jsonb,
    evidence_digest text CHECK(evidence_digest IS NULL OR evidence_digest ~ '^[0-9a-f]{64}$'),
    committed_revision bigint NOT NULL CHECK(committed_revision > 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,occurrence_id,event_ordinal),
    UNIQUE(workspace_id,application_id,occurrence_id,operation_id),
    FOREIGN KEY(workspace_id,application_id,occurrence_id)
      REFERENCES epm.application_task_flow_occurrence
        (workspace_id,application_id,occurrence_id) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(workspace_id,application_id,occurrence_id,activity_id)
      REFERENCES epm.application_task_flow_activity
        (workspace_id,application_id,occurrence_id,activity_id) ON DELETE RESTRICT,
    CHECK((event_type='ActivityCompleted')=(activity_id IS NOT NULL)),
    CHECK((evidence IS NULL)=(evidence_digest IS NULL)),
    CHECK((event_type='ActivityCompleted')=(evidence IS NOT NULL)),
    CHECK(evidence IS NULL OR (jsonb_typeof(evidence)='object'
      AND octet_length(evidence::text)<=1048576))
);

CREATE INDEX application_task_flow_version_created
  ON epm.application_task_flow_version
    (workspace_id,application_id,flow_id,version);
CREATE INDEX application_task_flow_occurrence_status
  ON epm.application_task_flow_occurrence
    (workspace_id,application_id,status,started_at,occurrence_id);
CREATE INDEX application_task_flow_activity_worklist
  ON epm.application_task_flow_activity
    (workspace_id,application_id,status,assignment_set_id,assignment_version,
     assignment_id,occurrence_id,activity_id);

CREATE FUNCTION epm.application_task_flow_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $body$
BEGIN
  IF TG_OP='DELETE' AND
     current_setting('epm.projection_cleanup_reset_context',true)=
       jsonb_build_array(OLD.workspace_id,pg_current_xact_id()::text,
                         pg_backend_pid())::text THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'APPLICATION_TASK_FLOW_IMMUTABLE' USING ERRCODE='23514';
END $body$;
CREATE TRIGGER application_task_flow_version_immutable
  BEFORE UPDATE OR DELETE ON epm.application_task_flow_version
  FOR EACH ROW EXECUTE FUNCTION epm.application_task_flow_immutable();
CREATE TRIGGER application_task_flow_event_immutable
  BEFORE UPDATE OR DELETE ON epm.application_task_flow_event
  FOR EACH ROW EXECUTE FUNCTION epm.application_task_flow_immutable();
REVOKE ALL ON FUNCTION epm.application_task_flow_immutable()
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;

DO $migration$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'application_task_flow_version','application_task_flow_state',
    'application_task_flow_occurrence','application_task_flow_activity',
    'application_task_flow_event']
  LOOP
    EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format(
      'CREATE POLICY %I ON epm.%I TO epm_runtime USING '
      '(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true)) WITH CHECK '
      '(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true))',
      table_name||'_runtime_scope',table_name);
    EXECUTE format(
      'CREATE POLICY %I ON epm.%I FOR SELECT TO epm_lifecycle USING '
      '(workspace_id=current_setting(''epm.workspace_id'',true))',
      table_name||'_lifecycle_scope',table_name);
  END LOOP;
END $migration$;

REVOKE ALL ON epm.application_task_flow_version,
  epm.application_task_flow_state,epm.application_task_flow_occurrence,
  epm.application_task_flow_activity,epm.application_task_flow_event
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT ON epm.application_task_flow_version TO epm_runtime;
GRANT SELECT,INSERT ON epm.application_task_flow_state TO epm_runtime;
GRANT UPDATE(latest_version,published_version,state_revision,last_operation_id,
  updated_at) ON epm.application_task_flow_state TO epm_runtime;
GRANT SELECT,INSERT ON epm.application_task_flow_occurrence TO epm_runtime;
GRANT UPDATE(status,occurrence_version,last_operation_id,completed_at,cancelled_at)
  ON epm.application_task_flow_occurrence TO epm_runtime;
GRANT SELECT,INSERT ON epm.application_task_flow_activity TO epm_runtime;
GRANT UPDATE(status,activity_version,operation_id,
  completed_by_issuer,completed_by_subject_id,completed_at)
  ON epm.application_task_flow_activity TO epm_runtime;
GRANT SELECT,INSERT ON epm.application_task_flow_event TO epm_runtime;
GRANT SELECT ON epm.application_task_flow_version,
  epm.application_task_flow_state,epm.application_task_flow_occurrence,
  epm.application_task_flow_activity,epm.application_task_flow_event
  TO epm_lifecycle;

-- Extend the exact owner reset in child-first order.  The reviewed schema
-- fingerprint is pinned after a clean disposable 0172 migration run.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_pair text := $pattern$'planning_assignment_state','planning_assignment_version',$pattern$;
DECLARE new_pair text := $pattern$'application_task_flow_event','application_task_flow_activity','application_task_flow_occurrence','application_task_flow_state','application_task_flow_version','planning_assignment_state','planning_assignment_version',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0172_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0172_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

-- Active human work is a destructive-reset blocker just like unsettled
-- technical work.  Completed and cancelled occurrences remain auditable but
-- no longer block the exact owner workflow.
DO $migration$
DECLARE definition text; revised text;
DECLARE marker text := $pattern$    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),$pattern$;
DECLARE guard text := $pattern$    IF EXISTS (SELECT 1 FROM epm.application_task_flow_occurrence
        WHERE workspace_id=p_workspace_id AND status='Active') THEN
        RAISE EXCEPTION 'UNSETTLED_APPLICATION_TASK_FLOW_OCCURRENCES';
    END IF;

$pattern$;
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(marker IN definition)=0 OR position(guard IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0172_ACTIVE_GUARD_MISMATCH';
  END IF;
  revised := replace(definition,marker,guard||marker);
  IF revised=definition THEN
    RAISE EXCEPTION 'RESET_0172_ACTIVE_GUARD_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '8ca1b7ca5f7d2faf6e4cb3332bea5aee7f8d8ba6f871b1e2b9d762598774c0f1';
DECLARE new_fingerprint constant text :=
  'f4c61e0ffcea272096926407cb6ec06563fc817b57738e1e57a5029d6c4035ef';
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0172_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0172_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

REVOKE ALL ON epm.application_task_flow_version,
  epm.application_task_flow_state,epm.application_task_flow_occurrence,
  epm.application_task_flow_activity,epm.application_task_flow_event
  FROM epm_lifecycle;
GRANT SELECT ON epm.application_task_flow_version,
  epm.application_task_flow_state,epm.application_task_flow_occurrence,
  epm.application_task_flow_activity,epm.application_task_flow_event
  TO epm_lifecycle;
