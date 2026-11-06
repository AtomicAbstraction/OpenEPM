-- Immutable, application-scoped statement definitions.  The definition owns
-- structural source slots, equations, section identities and signs.  It does
-- not assert accounting-policy review or whole-statement certification.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=172) THEN
    RAISE EXCEPTION 'MIGRATION_0173_PREDECESSOR_0172_REQUIRED';
  END IF;
END $migration$;

CREATE TABLE epm.statement_definition_version (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    definition_id text NOT NULL
      CHECK(definition_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$'),
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
    PRIMARY KEY(workspace_id,application_id,definition_id,version),
    UNIQUE(workspace_id,application_id,definition_id,version,canonical_digest),
    FOREIGN KEY(workspace_id,application_id)
      REFERENCES epm.application_state(workspace_id,application_id)
      ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE epm.statement_definition_state (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    definition_id text NOT NULL,
    latest_version bigint NOT NULL CHECK(latest_version > 0),
    active_version bigint,
    active_digest text CHECK(active_digest IS NULL OR active_digest ~ '^[0-9a-f]{64}$'),
    pointer_version bigint NOT NULL CHECK(pointer_version >= 0),
    state_revision bigint NOT NULL CHECK(state_revision > 0),
    last_operation_id text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,definition_id),
    FOREIGN KEY(workspace_id,application_id,definition_id,latest_version)
      REFERENCES epm.statement_definition_version
        (workspace_id,application_id,definition_id,version) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,definition_id,
                active_version,active_digest)
      REFERENCES epm.statement_definition_version
        (workspace_id,application_id,definition_id,version,canonical_digest)
      ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,last_operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK((active_version IS NULL)=(active_digest IS NULL)),
    CHECK(active_version IS NULL OR active_version <= latest_version)
);

CREATE TABLE epm.statement_definition_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    definition_id text NOT NULL,
    event_ordinal bigint NOT NULL CHECK(event_ordinal > 0),
    event_type text NOT NULL CHECK(event_type IN ('Published','Deactivated')),
    definition_version bigint,
    definition_digest text
      CHECK(definition_digest IS NULL OR definition_digest ~ '^[0-9a-f]{64}$'),
    pointer_version bigint NOT NULL CHECK(pointer_version > 0),
    operation_id text NOT NULL,
    actor_issuer text NOT NULL
      CHECK(length(actor_issuer) BETWEEN 1 AND 300
        AND actor_issuer !~ '[[:cntrl:]]'),
    actor_subject_id text NOT NULL
      CHECK(length(actor_subject_id) BETWEEN 1 AND 300
        AND actor_subject_id !~ '[[:cntrl:]]'),
    command_digest text NOT NULL CHECK(command_digest ~ '^[0-9a-f]{64}$'),
    committed_revision bigint NOT NULL CHECK(committed_revision > 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,definition_id,event_ordinal),
    UNIQUE(workspace_id,application_id,definition_id,pointer_version),
    UNIQUE(workspace_id,application_id,operation_id),
    FOREIGN KEY(workspace_id,application_id,definition_id)
      REFERENCES epm.statement_definition_state
        (workspace_id,application_id,definition_id) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,definition_id,
                definition_version,definition_digest)
      REFERENCES epm.statement_definition_version
        (workspace_id,application_id,definition_id,version,canonical_digest)
      ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK((definition_version IS NULL)=(definition_digest IS NULL)),
    CHECK((event_type='Published')=(definition_version IS NOT NULL))
);

CREATE INDEX statement_definition_version_created
  ON epm.statement_definition_version
    (workspace_id,application_id,definition_id,version);
CREATE INDEX statement_definition_state_active
  ON epm.statement_definition_state
    (workspace_id,application_id,active_version,definition_id)
  WHERE active_version IS NOT NULL;
CREATE UNIQUE INDEX statement_definition_one_active_per_application
  ON epm.statement_definition_state(workspace_id,application_id)
  WHERE active_version IS NOT NULL;
CREATE INDEX statement_definition_event_history
  ON epm.statement_definition_event
    (workspace_id,application_id,definition_id,event_ordinal);

CREATE FUNCTION epm.statement_definition_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $body$
BEGIN
  IF TG_OP='DELETE' AND
     current_setting('epm.projection_cleanup_reset_context',true)=
       jsonb_build_array(OLD.workspace_id,pg_current_xact_id()::text,
                         pg_backend_pid())::text THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'STATEMENT_DEFINITION_IMMUTABLE' USING ERRCODE='23514';
END $body$;
CREATE TRIGGER statement_definition_version_immutable
  BEFORE UPDATE OR DELETE ON epm.statement_definition_version
  FOR EACH ROW EXECUTE FUNCTION epm.statement_definition_immutable();
CREATE TRIGGER statement_definition_event_immutable
  BEFORE UPDATE OR DELETE ON epm.statement_definition_event
  FOR EACH ROW EXECUTE FUNCTION epm.statement_definition_immutable();
REVOKE ALL ON FUNCTION epm.statement_definition_immutable()
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;

DO $migration$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'statement_definition_version','statement_definition_state',
    'statement_definition_event']
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

REVOKE ALL ON epm.statement_definition_version,
  epm.statement_definition_state,epm.statement_definition_event
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT ON epm.statement_definition_version TO epm_runtime;
GRANT SELECT,INSERT ON epm.statement_definition_state TO epm_runtime;
GRANT UPDATE(latest_version,active_version,active_digest,pointer_version,
  state_revision,last_operation_id,updated_at)
  ON epm.statement_definition_state TO epm_runtime;
GRANT SELECT,INSERT ON epm.statement_definition_event TO epm_runtime;
GRANT SELECT ON epm.statement_definition_version,
  epm.statement_definition_state,epm.statement_definition_event
  TO epm_lifecycle;

-- Extend exact owner reset inventory in child-first order.  The immutable
-- version/event triggers permit deletion only inside the established owner
-- reset context.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_pair text := $pattern$'application_task_flow_event','application_task_flow_activity','application_task_flow_occurrence','application_task_flow_state','application_task_flow_version',$pattern$;
DECLARE new_pair text := $pattern$'statement_definition_event','statement_definition_state','statement_definition_version','application_task_flow_event','application_task_flow_activity','application_task_flow_occurrence','application_task_flow_state','application_task_flow_version',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0173_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0173_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

-- Pin the reset graph actually observed after a clean disposable schema-173
-- migration.  Fixed code must carry the same reviewed boundary.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  'f4c61e0ffcea272096926407cb6ec06563fc817b57738e1e57a5029d6c4035ef';
DECLARE new_fingerprint constant text :=
  '9997f508a4670a8879d7745d0ac8076bc4fe578aa94f58ef3f3f4526f1bbd946';
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0173_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0173_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;
