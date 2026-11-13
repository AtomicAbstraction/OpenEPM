BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=310) THEN
    RAISE EXCEPTION 'MIGRATION_0311_REQUIRES_0310';
  END IF;
END $migration$;

CREATE TABLE epm.execution_delegation_current(
  workspace_id text NOT NULL, application_id text NOT NULL,
  delegation_id text NOT NULL CHECK(delegation_id~'^[A-Za-z0-9._-]{1,200}$'),
  state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
  status text NOT NULL CHECK(status IN('Active','Revoked')),
  issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 300
    AND issuer !~ '[[:cntrl:]]'),
  subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 300
    AND subject_id !~ '[[:cntrl:]]'),
  operation_scope text[] NOT NULL
    CHECK(epm.valid_execution_operation_scope(operation_scope)),
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL CHECK(valid_until>valid_from),
  schedule_id text,
  verified_groups text[] NOT NULL DEFAULT '{}'::text[],
  authorization_scope_digest text NOT NULL
    CHECK(authorization_scope_digest~'^[0-9a-f]{64}$'),
  updated_operation_id text NOT NULL,
  updated_revision bigint NOT NULL CHECK(updated_revision>0),
  revoked_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,delegation_id),
  FOREIGN KEY(workspace_id,application_id,updated_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT,
  CHECK((status='Revoked')=(revoked_at IS NOT NULL))
);

INSERT INTO epm.execution_delegation_current(workspace_id,application_id,
  delegation_id,state_token,status,issuer,subject_id,operation_scope,
  valid_from,valid_until,schedule_id,verified_groups,
  authorization_scope_digest,updated_operation_id,updated_revision,
  revoked_at,updated_at)
SELECT v.workspace_id,v.application_id,v.delegation_id,
  encode(sha256(convert_to(v.workspace_id||E'\n'||v.application_id||E'\n'||
    v.delegation_id||E'\n'||v.version::text||E'\n'||v.operation_id||E'\n'||
    CASE WHEN s.active_version=v.version THEN 'Active' ELSE 'Revoked' END,
    'UTF8')),'hex'),
  CASE WHEN s.active_version=v.version THEN 'Active' ELSE 'Revoked' END,
  v.issuer,v.subject_id,v.operation_scope,v.valid_from,v.valid_until,
  v.schedule_id,v.verified_groups,v.authorization_scope_digest,
  v.operation_id,s.state_revision,s.revoked_at,s.updated_at
FROM epm.execution_delegation_version v
JOIN epm.execution_delegation_state s
  USING(workspace_id,application_id,delegation_id)
WHERE v.version=s.latest_version;

-- Operational rows retain only an opaque admission token. A row admitted
-- against an older delegation gets a deliberately stale token and therefore
-- cannot regain authority after the historical payload is removed.
DO $migration$ DECLARE relation text; id_column text; version_column text;
DECLARE token_column text;
BEGIN
  FOR relation,id_column,version_column,token_column IN VALUES
    ('application_schedule_version','delegation_id','delegation_version','delegation_state_token'),
    ('python_program_schedule_version','delegation_id','delegation_version','delegation_state_token'),
    ('python_program_build','delegation_id','delegation_version','delegation_state_token'),
    ('job','execution_delegation_id','execution_delegation_version','execution_delegation_state_token')
  LOOP
    EXECUTE format('ALTER TABLE epm.%I ADD COLUMN %I text',relation,token_column);
    EXECUTE format($sql$
      UPDATE epm.%I row SET %I=CASE
        WHEN current.state_token IS NOT NULL AND old.version=(
          SELECT latest_version FROM epm.execution_delegation_state s
          WHERE s.workspace_id=row.workspace_id
            AND s.application_id=row.application_id
            AND s.delegation_id=row.%I)
        THEN current.state_token
        ELSE encode(sha256(convert_to(row.workspace_id||E'\n'||
          row.application_id||E'\n'||coalesce(row.%I,'')||E'\nstale\n'||
          coalesce(old.version::text,''),'UTF8')),'hex') END
      FROM epm.execution_delegation_version old
      LEFT JOIN epm.execution_delegation_current current
        ON current.workspace_id=old.workspace_id
       AND current.application_id=old.application_id
       AND current.delegation_id=old.delegation_id
      WHERE row.workspace_id=old.workspace_id
        AND row.application_id=old.application_id
        AND row.%I=old.delegation_id
        AND row.%I=old.version$sql$,
      relation,token_column,id_column,id_column,id_column,version_column);
  END LOOP;
END $migration$;

DO $migration$ DECLARE edge record;
BEGIN
  FOR edge IN SELECT conrelid::regclass relation,conname
    FROM pg_constraint
    WHERE contype='f' AND confrelid='epm.execution_delegation_version'::regclass
  LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',edge.relation,edge.conname);
  END LOOP;
END $migration$;

ALTER TABLE epm.application_schedule_version
  ALTER COLUMN delegation_state_token SET NOT NULL,
  ADD CONSTRAINT application_schedule_delegation_state_token_format
    CHECK(delegation_state_token~'^[0-9a-f]{64}$'),
  DROP COLUMN delegation_version;
ALTER TABLE epm.python_program_schedule_version
  ALTER COLUMN delegation_state_token SET NOT NULL,
  ADD CONSTRAINT python_schedule_delegation_state_token_format
    CHECK(delegation_state_token~'^[0-9a-f]{64}$'),
  DROP COLUMN delegation_version;
ALTER TABLE epm.python_program_build
  ADD CONSTRAINT python_build_delegation_state_token_format
    CHECK(delegation_state_token IS NULL
      OR delegation_state_token~'^[0-9a-f]{64}$'),
  ADD CONSTRAINT python_build_delegation_binding_complete
    CHECK((delegation_id IS NULL)=(delegation_state_token IS NULL)),
  DROP COLUMN delegation_version;
ALTER TABLE epm.job
  ADD CONSTRAINT job_execution_delegation_state_token_format
    CHECK(execution_delegation_state_token IS NULL
      OR execution_delegation_state_token~'^[0-9a-f]{64}$'),
  ADD CONSTRAINT job_execution_delegation_binding_complete
    CHECK((execution_delegation_id IS NULL)=
      (execution_delegation_state_token IS NULL)),
  DROP COLUMN execution_delegation_version;

DROP FUNCTION epm.execution_delegation_is_current(
  text,text,text,bigint,text,text,text,text,bigint);
DROP TABLE epm.execution_delegation_state;
DROP TABLE epm.execution_delegation_version;
ALTER TABLE epm.execution_delegation_current
  RENAME TO execution_delegation_definition;

CREATE FUNCTION epm.execution_delegation_is_current(
  p_workspace text,p_application text,p_delegation text,p_state_token text,
  p_issuer text,p_subject text,p_operation text,p_schedule text)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT EXISTS(SELECT 1 FROM epm.execution_delegation_definition d
    WHERE d.workspace_id=p_workspace AND d.application_id=p_application
      AND d.delegation_id=p_delegation AND d.state_token=p_state_token
      AND d.status='Active' AND d.issuer=p_issuer AND d.subject_id=p_subject
      AND p_operation=ANY(d.operation_scope)
      AND d.schedule_id IS NOT DISTINCT FROM p_schedule
      AND clock_timestamp()>=d.valid_from AND clock_timestamp()<d.valid_until)
$$;
REVOKE ALL ON FUNCTION epm.execution_delegation_is_current(
  text,text,text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.execution_delegation_is_current(
  text,text,text,text,text,text,text,text) TO epm_runtime,epm_worker;

ALTER TABLE epm.execution_delegation_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY execution_delegation_definition_runtime_scope
  ON epm.execution_delegation_definition TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY execution_delegation_definition_lifecycle_scope
  ON epm.execution_delegation_definition TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.execution_delegation_definition
  FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE ON epm.execution_delegation_definition TO epm_runtime;
GRANT SELECT ON epm.execution_delegation_definition TO epm_lifecycle;

DO $migration$
DECLARE definition text;
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position('''execution_delegation_state'',' IN definition)=0
      OR position('''execution_delegation_version''' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0311_TABLES_MISMATCH'; END IF;
  definition:=replace(definition,'''execution_delegation_state'',','');
  definition:=replace(definition,'''execution_delegation_version''',
    '''execution_delegation_definition''');
  EXECUTE definition;
  SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure)
    INTO definition;
  IF position('execution_delegation_state,' IN definition)=0
      OR position('execution_delegation_version' IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0311_TABLES_MISMATCH'; END IF;
  definition:=replace(definition,'execution_delegation_state,','');
  definition:=replace(definition,'execution_delegation_version',
    'execution_delegation_definition');
  EXECUTE definition;
END $migration$;

DO $migration$
DECLARE definition text;
DECLARE previous constant text := '7fece1bbacd4a7d108b47b4a1fca88ba066409595e3649713f14083ccde3b090';
DECLARE current_graph constant text := '2ba9942b8ff4f7723f40efeb94aff3a679aaf1054eb6b6693ed217542c184e16';
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0311_PREDECESSOR_MISMATCH'; END IF;
  EXECUTE replace(definition,previous,current_graph);
  SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0311_PREDECESSOR_MISMATCH'; END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
