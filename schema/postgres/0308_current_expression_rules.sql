BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=307) THEN
    RAISE EXCEPTION 'MIGRATION_0308_REQUIRES_0307';
  END IF;
END $migration$;

CREATE TABLE epm.expression_rule_current(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  rule_id text NOT NULL CHECK(rule_id ~ '^[A-Za-z0-9._-]{1,100}$'),
  program jsonb NOT NULL CHECK(jsonb_typeof(program)='object'),
  program_digest text NOT NULL CHECK(program_digest ~ '^[0-9a-f]{64}$'),
  state_token text NOT NULL CHECK(state_token ~ '^[0-9a-f]{64}$'),
  status text NOT NULL CHECK(status IN('Saved','Active','Inactive')),
  metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
  source_build_id text,
  updated_operation_id text,
  updated_revision bigint NOT NULL CHECK(updated_revision>=0),
  updated_issuer text NOT NULL CHECK(length(updated_issuer) BETWEEN 1 AND 300),
  updated_subject_id text NOT NULL CHECK(length(updated_subject_id) BETWEEN 1 AND 300),
  activated_revision bigint CHECK(activated_revision IS NULL OR activated_revision>0),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,rule_id),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,source_build_id)
    REFERENCES epm.python_program_build(workspace_id,application_id,build_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,updated_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id) ON DELETE RESTRICT,
  CHECK((status='Active')=(activated_revision IS NOT NULL))
);

-- Keep exactly one editable current definition. If an unpublished edit exists,
-- it wins and starts Saved; an older publication is not retained as a second
-- executable truth. The deterministic migration token is only the initial
-- current-state fence and cannot retrieve prior content.
INSERT INTO epm.expression_rule_current(workspace_id,application_id,rule_id,
  program,program_digest,state_token,status,metadata_revision,source_build_id,
  updated_operation_id,updated_revision,updated_issuer,updated_subject_id,
  activated_revision,updated_at)
SELECT v.workspace_id,v.application_id,v.rule_id,v.program,v.program_digest,
  encode(sha256(convert_to(v.workspace_id||E'\n'||v.application_id||E'\n'||
    v.rule_id||E'\n'||v.version::text||E'\n'||v.program_digest||E'\n'||
    CASE WHEN p.version=v.version THEN 'Active' ELSE 'Saved' END,'UTF8')),'hex'),
  CASE WHEN p.version=v.version THEN 'Active' ELSE 'Saved' END,
  v.metadata_revision,v.source_build_id,v.created_operation_id,
  v.created_revision,v.created_issuer,v.created_subject_id,
  CASE WHEN p.version=v.version THEN p.published_revision ELSE NULL END,
  v.created_at
FROM epm.expression_rule_version v
LEFT JOIN epm.expression_rule_publication p
  USING(workspace_id,application_id,rule_id)
WHERE NOT EXISTS(SELECT 1 FROM epm.expression_rule_version newer
  WHERE newer.workspace_id=v.workspace_id
    AND newer.application_id=v.application_id
    AND newer.rule_id=v.rule_id AND newer.version>v.version);

-- Operational rows pin the current token, never a historical definition
-- locator. A row whose old program differs gets a deliberately stale token;
-- worker admission must reject it rather than replay old executable content.
ALTER TABLE epm.application_rule_workflow ADD COLUMN rule_state_token text;
UPDATE epm.application_rule_workflow w SET rule_state_token=CASE
  WHEN w.program_digest=c.program_digest THEN c.state_token
  ELSE encode(sha256(convert_to(w.workspace_id||E'\n'||w.application_id||E'\n'||
    w.rule_id||E'\nstale-workflow\n'||w.program_digest,'UTF8')),'hex') END
FROM epm.expression_rule_current c
WHERE c.workspace_id=w.workspace_id AND c.application_id=w.application_id
  AND c.rule_id=w.rule_id;
ALTER TABLE epm.application_rule_workflow ALTER COLUMN rule_state_token SET NOT NULL;

ALTER TABLE epm.application_schedule_version ADD COLUMN rule_state_token text;
UPDATE epm.application_schedule_version s SET rule_state_token=CASE
  WHEN s.rule_program_digest=c.program_digest THEN c.state_token
  ELSE encode(sha256(convert_to(s.workspace_id||E'\n'||s.application_id||E'\n'||
    s.rule_id||E'\nstale-schedule\n'||s.rule_program_digest,'UTF8')),'hex') END
FROM epm.expression_rule_current c
WHERE c.workspace_id=s.workspace_id AND c.application_id=s.application_id
  AND c.rule_id=s.rule_id;
ALTER TABLE epm.application_schedule_version ALTER COLUMN rule_state_token SET NOT NULL;

DO $migration$ DECLARE edge record;
BEGIN
  FOR edge IN SELECT conrelid::regclass AS relation,conname
    FROM pg_constraint
    WHERE contype='f' AND confrelid='epm.expression_rule_version'::regclass
  LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',edge.relation,edge.conname);
  END LOOP;
END $migration$;

ALTER TABLE epm.application_rule_workflow DROP COLUMN rule_version;
ALTER TABLE epm.application_schedule_version DROP COLUMN rule_version;
DROP TABLE epm.expression_rule_publication;
DROP TABLE epm.expression_rule_version;
ALTER TABLE epm.expression_rule_current RENAME TO expression_rule_definition;

ALTER TABLE epm.application_rule_workflow ADD CONSTRAINT
  application_rule_workflow_current_rule_fk
  FOREIGN KEY(workspace_id,application_id,rule_id)
  REFERENCES epm.expression_rule_definition(workspace_id,application_id,rule_id)
  ON DELETE RESTRICT;
ALTER TABLE epm.application_schedule_version ADD CONSTRAINT
  application_schedule_current_rule_fk
  FOREIGN KEY(workspace_id,application_id,rule_id)
  REFERENCES epm.expression_rule_definition(workspace_id,application_id,rule_id)
  ON DELETE RESTRICT;

ALTER TABLE epm.expression_rule_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY expression_rule_definition_runtime_scope
  ON epm.expression_rule_definition TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY expression_rule_definition_lifecycle_scope
  ON epm.expression_rule_definition TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.expression_rule_definition
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT ON epm.expression_rule_definition TO epm_runtime;
GRANT UPDATE(program,program_digest,state_token,status,metadata_revision,
  source_build_id,updated_operation_id,updated_revision,updated_issuer,
  updated_subject_id,activated_revision,updated_at)
  ON epm.expression_rule_definition TO epm_runtime;
GRANT SELECT ON epm.expression_rule_definition TO epm_worker,epm_analyst,epm_lifecycle;

DO $migration$
DECLARE definition text;
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position('''expression_rule_publication'',' IN definition)=0
     OR position('''expression_rule_version'',' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0308_RULE_TABLES_MISMATCH';
  END IF;
  definition:=replace(definition,
    '''expression_rule_publication'',','''expression_rule_definition'',');
  definition:=replace(definition,'''expression_rule_version'',','');
  EXECUTE definition;

  SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure)
    INTO definition;
  IF position('expression_rule_publication' IN definition)=0
     OR position('expression_rule_version' IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0308_RULE_TABLES_MISMATCH';
  END IF;
  definition:=replace(definition,'expression_rule_publication','expression_rule_definition');
  definition:=replace(definition,',expression_rule_version','');
  EXECUTE definition;
END $migration$;

DO $migration$
DECLARE definition text;
DECLARE previous constant text := '0dbbec70c6b0dacac73b377a97d29e4077a7e78ea8b30ab18c0b47b703269754';
DECLARE current_graph constant text := 'a3364f3b8d07556e476765f482793dcf0c9f12423f738b42397f44340c98c7f8';
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0308_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
  SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0308_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
