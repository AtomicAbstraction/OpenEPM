BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=304) THEN
    RAISE EXCEPTION 'MIGRATION_0305_REQUIRES_0304';
  END IF;
END $migration$;

CREATE TABLE epm.application_decision (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  decision_id text NOT NULL CHECK(decision_id ~ '^[A-Za-z0-9._-]{1,100}$'),
  title text NOT NULL CHECK(octet_length(title) BETWEEN 1 AND 200 AND length(btrim(title))>0),
  decision_text text NOT NULL CHECK(octet_length(decision_text) BETWEEN 1 AND 8000 AND length(btrim(decision_text))>0),
  rationale text NOT NULL DEFAULT '' CHECK(octet_length(rationale)<=2000),
  source_reference text NOT NULL DEFAULT '' CHECK(octet_length(source_reference)<=1000),
  provenance text NOT NULL CHECK(provenance IN ('UserDecision','AgentInterpretation')),
  status text NOT NULL CHECK(status IN ('Active','Withdrawn')),
  state_token text NOT NULL CHECK(state_token ~ '^[0-9a-f]{64}$'),
  content_digest text NOT NULL CHECK(content_digest ~ '^[0-9a-f]{64}$'),
  updated_operation_id text NOT NULL,
  updated_revision bigint NOT NULL CHECK(updated_revision>0),
  updated_issuer text NOT NULL,
  updated_subject_id text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,decision_id),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,updated_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id) ON DELETE RESTRICT
);

-- Preserve only the current head.  Earlier immutable rows are deliberately
-- not copied: product/application history has been retired.
INSERT INTO epm.application_decision(
  workspace_id,application_id,decision_id,title,decision_text,rationale,
  source_reference,provenance,status,state_token,content_digest,
  updated_operation_id,updated_revision,updated_issuer,updated_subject_id,updated_at)
SELECT v.workspace_id,v.application_id,v.decision_id,v.title,v.decision_text,
  v.rationale,v.source_reference,v.provenance,v.status,
  encode(sha256(convert_to(v.workspace_id||E'\n'||v.application_id||E'\n'||
    v.decision_id||E'\n'||v.version::text||E'\n'||v.content_digest,'UTF8')),'hex'),
  v.content_digest,v.created_operation_id,v.created_revision,v.created_issuer,
  v.created_subject_id,v.created_at
FROM epm.application_decision_head h
JOIN epm.application_decision_version v
  USING(workspace_id,application_id,decision_id,version);

GRANT SELECT,INSERT ON epm.application_decision TO epm_runtime;
GRANT UPDATE(title,decision_text,rationale,source_reference,provenance,status,
  state_token,content_digest,updated_operation_id,updated_revision,
  updated_issuer,updated_subject_id,updated_at) ON epm.application_decision TO epm_runtime;
GRANT SELECT ON epm.application_decision TO epm_lifecycle;
ALTER TABLE epm.application_decision ENABLE ROW LEVEL SECURITY;
CREATE POLICY application_decision_scope ON epm.application_decision TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY application_decision_lifecycle ON epm.application_decision
  FOR SELECT TO epm_lifecycle
  USING(current_setting('epm.lifecycle_context',true)='workspace_reset');

DROP TABLE epm.application_decision_head;
DROP TRIGGER application_decision_version_immutable ON epm.application_decision_version;
DROP FUNCTION epm.application_decision_version_immutable();
DROP TABLE epm.application_decision_version;

DO $migration$
DECLARE definition text; revised text; inventory text[]; head_idx integer;
DECLARE previous constant text := '15bbbfc786a9990e948fc7814a09bf6b176655e7442a4b09bd9411b25c66778c';
  DECLARE current_graph constant text := '94d2bca8ca4c1326f81af73f9c1b34200750567ebf2de9aac743f4bf74d4b301';
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0
     OR position('''application_decision_head'',''application_decision_version''' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0305_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,
    '''application_decision_head'',''application_decision_version''',
    '''application_decision''');
  EXECUTE replace(revised,previous,current_graph);

  inventory:=epm.application_purge_relations();
  head_idx:=array_position(inventory,'application_decision_head');
  IF head_idx IS NULL OR inventory[head_idx+1]<>'application_decision_version' THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0305_INVENTORY_MISMATCH';
  END IF;
  inventory:=inventory[1:head_idx-1]||ARRAY['application_decision']||inventory[head_idx+2:];
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');
  SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0305_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
