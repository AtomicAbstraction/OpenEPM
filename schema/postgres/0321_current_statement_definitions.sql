BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=320) THEN
  RAISE EXCEPTION 'MIGRATION_0321_REQUIRES_0320';
 END IF;
END $migration$;

CREATE FUNCTION epm.current_statement_canonical_json(value jsonb)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT CASE jsonb_typeof(value)
  WHEN 'object' THEN '{'||COALESCE((SELECT string_agg(to_jsonb(key)::text||':'||
    epm.current_statement_canonical_json(item),',' ORDER BY key)
    FROM jsonb_each(value) AS entry(key,item)),'')||'}'
  WHEN 'array' THEN '['||COALESCE((SELECT string_agg(
    epm.current_statement_canonical_json(item),',' ORDER BY ordinal)
    FROM jsonb_array_elements(value) WITH ORDINALITY AS entry(item,ordinal)),'')||']'
  ELSE value::text END
$$;
REVOKE ALL ON FUNCTION epm.current_statement_canonical_json(jsonb) FROM PUBLIC;

CREATE TABLE epm.statement_definition(
 workspace_id text NOT NULL,application_id text NOT NULL,
 definition_id text NOT NULL CHECK(definition_id~'^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$'),
 state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN('Saved','Active')),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
   AND octet_length(definition::text)<=4194304),
 canonical_digest text NOT NULL CHECK(canonical_digest~'^[0-9a-f]{64}$'),
 updated_operation_id text NOT NULL,updated_revision bigint NOT NULL CHECK(updated_revision>0),
 updated_issuer text NOT NULL CHECK(length(updated_issuer) BETWEEN 1 AND 300
   AND updated_issuer!~'[[:cntrl:]]'),
 updated_subject_id text NOT NULL CHECK(length(updated_subject_id) BETWEEN 1 AND 300
   AND updated_subject_id!~'[[:cntrl:]]'),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,definition_id),
 UNIQUE(workspace_id,application_id,definition_id,state_token,canonical_digest),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,updated_operation_id)
  REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
  ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE UNIQUE INDEX statement_definition_current_one_active_per_application
 ON epm.statement_definition(workspace_id,application_id) WHERE status='Active';

ALTER TABLE epm.statement_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY statement_definition_runtime_scope ON epm.statement_definition TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
CREATE POLICY statement_definition_lifecycle_scope ON epm.statement_definition
 FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.statement_definition
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE,DELETE ON epm.statement_definition TO epm_runtime;
GRANT SELECT ON epm.statement_definition TO epm_lifecycle;

WITH chosen AS(
 SELECT v.*,s.active_version,s.state_revision,s.last_operation_id,s.updated_at AS state_updated_at,
  row_number() OVER(PARTITION BY v.workspace_id,v.application_id,v.definition_id ORDER BY
   (v.version=s.active_version) DESC,v.version DESC) AS choice
 FROM epm.statement_definition_version v JOIN epm.statement_definition_state s
  USING(workspace_id,application_id,definition_id)
), normalized AS(
 SELECT *,definition-'version' AS current_definition FROM chosen WHERE choice=1
)
INSERT INTO epm.statement_definition(workspace_id,application_id,definition_id,
 state_token,status,definition,canonical_digest,updated_operation_id,
 updated_revision,updated_issuer,updated_subject_id,updated_at)
SELECT workspace_id,application_id,definition_id,
 encode(sha256(convert_to(workspace_id||E'\n'||application_id||E'\n'||definition_id||
   E'\n'||version::text||E'\n'||state_revision::text||E'\n'||canonical_digest,'UTF8')),'hex'),
 CASE WHEN version=active_version THEN 'Active' ELSE 'Saved' END,current_definition,
 encode(sha256(convert_to(epm.current_statement_canonical_json(current_definition),'UTF8')),'hex'),
 last_operation_id,state_revision,creator_issuer,creator_subject_id,state_updated_at
FROM normalized;

DROP TRIGGER statement_definition_version_immutable ON epm.statement_definition_version;
DROP TRIGGER statement_definition_event_immutable ON epm.statement_definition_event;
DROP TABLE epm.statement_definition_event;
DROP TABLE epm.statement_definition_state;
DROP TABLE epm.statement_definition_version;
DROP FUNCTION epm.statement_definition_immutable();
DROP FUNCTION epm.current_statement_canonical_json(jsonb);

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='64d706fe96d5f81f44b517ad285071918457908dd7e7328fd75ef5b5b383e10a';
DECLARE current_graph constant text:='a91b497fd9c7549c81b7ec234fb6d68a3a22211c410911a5a91261028419296b';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 OR
    position('''statement_definition_event'',''statement_definition_state'',''statement_definition_version''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0321_PREDECESSOR_MISMATCH';END IF;
 definition:=replace(definition,
  '''statement_definition_event'',''statement_definition_state'',''statement_definition_version''',
  '''statement_definition''');
 EXECUTE replace(definition,previous,current_graph);
 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure) INTO definition;
 IF position('statement_definition_event,statement_definition_state,statement_definition_version' IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0321_INVENTORY_MISMATCH';END IF;
 definition:=replace(definition,
  'statement_definition_event,statement_definition_state,statement_definition_version',
  'statement_definition');
 EXECUTE definition;
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0321_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
