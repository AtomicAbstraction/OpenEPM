BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=324) THEN
  RAISE EXCEPTION 'MIGRATION_0325_REQUIRES_0324';
 END IF;
END $migration$;

CREATE FUNCTION epm.current_inventory_schedule_canonical_json(value jsonb)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT CASE jsonb_typeof(value)
  WHEN 'object' THEN '{'||COALESCE((SELECT string_agg(to_jsonb(key)::text||':'||
    epm.current_inventory_schedule_canonical_json(item),',' ORDER BY key)
    FROM jsonb_each(value) AS entry(key,item)),'')||'}'
  WHEN 'array' THEN '['||COALESCE((SELECT string_agg(
    epm.current_inventory_schedule_canonical_json(item),',' ORDER BY ordinal)
    FROM jsonb_array_elements(value) WITH ORDINALITY AS entry(item,ordinal)),'')||']'
  ELSE value::text END
$$;
REVOKE ALL ON FUNCTION epm.current_inventory_schedule_canonical_json(jsonb) FROM PUBLIC;

CREATE TABLE epm.inventory_unrealized_schedule_definition(
 workspace_id text NOT NULL,application_id text NOT NULL,schedule_id text NOT NULL,
 state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN('Saved','Active')),
 effective_on date NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'),
 definition_digest text NOT NULL CHECK(definition_digest~'^[0-9a-f]{64}$'),
 updated_revision bigint NOT NULL CHECK(updated_revision>0),operation_id text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,schedule_id),
 UNIQUE(workspace_id,application_id,schedule_id,state_token,definition_digest),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application
  (workspace_id,application_id) ON DELETE RESTRICT);
REVOKE ALL ON epm.inventory_unrealized_schedule_definition
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE ON epm.inventory_unrealized_schedule_definition TO epm_runtime;
GRANT DELETE ON epm.inventory_unrealized_schedule_definition TO epm_lifecycle;
ALTER TABLE epm.inventory_unrealized_schedule_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY inventory_unrealized_schedule_definition_scope
 ON epm.inventory_unrealized_schedule_definition TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
CREATE POLICY inventory_unrealized_schedule_definition_lifecycle
 ON epm.inventory_unrealized_schedule_definition TO epm_lifecycle
 USING(current_setting('epm.lifecycle_context',true)='workspace_reset');

WITH chosen AS(
 SELECT v.*,s.active_version,s.state_revision,s.updated_at AS state_updated_at,
  row_number() OVER(PARTITION BY v.workspace_id,v.application_id,v.schedule_id ORDER BY
   (v.version=s.active_version) DESC,v.version DESC) AS choice
 FROM epm.inventory_unrealized_schedule_version v
 JOIN epm.inventory_unrealized_schedule_state s
 USING(workspace_id,application_id,schedule_id)
), normalized AS(
 SELECT *,definition-'scheduleVersion' AS current_definition FROM chosen WHERE choice=1
)
INSERT INTO epm.inventory_unrealized_schedule_definition(
 workspace_id,application_id,schedule_id,state_token,status,effective_on,definition,
 definition_digest,updated_revision,operation_id,updated_at)
SELECT workspace_id,application_id,schedule_id,
 encode(sha256(convert_to(workspace_id||E'\n'||application_id||E'\n'||schedule_id||
  E'\n'||version::text||E'\n'||state_revision::text||E'\n'||definition_digest,'UTF8')),'hex'),
 CASE WHEN version=active_version THEN 'Active' ELSE 'Saved' END,
 effective_on,current_definition,
 encode(sha256(convert_to(epm.current_inventory_schedule_canonical_json(current_definition),'UTF8')),'hex'),
 state_revision,operation_id,state_updated_at
FROM normalized;

DO $migration$ DECLARE definition text; old_fragment text; new_fragment text;
BEGIN
 SELECT pg_get_functiondef('epm.inventory_unrealized_pointer_complete()'::regprocedure)
 INTO definition;
 old_fragment:=$old$FROM epm.inventory_unrealized_schedule_state s
   JOIN epm.inventory_unrealized_schedule_version v ON
    (v.workspace_id,v.application_id,v.schedule_id,v.version)=
    (s.workspace_id,s.application_id,s.schedule_id,s.active_version)
   WHERE s.workspace_id=NEW.workspace_id AND s.application_id=NEW.application_id
    AND s.schedule_id=generation_row.normalized_program->'definition'->>'scheduleId'
    AND to_jsonb(s.active_version)=generation_row.normalized_program->'definition'->'scheduleVersion'
    AND v.definition=generation_row.normalized_program->'definition'
    AND v.definition_digest=receipt->>'scheduleDigest'$old$;
 new_fragment:=$new$FROM epm.inventory_unrealized_schedule_definition s
   WHERE s.workspace_id=NEW.workspace_id AND s.application_id=NEW.application_id
    AND s.schedule_id=generation_row.normalized_program->'definition'->>'scheduleId'
    AND s.status='Active'
    AND s.definition=generation_row.normalized_program->'definition'
    AND s.definition_digest=receipt->>'scheduleDigest'
    AND s.state_token=receipt->>'scheduleStateToken'$new$;
 IF position(old_fragment IN definition)=0 THEN
  RAISE EXCEPTION 'INVENTORY_SCHEDULE_0325_POINTER_FUNCTION_MISMATCH';
 END IF;
 EXECUTE replace(definition,old_fragment,new_fragment);
END $migration$;

DROP TABLE epm.inventory_unrealized_schedule_state;
DROP TABLE epm.inventory_unrealized_schedule_version;
DROP FUNCTION epm.current_inventory_schedule_canonical_json(jsonb);

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='85f75c3b7ab2114344d7e3d193562b4d81aad25f3d46ab26c45d7178ce67dd5a';
DECLARE current_graph constant text:='a96699a564f2f62cf7fbd9a7e07cfe3fb9cce2e4df679ae3dcf73c0a8e0fbc64';
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO definition;
 IF position(previous IN definition)=0 OR position(
  '''inventory_unrealized_schedule_state'',''inventory_unrealized_schedule_version''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0325_INVENTORY_SCHEDULE_PREDECESSOR_MISMATCH';END IF;
 definition:=replace(definition,
  '''inventory_unrealized_schedule_state'',''inventory_unrealized_schedule_version''',
  '''inventory_unrealized_schedule_definition''');
 EXECUTE replace(definition,previous,current_graph);

 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure)
 INTO definition;
 IF position('inventory_unrealized_schedule_state,inventory_unrealized_schedule_version' IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0325_INVENTORY_SCHEDULE_MISMATCH';END IF;
 EXECUTE replace(definition,
  'inventory_unrealized_schedule_state,inventory_unrealized_schedule_version',
  'inventory_unrealized_schedule_definition');

 SELECT pg_get_functiondef(
  'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
 INTO definition;
 IF position(previous IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0325_INVENTORY_SCHEDULE_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
