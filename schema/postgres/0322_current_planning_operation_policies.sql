BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=321) THEN
  RAISE EXCEPTION 'MIGRATION_0322_REQUIRES_0321';
 END IF;
END $migration$;

CREATE FUNCTION epm.current_planning_policy_canonical_json(value jsonb)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT CASE jsonb_typeof(value)
  WHEN 'object' THEN '{'||COALESCE((SELECT string_agg(to_jsonb(key)::text||':'||
    epm.current_planning_policy_canonical_json(item),',' ORDER BY key)
    FROM jsonb_each(value) AS entry(key,item)),'')||'}'
  WHEN 'array' THEN '['||COALESCE((SELECT string_agg(
    epm.current_planning_policy_canonical_json(item),',' ORDER BY ordinal)
    FROM jsonb_array_elements(value) WITH ORDINALITY AS entry(item,ordinal)),'')||']'
  ELSE value::text END
$$;
REVOKE ALL ON FUNCTION epm.current_planning_policy_canonical_json(jsonb) FROM PUBLIC;

CREATE TABLE epm.planning_operation_policy(
 workspace_id text NOT NULL,application_id text NOT NULL,
 policy_id text NOT NULL CHECK(policy_id~'^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$'),
 state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN('Saved','Active')),
 kind text NOT NULL CHECK(kind IN('Seed','Driver','Rollup','Spread','Allocation')),
 effective_from date NOT NULL,effective_before date NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
   AND octet_length(definition::text)<=1048576),
 canonical_digest text NOT NULL CHECK(canonical_digest~'^[0-9a-f]{64}$'),
 updated_operation_id text NOT NULL,
 updated_revision bigint NOT NULL CHECK(updated_revision>=0),
 updated_issuer text NOT NULL CHECK(length(updated_issuer) BETWEEN 1 AND 300),
 updated_subject_id text NOT NULL CHECK(length(updated_subject_id) BETWEEN 1 AND 300),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,policy_id),
 UNIQUE(workspace_id,application_id,policy_id,state_token,canonical_digest),
 FOREIGN KEY(workspace_id,application_id) REFERENCES
  epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
 CHECK(effective_from<effective_before));

ALTER TABLE epm.planning_operation_policy ENABLE ROW LEVEL SECURITY;
CREATE POLICY planning_operation_policy_runtime ON epm.planning_operation_policy
 TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
CREATE POLICY planning_operation_policy_lifecycle ON epm.planning_operation_policy
 FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.planning_operation_policy
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE,DELETE ON epm.planning_operation_policy TO epm_runtime;
GRANT SELECT ON epm.planning_operation_policy TO epm_lifecycle;

WITH chosen AS(
 SELECT v.*,s.active_version,s.pointer_version,s.state_revision,s.updated_at AS state_updated_at,
  row_number() OVER(PARTITION BY v.workspace_id,v.application_id,v.policy_id ORDER BY
   (v.version=s.active_version) DESC,v.version DESC) AS choice
 FROM epm.planning_operation_policy_version v JOIN epm.planning_operation_policy_state s
  USING(workspace_id,application_id,policy_id)
), normalized AS(
 SELECT *,definition-'version' AS current_definition FROM chosen WHERE choice=1
)
INSERT INTO epm.planning_operation_policy(workspace_id,application_id,policy_id,
 state_token,status,kind,effective_from,effective_before,definition,canonical_digest,
 updated_operation_id,updated_revision,updated_issuer,updated_subject_id,updated_at)
SELECT workspace_id,application_id,policy_id,
 encode(sha256(convert_to(workspace_id||E'\n'||application_id||E'\n'||policy_id||
   E'\n'||version::text||E'\n'||pointer_version::text||E'\n'||state_revision::text||
   E'\n'||canonical_digest,'UTF8')),'hex'),
 CASE WHEN version=active_version THEN 'Active' ELSE 'Saved' END,
 kind,effective_from,effective_before,current_definition,
 encode(sha256(convert_to(epm.current_planning_policy_canonical_json(current_definition),'UTF8')),'hex'),
 'migration-0322',state_revision,creator_issuer,creator_subject_id,state_updated_at
FROM normalized;

-- Seed lineage keeps exact current-policy authority, never an addressable
-- historical policy version. Evidence bound to a retired policy is removed.
ALTER TABLE epm.planning_seed_lineage DISABLE TRIGGER planning_seed_lineage_validate;
ALTER TABLE epm.planning_seed_lineage ADD COLUMN policy_state_token text;
WITH chosen AS(
 SELECT v.workspace_id,v.application_id,v.policy_id,v.version,
  row_number() OVER(PARTITION BY v.workspace_id,v.application_id,v.policy_id
   ORDER BY (v.version=s.active_version) DESC,v.version DESC) AS choice
 FROM epm.planning_operation_policy_version v
 JOIN epm.planning_operation_policy_state s
 USING(workspace_id,application_id,policy_id)
)
DELETE FROM epm.planning_seed_lineage l WHERE NOT EXISTS(
 SELECT 1 FROM chosen c WHERE c.choice=1
  AND (c.workspace_id,c.application_id,c.policy_id,c.version)=
      (l.workspace_id,l.application_id,l.policy_id,l.policy_version));
UPDATE epm.planning_seed_lineage l SET
 policy_state_token=p.state_token,policy_digest=p.canonical_digest
FROM epm.planning_operation_policy p
WHERE (p.workspace_id,p.application_id,p.policy_id)=
      (l.workspace_id,l.application_id,l.policy_id);
ALTER TABLE epm.planning_seed_lineage
 ALTER COLUMN policy_state_token SET NOT NULL,
 ADD CHECK(policy_state_token~'^[0-9a-f]{64}$'),
 DROP COLUMN policy_version;
ALTER TABLE epm.planning_seed_lineage ENABLE TRIGGER planning_seed_lineage_validate;

DROP TRIGGER planning_operation_policy_version_immutable
 ON epm.planning_operation_policy_version;
DROP TABLE epm.planning_operation_policy_state;
DROP TABLE epm.planning_operation_policy_version;
DROP FUNCTION epm.planning_operation_policy_version_immutable();
DROP FUNCTION epm.current_planning_policy_canonical_json(jsonb);

DO $migration$ DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,
  '''planning_operation_policy_state'',''planning_operation_policy_version''',
  '''planning_operation_policy''');
 IF position('''planning_operation_policy''' IN definition)=0
    OR position('''planning_operation_policy_state''' IN definition)>0
    OR position('''planning_operation_policy_version''' IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0322_POLICY_INVENTORY_MISMATCH';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure) INTO definition;
 definition:=replace(definition,
  'planning_operation_policy_state,planning_operation_policy_version',
  'planning_operation_policy');
 IF position('planning_operation_policy' IN definition)=0
    OR position('planning_operation_policy_state' IN definition)>0
    OR position('planning_operation_policy_version' IN definition)>0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0322_POLICY_INVENTORY_MISMATCH';END IF;
 EXECUTE definition;
END $migration$;

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='a91b497fd9c7549c81b7ec234fb6d68a3a22211c410911a5a91261028419296b';
DECLARE current_graph constant text:='6d5bcc1bf516bb535ac84fea95988cf9348010d3bd3b7b4f5ca2de0114b32835';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'RESET_0322_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0322_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
