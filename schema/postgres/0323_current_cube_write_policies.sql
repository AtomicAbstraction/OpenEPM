BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=322) THEN
  RAISE EXCEPTION 'MIGRATION_0323_REQUIRES_0322';
 END IF;
END $migration$;

CREATE FUNCTION epm.current_cube_write_policy_canonical_json(value jsonb)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT CASE jsonb_typeof(value)
  WHEN 'object' THEN '{'||COALESCE((SELECT string_agg(to_jsonb(key)::text||':'||
    epm.current_cube_write_policy_canonical_json(item),',' ORDER BY key)
    FROM jsonb_each(value) AS entry(key,item)),'')||'}'
  WHEN 'array' THEN '['||COALESCE((SELECT string_agg(
    epm.current_cube_write_policy_canonical_json(item),',' ORDER BY ordinal)
    FROM jsonb_array_elements(value) WITH ORDINALITY AS entry(item,ordinal)),'')||']'
  ELSE value::text END
$$;
REVOKE ALL ON FUNCTION epm.current_cube_write_policy_canonical_json(jsonb) FROM PUBLIC;

CREATE TABLE epm.cube_write_policy_definition(
 workspace_id text NOT NULL,application_id text NOT NULL,
 policy_id text NOT NULL CHECK(policy_id~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
 state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN('Saved','Active')),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
  AND octet_length(definition::text)<=4194304
  AND definition->>'workspaceId'=workspace_id
  AND definition->>'applicationId'=application_id
  AND definition->>'policyId'=policy_id
  AND NOT definition?'version'),
 canonical_digest text NOT NULL CHECK(canonical_digest~'^[0-9a-f]{64}$'),
 updated_operation_id text NOT NULL,updated_revision bigint NOT NULL CHECK(updated_revision>=0),
 updated_issuer text NOT NULL CHECK(length(updated_issuer) BETWEEN 1 AND 300),
 updated_subject_id text NOT NULL CHECK(length(updated_subject_id) BETWEEN 1 AND 300),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,policy_id),
 UNIQUE(workspace_id,application_id,policy_id,state_token,canonical_digest),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state(
  workspace_id,application_id) ON DELETE RESTRICT);
CREATE UNIQUE INDEX cube_write_policy_one_active_per_application
 ON epm.cube_write_policy_definition(workspace_id,application_id)
 WHERE status='Active';

ALTER TABLE epm.cube_write_policy_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY cube_write_policy_definition_runtime
 ON epm.cube_write_policy_definition TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
CREATE POLICY cube_write_policy_definition_lifecycle
 ON epm.cube_write_policy_definition FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.cube_write_policy_definition
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE,DELETE ON epm.cube_write_policy_definition TO epm_runtime;
GRANT SELECT ON epm.cube_write_policy_definition TO epm_lifecycle;

WITH chosen AS(
 SELECT v.*,s.active_policy_id,s.active_version,s.pointer_version,s.state_revision,
  row_number() OVER(PARTITION BY v.workspace_id,v.application_id,v.policy_id ORDER BY
   (v.policy_id=s.active_policy_id AND v.version=s.active_version) DESC,v.version DESC) choice
 FROM epm.cube_write_policy_version v LEFT JOIN epm.cube_write_policy_state s
  USING(workspace_id,application_id)
), normalized AS(
 SELECT *,definition-'version' current_definition FROM chosen WHERE choice=1
)
INSERT INTO epm.cube_write_policy_definition(workspace_id,application_id,policy_id,
 state_token,status,definition,canonical_digest,updated_operation_id,updated_revision,
 updated_issuer,updated_subject_id,updated_at)
SELECT workspace_id,application_id,policy_id,
 encode(sha256(convert_to(workspace_id||E'\n'||application_id||E'\n'||policy_id||
  E'\n'||version::text||E'\n'||coalesce(pointer_version,0)::text||E'\n'||
  coalesce(state_revision,0)::text||E'\n'||canonical_digest,'UTF8')),'hex'),
 CASE WHEN policy_id=active_policy_id AND version=active_version THEN 'Active' ELSE 'Saved' END,
 current_definition,encode(sha256(convert_to(
  epm.current_cube_write_policy_canonical_json(current_definition),'UTF8')),'hex'),
 'migration-0323',coalesce(state_revision,0),creator_issuer,creator_subject_id,created_at
FROM normalized;

-- Assigned-review records are retained only when their exact policy became the
-- one current policy. Stale historical review bindings are derived state and
-- are removed instead of preserving a hidden historical authority.
ALTER TABLE epm.cube_write_scope_assigned_submission ADD COLUMN policy_state_token text;
WITH chosen AS(
 SELECT v.workspace_id,v.application_id,v.policy_id,v.version,
  row_number() OVER(PARTITION BY v.workspace_id,v.application_id,v.policy_id ORDER BY
   (v.policy_id=s.active_policy_id AND v.version=s.active_version) DESC,v.version DESC) choice
 FROM epm.cube_write_policy_version v LEFT JOIN epm.cube_write_policy_state s
  USING(workspace_id,application_id)
)
UPDATE epm.cube_write_scope_assigned_submission a SET
 policy_state_token=p.state_token,policy_digest=p.canonical_digest
FROM chosen c JOIN epm.cube_write_policy_definition p
 USING(workspace_id,application_id,policy_id)
WHERE c.choice=1 AND (a.workspace_id,a.application_id,a.policy_id,a.policy_version)=
 (c.workspace_id,c.application_id,c.policy_id,c.version);
DELETE FROM epm.cube_write_scope_assigned_review_event e USING
 epm.cube_write_scope_assigned_submission a
WHERE (e.workspace_id,e.application_id,e.lock_id)=(a.workspace_id,a.application_id,a.lock_id)
 AND a.policy_state_token IS NULL;
DELETE FROM epm.cube_write_scope_assigned_reviewer r USING
 epm.cube_write_scope_assigned_submission a
WHERE (r.workspace_id,r.application_id,r.lock_id)=(a.workspace_id,a.application_id,a.lock_id)
 AND a.policy_state_token IS NULL;
DELETE FROM epm.cube_write_scope_assigned_submission WHERE policy_state_token IS NULL;
ALTER TABLE epm.cube_write_scope_assigned_submission
 ALTER COLUMN policy_state_token SET NOT NULL,
 ADD CONSTRAINT cube_write_scope_assigned_submission_policy_token_shape
  CHECK(policy_state_token~'^[0-9a-f]{64}$'),
 DROP COLUMN policy_version;

DROP TRIGGER cube_write_policy_version_immutable ON epm.cube_write_policy_version;
DROP TABLE epm.cube_write_policy_state;
DROP TABLE epm.cube_write_policy_version;
DROP FUNCTION epm.cube_write_policy_version_immutable();
DROP FUNCTION epm.current_cube_write_policy_canonical_json(jsonb);

DO $migration$ DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,
  '''cube_write_policy_state'',''cube_write_policy_version''',
  '''cube_write_policy_definition''');
 IF position('''cube_write_policy_definition''' IN definition)=0
    OR position('''cube_write_policy_state''' IN definition)>0
    OR position('''cube_write_policy_version''' IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0323_POLICY_INVENTORY_MISMATCH';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure) INTO definition;
 definition:=replace(definition,'cube_write_policy_state,cube_write_policy_version',
  'cube_write_policy_definition');
 IF position('cube_write_policy_definition' IN definition)=0
    OR position('cube_write_policy_state' IN definition)>0
    OR position('cube_write_policy_version' IN definition)>0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0323_POLICY_INVENTORY_MISMATCH';END IF;
 EXECUTE definition;
END $migration$;

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='6d5bcc1bf516bb535ac84fea95988cf9348010d3bd3b7b4f5ca2de0114b32835';
DECLARE current_graph constant text:='8af52f227ec8277a9a13490ed90df4754018992f70bc51018d709a7c02921a58';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'RESET_0323_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0323_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
