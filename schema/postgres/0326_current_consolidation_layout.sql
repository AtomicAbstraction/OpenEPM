BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=325) THEN
  RAISE EXCEPTION 'MIGRATION_0326_REQUIRES_0325';
 END IF;
END $migration$;

CREATE TABLE epm.consolidation_layout(
 workspace_id text NOT NULL,application_id text NOT NULL,
 state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
 layout_digest text NOT NULL CHECK(layout_digest~'^[0-9a-f]{64}$'),
 account_dimension_id text NOT NULL,entity_dimension_id text NOT NULL,
 currency_dimension_id text NOT NULL,stage_dimension_id text NOT NULL,
 movement_dimension_id text NOT NULL,
 metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
 policy_revision bigint NOT NULL CHECK(policy_revision>=0),
 issuer text NOT NULL,subject_id text NOT NULL,
 updated_revision bigint NOT NULL CHECK(updated_revision>0),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id),
 UNIQUE(workspace_id,application_id,state_token,layout_digest),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state
  (workspace_id,application_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,account_dimension_id) REFERENCES
  epm.dimension(workspace_id,application_id,dimension_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,entity_dimension_id) REFERENCES
  epm.dimension(workspace_id,application_id,dimension_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,currency_dimension_id) REFERENCES
  epm.dimension(workspace_id,application_id,dimension_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,stage_dimension_id) REFERENCES
  epm.dimension(workspace_id,application_id,dimension_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,movement_dimension_id) REFERENCES
  epm.dimension(workspace_id,application_id,dimension_id) ON DELETE RESTRICT,
 CHECK(stage_dimension_id<>movement_dimension_id));

REVOKE ALL ON epm.consolidation_layout
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE ON epm.consolidation_layout TO epm_runtime;
GRANT SELECT ON epm.consolidation_layout TO epm_lifecycle;
ALTER TABLE epm.consolidation_layout ENABLE ROW LEVEL SECURITY;
CREATE POLICY consolidation_layout_runtime ON epm.consolidation_layout TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
CREATE POLICY consolidation_layout_lifecycle ON epm.consolidation_layout
 FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));

INSERT INTO epm.consolidation_layout(workspace_id,application_id,state_token,
 layout_digest,account_dimension_id,entity_dimension_id,currency_dimension_id,
 stage_dimension_id,movement_dimension_id,metadata_revision,policy_revision,
 issuer,subject_id,updated_revision,updated_at)
SELECT v.workspace_id,v.application_id,
 encode(sha256(convert_to(v.workspace_id||E'\n'||v.application_id||E'\n'||
  v.layout_version::text||E'\n'||v.layout_digest,'UTF8')),'hex'),
 v.layout_digest,v.account_dimension_id,v.entity_dimension_id,
 v.currency_dimension_id,v.stage_dimension_id,v.movement_dimension_id,
 v.metadata_revision,v.policy_revision,v.issuer,v.subject_id,
 GREATEST(v.policy_revision,1),v.created_at
FROM epm.consolidation_layout_state s
JOIN epm.consolidation_layout_version v
 ON (v.workspace_id,v.application_id,v.layout_version,v.layout_digest)=
    (s.workspace_id,s.application_id,s.active_layout_version,s.active_layout_digest);

ALTER TABLE epm.cta_bridge ADD COLUMN layout_state_token text;
UPDATE epm.cta_bridge b SET layout_state_token=l.state_token
 FROM epm.consolidation_layout l
 WHERE (l.workspace_id,l.application_id,l.layout_digest)=
       (b.workspace_id,b.application_id,b.layout_digest);

-- A bridge produced under a replaced layout is not executable current state.
-- Its journal remains an accounting record, but the domain-specific calculated
-- bridge and its derived source/effect payload are removed.
DELETE FROM epm.cta_bridge_unit_effect e USING epm.cta_bridge b
 WHERE (e.workspace_id,e.application_id,e.bridge_id)=
       (b.workspace_id,b.application_id,b.bridge_id)
 AND b.layout_state_token IS NULL;
DELETE FROM epm.cta_bridge_source s USING epm.cta_bridge b
 WHERE (s.workspace_id,s.application_id,s.bridge_id)=
       (b.workspace_id,b.application_id,b.bridge_id)
 AND b.layout_state_token IS NULL;
DELETE FROM epm.cta_bridge WHERE layout_state_token IS NULL;

UPDATE epm.cta_bridge SET result=(result-'layoutVersion')||
 jsonb_build_object('layoutStateToken',layout_state_token);
ALTER TABLE epm.operation_receipt DISABLE TRIGGER USER;
UPDATE epm.operation_receipt r SET result=(r.result-'layoutVersion')||
 jsonb_build_object('layoutStateToken',b.layout_state_token)
 FROM epm.cta_bridge b
 WHERE (r.workspace_id,r.application_id)=(b.workspace_id,b.application_id)
 AND r.result->>'bridgeId'=b.bridge_id;
UPDATE epm.operation_receipt r SET result=jsonb_set(r.result,'{ctaBridge}',
 ((r.result->'ctaBridge')-'layoutVersion')||
 jsonb_build_object('layoutStateToken',b.layout_state_token))
 FROM epm.cta_bridge b
 WHERE (r.workspace_id,r.application_id,r.operation_id)=
       (b.workspace_id,b.application_id,b.journal_id)
 AND r.result ? 'ctaBridge';
-- Scrub any obsolete layout number from retained technical receipts that no
-- longer have a current bridge row. They cannot become historical locators.
UPDATE epm.operation_receipt SET result=result-'layoutVersion'
 WHERE result ? 'layoutVersion';
UPDATE epm.operation_receipt SET result=jsonb_set(result,'{ctaBridge}',
 (result->'ctaBridge')-'layoutVersion')
 WHERE result ? 'ctaBridge' AND result->'ctaBridge' ? 'layoutVersion';
ALTER TABLE epm.operation_receipt ENABLE TRIGGER USER;

ALTER TABLE epm.cta_bridge ALTER COLUMN layout_state_token SET NOT NULL;
ALTER TABLE epm.cta_bridge ADD CHECK(layout_state_token~'^[0-9a-f]{64}$');
ALTER TABLE epm.cta_bridge DROP CONSTRAINT cta_bridge_workspace_id_application_id_layout_version_layo_fkey;
ALTER TABLE epm.cta_bridge DROP COLUMN layout_version;
ALTER TABLE epm.cta_bridge ADD FOREIGN KEY(
 workspace_id,application_id,layout_state_token,layout_digest) REFERENCES
 epm.consolidation_layout(workspace_id,application_id,state_token,layout_digest)
 ON DELETE RESTRICT;

DROP TABLE epm.consolidation_layout_state;
DROP TABLE epm.consolidation_layout_version;

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='a96699a564f2f62cf7fbd9a7e07cfe3fb9cce2e4df679ae3dcf73c0a8e0fbc64';
DECLARE current_graph constant text:='e11667d7ab45f381db9f94f37159b3a84f72d1ac83f24e56756d40d4f8779eb7';
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO definition;
 IF position(previous IN definition)=0 OR position(
  '''consolidation_layout_state'',''consolidation_layout_version''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0326_LAYOUT_PREDECESSOR_MISMATCH';END IF;
 definition:=replace(definition,
  '''consolidation_layout_state'',''consolidation_layout_version''',
  '''consolidation_layout''');
 EXECUTE replace(definition,previous,current_graph);

 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure)
 INTO definition;
 IF position('consolidation_layout_state,consolidation_layout_version' IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0326_LAYOUT_MISMATCH';END IF;
 EXECUTE replace(definition,
  'consolidation_layout_state,consolidation_layout_version',
  'consolidation_layout');

 SELECT pg_get_functiondef(
  'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
 INTO definition;
 IF position(previous IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0326_LAYOUT_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
