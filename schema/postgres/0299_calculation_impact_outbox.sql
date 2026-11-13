BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=298) THEN
    RAISE EXCEPTION 'MIGRATION_0299_REQUIRES_0298';
  END IF;
END $migration$;

-- The business-impact clock is deliberately independent of metadata, data,
-- policy/security and commit revisions.  Only a contiguous applied prefix may
-- advance the processing watermark.
ALTER TABLE epm.application_state
  ADD COLUMN impact_epoch bigint NOT NULL DEFAULT 0 CHECK(impact_epoch>=0),
  ADD COLUMN processed_impact_epoch bigint NOT NULL DEFAULT 0
    CHECK(processed_impact_epoch>=0),
  ADD CONSTRAINT application_state_impact_watermark
    CHECK(processed_impact_epoch<=impact_epoch);
-- Existing W05 scope epochs become the already-processed baseline.  This
-- prevents the first W06 event from sorting behind a qualified publication.
WITH baseline AS (
  SELECT workspace_id,application_id,max(required_epoch) AS epoch
  FROM epm.calculation_scope_state GROUP BY workspace_id,application_id)
UPDATE epm.application_state AS state
SET impact_epoch=baseline.epoch,processed_impact_epoch=baseline.epoch
FROM baseline WHERE baseline.workspace_id=state.workspace_id
  AND baseline.application_id=state.application_id
  AND baseline.epoch>state.impact_epoch;

CREATE TABLE epm.calculation_impact_event(
  workspace_id text NOT NULL, application_id text NOT NULL,
  impact_epoch bigint NOT NULL CHECK(impact_epoch>0),
  operation_id text NOT NULL CHECK(length(operation_id) BETWEEN 1 AND 200),
  impact_digest text NOT NULL CHECK(impact_digest~'^[0-9a-f]{64}$'),
  source_kind text NOT NULL CHECK(source_kind IN(
    'numeric_fact','text_fact','line_detail','source_replace',
    'numeric_transform','calculation_publication','journal','metadata',
    'attribute','hierarchy','calendar','definition','layout','lifecycle',
    'elimination','ownership')),
  source_id text NOT NULL CHECK(length(source_id) BETWEEN 1 AND 200),
  causal_revision bigint NOT NULL CHECK(causal_revision>0),
  descriptor jsonb NOT NULL CHECK(jsonb_typeof(descriptor)='object'
    AND descriptor->>'format'='openepm-calculation-impact-v1'
    AND descriptor->>'sourceKind'=source_kind
    AND descriptor->>'sourceId'=source_id
    AND (descriptor->>'causalRevision')::bigint=causal_revision
    AND jsonb_typeof(descriptor->'effects')='array'
    AND jsonb_array_length(descriptor->'effects') BETWEEN 1 AND 500
    AND octet_length(descriptor::text)<=4194304),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,impact_epoch),
  UNIQUE(workspace_id,application_id,operation_id),
  UNIQUE(workspace_id,application_id,impact_digest),
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id)
    ON DELETE RESTRICT
);

CREATE TABLE epm.calculation_impact_progress(
  workspace_id text NOT NULL, application_id text NOT NULL,
  impact_epoch bigint NOT NULL,
  status text NOT NULL CHECK(status IN('pending','processing','applied','failed')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count>=0),
  claim_id text CHECK(claim_id IS NULL OR length(claim_id) BETWEEN 1 AND 200),
  claimed_at timestamptz, applied_at timestamptz,
  failure_code text CHECK(failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 200),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,impact_epoch),
  FOREIGN KEY(workspace_id,application_id,impact_epoch)
    REFERENCES epm.calculation_impact_event
      (workspace_id,application_id,impact_epoch) ON DELETE RESTRICT,
  CHECK((status='pending' AND claim_id IS NULL AND claimed_at IS NULL
          AND applied_at IS NULL AND failure_code IS NULL)
     OR (status='processing' AND claim_id IS NOT NULL AND claimed_at IS NOT NULL
          AND applied_at IS NULL AND failure_code IS NULL)
     OR (status='applied' AND claim_id IS NOT NULL AND claimed_at IS NOT NULL
          AND applied_at IS NOT NULL AND failure_code IS NULL)
     OR (status='failed' AND claim_id IS NOT NULL AND claimed_at IS NOT NULL
          AND applied_at IS NULL AND failure_code IS NOT NULL))
);
CREATE INDEX calculation_impact_pending
  ON epm.calculation_impact_progress(workspace_id,application_id,
    impact_epoch) WHERE status IN('pending','processing','failed');

CREATE TABLE epm.calculation_impact_fanout(
  workspace_id text NOT NULL, application_id text NOT NULL,
  impact_epoch bigint NOT NULL,
  binding_digest text NOT NULL, stage text NOT NULL,
  partition_key text NOT NULL,
  reason text NOT NULL CHECK(reason IN('data_changed','upstream_changed',
    'membership_changed','hierarchy_changed','definition_changed',
    'calendar_changed','unit_policy_changed','coverage_unknown')),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,impact_epoch,binding_digest,
              stage,partition_key,reason),
  FOREIGN KEY(workspace_id,application_id,impact_epoch)
    REFERENCES epm.calculation_impact_event
      (workspace_id,application_id,impact_epoch) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,binding_digest,stage,partition_key)
    REFERENCES epm.calculation_scope_state
      (workspace_id,application_id,binding_digest,stage,partition_key)
    ON DELETE RESTRICT
);

CREATE FUNCTION epm.calculation_impact_event_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
  IF TG_OP='DELETE' AND current_setting('epm.lifecycle_context',true)='workspace_reset'
     AND pg_has_role(session_user,'epm_lifecycle','member') THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'CALCULATION_IMPACT_EVENT_IMMUTABLE' USING ERRCODE='23514';
END $function$;
REVOKE ALL ON FUNCTION epm.calculation_impact_event_immutable() FROM PUBLIC;
CREATE TRIGGER calculation_impact_event_immutable
  BEFORE UPDATE OR DELETE ON epm.calculation_impact_event FOR EACH ROW
  EXECUTE FUNCTION epm.calculation_impact_event_immutable();

REVOKE ALL ON epm.calculation_impact_event,epm.calculation_impact_progress,
  epm.calculation_impact_fanout
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT UPDATE(impact_epoch) ON epm.application_state TO epm_runtime,epm_worker;
GRANT UPDATE(processed_impact_epoch) ON epm.application_state TO epm_worker;
CREATE POLICY application_state_worker_impact_update ON epm.application_state
  FOR UPDATE TO epm_worker
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
GRANT SELECT,INSERT ON epm.calculation_impact_event TO epm_runtime,epm_worker;
GRANT SELECT,INSERT,UPDATE ON epm.calculation_impact_progress TO epm_runtime,epm_worker;
GRANT SELECT,INSERT ON epm.calculation_impact_fanout TO epm_worker;
GRANT SELECT ON epm.calculation_impact_event,epm.calculation_impact_progress,
  epm.calculation_impact_fanout TO epm_analyst,epm_lifecycle;
GRANT DELETE ON epm.calculation_impact_event,epm.calculation_impact_progress,
  epm.calculation_impact_fanout TO epm_lifecycle;

DO $migration$ DECLARE relation text;
BEGIN
 FOREACH relation IN ARRAY ARRAY['calculation_impact_event',
   'calculation_impact_progress','calculation_impact_fanout'] LOOP
  EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',relation);
  EXECUTE format('CREATE POLICY %I_scope ON epm.%I TO epm_runtime,epm_worker,epm_analyst '
    'USING(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true)) '
    'WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true))',relation,relation);
  EXECUTE format('CREATE POLICY %I_lifecycle ON epm.%I TO epm_lifecycle '
    'USING(current_setting(''epm.lifecycle_context'',true)=''workspace_reset'')',relation,relation);
 END LOOP;
END $migration$;

-- Extend both qualified child-first lifecycle inventories.  Fanout must be
-- removed before its scope/event parents; progress before its event parent.
DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer; edge record;
DECLARE previous constant text := '3f298fc1e53a0ebdb1ae956053ead05d925ab9d763c48bd980b9920e924dd31e';
DECLARE current_graph constant text := '5e1a1826f3febb4b5a8e9e9893e3bc2e5040660589e12ec0bb0dbf650065092b';
DECLARE additions constant text := '''calculation_impact_fanout'',''calculation_impact_progress'',''calculation_impact_event'',';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 OR position('''calculation_generation_partition'',''calculation_generation_manifest''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0299_PREDECESSOR_MISMATCH'; END IF;
 revised:=replace(definition,
   '''calculation_generation_partition'',''calculation_generation_manifest''',
   additions||'''calculation_generation_partition'',''calculation_generation_manifest''');
 EXECUTE replace(revised,previous,current_graph);

 inventory:=epm.application_purge_relations();
 idx:=array_position(inventory,'calculation_generation_partition');
 IF idx IS NULL THEN RAISE EXCEPTION 'APPLICATION_PURGE_0299_INVENTORY_MISMATCH'; END IF;
 inventory:=inventory[1:idx-1]||ARRAY[
   'calculation_impact_fanout','calculation_impact_progress',
   'calculation_impact_event']||inventory[idx:];
 FOR edge IN SELECT child.relname child,parent.relname parent FROM pg_constraint c
   JOIN pg_class child ON child.oid=c.conrelid JOIN pg_namespace cn ON cn.oid=child.relnamespace
   JOIN pg_class parent ON parent.oid=c.confrelid JOIN pg_namespace pn ON pn.oid=parent.relnamespace
   WHERE c.contype='f' AND cn.nspname='epm' AND pn.nspname='epm' AND child.oid<>parent.oid
 LOOP
  IF edge.child=ANY(inventory) AND edge.parent=ANY(inventory)
     AND array_position(inventory,edge.child)>array_position(inventory,edge.parent) THEN
   RAISE EXCEPTION 'APPLICATION_PURGE_0299_FK_ORDER_INVALID'; END IF;
 END LOOP;
 EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
   'SELECT '||quote_literal(inventory::text)||'::text[]');
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0299_PREDECESSOR_MISMATCH'; END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
