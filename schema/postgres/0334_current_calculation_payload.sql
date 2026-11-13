BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=333) THEN
    RAISE EXCEPTION 'MIGRATION_0334_REQUIRES_0333';
  END IF;
END $migration$;

-- Authoritative current payloads are keyed by the stable result key.  The
-- generation-keyed relations remain only as bounded worker staging during the
-- writer conversion and are not a readable product history.
CREATE TABLE epm.calculation_result_current(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  result_key text NOT NULL CHECK(result_key~'^[A-Za-z0-9._-]{8,128}$'),
  coordinate_id bigint NOT NULL,
  source_amount numeric(28,8),
  source_change_id text,
  source_present boolean NOT NULL,
  amount numeric(28,8) NOT NULL,
  source_lookup_lineage jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(
    jsonb_typeof(source_lookup_lineage)='array'),
  PRIMARY KEY(workspace_id,application_id,result_key,coordinate_id),
  FOREIGN KEY(workspace_id,application_id,result_key)
    REFERENCES epm.calculation_result_state(
      workspace_id,application_id,result_key) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(workspace_id,application_id,coordinate_id)
    REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
    ON DELETE RESTRICT,
  CHECK((source_present AND source_amount IS NOT NULL
                        AND source_change_id IS NOT NULL)
     OR (NOT source_present AND source_amount IS NULL
                            AND source_change_id IS NULL))
);

CREATE TABLE epm.calculation_unit_result_current(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  result_key text NOT NULL CHECK(result_key~'^[A-Za-z0-9._-]{8,128}$'),
  coordinate_id bigint NOT NULL,
  output_unit_currency_dimension_id text NOT NULL,
  output_unit_currency_member_id text NOT NULL,
  source_amount numeric(28,8) NOT NULL,
  source_change_id text,
  source_evidence_digest text CHECK(
    source_evidence_digest IS NULL OR
    source_evidence_digest~'^[0-9a-f]{64}$'),
  amount numeric(28,8) NOT NULL,
  rate_strategy text NOT NULL CHECK(length(rate_strategy) BETWEEN 1 AND 100),
  rate_numerator numeric NOT NULL CHECK(rate_numerator>0 AND scale(rate_numerator)=0),
  rate_denominator numeric NOT NULL CHECK(rate_denominator>0 AND scale(rate_denominator)=0),
  rate_sources jsonb NOT NULL CHECK(jsonb_typeof(rate_sources)='array'
    AND jsonb_array_length(rate_sources) BETWEEN 1 AND 2),
  source_lookup_lineage jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(
    jsonb_typeof(source_lookup_lineage)='array'
    AND jsonb_array_length(source_lookup_lineage) BETWEEN 0 AND 64
    AND octet_length(source_lookup_lineage::text)<=65536),
  PRIMARY KEY(workspace_id,application_id,result_key,coordinate_id,
    output_unit_currency_dimension_id,output_unit_currency_member_id),
  FOREIGN KEY(workspace_id,application_id,result_key)
    REFERENCES epm.calculation_result_state(
      workspace_id,application_id,result_key) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(workspace_id,application_id,coordinate_id)
    REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,
      output_unit_currency_dimension_id,output_unit_currency_member_id)
    REFERENCES epm.member(workspace_id,application_id,dimension_id,member_id)
    ON DELETE RESTRICT,
  CHECK(source_change_id IS NOT NULL OR source_evidence_digest IS NOT NULL)
);

CREATE TABLE epm.calculation_ratio_result_current(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  result_key text NOT NULL CHECK(result_key~'^[A-Za-z0-9._-]{8,128}$'),
  coordinate_id bigint NOT NULL,
  source_amount numeric(28,8),
  source_change_id text,
  source_present boolean NOT NULL,
  ratio numeric(20,12) NOT NULL,
  source_lookup_lineage jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(
    jsonb_typeof(source_lookup_lineage)='array'),
  PRIMARY KEY(workspace_id,application_id,result_key,coordinate_id),
  FOREIGN KEY(workspace_id,application_id,result_key)
    REFERENCES epm.calculation_result_state(
      workspace_id,application_id,result_key) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(workspace_id,application_id,coordinate_id)
    REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
    ON DELETE RESTRICT,
  CHECK((source_present AND source_amount IS NOT NULL
                        AND source_change_id IS NOT NULL)
     OR (NOT source_present AND source_amount IS NULL
                            AND source_change_id IS NULL))
);

DO $migration$
DECLARE mixed bigint;
BEGIN
  SELECT count(*) INTO mixed FROM epm.calculation_result_state s
  WHERE ((SELECT count(*) FROM epm.calculation_result r
           WHERE r.workspace_id=s.workspace_id
             AND r.application_id=s.application_id
             AND r.generation_id=s.bridge_generation_id)>0)::int
      + ((SELECT count(*) FROM epm.calculation_unit_result r
           WHERE r.workspace_id=s.workspace_id
             AND r.application_id=s.application_id
             AND r.generation_id=s.bridge_generation_id)>0)::int
      + ((SELECT count(*) FROM epm.calculation_ratio_result r
           WHERE r.workspace_id=s.workspace_id
             AND r.application_id=s.application_id
             AND r.generation_id=s.bridge_generation_id)>0)::int > 1;
  IF mixed<>0 THEN
    RAISE EXCEPTION 'CURRENT_CALCULATION_PAYLOAD_MIXED_KIND';
  END IF;
END $migration$;

INSERT INTO epm.calculation_result_current(
  workspace_id,application_id,result_key,coordinate_id,source_amount,
  source_change_id,source_present,amount,source_lookup_lineage)
SELECT s.workspace_id,s.application_id,s.result_key,r.coordinate_id,
  r.source_amount,r.source_change_id,r.source_present,r.amount,
  r.source_lookup_lineage
FROM epm.calculation_result_state s JOIN epm.calculation_result r
  ON r.workspace_id=s.workspace_id AND r.application_id=s.application_id
 AND r.generation_id=s.bridge_generation_id;

INSERT INTO epm.calculation_unit_result_current(
  workspace_id,application_id,result_key,coordinate_id,
  output_unit_currency_dimension_id,output_unit_currency_member_id,
  source_amount,source_change_id,source_evidence_digest,amount,rate_strategy,
  rate_numerator,rate_denominator,rate_sources,source_lookup_lineage)
SELECT s.workspace_id,s.application_id,s.result_key,r.coordinate_id,
  r.output_unit_currency_dimension_id,r.output_unit_currency_member_id,
  r.source_amount,r.source_change_id,r.source_evidence_digest,r.amount,
  r.rate_strategy,r.rate_numerator,r.rate_denominator,r.rate_sources,
  r.source_lookup_lineage
FROM epm.calculation_result_state s JOIN epm.calculation_unit_result r
  ON r.workspace_id=s.workspace_id AND r.application_id=s.application_id
 AND r.generation_id=s.bridge_generation_id;

INSERT INTO epm.calculation_ratio_result_current(
  workspace_id,application_id,result_key,coordinate_id,source_amount,
  source_change_id,source_present,ratio,source_lookup_lineage)
SELECT s.workspace_id,s.application_id,s.result_key,r.coordinate_id,
  r.source_amount,r.source_change_id,r.source_present,r.ratio,
  r.source_lookup_lineage
FROM epm.calculation_result_state s JOIN epm.calculation_ratio_result r
  ON r.workspace_id=s.workspace_id AND r.application_id=s.application_id
 AND r.generation_id=s.bridge_generation_id;

-- Every backfilled child already has both parents.  Flush the initially
-- deferred foreign-key events before altering the populated relations below;
-- PostgreSQL otherwise rejects the ALTER with pending trigger events.
SET CONSTRAINTS ALL IMMEDIATE;

ALTER TABLE epm.calculation_result_state
  ADD COLUMN payload_kind text,
  ADD COLUMN row_count bigint,
  ADD COLUMN content_digest text;
ALTER TABLE epm.calculation_result_state DISABLE TRIGGER USER;
UPDATE epm.calculation_result_state s SET
  payload_kind=CASE
    WHEN EXISTS(SELECT 1 FROM epm.calculation_result_current r WHERE
      r.workspace_id=s.workspace_id AND r.application_id=s.application_id
      AND r.result_key=s.result_key) THEN 'numeric'
    WHEN EXISTS(SELECT 1 FROM epm.calculation_unit_result_current r WHERE
      r.workspace_id=s.workspace_id AND r.application_id=s.application_id
      AND r.result_key=s.result_key) THEN 'typed_currency'
    WHEN EXISTS(SELECT 1 FROM epm.calculation_ratio_result_current r WHERE
      r.workspace_id=s.workspace_id AND r.application_id=s.application_id
      AND r.result_key=s.result_key) THEN 'ratio'
    ELSE 'empty' END,
  row_count=(SELECT count(*) FROM (
    SELECT coordinate_id FROM epm.calculation_result_current r WHERE
      r.workspace_id=s.workspace_id AND r.application_id=s.application_id
      AND r.result_key=s.result_key
    UNION ALL SELECT coordinate_id FROM epm.calculation_unit_result_current r WHERE
      r.workspace_id=s.workspace_id AND r.application_id=s.application_id
      AND r.result_key=s.result_key
    UNION ALL SELECT coordinate_id FROM epm.calculation_ratio_result_current r WHERE
      r.workspace_id=s.workspace_id AND r.application_id=s.application_id
      AND r.result_key=s.result_key) payload),
  content_digest=encode(sha256(convert_to(coalesce((SELECT jsonb_agg(payload ORDER BY
      payload->>'kind',payload->>'coordinateId',payload->>'unitDimensionId',
      payload->>'unitMemberId')::text FROM (
    SELECT jsonb_build_object('kind','numeric','coordinateId',coordinate_id,
      'sourceAmount',source_amount,'sourceChangeId',source_change_id,
      'sourcePresent',source_present,'amount',amount,
      'sourceLookupLineage',source_lookup_lineage) payload
      FROM epm.calculation_result_current r WHERE r.workspace_id=s.workspace_id
       AND r.application_id=s.application_id AND r.result_key=s.result_key
    UNION ALL SELECT jsonb_build_object('kind','typed_currency',
      'coordinateId',coordinate_id,'unitDimensionId',output_unit_currency_dimension_id,
      'unitMemberId',output_unit_currency_member_id,'sourceAmount',source_amount,
      'sourceChangeId',source_change_id,'sourceEvidenceDigest',source_evidence_digest,
      'amount',amount,'rateStrategy',rate_strategy,'rateNumerator',rate_numerator,
      'rateDenominator',rate_denominator,'rateSources',rate_sources,
      'sourceLookupLineage',source_lookup_lineage)
      FROM epm.calculation_unit_result_current r WHERE r.workspace_id=s.workspace_id
       AND r.application_id=s.application_id AND r.result_key=s.result_key
    UNION ALL SELECT jsonb_build_object('kind','ratio','coordinateId',coordinate_id,
      'sourceAmount',source_amount,'sourceChangeId',source_change_id,
      'sourcePresent',source_present,'ratio',ratio,
      'sourceLookupLineage',source_lookup_lineage)
      FROM epm.calculation_ratio_result_current r WHERE r.workspace_id=s.workspace_id
       AND r.application_id=s.application_id AND r.result_key=s.result_key
  ) current_payload),'[]'),'UTF8')),'hex');
ALTER TABLE epm.calculation_result_state ENABLE TRIGGER USER;
ALTER TABLE epm.calculation_result_state
  ALTER COLUMN payload_kind SET NOT NULL,
  ALTER COLUMN row_count SET NOT NULL,
  ALTER COLUMN content_digest SET NOT NULL,
  ADD CONSTRAINT calculation_result_state_payload_kind CHECK(
    payload_kind IN('numeric','typed_currency','ratio','empty')),
  ADD CONSTRAINT calculation_result_state_row_count CHECK(row_count>=0),
  ADD CONSTRAINT calculation_result_state_content_digest CHECK(
    content_digest~'^[0-9a-f]{64}$'),
  ADD CONSTRAINT calculation_result_state_empty_exact CHECK(
    (payload_kind='empty')=(row_count=0));

ALTER TABLE epm.calculation_result_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.calculation_unit_result_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.calculation_ratio_result_current ENABLE ROW LEVEL SECURITY;
DO $migration$ DECLARE relation text; BEGIN
  FOREACH relation IN ARRAY ARRAY['calculation_result_current',
    'calculation_unit_result_current','calculation_ratio_result_current'] LOOP
    EXECUTE format('CREATE POLICY %I_scope ON epm.%I TO epm_runtime,epm_worker,epm_analyst '
      'USING(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true)) '
      'WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true))',relation,relation);
    EXECUTE format('CREATE POLICY %I_lifecycle ON epm.%I FOR SELECT TO epm_lifecycle '
      'USING(current_setting(''epm.lifecycle_context'',true)=''workspace_reset'')',relation,relation);
    EXECUTE format('REVOKE ALL ON epm.%I FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle',relation);
    EXECUTE format('GRANT SELECT,INSERT,DELETE ON epm.%I TO epm_runtime',relation);
    EXECUTE format('GRANT SELECT ON epm.%I TO epm_worker,epm_analyst,epm_lifecycle',relation);
  END LOOP;
END $migration$;

DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer;
DECLARE previous constant text:='da326bcb0c075788a3e4810931671e2ee6fc66b14b72a1fb9796336d5ec46e67';
DECLARE current_graph constant text:='79ba54ed9d83d76880f9b52462bf2e1ce68c745e47b87541bd476d55968a8cb1';
DECLARE old_ratio constant text:=$pattern$'calculation_ratio_result',$pattern$;
DECLARE new_ratio constant text:=$pattern$'calculation_ratio_result_current','calculation_ratio_result',$pattern$;
DECLARE old_amount constant text:=$pattern$'calculation_unit_result','calculation_result','calculation_result_state'$pattern$;
DECLARE new_amount constant text:=$pattern$'calculation_unit_result_current','calculation_result_current','calculation_unit_result','calculation_result','calculation_result_state'$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
  INTO definition;
  IF position(previous IN definition)=0 OR
     position(old_ratio IN definition)=0 OR
     position(old_amount IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0334_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,old_ratio,new_ratio);
  revised:=replace(revised,old_amount,new_amount);
  EXECUTE replace(revised,previous,current_graph);

  inventory:=epm.application_purge_relations();
  idx:=array_position(inventory,'calculation_ratio_result');
  IF idx IS NULL THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0334_ORDER_MISMATCH';
  END IF;
  inventory:=inventory[1:idx-1]||ARRAY['calculation_ratio_result_current']||
    inventory[idx:];
  idx:=array_position(inventory,'calculation_unit_result');
  IF idx IS NULL OR inventory[idx:idx+2]<>ARRAY['calculation_unit_result',
      'calculation_result','calculation_result_state'] THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0334_ORDER_MISMATCH';
  END IF;
  inventory:=inventory[1:idx-1]||ARRAY['calculation_unit_result_current',
    'calculation_result_current']||inventory[idx:];
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
    'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');
  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
  INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0334_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
