-- Admit the bounded calculated-only inventory unrealized-profit generation.
DO $$BEGIN
 IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=161) THEN
  RAISE EXCEPTION 'MIGRATION_0162_PREDECESSOR_0161_REQUIRED';
 END IF;
END$$;

CREATE TABLE epm.inventory_unrealized_schedule_version(
 workspace_id text NOT NULL,application_id text NOT NULL,schedule_id text NOT NULL,
 version bigint NOT NULL CHECK(version>0),effective_on date NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'),
 definition_digest text NOT NULL CHECK(definition_digest~'^[0-9a-f]{64}$'),
 created_revision bigint NOT NULL CHECK(created_revision>=0),
 operation_id text NOT NULL,
 PRIMARY KEY(workspace_id,application_id,schedule_id,version),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application
  (workspace_id,application_id) ON DELETE RESTRICT);
CREATE TABLE epm.inventory_unrealized_schedule_state(
 workspace_id text NOT NULL,application_id text NOT NULL,schedule_id text NOT NULL,
 latest_version bigint NOT NULL CHECK(latest_version>0),active_version bigint,
 state_revision bigint NOT NULL CHECK(state_revision>0),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 CHECK(active_version IS NULL OR active_version<=latest_version),
 PRIMARY KEY(workspace_id,application_id,schedule_id),
 FOREIGN KEY(workspace_id,application_id,schedule_id,latest_version) REFERENCES
  epm.inventory_unrealized_schedule_version(workspace_id,application_id,schedule_id,version) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,schedule_id,active_version) REFERENCES
  epm.inventory_unrealized_schedule_version(workspace_id,application_id,schedule_id,version) ON DELETE RESTRICT);
REVOKE ALL ON epm.inventory_unrealized_schedule_version,
 epm.inventory_unrealized_schedule_state FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT ON epm.inventory_unrealized_schedule_version TO epm_runtime;
GRANT SELECT,INSERT,UPDATE ON epm.inventory_unrealized_schedule_state TO epm_runtime;
GRANT DELETE ON epm.inventory_unrealized_schedule_state,
 epm.inventory_unrealized_schedule_version TO epm_lifecycle;
ALTER TABLE epm.inventory_unrealized_schedule_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.inventory_unrealized_schedule_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY inventory_unrealized_schedule_version_scope ON epm.inventory_unrealized_schedule_version
 TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY inventory_unrealized_schedule_state_scope ON epm.inventory_unrealized_schedule_state
 TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY inventory_unrealized_schedule_version_lifecycle ON epm.inventory_unrealized_schedule_version
 TO epm_lifecycle USING(current_setting('epm.lifecycle_context',true)='workspace_reset');
CREATE POLICY inventory_unrealized_schedule_state_lifecycle ON epm.inventory_unrealized_schedule_state
 TO epm_lifecycle USING(current_setting('epm.lifecycle_context',true)='workspace_reset');

ALTER TABLE epm.calculation_generation DROP CONSTRAINT generation_function_parameters;
ALTER TABLE epm.calculation_generation ADD CONSTRAINT generation_function_parameters CHECK (
 (function_name='facts.numeric.scale' AND factor IS NOT NULL)
 OR (function_name IN ('facts.planning.spread.equal','facts.planning.spread.calendar.equal',
  'facts.planning.allocate.weighted','facts.planning.rollup.sum','facts.planning.group.sum',
  'facts.planning.group.sum.bulk','facts.expression.calculate','consolidation.full.contribute',
  'consolidation.full.typed.contribute','consolidation.full.aggregate',
  'currency.amount.translate.publish','currency.translation.publish',
  'currency.calculation.translation.publish','consolidation.full.translated.aggregate',
  'consolidation.equity.contribution.publish','consolidation.proportional.contribution.publish',
  'consolidation.method.total.publish') AND factor IS NULL)
 OR (function_name='consolidation.inventory.unrealized_profit.request'
     AND factor IS NULL AND row_count=4)
 OR (function_name='consolidation.nci.period.publish' AND factor IS NULL AND row_count=2)
 OR (function_name='consolidation.nci.period.withdraw' AND factor IS NULL AND row_count=0)
) NOT VALID;

-- Inventory unrealized-profit results are typed-only and writable only while
-- the exact fixed compiler still owns a running job.  The pointer constraint
-- below proves completeness at commit; these statement triggers prevent a
-- terminal generation from being appended to after publication.
CREATE OR REPLACE FUNCTION epm.inventory_unrealized_unit_line_open()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM inventory_unrealized_unit_inserted i
  JOIN epm.calculation_generation g USING(workspace_id,application_id,generation_id)
  JOIN epm.job j ON (j.workspace_id,j.application_id,j.job_id)=
   (g.workspace_id,g.application_id,g.job_id)
  WHERE g.function_name='consolidation.inventory.unrealized_profit.request'
   AND (j.compiler_version<>'inventory-unrealized-profit-v2-typed-unit'
        OR j.status<>'running')) THEN
  RAISE EXCEPTION 'INVENTORY_UNREALIZED_GENERATION_SEALED' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END$$;
REVOKE ALL ON FUNCTION epm.inventory_unrealized_unit_line_open() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.inventory_unrealized_unit_line_open() TO epm_runtime;
DROP TRIGGER IF EXISTS inventory_unrealized_unit_line_open ON epm.calculation_unit_result;
CREATE TRIGGER inventory_unrealized_unit_line_open
AFTER INSERT ON epm.calculation_unit_result
REFERENCING NEW TABLE AS inventory_unrealized_unit_inserted
FOR EACH STATEMENT EXECUTE FUNCTION epm.inventory_unrealized_unit_line_open();

CREATE OR REPLACE FUNCTION epm.inventory_unrealized_legacy_line_forbidden()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM inventory_unrealized_legacy_inserted i
  JOIN epm.calculation_generation g USING(workspace_id,application_id,generation_id)
  WHERE g.function_name='consolidation.inventory.unrealized_profit.request') THEN
  RAISE EXCEPTION 'INVENTORY_UNREALIZED_TYPED_STORAGE_REQUIRED' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END$$;
REVOKE ALL ON FUNCTION epm.inventory_unrealized_legacy_line_forbidden() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.inventory_unrealized_legacy_line_forbidden() TO epm_runtime;
DROP TRIGGER IF EXISTS inventory_unrealized_legacy_line_forbidden ON epm.calculation_result;
CREATE TRIGGER inventory_unrealized_legacy_line_forbidden
AFTER INSERT ON epm.calculation_result
REFERENCING NEW TABLE AS inventory_unrealized_legacy_inserted
FOR EACH STATEMENT EXECUTE FUNCTION epm.inventory_unrealized_legacy_line_forbidden();

CREATE OR REPLACE FUNCTION epm.inventory_unrealized_pointer_complete()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE actual bigint; units bigint; evidence bigint; receipt jsonb;
 evidence_min text; evidence_max text; lineage_count bigint;
 legacy_count bigint; generation_row record; invalid_rows bigint;
 opening numeric; creation numeric; release numeric; closing numeric;
 source_min numeric;source_max numeric;revenue numeric;cost numeric;prior numeric;
 source_count bigint;source_mapping_invalid bigint;
 schedule_matches bigint;invalid_storage bigint;
 entity_dimension text;expected_entity text;
BEGIN
 IF EXISTS(SELECT 1 FROM epm.calculation_generation g WHERE
  g.workspace_id=NEW.workspace_id AND g.application_id=NEW.application_id
  AND g.generation_id=NEW.generation_id
  AND g.function_name='consolidation.inventory.unrealized_profit.request') THEN
  SELECT g.row_count,g.result_key,g.published_revision,j.compiler_version,
    j.normalized_program,j.expected_metadata_revision,
    j.expected_data_revision,j.expected_policy_revision
   INTO generation_row FROM epm.calculation_generation g JOIN epm.job j
    ON (j.workspace_id,j.application_id,j.job_id)=(g.workspace_id,g.application_id,g.job_id)
   WHERE g.workspace_id=NEW.workspace_id AND g.application_id=NEW.application_id
    AND g.generation_id=NEW.generation_id;
  SELECT count(*),count(DISTINCT (output_unit_currency_dimension_id,
    output_unit_currency_member_id)),count(DISTINCT source_evidence_digest),
    min(source_evidence_digest),max(source_evidence_digest),
    count(DISTINCT source_lookup_lineage),min(source_amount),max(source_amount),
    count(*) FILTER(WHERE rate_strategy<>'identity-same-currency'
      OR rate_numerator<>1 OR rate_denominator<>1
      OR rate_sources IS DISTINCT FROM jsonb_build_array(jsonb_build_object(
       'kind','Identity','currency',jsonb_build_object(
        'dimensionId',output_unit_currency_dimension_id,
        'memberId',output_unit_currency_member_id))))
   INTO actual,units,evidence,evidence_min,evidence_max,lineage_count,
    source_min,source_max,invalid_storage
   FROM epm.calculation_unit_result WHERE
    workspace_id=NEW.workspace_id AND application_id=NEW.application_id
    AND generation_id=NEW.generation_id;
  SELECT result INTO receipt FROM epm.operation_receipt WHERE
    workspace_id=NEW.workspace_id AND application_id=NEW.application_id
    AND operation_id=NEW.generation_id;
  SELECT count(*) INTO legacy_count FROM epm.calculation_result WHERE
   workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND generation_id=NEW.generation_id;
  IF receipt IS NOT NULL AND jsonb_typeof(receipt->'rows')='array' THEN
   SELECT count(*) FILTER(WHERE r.coordinate_id IS NULL OR
      c.members IS DISTINCT FROM generation_row.normalized_program->
       'targetMembers'->(x->>'role')),
    max(CASE WHEN x->>'role'='Opening' AND x->>'amount'~'^-?[0-9]+(\.[0-9]+)?$'
      THEN (x->>'amount')::numeric END),
    max(CASE WHEN x->>'role'='Creation' AND x->>'amount'~'^-?[0-9]+(\.[0-9]+)?$'
      THEN (x->>'amount')::numeric END),
    max(CASE WHEN x->>'role'='Release' AND x->>'amount'~'^-?[0-9]+(\.[0-9]+)?$'
      THEN (x->>'amount')::numeric END),
    max(CASE WHEN x->>'role'='Closing' AND x->>'amount'~'^-?[0-9]+(\.[0-9]+)?$'
      THEN (x->>'amount')::numeric END)
   INTO invalid_rows,opening,creation,release,closing
   FROM jsonb_array_elements(receipt->'rows') x
   LEFT JOIN epm.coordinate c ON c.workspace_id=NEW.workspace_id
    AND c.application_id=NEW.application_id AND c.members=x->'members'
   LEFT JOIN epm.calculation_unit_result r ON r.workspace_id=c.workspace_id
    AND r.application_id=c.application_id AND r.coordinate_id=c.coordinate_id
    AND r.generation_id=NEW.generation_id AND r.amount=CASE
     WHEN x->>'amount'~'^-?[0-9]+(\.[0-9]+)?$' THEN (x->>'amount')::numeric END;
  ELSE invalid_rows:=1; END IF;
  IF receipt IS NOT NULL AND CASE
   WHEN jsonb_typeof(receipt->'sourceLookupLineage')='array'
    THEN jsonb_array_length(receipt->'sourceLookupLineage')=1
   ELSE false END THEN
   IF jsonb_typeof(receipt->'sourceLookupLineage'->0->'sources')='array' THEN
    SELECT count(*),
     count(*) FILTER(WHERE NOT (
      (s->'members'=generation_row.normalized_program->'definition'->
        'transferRevenue'->'members' AND s->>'changeId'=
        generation_row.normalized_program->'definition'->'transferRevenue'->>'changeId')
      OR (s->'members'=generation_row.normalized_program->'definition'->
        'transferCost'->'members' AND s->>'changeId'=
        generation_row.normalized_program->'definition'->'transferCost'->>'changeId')
      OR (s->'members'=generation_row.normalized_program->'definition'->
        'priorUnrealizedProfit'->'members' AND s->>'changeId'=
        generation_row.normalized_program->'definition'->'priorUnrealizedProfit'->>'changeId'))),
     max(CASE WHEN s->>'changeId'=generation_row.normalized_program->'definition'->
       'transferRevenue'->>'changeId' AND s->'members'=
       generation_row.normalized_program->'definition'->'transferRevenue'->'members'
       AND s->>'amount'~'^[0-9]+(\.[0-9]+)?$'
       THEN (s->>'amount')::numeric END),
     max(CASE WHEN s->>'changeId'=generation_row.normalized_program->'definition'->
       'transferCost'->>'changeId' AND s->'members'=
       generation_row.normalized_program->'definition'->'transferCost'->'members'
       AND s->>'amount'~'^[0-9]+(\.[0-9]+)?$'
       THEN (s->>'amount')::numeric END),
     max(CASE WHEN s->>'changeId'=generation_row.normalized_program->'definition'->
       'priorUnrealizedProfit'->>'changeId' AND s->'members'=
       generation_row.normalized_program->'definition'->'priorUnrealizedProfit'->'members'
       AND s->>'amount'~'^[0-9]+(\.[0-9]+)?$'
       THEN (s->>'amount')::numeric END)
    INTO source_count,source_mapping_invalid,revenue,cost,prior
    FROM jsonb_array_elements(receipt->'sourceLookupLineage'->0->'sources') s;
   ELSE source_count:=-1;source_mapping_invalid:=-1; END IF;
  ELSE source_count:=-1;source_mapping_invalid:=-1; END IF;
  SELECT count(*) INTO schedule_matches
   FROM epm.inventory_unrealized_schedule_state s
   JOIN epm.inventory_unrealized_schedule_version v ON
    (v.workspace_id,v.application_id,v.schedule_id,v.version)=
    (s.workspace_id,s.application_id,s.schedule_id,s.active_version)
   WHERE s.workspace_id=NEW.workspace_id AND s.application_id=NEW.application_id
    AND s.schedule_id=generation_row.normalized_program->'definition'->>'scheduleId'
    AND to_jsonb(s.active_version)=generation_row.normalized_program->'definition'->'scheduleVersion'
    AND v.definition=generation_row.normalized_program->'definition'
    AND v.definition_digest=receipt->>'scheduleDigest';
  SELECT dimension_id INTO entity_dimension FROM epm.dimension
   WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
    AND model_role='Entity' AND status='Active';
  expected_entity:=generation_row.normalized_program->'targetMembers'->'Opening'->>entity_dimension;
  IF actual<>4 OR generation_row.row_count<>4 OR legacy_count<>0
   OR generation_row.result_key IS DISTINCT FROM NEW.result_key
   OR generation_row.published_revision IS DISTINCT FROM NEW.published_revision
   OR generation_row.compiler_version IS DISTINCT FROM 'inventory-unrealized-profit-v2-typed-unit'
   OR units<>1 OR evidence<>1 OR evidence_min IS NULL
   OR evidence_min<>evidence_max OR lineage_count<>1 OR receipt IS NULL
   OR invalid_storage<>0 OR source_min IS NULL OR source_min<>source_max
   OR source_count<>3 OR source_mapping_invalid<>0
   OR revenue IS NULL OR cost IS NULL OR prior IS NULL
   OR source_min IS DISTINCT FROM revenue-cost OR opening IS DISTINCT FROM prior
   OR schedule_matches<>1
   OR CASE WHEN jsonb_typeof(receipt->'rows')='array'
      THEN jsonb_array_length(receipt->'rows') IS DISTINCT FROM 4 ELSE true END
   OR CASE WHEN jsonb_typeof(receipt->'rows')='array' THEN
      (SELECT count(DISTINCT x->>'role') FROM jsonb_array_elements(receipt->'rows') x
       WHERE x->>'role' IN ('Opening','Creation','Release','Closing'))<>4
      ELSE true END
   OR invalid_rows<>0 OR opening IS NULL OR creation IS NULL OR release IS NULL
   OR closing IS NULL OR opening+creation+release IS DISTINCT FROM closing
   OR receipt->>'generationId' IS DISTINCT FROM NEW.generation_id
   OR receipt->>'resultKey' IS DISTINCT FROM NEW.result_key
   OR receipt->'publishedRevision' IS DISTINCT FROM to_jsonb(NEW.published_revision)
   OR receipt->>'sourceEvidenceDigest' IS DISTINCT FROM evidence_min
   OR receipt->'sourceLookupLineage' IS DISTINCT FROM
      (SELECT source_lookup_lineage FROM epm.calculation_unit_result WHERE
       workspace_id=NEW.workspace_id AND application_id=NEW.application_id
       AND generation_id=NEW.generation_id LIMIT 1)
   OR receipt->>'compilerVersion' IS DISTINCT FROM generation_row.compiler_version
   OR receipt->>'scheduleId' IS DISTINCT FROM
      generation_row.normalized_program->'definition'->>'scheduleId'
   OR receipt->'scheduleVersion' IS DISTINCT FROM
      generation_row.normalized_program->'definition'->'scheduleVersion'
   OR receipt->>'scheduleDigest' IS DISTINCT FROM
      receipt->'sourceLookupLineage'->0->>'scheduleDigest'
   OR receipt->'revisionPins' IS DISTINCT FROM jsonb_build_object(
      'metadata',generation_row.expected_metadata_revision,
      'data',generation_row.expected_data_revision,
      'policy',generation_row.expected_policy_revision)
   OR entity_dimension IS NULL OR expected_entity IS NULL
   OR receipt->'functionalCurrencyContext' IS DISTINCT FROM jsonb_build_object(
      'entity',jsonb_build_object('dimensionId',entity_dimension,
       'memberId',expected_entity))
   OR receipt->'outputUnit' IS DISTINCT FROM jsonb_build_object(
      'dimensionId',generation_row.normalized_program->'definition'->>'currencyDimensionId',
      'memberId',generation_row.normalized_program->'definition'->>'currencyMemberId')
   OR NOT EXISTS(SELECT 1 FROM epm.member m WHERE
      m.workspace_id=NEW.workspace_id AND m.application_id=NEW.application_id
      AND m.dimension_id=entity_dimension AND m.member_id=expected_entity
      AND m.status='Active' AND m.entity_default_currency_member_id=
       generation_row.normalized_program->'definition'->>'currencyMemberId')
   OR receipt->'outputUnit' IS DISTINCT FROM
      (SELECT jsonb_build_object('dimensionId',output_unit_currency_dimension_id,
       'memberId',output_unit_currency_member_id) FROM epm.calculation_unit_result WHERE
       workspace_id=NEW.workspace_id AND application_id=NEW.application_id
       AND generation_id=NEW.generation_id LIMIT 1) THEN
   RAISE EXCEPTION 'INVENTORY_UNREALIZED_PUBLICATION_INCOMPLETE' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END$$;
REVOKE ALL ON FUNCTION epm.inventory_unrealized_pointer_complete() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.inventory_unrealized_pointer_complete() TO epm_runtime;
DROP TRIGGER IF EXISTS inventory_unrealized_pointer_complete ON epm.calculation_publication;
CREATE CONSTRAINT TRIGGER inventory_unrealized_pointer_complete
AFTER INSERT OR UPDATE ON epm.calculation_publication DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION epm.inventory_unrealized_pointer_complete();

DO $$DECLARE d text;r text;old text:=$p$'calculation_ratio_result','calculation_unit_result',$p$;
 new text:=$p$'inventory_unrealized_schedule_state','inventory_unrealized_schedule_version','calculation_ratio_result','calculation_unit_result',$p$;
BEGIN SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO d;
 IF position(old IN d)=0 OR position(new IN d)>0 THEN RAISE EXCEPTION 'RESET_0162_DEFINITION_MISMATCH';END IF;
 r:=replace(d,old,new);IF r=d THEN RAISE EXCEPTION 'RESET_0162_DEFINITION_MISMATCH';END IF;EXECUTE r;END$$;
