-- Admit the bounded Unreviewed calculated mixed-method parent total.
DO $$BEGIN
 IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=152) THEN
  RAISE EXCEPTION 'MIGRATION_0153_PREDECESSOR_0152_REQUIRED';
 END IF;
END$$;
ALTER TABLE epm.calculation_generation DROP CONSTRAINT generation_function_parameters;
ALTER TABLE epm.calculation_generation ADD CONSTRAINT generation_function_parameters CHECK (
 (function_name='facts.numeric.scale' AND factor IS NOT NULL)
 OR (function_name IN ('facts.planning.spread.equal','facts.planning.spread.calendar.equal',
  'facts.planning.allocate.weighted','facts.planning.rollup.sum','facts.planning.group.sum',
  'facts.planning.group.sum.bulk','facts.expression.calculate','consolidation.full.contribute',
  'consolidation.full.aggregate','currency.amount.translate.publish','currency.translation.publish',
  'currency.calculation.translation.publish','consolidation.full.translated.aggregate',
  'consolidation.equity.contribution.publish','consolidation.proportional.contribution.publish',
  'consolidation.method.total.publish') AND factor IS NULL)
 OR (function_name='consolidation.nci.period.publish' AND factor IS NULL AND row_count=2)
 OR (function_name='consolidation.nci.period.withdraw' AND factor IS NULL AND row_count=0)
) NOT VALID;

-- Existing single-source producers retain their exact source_change_id.  A
-- bounded multi-source result instead carries a canonical evidence digest and
-- must never manufacture a raw fact change identity.
ALTER TABLE epm.calculation_unit_result
    ALTER COLUMN source_change_id DROP NOT NULL,
    ADD COLUMN source_evidence_digest text,
    ADD CONSTRAINT calculation_unit_source_evidence CHECK (
      (source_change_id IS NOT NULL OR source_evidence_digest IS NOT NULL)
      AND (source_evidence_digest IS NULL OR
           source_evidence_digest ~ '^[0-9a-f]{64}$')) NOT VALID;

-- Mixed-method totals have at most 64 explicitly sealed contributions.  Keep
-- the complete stored JSON evidence bounded independently of row count.
ALTER TABLE epm.calculation_unit_result
    DROP CONSTRAINT calculation_unit_source_lookup_lineage_array,
    ADD CONSTRAINT calculation_unit_source_lookup_lineage_array CHECK
      (jsonb_typeof(source_lookup_lineage)='array'
       AND jsonb_array_length(source_lookup_lineage) BETWEEN 0 AND 64
       AND octet_length(source_lookup_lineage::text)<=65536) NOT VALID;
