-- Admit the separately versioned, Unreviewed Equity carrying-value publisher.
-- It publishes a typed Currency Amount and leaves legacy method-preview and
-- calculation-result semantics unchanged.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=147) THEN
    RAISE EXCEPTION 'MIGRATION_0148_PREDECESSOR_0147_REQUIRED';
  END IF;
END $$;

ALTER TABLE epm.calculation_generation
    DROP CONSTRAINT generation_function_parameters;
ALTER TABLE epm.calculation_generation
    ADD CONSTRAINT generation_function_parameters CHECK (
        (function_name='facts.numeric.scale' AND factor IS NOT NULL)
        OR (function_name IN ('facts.planning.spread.equal',
            'facts.planning.spread.calendar.equal',
            'facts.planning.allocate.weighted',
            'facts.planning.rollup.sum',
            'facts.planning.group.sum',
            'facts.planning.group.sum.bulk',
            'facts.expression.calculate',
            'consolidation.full.contribute',
            'consolidation.full.aggregate',
            'currency.amount.translate.publish',
            'currency.translation.publish',
            'currency.calculation.translation.publish',
            'consolidation.full.translated.aggregate',
            'consolidation.equity.contribution.publish') AND factor IS NULL)
        OR (function_name='consolidation.nci.period.publish'
            AND factor IS NULL AND row_count=2)
        OR (function_name='consolidation.nci.period.withdraw'
            AND factor IS NULL AND row_count=0)
    ) NOT VALID;

ALTER TABLE epm.calculation_unit_result
    ADD COLUMN source_lookup_lineage jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD CONSTRAINT calculation_unit_source_lookup_lineage_array CHECK
      (jsonb_typeof(source_lookup_lineage)='array'
       AND jsonb_array_length(source_lookup_lineage) BETWEEN 0 AND 16) NOT VALID;
