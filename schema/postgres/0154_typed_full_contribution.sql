-- Admit a Currency-typed Full contribution without putting Currency into the
-- cube coordinate.  No table, privilege, RLS or reset inventory changes are
-- required because calculation_unit_result already owns the typed result.
DO $$BEGIN
 IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=153) THEN
  RAISE EXCEPTION 'MIGRATION_0154_PREDECESSOR_0153_REQUIRED';
 END IF;
END$$;

ALTER TABLE epm.calculation_generation
 DROP CONSTRAINT generation_function_parameters;
ALTER TABLE epm.calculation_generation
 ADD CONSTRAINT generation_function_parameters CHECK (
 (function_name='facts.numeric.scale' AND factor IS NOT NULL)
 OR (function_name IN ('facts.planning.spread.equal',
  'facts.planning.spread.calendar.equal','facts.planning.allocate.weighted',
  'facts.planning.rollup.sum','facts.planning.group.sum',
  'facts.planning.group.sum.bulk','facts.expression.calculate',
  'consolidation.full.contribute','consolidation.full.typed.contribute',
  'consolidation.full.aggregate','currency.amount.translate.publish',
  'currency.translation.publish','currency.calculation.translation.publish',
  'consolidation.full.translated.aggregate',
  'consolidation.equity.contribution.publish',
  'consolidation.proportional.contribution.publish',
  'consolidation.method.total.publish') AND factor IS NULL)
 OR (function_name='consolidation.nci.period.publish'
     AND factor IS NULL AND row_count=2)
 OR (function_name='consolidation.nci.period.withdraw'
     AND factor IS NULL AND row_count=0)
) NOT VALID;
