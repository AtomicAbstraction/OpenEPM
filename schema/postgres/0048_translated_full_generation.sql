-- Fixed Full-method parent sum over pinned translated child generations.
-- This is an Unreviewed pre-NCI stage, not a complete close output.
ALTER TABLE epm.calculation_generation
    DROP CONSTRAINT generation_function_parameters;
ALTER TABLE epm.calculation_generation
    ADD CONSTRAINT generation_function_parameters CHECK (
        (function_name='facts.numeric.scale' AND factor IS NOT NULL)
        OR (function_name IN ('facts.planning.spread.equal',
            'facts.planning.spread.calendar.equal',
            'facts.planning.allocate.weighted',
            'facts.planning.rollup.sum',
            'facts.expression.calculate',
            'consolidation.full.contribute',
            'consolidation.full.aggregate',
            'currency.translation.publish',
            'consolidation.full.translated.aggregate') AND factor IS NULL));
