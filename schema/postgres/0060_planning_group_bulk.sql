-- Several explicit planning groups publish one immutable multi-row result.
-- Only the calculation function CHECK changes; the workspace FK/reset graph
-- remains the reviewed 0057 graph. Existing rows satisfied the prior CHECK.
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
            'currency.translation.publish',
            'currency.calculation.translation.publish',
            'consolidation.full.translated.aggregate') AND factor IS NULL)
    ) NOT VALID;
