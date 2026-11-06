-- Permit the fixed pre-NCI Full contribution publisher to use the existing
-- immutable calculation generation/result/publication protocol. No general
-- consolidation policy or arbitrary function is admitted by this constraint.
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
            'consolidation.full.contribute') AND factor IS NULL));
