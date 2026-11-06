-- Explicit many-to-one planning sum. Preserve the existing hierarchy rollup
-- rows while allowing the same immutable per-source lineage table to record
-- a declared member set that does not depend on a hierarchy version.
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
            'facts.expression.calculate',
            'consolidation.full.contribute',
            'consolidation.full.aggregate',
            'currency.translation.publish',
            'currency.calculation.translation.publish',
            'consolidation.full.translated.aggregate') AND factor IS NULL));

ALTER TABLE epm.rollup_source_lineage
    ALTER COLUMN hierarchy_dimension_id DROP NOT NULL,
    ALTER COLUMN hierarchy_version DROP NOT NULL;
ALTER TABLE epm.rollup_source_lineage
    ADD COLUMN source_selection text NOT NULL DEFAULT 'hierarchy'
        CHECK (source_selection IN ('hierarchy','explicit'));
ALTER TABLE epm.rollup_source_lineage
    ADD CONSTRAINT rollup_source_selection_shape CHECK (
        (source_selection='hierarchy' AND hierarchy_dimension_id IS NOT NULL
            AND hierarchy_version IS NOT NULL)
        OR (source_selection='explicit' AND hierarchy_dimension_id IS NULL
            AND hierarchy_version IS NULL));
