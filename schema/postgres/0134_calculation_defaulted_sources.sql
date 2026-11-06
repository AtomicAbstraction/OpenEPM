-- Preserve actual-source compatibility while permitting an explicit absent
-- source in a bounded calculation domain.  Absence never receives a synthetic
-- business change identity.
ALTER TABLE epm.calculation_result
    ADD COLUMN source_present boolean NOT NULL DEFAULT true;

ALTER TABLE epm.calculation_result
    ALTER COLUMN source_amount DROP NOT NULL,
    ALTER COLUMN source_change_id DROP NOT NULL;

ALTER TABLE epm.calculation_result
    ADD CONSTRAINT calculation_result_source_presence_exact
    CHECK ((source_present AND source_amount IS NOT NULL
                         AND source_change_id IS NOT NULL)
        OR (NOT source_present AND source_amount IS NULL
                               AND source_change_id IS NULL));

COMMENT ON COLUMN epm.calculation_result.source_present IS
    'True for an actual present numeric source; false only for an explicitly defaulted absent source.';
