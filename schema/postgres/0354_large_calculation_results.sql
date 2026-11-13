BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=353) THEN
    RAISE EXCEPTION 'MIGRATION_0354_REQUIRES_0353';
  END IF;
  IF EXISTS(SELECT 1 FROM epm.calculation_generation
            WHERE row_count<0 OR row_count>100000) THEN
    RAISE EXCEPTION 'CALCULATION_RESULT_ROW_COUNT_OUT_OF_RANGE';
  END IF;
END $migration$;

-- A business rule is not split into authored batches at the old direct-path
-- boundary.  One current result can contain the same bounded 100,000 rows as
-- its server-resolved applicability relation; private execution windows are
-- an engine concern and do not create product objects.
ALTER TABLE epm.calculation_generation
  DROP CONSTRAINT calculation_generation_row_count_check;
ALTER TABLE epm.calculation_generation
  ADD CONSTRAINT calculation_generation_row_count_check
  CHECK(row_count BETWEEN 0 AND 100000);

COMMIT;
