-- Versioned exact non-additive cube reductions. Existing Sum/Count rows and
-- accepted v1 plan digests remain unchanged; nullable extrema also represent
-- an explicit missing scalar result when no present numeric source exists.
ALTER TABLE epm.cube_aggregate_result
    ADD COLUMN min_amount numeric(38,8),
    ADD COLUMN max_amount numeric(38,8),
    ADD COLUMN empty_scalar boolean NOT NULL DEFAULT false;

-- The original table-level constraint required Sum or Count to be non-null.
-- A requested Min/Max over an empty scalar domain is a real result row whose
-- exact value is missing, so all measure columns may legitimately be NULL.
ALTER TABLE epm.cube_aggregate_result
    DROP CONSTRAINT cube_aggregate_result_check;

ALTER TABLE epm.cube_aggregate_result
    ADD CONSTRAINT cube_aggregate_result_measure_shape_check CHECK (
        sum_amount IS NOT NULL OR count_present IS NOT NULL
        OR min_amount IS NOT NULL OR max_amount IS NOT NULL
        OR (empty_scalar AND members='{}'::jsonb));

-- Every new writer must state the exceptional empty-scalar case explicitly.
ALTER TABLE epm.cube_aggregate_result
    ALTER COLUMN empty_scalar DROP DEFAULT;

COMMENT ON COLUMN epm.cube_aggregate_result.min_amount IS
    'Exact MinAmount over present numeric sources; NULL is explicit missing for an empty scalar group';
COMMENT ON COLUMN epm.cube_aggregate_result.max_amount IS
    'Exact MaxAmount over present numeric sources; NULL is explicit missing for an empty scalar group';
COMMENT ON COLUMN epm.cube_aggregate_result.empty_scalar IS
    'True only for the single scalar row produced by an empty present-numeric source domain';
