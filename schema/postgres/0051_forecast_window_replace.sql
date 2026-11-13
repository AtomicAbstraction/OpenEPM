-- A fixed rolling-forecast program may replace only explicitly selected
-- fiscal Year/Period pairs inside its target scenario/member slice.
-- Ordinary source batches retain their existing full-scope behavior.
ALTER TABLE epm.source_batch
    ADD COLUMN period_selection jsonb,
    ADD CONSTRAINT source_batch_period_selection_shape CHECK (
        period_selection IS NULL OR (
            mode='replace'
            AND jsonb_typeof(period_selection)='object'
            AND period_selection ? 'yearDimension'
            AND period_selection ? 'periodDimension'
            AND period_selection ? 'periods'
            AND jsonb_typeof(period_selection->'yearDimension')='string'
            AND jsonb_typeof(period_selection->'periodDimension')='string'
            AND jsonb_typeof(period_selection->'periods')='array'
            AND jsonb_array_length(period_selection->'periods') BETWEEN 1 AND 36
        ));
