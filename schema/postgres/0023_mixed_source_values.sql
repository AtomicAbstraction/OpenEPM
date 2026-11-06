-- Preserve existing numeric rows and allow a staged batch to carry both
-- exact numeric and present text values at distinct full coordinates.
ALTER TABLE epm.source_batch_row
    ALTER COLUMN amount DROP NOT NULL,
    ADD COLUMN value_kind text NOT NULL DEFAULT 'numeric',
    ADD COLUMN text_value text,
    ADD CONSTRAINT source_batch_row_typed_value CHECK (
        (value_kind='numeric' AND amount IS NOT NULL AND text_value IS NULL)
        OR (value_kind='text' AND amount IS NULL AND text_value IS NOT NULL
            AND length(text_value)<=32768)
    );
