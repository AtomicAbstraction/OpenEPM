-- Persist each expression row's alternate raw inputs in the same generation.
-- Existing generations have no alternate raw lookup and keep an empty array.
ALTER TABLE epm.calculation_result
    ADD COLUMN source_lookup_lineage jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE epm.calculation_result
    ADD CONSTRAINT calculation_source_lookup_lineage_array
    CHECK (jsonb_typeof(source_lookup_lineage) = 'array') NOT VALID;
