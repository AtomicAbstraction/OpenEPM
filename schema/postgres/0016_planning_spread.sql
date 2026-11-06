-- Permit immutable calculation generations for deterministic planning spreads.
-- Existing scale generations retain their factor and function identity.

ALTER TABLE epm.calculation_generation
    ADD COLUMN function_name text NOT NULL DEFAULT 'facts.numeric.scale'
        CHECK (length(function_name) BETWEEN 1 AND 200);
ALTER TABLE epm.calculation_generation ALTER COLUMN factor DROP NOT NULL;
ALTER TABLE epm.calculation_generation ADD CONSTRAINT generation_function_parameters
    CHECK ((function_name='facts.numeric.scale' AND factor IS NOT NULL)
        OR (function_name='facts.planning.spread.equal' AND factor IS NULL));
