-- Immutable source lineage for a bounded exact bottom-up planning rollup.
-- This is generic summation, not a consolidation accounting treatment.

ALTER TABLE epm.calculation_generation
    DROP CONSTRAINT generation_function_parameters;
ALTER TABLE epm.calculation_generation
    ADD CONSTRAINT generation_function_parameters CHECK (
        (function_name='facts.numeric.scale' AND factor IS NOT NULL)
        OR (function_name IN ('facts.planning.spread.equal',
            'facts.planning.allocate.weighted',
            'facts.planning.rollup.sum') AND factor IS NULL));

CREATE TABLE epm.rollup_source_lineage (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    generation_id text NOT NULL,
    coordinate_id bigint NOT NULL,
    source_coordinate_id bigint NOT NULL,
    source_amount numeric(28,8) NOT NULL,
    source_change_id text NOT NULL,
    hierarchy_dimension_id text NOT NULL,
    hierarchy_version bigint NOT NULL,
    PRIMARY KEY (workspace_id,application_id,generation_id,
                 coordinate_id,source_coordinate_id),
    FOREIGN KEY (workspace_id,application_id,generation_id,coordinate_id)
        REFERENCES epm.calculation_result
        (workspace_id,application_id,generation_id,coordinate_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,source_coordinate_id)
        REFERENCES epm.coordinate
        (workspace_id,application_id,coordinate_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,hierarchy_dimension_id,
                 hierarchy_version)
        REFERENCES epm.hierarchy_version
        (workspace_id,application_id,dimension_id,version)
        ON DELETE RESTRICT
);
CREATE INDEX rollup_source_coordinate ON epm.rollup_source_lineage
    (workspace_id,application_id,source_coordinate_id,generation_id);
GRANT SELECT,INSERT ON epm.rollup_source_lineage TO epm_runtime;
ALTER TABLE epm.rollup_source_lineage ENABLE ROW LEVEL SECURITY;
CREATE POLICY rollup_source_lineage_scope
    ON epm.rollup_source_lineage TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
