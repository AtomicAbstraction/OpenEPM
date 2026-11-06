-- Immutable exact-basis lineage for weighted planning allocations.

ALTER TABLE epm.calculation_generation
    DROP CONSTRAINT generation_function_parameters;
ALTER TABLE epm.calculation_generation
    ADD CONSTRAINT generation_function_parameters CHECK (
        (function_name='facts.numeric.scale' AND factor IS NOT NULL)
        OR (function_name IN ('facts.planning.spread.equal',
            'facts.planning.allocate.weighted') AND factor IS NULL));

CREATE TABLE epm.allocation_basis_lineage (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    generation_id text NOT NULL,
    coordinate_id bigint NOT NULL,
    basis_coordinate_id bigint NOT NULL,
    basis_amount numeric(28,8) NOT NULL CHECK (basis_amount>0),
    basis_change_id text NOT NULL,
    total_basis numeric NOT NULL CHECK (total_basis>0),
    base_units numeric NOT NULL CHECK (base_units>=0 AND scale(base_units)=0),
    remainder_numerator numeric NOT NULL CHECK (remainder_numerator>=0),
    extra_unit integer NOT NULL CHECK (extra_unit IN (0,1)),
    PRIMARY KEY (workspace_id,application_id,generation_id,coordinate_id),
    FOREIGN KEY (workspace_id,application_id,generation_id,coordinate_id)
        REFERENCES epm.calculation_result
        (workspace_id,application_id,generation_id,coordinate_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,basis_coordinate_id)
        REFERENCES epm.coordinate
        (workspace_id,application_id,coordinate_id)
        ON DELETE RESTRICT,
    CHECK (remainder_numerator<total_basis)
);
GRANT SELECT,INSERT ON epm.allocation_basis_lineage TO epm_runtime;
ALTER TABLE epm.allocation_basis_lineage ENABLE ROW LEVEL SECURITY;
CREATE POLICY allocation_basis_lineage_scope
    ON epm.allocation_basis_lineage TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
