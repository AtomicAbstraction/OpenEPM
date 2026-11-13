-- Dimensionless Ratio results are typed calculation outputs. They remain
-- outside cube coordinate grain and cannot be read as Amount or Currency.
CREATE TABLE epm.calculation_ratio_result (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    generation_id text NOT NULL,
    coordinate_id bigint NOT NULL,
    source_amount numeric(28,8),
    source_change_id text,
    source_present boolean NOT NULL,
    ratio numeric(20,12) NOT NULL,
    source_lookup_lineage jsonb NOT NULL DEFAULT '[]'::jsonb CHECK
        (jsonb_typeof(source_lookup_lineage)='array'),
    PRIMARY KEY (workspace_id,application_id,generation_id,coordinate_id),
    FOREIGN KEY (workspace_id,application_id,generation_id)
        REFERENCES epm.calculation_generation
        (workspace_id,application_id,generation_id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,coordinate_id)
        REFERENCES epm.coordinate
        (workspace_id,application_id,coordinate_id) ON DELETE RESTRICT,
    CHECK ((source_present AND source_amount IS NOT NULL
            AND source_change_id IS NOT NULL)
        OR (NOT source_present AND source_amount IS NULL
            AND source_change_id IS NULL))
);
CREATE INDEX calculation_ratio_result_coordinate
    ON epm.calculation_ratio_result
    (workspace_id,application_id,coordinate_id,generation_id);
GRANT SELECT,INSERT ON epm.calculation_ratio_result TO epm_runtime;
GRANT SELECT ON epm.calculation_ratio_result TO epm_lifecycle;
ALTER TABLE epm.calculation_ratio_result ENABLE ROW LEVEL SECURITY;
CREATE POLICY calculation_ratio_result_scope ON epm.calculation_ratio_result
    TO epm_runtime USING
    (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true))
    WITH CHECK
    (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true));
CREATE POLICY calculation_ratio_result_lifecycle_read
    ON epm.calculation_ratio_result FOR SELECT TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));

-- Extend the owner-only reset in reviewed child-before-parent order.
DO $$
DECLARE definition text; revised text;
DECLARE old_pair text := $pattern$'calculation_unit_result','calculation_result','calculation_publication',$pattern$;
DECLARE new_pair text := $pattern$'calculation_ratio_result','calculation_unit_result','calculation_result','calculation_publication',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0144_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0144_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $$;
