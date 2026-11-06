-- Generic Currency Amount results whose Currency is a typed output unit, not
-- part of cube coordinate grain. Existing calculation_result identities and
-- their allocation/rollup foreign keys remain unchanged for v1/v2 programs.
CREATE TABLE epm.calculation_unit_result (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    generation_id text NOT NULL,
    coordinate_id bigint NOT NULL,
    output_unit_currency_dimension_id text NOT NULL,
    output_unit_currency_member_id text NOT NULL,
    source_amount numeric(28,8) NOT NULL,
    source_change_id text NOT NULL,
    amount numeric(28,8) NOT NULL,
    rate_strategy text NOT NULL CHECK (length(rate_strategy) BETWEEN 1 AND 100),
    rate_numerator numeric NOT NULL CHECK
        (rate_numerator > 0 AND scale(rate_numerator)=0),
    rate_denominator numeric NOT NULL CHECK
        (rate_denominator > 0 AND scale(rate_denominator)=0),
    rate_sources jsonb NOT NULL CHECK
        (jsonb_typeof(rate_sources)='array'
         AND jsonb_array_length(rate_sources) BETWEEN 1 AND 2),
    PRIMARY KEY (workspace_id,application_id,generation_id,coordinate_id,
        output_unit_currency_dimension_id,output_unit_currency_member_id),
    FOREIGN KEY (workspace_id,application_id,generation_id)
        REFERENCES epm.calculation_generation
        (workspace_id,application_id,generation_id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,coordinate_id)
        REFERENCES epm.coordinate
        (workspace_id,application_id,coordinate_id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,
        output_unit_currency_dimension_id,output_unit_currency_member_id)
        REFERENCES epm.member
        (workspace_id,application_id,dimension_id,member_id) ON DELETE RESTRICT
);
CREATE INDEX calculation_unit_result_coordinate
    ON epm.calculation_unit_result
    (workspace_id,application_id,coordinate_id,
     output_unit_currency_dimension_id,output_unit_currency_member_id,
     generation_id);
GRANT SELECT,INSERT ON epm.calculation_unit_result TO epm_runtime;
ALTER TABLE epm.calculation_unit_result ENABLE ROW LEVEL SECURITY;
CREATE POLICY calculation_unit_result_scope ON epm.calculation_unit_result
    TO epm_runtime USING
    (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true))
    WITH CHECK
    (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true));

-- Keep owner reset dependency ordered without replacing the qualified reset
-- implementation wholesale.
DO $$
DECLARE definition text; revised text;
DECLARE old_pair text := $pattern$'calculation_result','calculation_publication',$pattern$;
DECLARE new_pair text := $pattern$'calculation_unit_result','calculation_result','calculation_publication',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0143_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0143_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $$;
