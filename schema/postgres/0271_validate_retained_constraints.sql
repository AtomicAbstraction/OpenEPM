-- Complete the deferred validation work left by additive compatibility
-- migrations.  PostgreSQL has enforced these CHECK constraints for every new
-- or changed row since their creation; VALIDATE now proves all pre-existing
-- rows and changes the catalogue state without taking an ACCESS EXCLUSIVE
-- table lock.
ALTER TABLE epm.calculation_generation
    VALIDATE CONSTRAINT generation_function_parameters;
ALTER TABLE epm.calculation_result
    VALIDATE CONSTRAINT calculation_source_lookup_lineage_array;
ALTER TABLE epm.calculation_unit_result
    VALIDATE CONSTRAINT calculation_unit_source_evidence;
ALTER TABLE epm.calculation_unit_result
    VALIDATE CONSTRAINT calculation_unit_source_lookup_lineage_array;
ALTER TABLE epm.member
    VALIDATE CONSTRAINT member_numeric_value_kind_valid;
