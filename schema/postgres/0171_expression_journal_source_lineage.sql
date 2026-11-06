-- Generic lineage from a fixed-core journal line to the exact published
-- calculation result that supplied its amount.  Accounting policy stays in a
-- user-authored expression or optional template; this table records facts,
-- units and dependency evidence only.
CREATE TABLE epm.manual_journal_calculation_source (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    journal_id text NOT NULL,
    line_ordinal integer NOT NULL CHECK (line_ordinal BETWEEN 1 AND 100),
    result_key text NOT NULL
        CHECK (result_key ~ '^[A-Za-z0-9._-]{8,128}$'),
    generation_id text NOT NULL CHECK (generation_id ~ '^[0-9a-f]{32}$'),
    published_revision bigint NOT NULL CHECK (published_revision > 0),
    source_coordinate_id bigint NOT NULL,
    unit_dimension_id text NOT NULL,
    unit_member_id text NOT NULL,
    dependency_status jsonb NOT NULL
        CHECK (jsonb_typeof(dependency_status) = 'object'),
    PRIMARY KEY (workspace_id,application_id,journal_id,line_ordinal),
    FOREIGN KEY (workspace_id,application_id,journal_id,line_ordinal)
        REFERENCES epm.manual_journal_line
        (workspace_id,application_id,journal_id,line_ordinal)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,generation_id,source_coordinate_id,
                 unit_dimension_id,unit_member_id)
        REFERENCES epm.calculation_unit_result
        (workspace_id,application_id,generation_id,coordinate_id,
         output_unit_currency_dimension_id,output_unit_currency_member_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,result_key)
        REFERENCES epm.calculation_publication
        (workspace_id,application_id,result_key)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,unit_dimension_id,unit_member_id)
        REFERENCES epm.member
        (workspace_id,application_id,dimension_id,member_id)
        ON DELETE RESTRICT
);

CREATE INDEX manual_journal_calculation_source_generation
    ON epm.manual_journal_calculation_source
    (workspace_id,application_id,result_key,generation_id,published_revision);

GRANT SELECT,INSERT ON epm.manual_journal_calculation_source TO epm_runtime;
ALTER TABLE epm.manual_journal_calculation_source ENABLE ROW LEVEL SECURITY;
CREATE POLICY manual_journal_calculation_source_runtime_scope
    ON epm.manual_journal_calculation_source TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));

-- Extend the owner-only reset in dependency order.  Lifecycle service roles
-- receive no direct DELETE privilege.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_pair text := $pattern$'planning_submission_event','manual_journal_line',$pattern$;
DECLARE new_pair text := $pattern$'planning_submission_event','manual_journal_calculation_source','manual_journal_line',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0171_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0171_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END
$migration$;

-- Pin the reviewed schema-171 reset relation/FK graph.  The fixed owner-only
-- primitive accepts exactly this graph identity and no earlier/later schema.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '56b75344dc664fe2bf602628e5ec9f7bc5bd4f789baec22d66d81adeb91cd20e';
DECLARE new_fingerprint constant text :=
  '8ca1b7ca5f7d2faf6e4cb3332bea5aee7f8d8ba6f871b1e2b9d762598774c0f1';
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0171_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0171_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END
$migration$;

REVOKE ALL ON epm.manual_journal_calculation_source FROM epm_lifecycle;
