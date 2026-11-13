ALTER TABLE epm.calculation_generation
    DROP CONSTRAINT generation_function_parameters;
ALTER TABLE epm.calculation_generation
    ADD CONSTRAINT generation_function_parameters CHECK (
        (function_name='facts.numeric.scale' AND factor IS NOT NULL)
        OR (function_name IN ('facts.planning.spread.equal',
            'facts.planning.spread.calendar.equal',
            'facts.planning.allocate.weighted',
            'facts.planning.rollup.sum',
            'facts.planning.group.sum',
            'facts.planning.group.sum.bulk',
            'facts.expression.calculate',
            'consolidation.full.contribute',
            'consolidation.full.aggregate',
            'currency.translation.publish',
            'currency.calculation.translation.publish',
            'consolidation.full.translated.aggregate') AND factor IS NULL)
        OR (function_name='consolidation.nci.period.publish' AND factor IS NULL AND row_count=2)
        OR (function_name='consolidation.nci.period.withdraw' AND factor IS NULL AND row_count=0)
    ) NOT VALID;

-- Existing calculation tables retain the period split and empty withdrawal.
-- Seal this new accounting stage at its job's atomic publication boundary.
CREATE FUNCTION epm.period_attribution_line_open() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM period_inserted i
      JOIN epm.calculation_generation g USING(workspace_id,application_id,generation_id)
      JOIN epm.job j ON j.workspace_id=g.workspace_id AND j.application_id=g.application_id AND j.job_id=g.job_id
      WHERE g.function_name IN ('consolidation.nci.period.publish','consolidation.nci.period.withdraw')
        AND (g.function_name<>'consolidation.nci.period.publish' OR j.status<>'running')) THEN
        RAISE EXCEPTION 'PERIOD_ATTRIBUTION_GENERATION_SEALED' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION epm.period_attribution_line_open() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.period_attribution_line_open() TO epm_runtime;
CREATE TRIGGER period_attribution_line_open AFTER INSERT ON epm.calculation_result
REFERENCING NEW TABLE AS period_inserted
FOR EACH STATEMENT EXECUTE FUNCTION epm.period_attribution_line_open();

CREATE FUNCTION epm.period_attribution_pointer_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE kind text; expected_rows integer; actual_rows bigint; generation_key text; generation_revision bigint;
        basis_min numeric; basis_max numeric; attributed numeric; receipt_exists boolean;
BEGIN
    SELECT function_name,row_count,result_key,published_revision INTO kind,expected_rows,generation_key,generation_revision FROM epm.calculation_generation
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id AND generation_id=NEW.generation_id;
    IF kind IN ('consolidation.nci.period.publish','consolidation.nci.period.withdraw') THEN
        SELECT count(*),min(source_amount),max(source_amount),sum(amount)
          INTO actual_rows,basis_min,basis_max,attributed FROM epm.calculation_result
          WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id AND generation_id=NEW.generation_id;
        SELECT EXISTS(SELECT 1 FROM epm.operation_receipt WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
          AND operation_id=NEW.generation_id AND committed_revision=NEW.published_revision AND result->>'function'=kind)
          INTO receipt_exists;
        IF generation_key<>NEW.result_key OR generation_revision<>NEW.published_revision OR expected_rows<>actual_rows OR NOT receipt_exists
           OR (kind='consolidation.nci.period.publish' AND (actual_rows<>2 OR basis_min<>basis_max OR attributed<>basis_min))
           OR (kind='consolidation.nci.period.withdraw' AND actual_rows<>0) THEN
            RAISE EXCEPTION 'PERIOD_ATTRIBUTION_PUBLICATION_INCOMPLETE' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.period_attribution_pointer_complete() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.period_attribution_pointer_complete() TO epm_runtime;
CREATE TRIGGER period_attribution_pointer_complete BEFORE INSERT OR UPDATE ON epm.calculation_publication
FOR EACH ROW EXECUTE FUNCTION epm.period_attribution_pointer_complete();
