-- An exact native index of operations that have numeric/text/detail events.
-- This avoids making the empty-receipt bound depend on a history query plan.
CREATE TABLE epm.raw_operation_membership (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    operation_id text NOT NULL,
    PRIMARY KEY(workspace_id,application_id,operation_id),
    CONSTRAINT raw_operation_membership_receipt_fkey FOREIGN KEY(workspace_id,application_id,operation_id)
        REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE epm.raw_operation_membership ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON epm.raw_operation_membership FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;

-- Migration DDL locks on all three event tables are retained through backfill
-- and commit. No legal insert can fall between installing its trigger and the
-- snapshot that covers existing canonical events.
CREATE FUNCTION epm.raw_operation_membership_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm,pg_temp AS $$
BEGIN
    IF TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'epm'
       OR TG_TABLE_NAME NOT IN ('numeric_fact_event','text_fact_event','line_detail_event') THEN
        RAISE EXCEPTION 'RAW_OPERATION_MEMBERSHIP_TRIGGER_INVALID' USING ERRCODE='23514';
    END IF;
    INSERT INTO epm.raw_operation_membership(workspace_id,application_id,operation_id)
        SELECT DISTINCT workspace_id,application_id,operation_id FROM raw_operation_inserted
        ON CONFLICT(workspace_id,application_id,operation_id) DO NOTHING;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION epm.raw_operation_membership_insert() FROM PUBLIC;
CREATE TRIGGER raw_operation_membership_insert AFTER INSERT ON epm.numeric_fact_event
    REFERENCING NEW TABLE AS raw_operation_inserted FOR EACH STATEMENT
    EXECUTE FUNCTION epm.raw_operation_membership_insert();
CREATE TRIGGER raw_operation_membership_insert AFTER INSERT ON epm.text_fact_event
    REFERENCING NEW TABLE AS raw_operation_inserted FOR EACH STATEMENT
    EXECUTE FUNCTION epm.raw_operation_membership_insert();
CREATE TRIGGER raw_operation_membership_insert AFTER INSERT ON epm.line_detail_event
    REFERENCING NEW TABLE AS raw_operation_inserted FOR EACH STATEMENT
    EXECUTE FUNCTION epm.raw_operation_membership_insert();
INSERT INTO epm.raw_operation_membership(workspace_id,application_id,operation_id)
    SELECT workspace_id,application_id,operation_id FROM epm.numeric_fact_event
    UNION SELECT workspace_id,application_id,operation_id FROM epm.text_fact_event
    UNION SELECT workspace_id,application_id,operation_id FROM epm.line_detail_event
    ON CONFLICT(workspace_id,application_id,operation_id) DO NOTHING;

-- Only one exact primary-key access path exists. The function-local planner
-- setting cannot leak to a caller, and only this private point lookup runs
-- while it applies. Definer identity must not bypass explicit caller scope.
CREATE FUNCTION epm.raw_operation_membership_exists(w text,a text,op text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,epm SET enable_seqscan=off AS $$
BEGIN
    IF current_setting('epm.workspace_id',true) IS DISTINCT FROM w
       OR current_setting('epm.application_id',true) IS DISTINCT FROM a THEN
        RAISE EXCEPTION 'FACT_PUBLICATION_SCOPE_CHANGED' USING ERRCODE='23514';
    END IF;
    RETURN EXISTS(SELECT 1 FROM epm.raw_operation_membership
        WHERE workspace_id=w AND application_id=a AND operation_id=op);
END $$;
REVOKE ALL ON FUNCTION epm.raw_operation_membership_exists(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.raw_operation_membership_exists(text,text,text) TO epm_runtime;

CREATE OR REPLACE FUNCTION epm.fact_reconcile(w text,a text,op text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    PERFORM epm.fact_scope_check(w,a);
    -- Every original predicate below is rooted in one of the three raw event
    -- sets represented by this transactionally maintained membership key.
    -- No membership is the exact empty-operation proof. Nonempty operations
    -- retain every original validation, and late inserts still meet the
    -- original sealed-receipt/event guards before their transaction commits.
    IF NOT epm.raw_operation_membership_exists(w,a,op) THEN RETURN; END IF;
    IF EXISTS(WITH touched AS (SELECT DISTINCT coordinate_id FROM epm.numeric_fact_event
         WHERE workspace_id=w AND application_id=a AND operation_id=op)
       SELECT 1 FROM touched i LEFT JOIN epm.numeric_cell_current c
         ON c.workspace_id=w AND c.application_id=a AND c.coordinate_id=i.coordinate_id
       LEFT JOIN LATERAL(SELECT present,resulting_amount,change_id,committed_revision FROM epm.numeric_fact_event
         WHERE workspace_id=w AND application_id=a AND coordinate_id=i.coordinate_id
         ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)e ON true
       WHERE c.coordinate_id IS NULL OR ROW(c.present,c.amount,c.change_id,c.last_revision)
         IS DISTINCT FROM ROW(e.present,e.resulting_amount,e.change_id,e.committed_revision)) THEN
        RAISE EXCEPTION 'FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
    IF EXISTS(SELECT 1 FROM epm.numeric_fact_event e
       JOIN epm.line_detail_current d USING(workspace_id,application_id,coordinate_id)
       JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
       WHERE e.workspace_id=w AND e.application_id=a AND e.operation_id=op
         AND (NOT n.present OR n.amount<>d.total)) THEN
        RAISE EXCEPTION 'FACT_DETAIL_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH touched AS (SELECT DISTINCT coordinate_id FROM epm.text_fact_event
         WHERE workspace_id=w AND application_id=a AND operation_id=op)
       SELECT 1 FROM touched i LEFT JOIN epm.text_cell_current c
         ON c.workspace_id=w AND c.application_id=a AND c.coordinate_id=i.coordinate_id
       LEFT JOIN LATERAL(SELECT present,resulting_value,change_id,committed_revision FROM epm.text_fact_event
         WHERE workspace_id=w AND application_id=a AND coordinate_id=i.coordinate_id
         ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)e ON true
       WHERE c.coordinate_id IS NULL OR ROW(c.present,c.text_value,c.change_id,c.last_revision)
         IS DISTINCT FROM ROW(e.present,e.resulting_value,e.change_id,e.committed_revision)) THEN
        RAISE EXCEPTION 'FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH touched AS (SELECT DISTINCT coordinate_id FROM epm.line_detail_event
         WHERE workspace_id=w AND application_id=a AND operation_id=op)
       SELECT 1 FROM touched i LEFT JOIN epm.line_detail_current c
         ON c.workspace_id=w AND c.application_id=a AND c.coordinate_id=i.coordinate_id
       LEFT JOIN epm.numeric_cell_current n ON n.workspace_id=w AND n.application_id=a AND n.coordinate_id=i.coordinate_id
       LEFT JOIN LATERAL(SELECT present,items,total,change_id,committed_revision FROM epm.line_detail_event
         WHERE workspace_id=w AND application_id=a AND coordinate_id=i.coordinate_id
         ORDER BY committed_revision DESC LIMIT 1)e ON true
       WHERE (e.present AND (c.coordinate_id IS NULL OR ROW(c.items,c.total,c.change_id,c.last_revision)
           IS DISTINCT FROM ROW(e.items,e.total,e.change_id,e.committed_revision) OR NOT coalesce(n.present,false) OR n.amount<>e.total))
         OR (NOT e.present AND c.coordinate_id IS NOT NULL)) THEN
        RAISE EXCEPTION 'FACT_DETAIL_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
END $$;
