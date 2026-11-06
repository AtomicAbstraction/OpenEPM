-- Preserve nonempty reconciliation and bind the actual deferred close work.
-- No private exemption, history purge or change to event/seal authority.
CREATE OR REPLACE FUNCTION epm.fact_reconcile(w text,a text,op text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    PERFORM epm.fact_scope_check(w,a);
    -- Ordering a lower-bound seek keeps operation_id nonconstant in ORDER BY.
    -- The operation index supplies that order, avoiding the cold-statistics
    -- scope-only coordinate/history scan chosen for equality EXISTS or MIN.
    -- A next greater key is absence too; exact matching is tested outside.
    IF op IS NULL OR (
       (SELECT operation_id FROM epm.numeric_fact_event
            WHERE workspace_id=w AND application_id=a AND operation_id>=op
            ORDER BY operation_id LIMIT 1) IS DISTINCT FROM op
       AND (SELECT operation_id FROM epm.text_fact_event
            WHERE workspace_id=w AND application_id=a AND operation_id>=op
            ORDER BY operation_id LIMIT 1) IS DISTINCT FROM op
       AND (SELECT operation_id FROM epm.line_detail_event
            WHERE workspace_id=w AND application_id=a AND operation_id>=op
            ORDER BY operation_id LIMIT 1) IS DISTINCT FROM op) THEN
        RETURN;
    END IF;
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

-- The deferred row is the immutable receipt just inserted. The only permitted
-- intervening UPDATE already seals it and reconciles all original columns;
-- an old TID then correctly finds no remaining unsealed version. Retain full
-- logical identity checks and the original scope guard, not a naked TID update.
CREATE OR REPLACE FUNCTION epm.fact_receipt_close() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    PERFORM epm.fact_scope_check(NEW.workspace_id,NEW.application_id);
    UPDATE epm.operation_receipt SET sealed=true WHERE ctid=NEW.ctid
      AND workspace_id=NEW.workspace_id AND application_id=NEW.application_id
      AND operation_id=NEW.operation_id AND NOT sealed;
    RETURN NULL;
END $$;
