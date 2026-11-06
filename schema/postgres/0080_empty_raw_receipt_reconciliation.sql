-- Bound the full deferred seal transaction, not only native activation.
-- Generic closure, ordinary nonempty reconciliation and event/receipt seals
-- are unchanged. CREATE OR REPLACE preserves the original execute grants.
CREATE OR REPLACE FUNCTION epm.fact_reconcile(w text,a text,op text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    PERFORM epm.fact_scope_check(w,a);
    -- Every reconciliation below is rooted in one of these exact operation
    -- event sets. When all are empty, every original predicate is false.
    -- Avoid planning/executing broad secured-view joins for a technical or
    -- metadata receipt. Nonempty operations retain every original check.
    IF NOT EXISTS(SELECT 1 FROM epm.numeric_fact_event
            WHERE workspace_id=w AND application_id=a AND operation_id=op)
       AND NOT EXISTS(SELECT 1 FROM epm.text_fact_event
            WHERE workspace_id=w AND application_id=a AND operation_id=op)
       AND NOT EXISTS(SELECT 1 FROM epm.line_detail_event
            WHERE workspace_id=w AND application_id=a AND operation_id=op) THEN
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
