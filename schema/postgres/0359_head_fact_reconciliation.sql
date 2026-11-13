BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=358) THEN
    RAISE EXCEPTION 'MIGRATION_0359_REQUIRES_0358';
  END IF;
END $migration$;

-- The common publication case seals the operation at the current application
-- head.  Its last event per touched coordinate is therefore already the
-- expected projection; do one set-wise comparison instead of one history
-- lookup per coordinate.  The uncommon multi-operation transaction retains
-- the established general reconciliation path below.
CREATE OR REPLACE FUNCTION epm.fact_reconcile(w text,a text,op text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE head_revision bigint; operation_revision bigint;
BEGIN
  PERFORM epm.fact_scope_check(w,a);
  IF NOT epm.raw_operation_membership_exists(w,a,op) THEN RETURN; END IF;
  SELECT s.commit_revision,r.committed_revision
    INTO head_revision,operation_revision
  FROM epm.application_state s
  JOIN epm.operation_receipt r USING(workspace_id,application_id)
  WHERE s.workspace_id=w AND s.application_id=a AND r.operation_id=op;

  IF operation_revision=head_revision THEN
    IF EXISTS(WITH expected AS (
        SELECT DISTINCT ON(coordinate_id) coordinate_id,present,
          resulting_amount,change_id,committed_revision
        FROM epm.numeric_fact_event WHERE workspace_id=w
          AND application_id=a AND operation_id=op
        ORDER BY coordinate_id,committed_revision DESC,line_ordinal DESC)
      SELECT 1 FROM expected e LEFT JOIN epm.numeric_cell_current c
        ON c.workspace_id=w AND c.application_id=a
       AND c.coordinate_id=e.coordinate_id
      WHERE c.coordinate_id IS NULL OR
        ROW(c.present,c.amount,c.change_id,c.last_revision) IS DISTINCT FROM
        ROW(e.present,e.resulting_amount,e.change_id,e.committed_revision)) THEN
      RAISE EXCEPTION 'FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
    IF EXISTS(SELECT 1 FROM epm.numeric_fact_event e
      JOIN epm.line_detail_current d USING(workspace_id,application_id,coordinate_id)
      JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
      WHERE e.workspace_id=w AND e.application_id=a AND e.operation_id=op
        AND (NOT n.present OR n.amount<>d.total)) THEN
      RAISE EXCEPTION 'FACT_DETAIL_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH expected AS (
        SELECT DISTINCT ON(coordinate_id) coordinate_id,present,
          resulting_value,change_id,committed_revision
        FROM epm.text_fact_event WHERE workspace_id=w
          AND application_id=a AND operation_id=op
        ORDER BY coordinate_id,committed_revision DESC,line_ordinal DESC)
      SELECT 1 FROM expected e LEFT JOIN epm.text_cell_current c
        ON c.workspace_id=w AND c.application_id=a
       AND c.coordinate_id=e.coordinate_id
      WHERE c.coordinate_id IS NULL OR
        ROW(c.present,c.text_value,c.change_id,c.last_revision) IS DISTINCT FROM
        ROW(e.present,e.resulting_value,e.change_id,e.committed_revision)) THEN
      RAISE EXCEPTION 'FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH expected AS (
        SELECT DISTINCT ON(coordinate_id) coordinate_id,present,items,total,
          change_id,committed_revision
        FROM epm.line_detail_event WHERE workspace_id=w
          AND application_id=a AND operation_id=op
        ORDER BY coordinate_id,committed_revision DESC)
      SELECT 1 FROM expected e LEFT JOIN epm.line_detail_current c
        ON c.workspace_id=w AND c.application_id=a
       AND c.coordinate_id=e.coordinate_id
      LEFT JOIN epm.numeric_cell_current n ON n.workspace_id=w
       AND n.application_id=a AND n.coordinate_id=e.coordinate_id
      WHERE (e.present AND (c.coordinate_id IS NULL OR
        ROW(c.items,c.total,c.change_id,c.last_revision) IS DISTINCT FROM
        ROW(e.items,e.total,e.change_id,e.committed_revision) OR
        NOT coalesce(n.present,false) OR n.amount<>e.total)) OR
        (NOT e.present AND c.coordinate_id IS NOT NULL)) THEN
      RAISE EXCEPTION 'FACT_DETAIL_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
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
       IS DISTINCT FROM ROW(e.items,e.total,e.change_id,e.committed_revision) OR
       NOT coalesce(n.present,false) OR n.amount<>e.total)) OR
       (NOT e.present AND c.coordinate_id IS NOT NULL)) THEN
    RAISE EXCEPTION 'FACT_DETAIL_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
  END IF;
END $$;

COMMIT;
