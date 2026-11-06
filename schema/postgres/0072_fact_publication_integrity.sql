-- Close each committed operation/epoch. Old immutable events cannot acquire
-- later lines, wrong revision stamps, or an unbacked current projection.
ALTER TABLE epm.operation_receipt ADD COLUMN sealed boolean NOT NULL DEFAULT true;
ALTER TABLE epm.operation_receipt ALTER COLUMN sealed SET DEFAULT false;
ALTER TABLE epm.application_state ADD COLUMN commit_open boolean NOT NULL DEFAULT false;
CREATE INDEX numeric_event_operation ON epm.numeric_fact_event(workspace_id,application_id,operation_id,coordinate_id);
CREATE INDEX text_event_operation ON epm.text_fact_event(workspace_id,application_id,operation_id,coordinate_id);
CREATE INDEX detail_event_operation ON epm.line_detail_event(workspace_id,application_id,operation_id,coordinate_id);

CREATE FUNCTION epm.fact_scope_check(w text,a text,workspace_only boolean DEFAULT false) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    -- Owners bypass RLS for migration/recovery; normal invoker callbacks must
    -- never silently skip their rows after a transaction changes its RLS scope.
    IF pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid='epm.operation_receipt'::regclass),'USAGE') THEN RETURN; END IF;
    IF current_setting('epm.workspace_id',true) IS DISTINCT FROM w OR
       (current_setting('epm.application_id',true) IS DISTINCT FROM a AND NOT
          (workspace_only AND pg_has_role(current_user,'epm_lifecycle','member'))) THEN
        RAISE EXCEPTION 'FACT_PUBLICATION_SCOPE_CHANGED' USING ERRCODE='23514';
    END IF;
END $$;

CREATE FUNCTION epm.fact_commit_epoch_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF TG_OP='INSERT' THEN NEW.commit_open=false; RETURN NEW; END IF;
    IF NEW.commit_revision<OLD.commit_revision THEN
        RAISE EXCEPTION 'FACT_COMMIT_REVISION_REGRESSION' USING ERRCODE='23514';
    ELSIF NEW.commit_revision>OLD.commit_revision THEN NEW.commit_open=true;
    ELSIF NEW.commit_open AND NOT OLD.commit_open THEN
        RAISE EXCEPTION 'FACT_COMMIT_EPOCH_REOPENED' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER fact_commit_epoch_guard BEFORE INSERT OR UPDATE ON epm.application_state
    FOR EACH ROW EXECUTE FUNCTION epm.fact_commit_epoch_guard();
CREATE FUNCTION epm.fact_commit_epoch_close() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    PERFORM epm.fact_scope_check(NEW.workspace_id,NEW.application_id,true);
    UPDATE epm.application_state SET commit_open=false WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id AND commit_open;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER fact_commit_epoch_close AFTER UPDATE ON epm.application_state
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(OLD.commit_revision<>NEW.commit_revision)
    EXECUTE FUNCTION epm.fact_commit_epoch_close();

CREATE FUNCTION epm.fact_reconcile(w text,a text,op text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    PERFORM epm.fact_scope_check(w,a);
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

CREATE FUNCTION epm.fact_receipt_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE head bigint; opened boolean;
BEGIN
    PERFORM epm.fact_scope_check(NEW.workspace_id,NEW.application_id);
    SELECT commit_revision,commit_open INTO head,opened FROM epm.application_state
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id FOR UPDATE;
    IF TG_OP='INSERT' THEN
        IF head IS NULL OR NOT(NEW.committed_revision=head+1 OR (NEW.committed_revision=head AND opened)) THEN
            RAISE EXCEPTION 'FACT_RECEIPT_REVISION_INVALID' USING ERRCODE='23514';
        END IF;
        NEW.sealed=false; RETURN NEW;
    END IF;
    IF OLD.sealed OR NOT NEW.sealed OR (to_jsonb(NEW)-'sealed') IS DISTINCT FROM (to_jsonb(OLD)-'sealed') THEN
        RAISE EXCEPTION 'FACT_OPERATION_SEALED' USING ERRCODE='23514';
    END IF;
    IF head<NEW.committed_revision THEN
        RAISE EXCEPTION 'FACT_RECEIPT_REVISION_UNPUBLISHED' USING ERRCODE='23514';
    END IF;
    PERFORM epm.fact_reconcile(NEW.workspace_id,NEW.application_id,NEW.operation_id);
    RETURN NEW;
END $$;
CREATE TRIGGER fact_receipt_guard BEFORE INSERT OR UPDATE ON epm.operation_receipt
    FOR EACH ROW EXECUTE FUNCTION epm.fact_receipt_guard();
CREATE FUNCTION epm.fact_receipt_close() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    PERFORM epm.fact_scope_check(NEW.workspace_id,NEW.application_id);
    UPDATE epm.operation_receipt SET sealed=true WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id AND operation_id=NEW.operation_id AND NOT sealed;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER fact_receipt_close AFTER INSERT ON epm.operation_receipt
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION epm.fact_receipt_close();

CREATE FUNCTION epm.fact_event_open() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM fact_inserted i JOIN epm.operation_receipt r
        USING(workspace_id,application_id,operation_id) WHERE r.sealed) THEN
        RAISE EXCEPTION 'FACT_OPERATION_SEALED' USING ERRCODE='23514';
    END IF;
    IF EXISTS(SELECT 1 FROM fact_inserted i JOIN epm.operation_receipt r
        USING(workspace_id,application_id,operation_id) WHERE i.committed_revision<>r.committed_revision) THEN
        RAISE EXCEPTION 'FACT_EVENT_REVISION_MISMATCH' USING ERRCODE='23514';
    END IF;
    IF TG_TABLE_NAME='numeric_fact_event' THEN
        IF EXISTS(SELECT 1 FROM fact_inserted i LEFT JOIN LATERAL(
            SELECT resulting_amount FROM epm.numeric_fact_event p WHERE p.workspace_id=i.workspace_id
              AND p.application_id=i.application_id AND p.coordinate_id=i.coordinate_id
              AND ROW(p.committed_revision,p.line_ordinal)<ROW(i.committed_revision,i.line_ordinal)
              ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)p ON true
            WHERE i.present<>(i.kind<>'clear') OR i.delta<>coalesce(i.resulting_amount,0)-coalesce(p.resulting_amount,0)) THEN
            RAISE EXCEPTION 'FACT_NUMERIC_LINEAGE_INCONSISTENT' USING ERRCODE='23514';
        END IF;
    ELSIF TG_TABLE_NAME='text_fact_event' THEN
        IF EXISTS(SELECT 1 FROM fact_inserted i LEFT JOIN LATERAL(
            SELECT present,resulting_value FROM epm.text_fact_event p WHERE p.workspace_id=i.workspace_id
              AND p.application_id=i.application_id AND p.coordinate_id=i.coordinate_id
              AND ROW(p.committed_revision,p.line_ordinal)<ROW(i.committed_revision,i.line_ordinal)
              ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)p ON true
            WHERE i.present<>(i.kind<>'clear') OR i.prior_present<>coalesce(p.present,false)
              OR i.prior_value IS DISTINCT FROM p.resulting_value) THEN
            RAISE EXCEPTION 'FACT_TEXT_LINEAGE_INCONSISTENT' USING ERRCODE='23514';
        END IF;
    ELSE
        IF EXISTS(SELECT 1 FROM fact_inserted i LEFT JOIN LATERAL(
            SELECT present,items,total FROM epm.line_detail_event p WHERE p.workspace_id=i.workspace_id
              AND p.application_id=i.application_id AND p.coordinate_id=i.coordinate_id
              AND p.committed_revision<i.committed_revision ORDER BY committed_revision DESC LIMIT 1)p ON true
            WHERE i.prior_items IS DISTINCT FROM CASE WHEN p.present THEN p.items ELSE NULL END
              OR i.prior_total IS DISTINCT FROM CASE WHEN p.present THEN p.total ELSE NULL END
              OR i.total<>(SELECT coalesce(sum((x->>'amount')::numeric),0) FROM jsonb_array_elements(i.items)x)) THEN
            RAISE EXCEPTION 'FACT_DETAIL_LINEAGE_INCONSISTENT' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER numeric_fact_event_open AFTER INSERT ON epm.numeric_fact_event
    REFERENCING NEW TABLE AS fact_inserted FOR EACH STATEMENT EXECUTE FUNCTION epm.fact_event_open();
CREATE TRIGGER text_fact_event_open AFTER INSERT ON epm.text_fact_event
    REFERENCING NEW TABLE AS fact_inserted FOR EACH STATEMENT EXECUTE FUNCTION epm.fact_event_open();
CREATE TRIGGER detail_fact_event_open AFTER INSERT ON epm.line_detail_event
    REFERENCING NEW TABLE AS fact_inserted FOR EACH STATEMENT EXECUTE FUNCTION epm.fact_event_open();

CREATE FUNCTION epm.fact_projection_matches() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF TG_TABLE_NAME='numeric_cell_current' THEN
        IF EXISTS(SELECT 1 FROM fact_projected c LEFT JOIN LATERAL(
            SELECT * FROM epm.numeric_fact_event e WHERE e.workspace_id=c.workspace_id AND e.application_id=c.application_id
              AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)e ON true
            LEFT JOIN epm.operation_receipt r ON r.workspace_id=e.workspace_id AND r.application_id=e.application_id AND r.operation_id=e.operation_id
            WHERE e.event_id IS NULL OR coalesce(r.sealed,true) OR ROW(c.present,c.amount,c.change_id,c.last_revision)
              IS DISTINCT FROM ROW(e.present,e.resulting_amount,e.change_id,e.committed_revision)) THEN
            RAISE EXCEPTION 'FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
        END IF;
    ELSIF TG_TABLE_NAME='text_cell_current' THEN
        IF EXISTS(SELECT 1 FROM fact_projected c LEFT JOIN LATERAL(
            SELECT * FROM epm.text_fact_event e WHERE e.workspace_id=c.workspace_id AND e.application_id=c.application_id
              AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)e ON true
            LEFT JOIN epm.operation_receipt r ON r.workspace_id=e.workspace_id AND r.application_id=e.application_id AND r.operation_id=e.operation_id
            WHERE e.event_id IS NULL OR coalesce(r.sealed,true) OR ROW(c.present,c.text_value,c.change_id,c.last_revision)
              IS DISTINCT FROM ROW(e.present,e.resulting_value,e.change_id,e.committed_revision)) THEN
            RAISE EXCEPTION 'FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
        END IF;
    ELSE
        IF EXISTS(SELECT 1 FROM fact_projected c LEFT JOIN LATERAL(
            SELECT * FROM epm.line_detail_event e WHERE e.workspace_id=c.workspace_id AND e.application_id=c.application_id
              AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC LIMIT 1)e ON true
            LEFT JOIN epm.operation_receipt r ON r.workspace_id=e.workspace_id AND r.application_id=e.application_id AND r.operation_id=e.operation_id
            WHERE e.event_id IS NULL OR coalesce(r.sealed,true) OR NOT e.present OR ROW(c.items,c.total,c.change_id,c.last_revision)
              IS DISTINCT FROM ROW(e.items,e.total,e.change_id,e.committed_revision)) THEN
            RAISE EXCEPTION 'FACT_DETAIL_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER numeric_projection_insert AFTER INSERT ON epm.numeric_cell_current REFERENCING NEW TABLE AS fact_projected
    FOR EACH STATEMENT EXECUTE FUNCTION epm.fact_projection_matches();
CREATE TRIGGER numeric_projection_update AFTER UPDATE ON epm.numeric_cell_current REFERENCING NEW TABLE AS fact_projected
    FOR EACH STATEMENT EXECUTE FUNCTION epm.fact_projection_matches();
CREATE TRIGGER text_projection_insert AFTER INSERT ON epm.text_cell_current REFERENCING NEW TABLE AS fact_projected
    FOR EACH STATEMENT EXECUTE FUNCTION epm.fact_projection_matches();
CREATE TRIGGER text_projection_update AFTER UPDATE ON epm.text_cell_current REFERENCING NEW TABLE AS fact_projected
    FOR EACH STATEMENT EXECUTE FUNCTION epm.fact_projection_matches();
CREATE TRIGGER detail_projection_insert AFTER INSERT ON epm.line_detail_current REFERENCING NEW TABLE AS fact_projected
    FOR EACH STATEMENT EXECUTE FUNCTION epm.fact_projection_matches();
CREATE TRIGGER detail_projection_update AFTER UPDATE ON epm.line_detail_current REFERENCING NEW TABLE AS fact_projected
    FOR EACH STATEMENT EXECUTE FUNCTION epm.fact_projection_matches();

REVOKE ALL ON FUNCTION epm.fact_scope_check(text,text,boolean),epm.fact_commit_epoch_guard(),epm.fact_commit_epoch_close(),
    epm.fact_reconcile(text,text,text),epm.fact_receipt_guard(),epm.fact_receipt_close(),epm.fact_event_open(),epm.fact_projection_matches() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.fact_scope_check(text,text,boolean),epm.fact_commit_epoch_guard(),epm.fact_commit_epoch_close()
    TO epm_runtime,epm_lifecycle;
GRANT EXECUTE ON FUNCTION epm.fact_reconcile(text,text,text),epm.fact_receipt_guard(),epm.fact_receipt_close(),epm.fact_event_open(),epm.fact_projection_matches()
    TO epm_runtime;
GRANT UPDATE(sealed) ON epm.operation_receipt TO epm_runtime;
GRANT UPDATE(commit_open) ON epm.application_state TO epm_runtime;

CREATE FUNCTION epm.fact_detail_delete_matches() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    -- Reset deletes history before projections under its existing privileged
    -- manifest workflow. Runtime cannot delete immutable detail history.
    IF EXISTS(SELECT 1 FROM fact_deleted c JOIN LATERAL(
        SELECT * FROM epm.line_detail_event e WHERE e.workspace_id=c.workspace_id AND e.application_id=c.application_id
          AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC LIMIT 1)e ON true
        LEFT JOIN epm.operation_receipt r ON r.workspace_id=e.workspace_id AND r.application_id=e.application_id AND r.operation_id=e.operation_id
        WHERE e.present OR coalesce(r.sealed,true)) THEN
        RAISE EXCEPTION 'FACT_DETAIL_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER detail_projection_delete AFTER DELETE ON epm.line_detail_current REFERENCING OLD TABLE AS fact_deleted
    FOR EACH STATEMENT EXECUTE FUNCTION epm.fact_detail_delete_matches();
REVOKE ALL ON FUNCTION epm.fact_detail_delete_matches() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.fact_detail_delete_matches() TO epm_runtime;

-- Fail rather than silently blessing inconsistent pre-upgrade state. These
-- checks do not rewrite business values/events or fabricate missing history.
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM epm.operation_receipt r JOIN epm.application_state s USING(workspace_id,application_id)
        WHERE r.committed_revision>s.commit_revision)
       OR EXISTS(SELECT 1 FROM (
          SELECT workspace_id,application_id,operation_id,committed_revision FROM epm.numeric_fact_event
          UNION ALL SELECT workspace_id,application_id,operation_id,committed_revision FROM epm.text_fact_event
          UNION ALL SELECT workspace_id,application_id,operation_id,committed_revision FROM epm.line_detail_event)e
          JOIN epm.operation_receipt r USING(workspace_id,application_id,operation_id)
          WHERE e.committed_revision<>r.committed_revision) THEN
        RAISE EXCEPTION 'LEGACY_FACT_PUBLICATION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
    IF EXISTS(SELECT 1 FROM epm.numeric_cell_current c LEFT JOIN LATERAL(
          SELECT * FROM epm.numeric_fact_event e WHERE e.workspace_id=c.workspace_id AND e.application_id=c.application_id
          AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)e ON true
          WHERE e.event_id IS NULL OR ROW(c.present,c.amount,c.change_id,c.last_revision)
            IS DISTINCT FROM ROW(e.present,e.resulting_amount,e.change_id,e.committed_revision))
       OR EXISTS(SELECT 1 FROM epm.text_cell_current c LEFT JOIN LATERAL(
          SELECT * FROM epm.text_fact_event e WHERE e.workspace_id=c.workspace_id AND e.application_id=c.application_id
          AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)e ON true
          WHERE e.event_id IS NULL OR ROW(c.present,c.text_value,c.change_id,c.last_revision)
            IS DISTINCT FROM ROW(e.present,e.resulting_value,e.change_id,e.committed_revision))
       OR EXISTS(SELECT 1 FROM epm.numeric_fact_event e WHERE NOT EXISTS(SELECT 1 FROM epm.numeric_cell_current c
          WHERE c.workspace_id=e.workspace_id AND c.application_id=e.application_id AND c.coordinate_id=e.coordinate_id))
       OR EXISTS(SELECT 1 FROM epm.text_fact_event e WHERE NOT EXISTS(SELECT 1 FROM epm.text_cell_current c
          WHERE c.workspace_id=e.workspace_id AND c.application_id=e.application_id AND c.coordinate_id=e.coordinate_id)) THEN
        RAISE EXCEPTION 'LEGACY_FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
END $$;

DO $$ BEGIN
    IF EXISTS(WITH latest AS (
          SELECT DISTINCT ON(workspace_id,application_id,coordinate_id) *
          FROM epm.line_detail_event
          ORDER BY workspace_id,application_id,coordinate_id,committed_revision DESC)
       SELECT 1 FROM latest e FULL JOIN epm.line_detail_current c
          USING(workspace_id,application_id,coordinate_id)
       LEFT JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
       WHERE e.event_id IS NULL
          OR (e.present AND (c.coordinate_id IS NULL
             OR ROW(c.items,c.total,c.change_id,c.last_revision)
                 IS DISTINCT FROM ROW(e.items,e.total,e.change_id,e.committed_revision)
             OR NOT coalesce(n.present,false) OR n.amount<>e.total))
          OR (NOT e.present AND c.coordinate_id IS NOT NULL))
       OR EXISTS(SELECT 1 FROM epm.line_detail_event e
          WHERE e.total<>(SELECT coalesce(sum((x->>'amount')::numeric),0)
             FROM jsonb_array_elements(e.items)x)) THEN
        RAISE EXCEPTION 'LEGACY_FACT_DETAIL_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
END $$;
