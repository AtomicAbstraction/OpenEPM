-- Generic JSON writes publish projections/events before their receipt. Validate
-- the open revision immediately, and the complete receipt/history at COMMIT.
CREATE UNIQUE INDEX generic_fact_event_revision_series
    ON epm.generic_fact_event(workspace_id,application_id,table_id,series_key,committed_revision);

CREATE FUNCTION epm.generic_fact_write_open() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    -- Serialize with the same short application publication gate as fixed core.
    PERFORM 1 FROM epm.application_state s WHERE EXISTS(SELECT 1 FROM generic_inserted i
       WHERE i.workspace_id=s.workspace_id AND i.application_id=s.application_id) FOR UPDATE;
    IF TG_TABLE_NAME='generic_fact_event' THEN
        IF EXISTS(SELECT 1 FROM generic_inserted i JOIN epm.operation_receipt r
           USING(workspace_id,application_id,operation_id) WHERE r.sealed) THEN
            RAISE EXCEPTION 'GENERIC_FACT_OPERATION_SEALED' USING ERRCODE='23514';
        END IF;
        IF EXISTS(SELECT 1 FROM generic_inserted i LEFT JOIN epm.application_state s
           USING(workspace_id,application_id) WHERE s.commit_revision IS NULL OR NOT
           (i.committed_revision=s.commit_revision+1 OR
             (i.committed_revision=s.commit_revision AND s.commit_open))) THEN
            RAISE EXCEPTION 'GENERIC_FACT_REVISION_INVALID' USING ERRCODE='23514';
        END IF;
        IF EXISTS(SELECT 1 FROM generic_inserted i WHERE
           i.resulting_change_id!~'^[0-9a-f]{32}$' OR
           (i.action='Create' AND (i.before_value IS NOT NULL OR i.before_change_id<>'')) OR
           (i.action IN ('Update','Delete') AND
             (i.before_value IS NULL OR i.before_value='null'::jsonb OR i.before_change_id!~'^[0-9a-f]{32}$')) OR
           (i.action='Delete' AND i.after_value IS NOT NULL) OR
           (i.action<>'Delete' AND (i.after_value IS NULL OR i.after_value='null'::jsonb))) THEN
            RAISE EXCEPTION 'GENERIC_FACT_EVENT_SHAPE_INVALID' USING ERRCODE='23514';
        END IF;
    ELSE
        IF EXISTS(SELECT 1 FROM generic_inserted i LEFT JOIN epm.application_state s
           USING(workspace_id,application_id) WHERE s.commit_revision IS NULL OR NOT
           (i.last_revision=s.commit_revision+1 OR
             (i.last_revision=s.commit_revision AND s.commit_open))) THEN
            RAISE EXCEPTION 'GENERIC_FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER generic_event_write_open AFTER INSERT ON epm.generic_fact_event
    REFERENCING NEW TABLE AS generic_inserted FOR EACH STATEMENT EXECUTE FUNCTION epm.generic_fact_write_open();
CREATE TRIGGER generic_projection_insert_open AFTER INSERT ON epm.generic_fact_current
    REFERENCING NEW TABLE AS generic_inserted FOR EACH STATEMENT EXECUTE FUNCTION epm.generic_fact_write_open();
CREATE TRIGGER generic_projection_update_open AFTER UPDATE ON epm.generic_fact_current
    REFERENCING NEW TABLE AS generic_inserted FOR EACH STATEMENT EXECUTE FUNCTION epm.generic_fact_write_open();

CREATE FUNCTION epm.generic_fact_projection_check(w text,a text,t text,k text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE e epm.generic_fact_event%ROWTYPE; c epm.generic_fact_current%ROWTYPE;
BEGIN
    PERFORM epm.fact_scope_check(w,a);
    SELECT * INTO e FROM epm.generic_fact_event WHERE workspace_id=w AND application_id=a
      AND table_id=t AND series_key=k ORDER BY committed_revision DESC LIMIT 1;
    SELECT * INTO c FROM epm.generic_fact_current WHERE workspace_id=w AND application_id=a
      AND table_id=t AND series_key=k;
    IF (e.event_id IS NULL AND c.series_key IS NOT NULL)
       OR (e.action='Delete' AND c.series_key IS NOT NULL)
       OR (e.action<>'Delete' AND (c.series_key IS NULL OR
           ROW(c.value,c.change_id,c.last_revision) IS DISTINCT FROM
           ROW(e.after_value,e.resulting_change_id,e.committed_revision))) THEN
        RAISE EXCEPTION 'GENERIC_FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
END $$;

CREATE FUNCTION epm.generic_fact_event_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE r epm.operation_receipt%ROWTYPE; p epm.generic_fact_event%ROWTYPE; head bigint;
BEGIN
    PERFORM epm.fact_scope_check(NEW.workspace_id,NEW.application_id);
    SELECT * INTO r FROM epm.operation_receipt WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id AND operation_id=NEW.operation_id;
    IF r.operation_id IS NULL THEN
        RAISE EXCEPTION 'GENERIC_FACT_RECEIPT_REQUIRED' USING ERRCODE='23514';
    END IF;
    SELECT commit_revision INTO head FROM epm.application_state WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id;
    IF NEW.committed_revision<>r.committed_revision OR r.committed_revision>head
       OR NEW.actor_id<>r.actor_id THEN
        RAISE EXCEPTION 'GENERIC_FACT_RECEIPT_MISMATCH' USING ERRCODE='23514';
    END IF;
    SELECT * INTO p FROM epm.generic_fact_event WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id AND table_id=NEW.table_id AND series_key=NEW.series_key
      AND committed_revision<NEW.committed_revision ORDER BY committed_revision DESC LIMIT 1;
    IF NEW.before_value IS DISTINCT FROM (CASE WHEN p.action<>'Delete' THEN p.after_value ELSE NULL END)
       OR NEW.before_change_id IS DISTINCT FROM (CASE WHEN p.action<>'Delete' THEN p.resulting_change_id ELSE '' END)
       OR (NEW.action='Create') IS DISTINCT FROM (p.event_id IS NULL OR p.action='Delete') THEN
        RAISE EXCEPTION 'GENERIC_FACT_LINEAGE_INCONSISTENT' USING ERRCODE='23514';
    END IF;
    PERFORM epm.generic_fact_projection_check(NEW.workspace_id,NEW.application_id,NEW.table_id,NEW.series_key);
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER generic_event_complete AFTER INSERT ON epm.generic_fact_event
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION epm.generic_fact_event_complete();

CREATE FUNCTION epm.generic_fact_projection_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        PERFORM epm.fact_scope_check(OLD.workspace_id,OLD.application_id);
        -- The reviewed owner-only reset deletes history before projections.
        IF NOT EXISTS(SELECT 1 FROM epm.generic_fact_event WHERE workspace_id=OLD.workspace_id
            AND application_id=OLD.application_id AND table_id=OLD.table_id AND series_key=OLD.series_key)
           AND pg_has_role(current_user,(SELECT relowner FROM pg_class
               WHERE oid='epm.operation_receipt'::regclass),'USAGE') THEN RETURN NULL; END IF;
        IF NOT EXISTS(SELECT 1 FROM epm.generic_fact_event WHERE workspace_id=OLD.workspace_id
            AND application_id=OLD.application_id AND table_id=OLD.table_id AND series_key=OLD.series_key
            AND action='Delete' AND committed_revision>OLD.last_revision) THEN
            RAISE EXCEPTION 'GENERIC_FACT_DELETE_EVENT_REQUIRED' USING ERRCODE='23514';
        END IF;
        PERFORM epm.generic_fact_projection_check(OLD.workspace_id,OLD.application_id,OLD.table_id,OLD.series_key);
    ELSE
        PERFORM epm.generic_fact_projection_check(NEW.workspace_id,NEW.application_id,NEW.table_id,NEW.series_key);
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER generic_projection_complete AFTER INSERT OR UPDATE OR DELETE ON epm.generic_fact_current
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION epm.generic_fact_projection_complete();

REVOKE ALL ON FUNCTION epm.generic_fact_write_open(),epm.generic_fact_projection_check(text,text,text,text),
    epm.generic_fact_event_complete(),epm.generic_fact_projection_complete() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.generic_fact_write_open(),epm.generic_fact_projection_check(text,text,text,text),
    epm.generic_fact_event_complete(),epm.generic_fact_projection_complete() TO epm_runtime;

-- Refuse inconsistent legacy state; never synthesize or rewrite business history.
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM epm.generic_fact_event e LEFT JOIN epm.operation_receipt r
       USING(workspace_id,application_id,operation_id)
       LEFT JOIN epm.application_state s USING(workspace_id,application_id)
       WHERE r.operation_id IS NULL OR e.committed_revision<>r.committed_revision
          OR e.actor_id<>r.actor_id OR e.committed_revision>s.commit_revision) THEN
        RAISE EXCEPTION 'LEGACY_GENERIC_FACT_RECEIPT_INCONSISTENT' USING ERRCODE='23514';
    END IF;
    IF EXISTS(SELECT 1 FROM epm.generic_fact_event e WHERE
       e.resulting_change_id!~'^[0-9a-f]{32}$' OR
       (e.action='Create' AND (e.before_value IS NOT NULL OR e.before_change_id<>'')) OR
       (e.action IN ('Update','Delete') AND
          (e.before_value IS NULL OR e.before_value='null'::jsonb OR e.before_change_id!~'^[0-9a-f]{32}$')) OR
       (e.action='Delete' AND e.after_value IS NOT NULL) OR
       (e.action<>'Delete' AND (e.after_value IS NULL OR e.after_value='null'::jsonb))) THEN
        RAISE EXCEPTION 'LEGACY_GENERIC_FACT_EVENT_SHAPE_INVALID' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH history AS(SELECT *,lag(action) OVER series AS prior_action,
       lag(after_value) OVER series AS prior_value,lag(resulting_change_id) OVER series AS prior_id
       FROM epm.generic_fact_event WINDOW series AS(PARTITION BY workspace_id,application_id,table_id,series_key
          ORDER BY committed_revision))
       SELECT 1 FROM history WHERE
          before_value IS DISTINCT FROM CASE WHEN prior_action<>'Delete' THEN prior_value ELSE NULL END OR
          before_change_id IS DISTINCT FROM CASE WHEN prior_action<>'Delete' THEN prior_id ELSE '' END OR
          (action='Create') IS DISTINCT FROM (prior_action IS NULL OR prior_action='Delete')) THEN
        RAISE EXCEPTION 'LEGACY_GENERIC_FACT_LINEAGE_INCONSISTENT' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH latest AS(SELECT DISTINCT ON(workspace_id,application_id,table_id,series_key) *
       FROM epm.generic_fact_event ORDER BY workspace_id,application_id,table_id,series_key,committed_revision DESC)
       SELECT 1 FROM latest e FULL JOIN epm.generic_fact_current c USING(workspace_id,application_id,table_id,series_key)
       WHERE (e.event_id IS NULL AND c.series_key IS NOT NULL) OR
          (e.action='Delete' AND c.series_key IS NOT NULL) OR
          (e.action<>'Delete' AND (c.series_key IS NULL OR
             ROW(c.value,c.change_id,c.last_revision) IS DISTINCT FROM ROW(e.after_value,e.resulting_change_id,e.committed_revision)))) THEN
        RAISE EXCEPTION 'LEGACY_GENERIC_FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
END $$;
