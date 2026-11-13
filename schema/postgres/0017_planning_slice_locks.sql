-- Generic planning slice locks fence authoritative numeric/text/detail writes.
-- A lock is a stable-ID equality filter over any subset of active dimensions.

CREATE TABLE epm.planning_slice_lock (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    lock_id text NOT NULL CHECK (lock_id ~ '^[0-9a-f]{32}$'),
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 300),
    idempotency_key text NOT NULL
        CHECK (idempotency_key ~ '^[A-Za-z0-9._-]{8,128}$'),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    scope_members jsonb NOT NULL CHECK (jsonb_typeof(scope_members)='object'),
    scope_all boolean NOT NULL,
    status text NOT NULL CHECK (status IN ('Locked','Open')),
    version bigint NOT NULL CHECK (version>=1),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    locked_revision bigint NOT NULL CHECK (locked_revision>0),
    reopened_revision bigint CHECK (reopened_revision IS NULL
                                  OR reopened_revision>locked_revision),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,lock_id),
    UNIQUE (workspace_id,application_id,issuer,subject_id,idempotency_key),
    FOREIGN KEY (workspace_id,application_id)
        REFERENCES epm.application_state(workspace_id,application_id)
        ON DELETE RESTRICT,
    CHECK (scope_all=(scope_members='{}'::jsonb)),
    CHECK ((status='Locked')=(reopened_revision IS NULL))
);
CREATE INDEX planning_slice_active ON epm.planning_slice_lock
    (workspace_id,application_id,status,created_at);

CREATE TABLE epm.planning_lock_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    lock_id text NOT NULL,
    event_ordinal integer NOT NULL CHECK (event_ordinal IN (1,2)),
    kind text NOT NULL CHECK (kind IN ('Locked','Reopened')),
    issuer text NOT NULL,
    subject_id text NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    committed_revision bigint NOT NULL CHECK (committed_revision>0),
    occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,lock_id,event_ordinal),
    FOREIGN KEY (workspace_id,application_id,lock_id)
        REFERENCES epm.planning_slice_lock
        (workspace_id,application_id,lock_id) ON DELETE RESTRICT,
    CHECK ((event_ordinal=1 AND kind='Locked')
        OR (event_ordinal=2 AND kind='Reopened'))
);

GRANT SELECT,INSERT ON epm.planning_slice_lock TO epm_runtime;
GRANT UPDATE (status,version,reopened_revision,updated_at)
    ON epm.planning_slice_lock TO epm_runtime;
GRANT SELECT,INSERT ON epm.planning_lock_event TO epm_runtime;
GRANT UPDATE (policy_revision,commit_revision)
    ON epm.application_state TO epm_runtime;
ALTER TABLE epm.planning_slice_lock ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.planning_lock_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY planning_slice_scope ON epm.planning_slice_lock TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY planning_lock_event_scope ON epm.planning_lock_event TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));

CREATE FUNCTION epm.validate_planning_lock_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.status<>'Locked' OR NEW.version<>1
           OR NEW.reopened_revision IS NOT NULL THEN
            RAISE EXCEPTION 'PLANNING_LOCK_INITIAL_STATE_INVALID';
        END IF;
    ELSIF OLD.status<>'Locked' OR NEW.status<>'Open'
          OR NEW.version<>OLD.version+1
          OR NEW.reopened_revision IS NULL
          OR NEW.reopened_revision<=OLD.locked_revision THEN
        RAISE EXCEPTION 'PLANNING_LOCK_TRANSITION_INVALID';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.validate_planning_lock_transition() FROM PUBLIC;
CREATE TRIGGER planning_lock_transition BEFORE INSERT OR UPDATE
    ON epm.planning_slice_lock FOR EACH ROW
    EXECUTE FUNCTION epm.validate_planning_lock_transition();

CREATE FUNCTION epm.reject_locked_fact_write()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM affected_rows point
        JOIN epm.coordinate c ON c.workspace_id=point.workspace_id
        AND c.application_id=point.application_id
        AND c.coordinate_id=point.coordinate_id
        JOIN epm.planning_slice_lock l
        ON l.workspace_id=point.workspace_id
        AND l.application_id=point.application_id
        AND l.status='Locked'
        AND (l.scope_all OR c.members @> l.scope_members)
        LIMIT 1) THEN
        RAISE EXCEPTION 'PLANNING_SLICE_LOCKED'
            USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' THEN
        IF EXISTS (
            SELECT 1 FROM prior_rows point
            JOIN epm.coordinate c ON c.workspace_id=point.workspace_id
            AND c.application_id=point.application_id
            AND c.coordinate_id=point.coordinate_id
            JOIN epm.planning_slice_lock l
            ON l.workspace_id=point.workspace_id
            AND l.application_id=point.application_id
            AND l.status='Locked'
            AND (l.scope_all OR c.members @> l.scope_members)
            LIMIT 1) THEN
            RAISE EXCEPTION 'PLANNING_SLICE_LOCKED'
                USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION epm.reject_locked_fact_write() FROM PUBLIC;
CREATE TRIGGER planning_lock_numeric_insert AFTER INSERT
    ON epm.numeric_cell_current REFERENCING NEW TABLE AS affected_rows
    FOR EACH STATEMENT EXECUTE FUNCTION epm.reject_locked_fact_write();
CREATE TRIGGER planning_lock_numeric_update AFTER UPDATE
    ON epm.numeric_cell_current
    REFERENCING OLD TABLE AS prior_rows NEW TABLE AS affected_rows
    FOR EACH STATEMENT EXECUTE FUNCTION epm.reject_locked_fact_write();
CREATE TRIGGER planning_lock_numeric_delete AFTER DELETE
    ON epm.numeric_cell_current REFERENCING OLD TABLE AS affected_rows
    FOR EACH STATEMENT EXECUTE FUNCTION epm.reject_locked_fact_write();
CREATE TRIGGER planning_lock_text_insert AFTER INSERT
    ON epm.text_cell_current REFERENCING NEW TABLE AS affected_rows
    FOR EACH STATEMENT EXECUTE FUNCTION epm.reject_locked_fact_write();
CREATE TRIGGER planning_lock_text_update AFTER UPDATE
    ON epm.text_cell_current
    REFERENCING OLD TABLE AS prior_rows NEW TABLE AS affected_rows
    FOR EACH STATEMENT EXECUTE FUNCTION epm.reject_locked_fact_write();
CREATE TRIGGER planning_lock_text_delete AFTER DELETE
    ON epm.text_cell_current REFERENCING OLD TABLE AS affected_rows
    FOR EACH STATEMENT EXECUTE FUNCTION epm.reject_locked_fact_write();
CREATE TRIGGER planning_lock_detail_insert AFTER INSERT
    ON epm.line_detail_current REFERENCING NEW TABLE AS affected_rows
    FOR EACH STATEMENT EXECUTE FUNCTION epm.reject_locked_fact_write();
CREATE TRIGGER planning_lock_detail_update AFTER UPDATE
    ON epm.line_detail_current
    REFERENCING OLD TABLE AS prior_rows NEW TABLE AS affected_rows
    FOR EACH STATEMENT EXECUTE FUNCTION epm.reject_locked_fact_write();
CREATE TRIGGER planning_lock_detail_delete AFTER DELETE
    ON epm.line_detail_current REFERENCING OLD TABLE AS affected_rows
    FOR EACH STATEMENT EXECUTE FUNCTION epm.reject_locked_fact_write();
