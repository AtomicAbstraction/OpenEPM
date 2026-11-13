-- Durable, application-scoped financial period close bound to the generic
-- planning lock that every authoritative fact writer already enforces.
CREATE TABLE epm.financial_period_close (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    close_id text NOT NULL CHECK (close_id ~ '^[0-9a-f]{32}$'),
    lock_id text NOT NULL CHECK (lock_id ~ '^[0-9a-f]{32}$'),
    scope_members jsonb NOT NULL CHECK (jsonb_typeof(scope_members)='object'),
    reconciliation_digest text NOT NULL CHECK (reconciliation_digest ~ '^[0-9a-f]{64}$'),
    reconciliation_lineage_digest text NOT NULL CHECK (reconciliation_lineage_digest ~ '^[0-9a-f]{64}$'),
    reconciliation_program jsonb NOT NULL CHECK (jsonb_typeof(reconciliation_program)='object'),
    status text NOT NULL CHECK (status IN ('Closed','Reopened')),
    version bigint NOT NULL CHECK (version IN (1,2)),
    close_issuer text NOT NULL CHECK (length(close_issuer) BETWEEN 1 AND 300),
    close_subject_id text NOT NULL CHECK (length(close_subject_id) BETWEEN 1 AND 300),
    close_reason text NOT NULL CHECK (length(close_reason) BETWEEN 1 AND 500),
    closed_revision bigint NOT NULL CHECK (closed_revision>0),
    reopen_issuer text,
    reopen_subject_id text,
    reopen_reason text,
    reopened_revision bigint,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,close_id),
    UNIQUE (workspace_id,application_id,lock_id),
    FOREIGN KEY (workspace_id,application_id,lock_id)
        REFERENCES epm.planning_slice_lock(workspace_id,application_id,lock_id)
        ON DELETE RESTRICT,
    CHECK ((status='Closed' AND version=1 AND reopen_issuer IS NULL
            AND reopen_subject_id IS NULL AND reopen_reason IS NULL
            AND reopened_revision IS NULL)
        OR (status='Reopened' AND version=2 AND reopen_issuer IS NOT NULL
            AND reopen_subject_id IS NOT NULL AND reopen_reason IS NOT NULL
            AND reopened_revision>closed_revision))
);
CREATE INDEX financial_period_close_active ON epm.financial_period_close
    (workspace_id,application_id,status,created_at);

CREATE TABLE epm.financial_period_close_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    close_id text NOT NULL,
    event_ordinal integer NOT NULL CHECK (event_ordinal IN (1,2)),
    kind text NOT NULL CHECK (kind IN ('Closed','Reopened')),
    issuer text NOT NULL,
    subject_id text NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    committed_revision bigint NOT NULL CHECK (committed_revision>0),
    occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,close_id,event_ordinal),
    FOREIGN KEY (workspace_id,application_id,close_id)
        REFERENCES epm.financial_period_close(workspace_id,application_id,close_id)
        ON DELETE RESTRICT,
    CHECK ((event_ordinal=1 AND kind='Closed')
        OR (event_ordinal=2 AND kind='Reopened'))
);

GRANT SELECT,INSERT ON epm.financial_period_close,
    epm.financial_period_close_event TO epm_runtime;
GRANT UPDATE (status,version,reopen_issuer,reopen_subject_id,reopen_reason,
    reopened_revision,updated_at) ON epm.financial_period_close TO epm_runtime;
ALTER TABLE epm.financial_period_close ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.financial_period_close_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY financial_period_close_scope ON epm.financial_period_close
    TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY financial_period_close_event_scope
    ON epm.financial_period_close_event TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));

CREATE FUNCTION epm.validate_financial_period_close_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.status<>'Closed' OR NEW.version<>1
           OR NEW.reopened_revision IS NOT NULL THEN
            RAISE EXCEPTION 'FINANCIAL_CLOSE_INITIAL_STATE_INVALID';
        END IF;
    ELSIF OLD.status<>'Closed' OR NEW.status<>'Reopened'
          OR NEW.version<>2 OR NEW.reopened_revision IS NULL
          OR NEW.reopened_revision<=OLD.closed_revision THEN
        RAISE EXCEPTION 'FINANCIAL_CLOSE_TRANSITION_INVALID';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.validate_financial_period_close_transition() FROM PUBLIC;
CREATE TRIGGER financial_period_close_transition BEFORE INSERT OR UPDATE
    ON epm.financial_period_close FOR EACH ROW
    EXECUTE FUNCTION epm.validate_financial_period_close_transition();

-- Reset/delete remains child-first: close events, close records, then their
-- generic planning locks. Active closes are history, not unsettled work.
DO $$DECLARE d text;r text;needle text:='''planning_submission'',''planning_lock_event''';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO d;
 IF position(needle in d)=0
    OR position(needle in substring(d FROM position(needle in d)+length(needle)))>0
 THEN RAISE EXCEPTION 'RESET_0137_DEFINITION_MISMATCH'; END IF;
 r:=replace(d,needle,'''financial_period_close_event'',''financial_period_close'',''planning_submission'',''planning_lock_event''');
 EXECUTE r;
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO r;
 IF position('''financial_period_close_event'',''financial_period_close'',''planning_submission'',''planning_lock_event''' in r)=0
 THEN RAISE EXCEPTION 'RESET_0137_RESULT_MISMATCH'; END IF;
END $$;
