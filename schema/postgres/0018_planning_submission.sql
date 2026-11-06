-- Optional, explicit planning submission and assigned-reviewer decision.
-- A submission owns an ordinary planning slice lock; no application has a
-- mandatory review queue merely because this schema exists.

CREATE TABLE epm.planning_submission (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    lock_id text NOT NULL,
    submitter_issuer text NOT NULL CHECK (length(submitter_issuer) BETWEEN 1 AND 300),
    submitter_subject_id text NOT NULL CHECK (length(submitter_subject_id) BETWEEN 1 AND 300),
    reviewer_issuer text NOT NULL CHECK (length(reviewer_issuer) BETWEEN 1 AND 300),
    reviewer_subject_id text NOT NULL CHECK (length(reviewer_subject_id) BETWEEN 1 AND 300),
    status text NOT NULL CHECK (status IN ('Submitted','Approved','Reopened')),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 3),
    submitted_revision bigint NOT NULL CHECK (submitted_revision>0),
    approved_revision bigint,
    reopened_revision bigint,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,lock_id),
    FOREIGN KEY (workspace_id,application_id,lock_id)
        REFERENCES epm.planning_slice_lock
        (workspace_id,application_id,lock_id) ON DELETE RESTRICT,
    CHECK ((status='Submitted' AND version=1
            AND approved_revision IS NULL AND reopened_revision IS NULL)
        OR (status='Approved' AND version=2
            AND approved_revision>submitted_revision
            AND reopened_revision IS NULL)
        OR (status='Reopened' AND version IN (2,3)
            AND reopened_revision>submitted_revision
            AND ((version=2 AND approved_revision IS NULL)
              OR (version=3 AND approved_revision>submitted_revision
                  AND reopened_revision>approved_revision))))
);

CREATE TABLE epm.planning_submission_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    lock_id text NOT NULL,
    event_ordinal integer NOT NULL CHECK (event_ordinal BETWEEN 1 AND 3),
    kind text NOT NULL CHECK (kind IN ('Submitted','Approved','Reopened')),
    issuer text NOT NULL,
    subject_id text NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    committed_revision bigint NOT NULL CHECK (committed_revision>0),
    occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,lock_id,event_ordinal),
    FOREIGN KEY (workspace_id,application_id,lock_id)
        REFERENCES epm.planning_submission
        (workspace_id,application_id,lock_id) ON DELETE RESTRICT,
    CHECK ((event_ordinal=1 AND kind='Submitted')
        OR (event_ordinal=2 AND kind IN ('Approved','Reopened'))
        OR (event_ordinal=3 AND kind='Reopened'))
);

GRANT SELECT,INSERT ON epm.planning_submission TO epm_runtime;
GRANT UPDATE (status,version,approved_revision,reopened_revision,updated_at)
    ON epm.planning_submission TO epm_runtime;
GRANT SELECT,INSERT ON epm.planning_submission_event TO epm_runtime;
ALTER TABLE epm.planning_submission ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.planning_submission_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY planning_submission_scope ON epm.planning_submission TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY planning_submission_event_scope
    ON epm.planning_submission_event TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));

CREATE FUNCTION epm.validate_planning_submission_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.status<>'Submitted' OR NEW.version<>1 THEN
            RAISE EXCEPTION 'PLANNING_SUBMISSION_INITIAL_STATE_INVALID';
        END IF;
    ELSIF NOT (
        (OLD.status='Submitted' AND NEW.status='Approved'
            AND NEW.version=2 AND NEW.approved_revision IS NOT NULL)
        OR (OLD.status='Submitted' AND NEW.status='Reopened'
            AND NEW.version=2 AND NEW.reopened_revision IS NOT NULL)
        OR (OLD.status='Approved' AND NEW.status='Reopened'
            AND NEW.version=3 AND NEW.reopened_revision IS NOT NULL)) THEN
        RAISE EXCEPTION 'PLANNING_SUBMISSION_TRANSITION_INVALID';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.validate_planning_submission_transition() FROM PUBLIC;
CREATE TRIGGER planning_submission_transition BEFORE INSERT OR UPDATE
    ON epm.planning_submission FOR EACH ROW
    EXECUTE FUNCTION epm.validate_planning_submission_transition();
