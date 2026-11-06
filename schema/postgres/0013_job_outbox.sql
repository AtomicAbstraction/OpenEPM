-- Commit-ordered application job events. A transactional per-application
-- cursor serializes event writers so a reconnecting reader cannot skip an
-- event whose sequence was allocated before a later transaction committed.

CREATE TABLE epm.job_event_cursor (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    last_sequence bigint NOT NULL CHECK (last_sequence > 0),
    PRIMARY KEY (workspace_id,application_id),
    FOREIGN KEY (workspace_id,application_id)
        REFERENCES epm.application_state(workspace_id,application_id)
        ON DELETE CASCADE
);

CREATE TABLE epm.job_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    job_id text NOT NULL,
    issuer text NOT NULL,
    subject_id text NOT NULL,
    status text NOT NULL,
    claim_generation bigint NOT NULL CHECK (claim_generation >= 0),
    receipt_revision bigint,
    error_code text,
    occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,sequence),
    FOREIGN KEY (workspace_id,application_id,job_id)
        REFERENCES epm.job(workspace_id,application_id,job_id)
        ON DELETE CASCADE
);
CREATE INDEX job_event_owner_page ON epm.job_event
    (workspace_id,application_id,issuer,subject_id,sequence);

CREATE FUNCTION epm.record_job_transition() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE next_sequence bigint;
BEGIN
    IF TG_OP='UPDATE' AND NEW.status=OLD.status
       AND NEW.claim_generation=OLD.claim_generation THEN
        RETURN NEW;
    END IF;
    INSERT INTO epm.job_event_cursor
        (workspace_id,application_id,last_sequence)
        VALUES (NEW.workspace_id,NEW.application_id,1)
        ON CONFLICT (workspace_id,application_id) DO UPDATE
        SET last_sequence=epm.job_event_cursor.last_sequence+1
        RETURNING last_sequence INTO next_sequence;
    INSERT INTO epm.job_event
        (workspace_id,application_id,sequence,job_id,issuer,subject_id,
         status,claim_generation,receipt_revision,error_code)
        VALUES (NEW.workspace_id,NEW.application_id,next_sequence,
                NEW.job_id,NEW.issuer,NEW.subject_id,NEW.status,
                NEW.claim_generation,NEW.receipt_revision,NEW.error_code);
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.record_job_transition() FROM PUBLIC;

CREATE TRIGGER job_transition_outbox
AFTER INSERT OR UPDATE OF status,claim_generation ON epm.job
FOR EACH ROW EXECUTE FUNCTION epm.record_job_transition();

GRANT SELECT ON epm.job_event TO epm_runtime;
ALTER TABLE epm.job_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY job_event_runtime_scope ON epm.job_event FOR SELECT TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
