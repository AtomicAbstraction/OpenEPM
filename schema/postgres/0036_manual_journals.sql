-- Immutable, explicitly authored financial adjustments. Journals are a
-- distinct layer: posting never overwrites input balances. A reversal is a
-- second balanced journal linked to the first, not an UPDATE of its lines.
CREATE TABLE epm.manual_journal (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    journal_id text NOT NULL CHECK
        (journal_id ~ '^[A-Za-z0-9._-]{8,128}$'),
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 300),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    reversal_of text,
    metadata_revision bigint NOT NULL CHECK (metadata_revision>=0),
    policy_revision bigint NOT NULL CHECK (policy_revision>=0),
    committed_revision bigint NOT NULL CHECK (committed_revision>0),
    posted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,journal_id),
    FOREIGN KEY (workspace_id,application_id)
        REFERENCES epm.application_state(workspace_id,application_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,journal_id)
        REFERENCES epm.operation_receipt
        (workspace_id,application_id,operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,reversal_of)
        REFERENCES epm.manual_journal
        (workspace_id,application_id,journal_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX manual_journal_one_reversal
    ON epm.manual_journal(workspace_id,application_id,reversal_of)
    WHERE reversal_of IS NOT NULL;

CREATE TABLE epm.manual_journal_line (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    journal_id text NOT NULL,
    line_ordinal integer NOT NULL CHECK (line_ordinal BETWEEN 1 AND 100),
    coordinate_id bigint NOT NULL,
    signed_amount numeric(28,8) NOT NULL CHECK (signed_amount<>0),
    source_ref text NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 200),
    PRIMARY KEY (workspace_id,application_id,journal_id,line_ordinal),
    UNIQUE (workspace_id,application_id,journal_id,coordinate_id),
    FOREIGN KEY (workspace_id,application_id,journal_id)
        REFERENCES epm.manual_journal
        (workspace_id,application_id,journal_id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,coordinate_id)
        REFERENCES epm.coordinate
        (workspace_id,application_id,coordinate_id) ON DELETE RESTRICT
);
CREATE INDEX manual_journal_line_coordinate
    ON epm.manual_journal_line
    (workspace_id,application_id,coordinate_id,journal_id);

-- Apply the same closed-slice invariant as current facts. A journal is an
-- effective write to a finance slice even though it leaves raw facts intact.
CREATE TRIGGER planning_lock_manual_journal_insert AFTER INSERT
    ON epm.manual_journal_line REFERENCING NEW TABLE AS affected_rows
    FOR EACH STATEMENT EXECUTE FUNCTION epm.reject_locked_fact_write();

GRANT SELECT,INSERT ON epm.manual_journal,
    epm.manual_journal_line TO epm_runtime;
ALTER TABLE epm.manual_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.manual_journal_line ENABLE ROW LEVEL SECURITY;
CREATE POLICY manual_journal_runtime_scope ON epm.manual_journal
    TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY manual_journal_line_runtime_scope ON epm.manual_journal_line
    TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
