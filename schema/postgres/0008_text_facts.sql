-- Generic text cells share coordinate/revision/receipt semantics with numeric
-- cells but do not admit arithmetic operations. Present empty text is valid.

CREATE TABLE epm.text_cell_current (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    coordinate_id bigint NOT NULL,
    present boolean NOT NULL,
    text_value text,
    change_id text NOT NULL CHECK (length(change_id) BETWEEN 1 AND 200),
    last_revision bigint NOT NULL CHECK (last_revision > 0),
    PRIMARY KEY (workspace_id, application_id, coordinate_id),
    FOREIGN KEY (workspace_id, application_id, coordinate_id)
        REFERENCES epm.coordinate(workspace_id, application_id, coordinate_id)
        ON DELETE RESTRICT,
    CHECK (present = (text_value IS NOT NULL)),
    CHECK (text_value IS NULL OR length(text_value) <= 32768)
);

CREATE TABLE epm.text_fact_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    event_id bigint GENERATED ALWAYS AS IDENTITY,
    coordinate_id bigint NOT NULL,
    operation_id text NOT NULL,
    line_ordinal integer NOT NULL CHECK (line_ordinal > 0),
    kind text NOT NULL CHECK (kind IN ('set','clear')),
    prior_present boolean NOT NULL,
    prior_value text,
    present boolean NOT NULL,
    resulting_value text,
    change_id text NOT NULL CHECK (length(change_id) BETWEEN 1 AND 200),
    committed_revision bigint NOT NULL CHECK (committed_revision > 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id, event_id),
    UNIQUE (workspace_id, application_id, committed_revision, line_ordinal),
    FOREIGN KEY (workspace_id, application_id, coordinate_id)
        REFERENCES epm.coordinate(workspace_id, application_id, coordinate_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id, application_id, operation_id)
        REFERENCES epm.operation_receipt(workspace_id, application_id,
                                         operation_id) ON DELETE RESTRICT,
    CHECK (prior_present = (prior_value IS NOT NULL)),
    CHECK (present = (resulting_value IS NOT NULL)),
    CHECK (prior_value IS NULL OR length(prior_value) <= 32768),
    CHECK (resulting_value IS NULL OR length(resulting_value) <= 32768)
);
CREATE INDEX text_fact_event_replay ON epm.text_fact_event
    (workspace_id, application_id, coordinate_id,
     committed_revision DESC, line_ordinal DESC);

GRANT SELECT ON epm.text_cell_current, epm.text_fact_event
    TO epm_runtime, epm_analyst;
GRANT INSERT ON epm.text_cell_current, epm.text_fact_event TO epm_runtime;
GRANT UPDATE ON epm.text_cell_current TO epm_runtime;
GRANT USAGE ON SEQUENCE epm.text_fact_event_event_id_seq TO epm_runtime;

ALTER TABLE epm.text_cell_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.text_fact_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY text_current_scope ON epm.text_cell_current
    TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY text_event_scope ON epm.text_fact_event
    TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
