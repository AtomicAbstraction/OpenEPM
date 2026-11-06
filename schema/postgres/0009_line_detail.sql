-- Supporting detail and its numeric cell total share one application revision.
-- The fixed core validates each item and exact sum before writing. The numeric
-- adapter rejects direct changes to a coordinate with attached detail.

CREATE TABLE epm.line_detail_current (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    coordinate_id bigint NOT NULL,
    items jsonb NOT NULL CHECK (jsonb_typeof(items) = 'array'
                                 AND jsonb_array_length(items) <= 500),
    total numeric(28,8) NOT NULL,
    change_id text NOT NULL CHECK (length(change_id) BETWEEN 1 AND 200),
    last_revision bigint NOT NULL CHECK (last_revision > 0),
    PRIMARY KEY (workspace_id, application_id, coordinate_id),
    FOREIGN KEY (workspace_id, application_id, coordinate_id)
        REFERENCES epm.coordinate(workspace_id, application_id, coordinate_id)
        ON DELETE RESTRICT
);

CREATE TABLE epm.line_detail_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    event_id bigint GENERATED ALWAYS AS IDENTITY,
    coordinate_id bigint NOT NULL,
    operation_id text NOT NULL,
    prior_items jsonb,
    prior_total numeric(28,8),
    items jsonb NOT NULL CHECK (jsonb_typeof(items) = 'array'
                                 AND jsonb_array_length(items) <= 500),
    total numeric(28,8) NOT NULL,
    change_id text NOT NULL CHECK (length(change_id) BETWEEN 1 AND 200),
    committed_revision bigint NOT NULL CHECK (committed_revision > 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id, event_id),
    UNIQUE (workspace_id, application_id, committed_revision),
    FOREIGN KEY (workspace_id, application_id, coordinate_id)
        REFERENCES epm.coordinate(workspace_id, application_id, coordinate_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id, application_id, operation_id)
        REFERENCES epm.operation_receipt(workspace_id, application_id,
                                         operation_id) ON DELETE RESTRICT,
    CHECK ((prior_items IS NULL) = (prior_total IS NULL)),
    CHECK (prior_items IS NULL OR jsonb_typeof(prior_items) = 'array')
);
CREATE INDEX line_detail_event_replay ON epm.line_detail_event
    (workspace_id, application_id, coordinate_id, committed_revision DESC);

GRANT SELECT ON epm.line_detail_current, epm.line_detail_event
    TO epm_runtime, epm_analyst;
GRANT INSERT ON epm.line_detail_current, epm.line_detail_event TO epm_runtime;
GRANT UPDATE ON epm.line_detail_current TO epm_runtime;
GRANT USAGE ON SEQUENCE epm.line_detail_event_event_id_seq TO epm_runtime;

ALTER TABLE epm.line_detail_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.line_detail_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY line_detail_current_scope ON epm.line_detail_current
    TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY line_detail_event_scope ON epm.line_detail_event
    TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
