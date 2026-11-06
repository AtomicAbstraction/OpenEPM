-- Generic numeric coordinate and event projection foundation.
-- Apply after 0001_foundation.sql through the migration runner.

CREATE TABLE epm.coordinate (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    coordinate_id bigint GENERATED ALWAYS AS IDENTITY,
    series_key text NOT NULL CHECK (series_key ~ '^[0-9a-f]{64}$'),
    members jsonb NOT NULL CHECK (jsonb_typeof(members) = 'object'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id, coordinate_id),
    UNIQUE (workspace_id, application_id, series_key),
    FOREIGN KEY (workspace_id, application_id)
        REFERENCES epm.application_state(workspace_id, application_id)
        ON DELETE RESTRICT
);

CREATE TABLE epm.numeric_cell_current (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    coordinate_id bigint NOT NULL,
    present boolean NOT NULL,
    amount numeric(28,8),
    change_id text NOT NULL CHECK (length(change_id) BETWEEN 1 AND 200),
    last_revision bigint NOT NULL CHECK (last_revision > 0),
    PRIMARY KEY (workspace_id, application_id, coordinate_id),
    FOREIGN KEY (workspace_id, application_id, coordinate_id)
        REFERENCES epm.coordinate(workspace_id, application_id, coordinate_id)
        ON DELETE RESTRICT,
    CHECK (present = (amount IS NOT NULL))
);

CREATE TABLE epm.numeric_fact_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    event_id bigint GENERATED ALWAYS AS IDENTITY,
    coordinate_id bigint NOT NULL,
    operation_id text NOT NULL,
    line_ordinal integer NOT NULL CHECK (line_ordinal > 0),
    kind text NOT NULL CHECK (kind IN ('set', 'add', 'clear')),
    delta numeric NOT NULL,
    present boolean NOT NULL,
    resulting_amount numeric(28,8),
    change_id text NOT NULL CHECK (length(change_id) BETWEEN 1 AND 200),
    committed_revision bigint NOT NULL CHECK (committed_revision > 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id, event_id),
    UNIQUE (workspace_id, application_id, committed_revision, line_ordinal),
    FOREIGN KEY (workspace_id, application_id, coordinate_id)
        REFERENCES epm.coordinate(workspace_id, application_id, coordinate_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id, application_id, operation_id)
        REFERENCES epm.operation_receipt(workspace_id, application_id, operation_id)
        ON DELETE RESTRICT,
    CHECK (present = (resulting_amount IS NOT NULL))
);

CREATE INDEX numeric_fact_event_replay
    ON epm.numeric_fact_event
       (workspace_id, application_id, coordinate_id, committed_revision DESC, line_ordinal DESC);

