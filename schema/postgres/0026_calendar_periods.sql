-- Explicit fiscal period ranges. End dates are exclusive; no Gregorian
-- calendar or monthly layout is inferred from Year/Period member names.

CREATE TABLE epm.calendar_period_current (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    year_dimension_id text NOT NULL,
    year_member_id text NOT NULL,
    period_dimension_id text NOT NULL,
    period_member_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 1 AND 366),
    starts_on date NOT NULL,
    ends_before date NOT NULL,
    change_id text NOT NULL CHECK (change_id ~ '^[0-9a-f]{32}$'),
    last_revision bigint NOT NULL CHECK (last_revision>0),
    PRIMARY KEY (workspace_id,application_id,year_member_id,period_member_id),
    UNIQUE (workspace_id,application_id,year_member_id,ordinal),
    FOREIGN KEY (workspace_id,application_id,year_dimension_id,year_member_id)
        REFERENCES epm.member
        (workspace_id,application_id,dimension_id,member_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,period_dimension_id,period_member_id)
        REFERENCES epm.member
        (workspace_id,application_id,dimension_id,member_id)
        ON DELETE RESTRICT,
    CHECK (starts_on<ends_before)
);

CREATE TABLE epm.calendar_period_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    operation_id text NOT NULL,
    year_dimension_id text NOT NULL,
    year_member_id text NOT NULL,
    period_dimension_id text NOT NULL,
    period_member_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 1 AND 366),
    starts_on date NOT NULL,
    ends_before date NOT NULL,
    previous_change_id text NOT NULL,
    change_id text NOT NULL CHECK (change_id ~ '^[0-9a-f]{32}$'),
    committed_revision bigint NOT NULL CHECK (committed_revision>0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,operation_id),
    FOREIGN KEY (workspace_id,application_id,operation_id)
        REFERENCES epm.operation_receipt
        (workspace_id,application_id,operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,year_dimension_id,year_member_id)
        REFERENCES epm.member
        (workspace_id,application_id,dimension_id,member_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,period_dimension_id,period_member_id)
        REFERENCES epm.member
        (workspace_id,application_id,dimension_id,member_id)
        ON DELETE RESTRICT,
    CHECK (starts_on<ends_before)
);
CREATE INDEX calendar_event_period ON epm.calendar_period_event
    (workspace_id,application_id,year_member_id,period_member_id,
     committed_revision);

CREATE FUNCTION epm.reject_calendar_overlap() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- Direct writers and fixed-core writers serialize on the application.
    PERFORM 1 FROM epm.application_state
        WHERE workspace_id=NEW.workspace_id
          AND application_id=NEW.application_id FOR UPDATE;
    IF EXISTS (
        SELECT 1 FROM epm.calendar_period_current existing
        WHERE existing.workspace_id=NEW.workspace_id
          AND existing.application_id=NEW.application_id
          AND (existing.year_member_id,existing.period_member_id)
              IS DISTINCT FROM
              (NEW.year_member_id,NEW.period_member_id)
          AND daterange(existing.starts_on,existing.ends_before,'[)') &&
              daterange(NEW.starts_on,NEW.ends_before,'[)')
    ) THEN
        RAISE EXCEPTION 'CALENDAR_PERIOD_OVERLAP' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER reject_calendar_overlap
    BEFORE INSERT OR UPDATE ON epm.calendar_period_current
    FOR EACH ROW EXECUTE FUNCTION epm.reject_calendar_overlap();

GRANT SELECT,INSERT,UPDATE ON epm.calendar_period_current TO epm_runtime;
GRANT SELECT,INSERT ON epm.calendar_period_event TO epm_runtime;
ALTER TABLE epm.calendar_period_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.calendar_period_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY calendar_current_scope ON epm.calendar_period_current
    TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY calendar_event_scope ON epm.calendar_period_event
    TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
