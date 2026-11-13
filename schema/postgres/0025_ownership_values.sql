-- Exact period-sensitive ownership inputs belong to a direct Entity placement.
-- These are declared facts for later policy resolution, not accounting results.

CREATE TABLE epm.ownership_value_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    operation_id text NOT NULL,
    relationship_id text NOT NULL,
    scenario_dimension_id text NOT NULL,
    scenario_member_id text NOT NULL,
    year_dimension_id text NOT NULL,
    year_member_id text NOT NULL,
    period_dimension_id text NOT NULL,
    period_member_id text NOT NULL,
    account_name text NOT NULL CHECK (account_name IN
        ('POWN','PCON','PCTRL','DOWN','Active','Method',
         'Consol1','Consol2','Consol3')),
    kind text NOT NULL CHECK (kind IN ('Set','Clear')),
    amount numeric(28,8),
    previous_change_id text NOT NULL,
    change_id text NOT NULL CHECK (change_id ~ '^[0-9a-f]{32}$'),
    committed_revision bigint NOT NULL CHECK (committed_revision>0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,operation_id),
    FOREIGN KEY (workspace_id,application_id,operation_id)
        REFERENCES epm.operation_receipt
        (workspace_id,application_id,operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,relationship_id)
        REFERENCES epm.relationship
        (workspace_id,application_id,relationship_id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,scenario_dimension_id,
                 scenario_member_id)
        REFERENCES epm.member
        (workspace_id,application_id,dimension_id,member_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,year_dimension_id,year_member_id)
        REFERENCES epm.member
        (workspace_id,application_id,dimension_id,member_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,period_dimension_id,
                 period_member_id)
        REFERENCES epm.member
        (workspace_id,application_id,dimension_id,member_id)
        ON DELETE RESTRICT,
    CHECK ((kind='Set' AND amount IS NOT NULL)
        OR (kind='Clear' AND amount IS NULL)),
    CHECK (amount IS NULL OR
        CASE account_name
            WHEN 'POWN' THEN amount BETWEEN 0 AND 100
            WHEN 'PCON' THEN amount BETWEEN -100 AND 100
            WHEN 'PCTRL' THEN amount BETWEEN 0 AND 100
            WHEN 'DOWN' THEN amount BETWEEN 0 AND 100
            WHEN 'Active' THEN amount IN (0,1)
            WHEN 'Method' THEN amount>=0 AND amount=trunc(amount)
            ELSE amount BETWEEN 0 AND 255 AND amount=trunc(amount)
        END)
);
CREATE INDEX ownership_event_context ON epm.ownership_value_event
    (workspace_id,application_id,relationship_id,scenario_member_id,
     year_member_id,period_member_id,account_name,committed_revision);

CREATE TABLE epm.ownership_value_current (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    relationship_id text NOT NULL,
    scenario_dimension_id text NOT NULL,
    scenario_member_id text NOT NULL,
    year_dimension_id text NOT NULL,
    year_member_id text NOT NULL,
    period_dimension_id text NOT NULL,
    period_member_id text NOT NULL,
    account_name text NOT NULL CHECK (account_name IN
        ('POWN','PCON','PCTRL','DOWN','Active','Method',
         'Consol1','Consol2','Consol3')),
    present boolean NOT NULL,
    amount numeric(28,8),
    change_id text NOT NULL CHECK (change_id ~ '^[0-9a-f]{32}$'),
    last_revision bigint NOT NULL CHECK (last_revision>0),
    PRIMARY KEY (workspace_id,application_id,relationship_id,
        scenario_member_id,year_member_id,period_member_id,account_name),
    FOREIGN KEY (workspace_id,application_id,relationship_id)
        REFERENCES epm.relationship
        (workspace_id,application_id,relationship_id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,scenario_dimension_id,
                 scenario_member_id)
        REFERENCES epm.member
        (workspace_id,application_id,dimension_id,member_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,year_dimension_id,year_member_id)
        REFERENCES epm.member
        (workspace_id,application_id,dimension_id,member_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,period_dimension_id,
                 period_member_id)
        REFERENCES epm.member
        (workspace_id,application_id,dimension_id,member_id)
        ON DELETE RESTRICT,
    CHECK ((present AND amount IS NOT NULL)
        OR (NOT present AND amount IS NULL)),
    CHECK (amount IS NULL OR
        CASE account_name
            WHEN 'POWN' THEN amount BETWEEN 0 AND 100
            WHEN 'PCON' THEN amount BETWEEN -100 AND 100
            WHEN 'PCTRL' THEN amount BETWEEN 0 AND 100
            WHEN 'DOWN' THEN amount BETWEEN 0 AND 100
            WHEN 'Active' THEN amount IN (0,1)
            WHEN 'Method' THEN amount>=0 AND amount=trunc(amount)
            ELSE amount BETWEEN 0 AND 255 AND amount=trunc(amount)
        END)
);

GRANT SELECT,INSERT ON epm.ownership_value_event TO epm_runtime;
GRANT SELECT,INSERT,UPDATE ON epm.ownership_value_current TO epm_runtime;
ALTER TABLE epm.ownership_value_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.ownership_value_current ENABLE ROW LEVEL SECURITY;
CREATE POLICY ownership_event_scope ON epm.ownership_value_event
    TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY ownership_current_scope ON epm.ownership_value_current
    TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
