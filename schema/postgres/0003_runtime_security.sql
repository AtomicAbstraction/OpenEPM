-- Scoped least-privilege runtime roles. Apply after numeric fact foundation
-- through the migration runner.

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epm_runtime') THEN
        CREATE ROLE epm_runtime NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epm_analyst') THEN
        CREATE ROLE epm_analyst NOLOGIN;
    END IF;
END $$;

GRANT USAGE ON SCHEMA epm TO epm_runtime, epm_analyst;
GRANT SELECT ON epm.workspace, epm.application, epm.application_state,
    epm.coordinate, epm.numeric_cell_current, epm.numeric_fact_event,
    epm.operation_receipt TO epm_runtime;
GRANT SELECT ON epm.workspace, epm.application, epm.application_state,
    epm.coordinate, epm.numeric_cell_current, epm.numeric_fact_event
    TO epm_analyst;
GRANT UPDATE (data_revision, commit_revision) ON epm.application_state
    TO epm_runtime;
GRANT INSERT ON epm.coordinate, epm.numeric_cell_current,
    epm.numeric_fact_event, epm.operation_receipt TO epm_runtime;
GRANT UPDATE ON epm.numeric_cell_current TO epm_runtime;
GRANT USAGE ON SEQUENCE epm.coordinate_coordinate_id_seq,
    epm.numeric_fact_event_event_id_seq TO epm_runtime;

ALTER TABLE epm.workspace ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.application ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.application_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.coordinate ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.numeric_cell_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.numeric_fact_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.operation_receipt ENABLE ROW LEVEL SECURITY;

CREATE POLICY workspace_scope ON epm.workspace TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true));

CREATE POLICY application_scope ON epm.application TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
           AND application_id=current_setting('epm.application_id',true));

CREATE POLICY application_state_scope ON epm.application_state
    TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
           AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
                AND application_id=current_setting('epm.application_id',true));

CREATE POLICY coordinate_scope ON epm.coordinate TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
           AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
                AND application_id=current_setting('epm.application_id',true));

CREATE POLICY numeric_current_scope ON epm.numeric_cell_current
    TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
           AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
                AND application_id=current_setting('epm.application_id',true));

CREATE POLICY numeric_event_scope ON epm.numeric_fact_event
    TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
           AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
                AND application_id=current_setting('epm.application_id',true));

CREATE POLICY receipt_scope ON epm.operation_receipt TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
           AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
                AND application_id=current_setting('epm.application_id',true));

