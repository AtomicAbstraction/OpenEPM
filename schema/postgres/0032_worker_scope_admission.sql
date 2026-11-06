-- The global worker must observe lifecycle state before claiming ready work.
-- These are read-only registry privileges; it cannot mutate lifecycle rows.
GRANT SELECT ON epm.workspace, epm.application,
    epm.application_state TO epm_worker;

CREATE POLICY workspace_worker_read ON epm.workspace
    FOR SELECT TO epm_worker USING (true);
CREATE POLICY application_worker_read ON epm.application
    FOR SELECT TO epm_worker USING (true);
CREATE POLICY application_state_worker_read ON epm.application_state
    FOR SELECT TO epm_worker USING (true);
