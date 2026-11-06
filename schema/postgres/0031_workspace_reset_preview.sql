-- A dedicated lifecycle principal may inventory one workspace before a
-- fixed-core reset. These are SELECT-only grants; no business deletion is
-- delegated by this migration.
GRANT SELECT ON epm.schema_migration, epm.platform_operator_grant,
    epm.application_state,
    epm.application_access_grant, epm.rule_access_grant, epm.job,
    epm.source_batch TO epm_lifecycle;

CREATE POLICY platform_operator_lifecycle_read
    ON epm.platform_operator_grant FOR SELECT TO epm_lifecycle USING (true);
CREATE POLICY application_state_lifecycle_read
    ON epm.application_state FOR SELECT TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY application_grant_lifecycle_read
    ON epm.application_access_grant FOR SELECT TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY rule_grant_lifecycle_read
    ON epm.rule_access_grant FOR SELECT TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY job_lifecycle_read
    ON epm.job FOR SELECT TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY source_batch_lifecycle_read
    ON epm.source_batch FOR SELECT TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));
