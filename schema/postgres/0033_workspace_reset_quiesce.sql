-- The fixed lifecycle service may toggle only its bound workspace status.
-- It cannot update names, create a workspace, delete business rows, or set a
-- workspace to Deleting. Quiesce/resume authorization lives in fixed Python.
GRANT UPDATE (status) ON epm.workspace TO epm_lifecycle;

CREATE POLICY workspace_lifecycle_status_update ON epm.workspace
    FOR UPDATE TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
        AND status IN ('Active','Maintenance'));
