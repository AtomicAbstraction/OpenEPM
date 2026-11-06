-- Runtime effect transactions recheck current grants under the shared
-- workspace revocation lock. RLS limits that read to the bound application.

GRANT SELECT ON epm.workspace_access_grant,
    epm.application_access_grant, epm.rule_access_grant TO epm_runtime;

ALTER TABLE epm.workspace_access_grant ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.application_access_grant ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.rule_access_grant ENABLE ROW LEVEL SECURITY;

CREATE POLICY workspace_grant_runtime_read ON epm.workspace_access_grant
    FOR SELECT TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY application_grant_runtime_read ON epm.application_access_grant
    FOR SELECT TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY rule_grant_runtime_read ON epm.rule_access_grant
    FOR SELECT TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));

CREATE POLICY workspace_grant_access_read ON epm.workspace_access_grant
    FOR SELECT TO epm_access, epm_security USING (true);
CREATE POLICY application_grant_access_read ON epm.application_access_grant
    FOR SELECT TO epm_access, epm_security USING (true);
CREATE POLICY rule_grant_access_read ON epm.rule_access_grant
    FOR SELECT TO epm_access, epm_security USING (true);
CREATE POLICY application_grant_security_write ON epm.application_access_grant
    TO epm_security USING (true) WITH CHECK (true);
CREATE POLICY rule_grant_security_write ON epm.rule_access_grant
    TO epm_security USING (true) WITH CHECK (true);
