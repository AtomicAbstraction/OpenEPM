-- The security service may change workspace Administrator grants, under the
-- fixed writer's exclusive workspace fence. It remains unable to write facts.
GRANT INSERT,UPDATE,DELETE ON epm.workspace_access_grant TO epm_security;
CREATE POLICY workspace_grant_security_write ON epm.workspace_access_grant
    TO epm_security USING (true) WITH CHECK (true);

ALTER TABLE epm.security_operation_receipt
    DROP CONSTRAINT security_operation_receipt_action_check;
ALTER TABLE epm.security_operation_receipt
    ADD CONSTRAINT security_operation_receipt_action_check CHECK
    (action IN ('application.grant','application.revoke',
                'workspace.grant','workspace.revoke'));
