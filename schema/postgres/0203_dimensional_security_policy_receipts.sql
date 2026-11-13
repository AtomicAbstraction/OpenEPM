-- Admit idempotent immutable dimensional-security policy version saves.
-- This adds no active policy pointer and changes no authorization behavior.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=202) THEN
        RAISE EXCEPTION 'MIGRATION_0203_PREDECESSOR_0202_REQUIRED';
    END IF;
END $migration$;

-- Migration 0201 granted the security writer the required column privileges
-- but did not add an RLS path for application_state.  Keep it scoped to the
-- server-set application context; the writer may update only security_revision
-- because its column grant remains narrow.
CREATE POLICY application_state_security_read
    ON epm.application_state FOR SELECT TO epm_security
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY application_state_security_update
    ON epm.application_state FOR UPDATE TO epm_security
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));

ALTER TABLE epm.security_operation_receipt
    DROP CONSTRAINT security_operation_receipt_action_check;
ALTER TABLE epm.security_operation_receipt
    ADD CONSTRAINT security_operation_receipt_action_check CHECK
    (action IN ('application.grant','application.revoke',
                'workspace.grant','workspace.revoke',
                'rule.set','rule.revoke','dimension-access.set',
                'dimension-policy.version.save'));
