-- Explicit activation pointer for a complete immutable dimensional-security
-- policy.  Existing applications remain unrestricted by dimensional policy
-- until an administrator activates a reviewed version.  Activation advances
-- the dedicated security revision so admitted work can be fenced separately
-- from business-data and metadata revisions.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=208) THEN
        RAISE EXCEPTION 'MIGRATION_0209_PREDECESSOR_0208_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.application_state
    ADD COLUMN active_dimensional_security_policy_version bigint NULL
        CHECK (active_dimensional_security_policy_version IS NULL OR
               active_dimensional_security_policy_version > 0);

GRANT UPDATE (active_dimensional_security_policy_version)
    ON epm.application_state TO epm_security;

ALTER TABLE epm.security_operation_receipt
    DROP CONSTRAINT security_operation_receipt_action_check;
ALTER TABLE epm.security_operation_receipt
    ADD CONSTRAINT security_operation_receipt_action_check CHECK
    (action IN ('application.grant','application.revoke',
                'workspace.grant','workspace.revoke',
                'rule.set','rule.revoke','dimension-access.set',
                'dimension-policy.version.save',
                'dimension-policy.activate','dimension-policy.deactivate'));
