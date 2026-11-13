-- Versioned, application-scoped dimensional-security assignment management.
-- The revision and assignments remain inert until the owner-selected resolver
-- is integrated.  This migration does not choose allow/deny semantics.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=200) THEN
        RAISE EXCEPTION 'MIGRATION_0201_PREDECESSOR_0200_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.application_state
    ADD COLUMN security_revision bigint NOT NULL DEFAULT 0
        CHECK (security_revision >= 0);

GRANT SELECT ON epm.application_state TO epm_security;
GRANT UPDATE (security_revision) ON epm.application_state
    TO epm_runtime,epm_security;

ALTER TABLE epm.security_operation_receipt
    DROP CONSTRAINT security_operation_receipt_action_check;
ALTER TABLE epm.security_operation_receipt
    ADD CONSTRAINT security_operation_receipt_action_check CHECK
    (action IN ('application.grant','application.revoke',
                'workspace.grant','workspace.revoke',
                'rule.set','rule.revoke','dimension-access.set'));
