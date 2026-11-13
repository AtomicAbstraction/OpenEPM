-- Generalize the original workspace-create receipt into a durable platform
-- operation intent/receipt.  A Pending row is committed before a bounded
-- Keycloak side effect, so request-key reuse with different content is
-- rejected even after a lost external acknowledgement or process restart.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=242) THEN
        RAISE EXCEPTION 'MIGRATION_0243_PREDECESSOR_0242_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.platform_workspace_receipt
    RENAME TO platform_operation_receipt;
ALTER TABLE epm.platform_operation_receipt
    ADD COLUMN function_name text NOT NULL
        DEFAULT 'platform.workspace.create'
        CHECK (length(function_name) BETWEEN 1 AND 200),
    ADD COLUMN status text NOT NULL DEFAULT 'Committed'
        CHECK (status IN ('Pending','Committed'));
ALTER TABLE epm.platform_operation_receipt
    ALTER COLUMN function_name DROP DEFAULT,
    ALTER COLUMN committed_at DROP NOT NULL,
    ALTER COLUMN committed_at DROP DEFAULT;

ALTER POLICY platform_workspace_receipt_provision
    ON epm.platform_operation_receipt
    RENAME TO platform_operation_receipt_provision;
GRANT UPDATE(status,result,committed_at)
    ON epm.platform_operation_receipt TO epm_provision;

COMMENT ON TABLE epm.platform_operation_receipt IS
    'Durable exact-replay intent and receipt for platform-operator operations';
