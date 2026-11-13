-- Optional application specialization. Existing/blank applications remain core.
-- No accounting metadata or implicit activation is inferred from existing rows.
ALTER TABLE epm.application_state
    ADD COLUMN enabled_capabilities text[] NOT NULL DEFAULT '{}',
    ADD COLUMN capability_revision bigint NOT NULL DEFAULT 0
        CHECK (capability_revision >= 0),
    ADD CONSTRAINT application_capabilities_known CHECK (
        enabled_capabilities = '{}'::text[] OR
        enabled_capabilities = ARRAY['financial_consolidation']::text[]);
-- State already has scoped RLS, runtime UPDATE and lifecycle INSERT grants.
GRANT UPDATE (enabled_capabilities, capability_revision)
    ON epm.application_state TO epm_runtime;
-- Changes use the existing immutable operation receipt for before/after audit.

CREATE INDEX application_capability_receipt_history
    ON epm.operation_receipt(workspace_id,application_id,committed_revision)
    WHERE result->>'function'='application.capabilities.configure';
