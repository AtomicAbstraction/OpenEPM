-- Domain-separated period policy events reuse immutable scoped receipts.
-- Function precedes bundle so future posting receipts cannot expand review scans.
CREATE INDEX period_policy_receipt_bundle ON epm.operation_receipt
    (workspace_id,application_id,(result->>'function'),(result->>'bundleOperationId'),committed_revision DESC)
    WHERE result->>'policyDomain'='period_nci';
-- Only activation/withdrawal controls participate in the current-variant index.
CREATE INDEX period_policy_receipt_variant ON epm.operation_receipt
    (workspace_id,application_id,(result->>'variantKey'),committed_revision DESC)
    WHERE result->>'policyDomain'='period_nci'
    AND result->>'function' IN ('consolidation.policy.period_nci.activate','consolidation.policy.period_nci.withdraw');
