-- Reuse of a deleted dimension's stable ID would make retained operation
-- history ambiguous. The receipt is the durable tombstone; this scoped
-- partial index keeps new-dimension admission bounded as receipts grow.
CREATE INDEX operation_receipt_deleted_dimension_id
    ON epm.operation_receipt
       (workspace_id, application_id, (result->>'dimensionId'))
    WHERE result->>'kind'='dimension.delete';
