-- Rule permission changes use the existing scoped security writer and receipt.
ALTER TABLE epm.security_operation_receipt
    DROP CONSTRAINT security_operation_receipt_action_check;
ALTER TABLE epm.security_operation_receipt
    ADD CONSTRAINT security_operation_receipt_action_check CHECK
    (action IN ('application.grant','application.revoke',
                'workspace.grant','workspace.revoke',
                'rule.set','rule.revoke'));
