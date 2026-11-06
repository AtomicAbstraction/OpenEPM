-- Typed finance metadata lives on the authoritative member row. The fixed
-- language validates role and active cross-member references before writing.
-- Nullable fields keep generic/non-financial applications unaffected.
ALTER TABLE epm.member ADD COLUMN financial_account_type text
    CHECK (financial_account_type IN (
        'REVENUE','EXPENSE','ASSET','LIABILITY','BALANCE','FLOW',
        'CURRENCYRATE','GROUPLABEL','BALANCERECURRING','DYNAMIC'));
ALTER TABLE epm.member ADD COLUMN entity_default_currency_member_id text
    CHECK (entity_default_currency_member_id IS NULL OR
           length(entity_default_currency_member_id) BETWEEN 1 AND 200);

GRANT UPDATE (financial_account_type,entity_default_currency_member_id)
    ON epm.member TO epm_runtime;
