-- A raw numeric driver can only be used in a typed expression when its
-- selected measure member declares the same arithmetic kind.
ALTER TABLE epm.member ADD COLUMN numeric_value_kind text;
ALTER TABLE epm.member ADD CONSTRAINT member_numeric_value_kind_valid
    CHECK (numeric_value_kind IN ('amount', 'ratio')) NOT VALID;
