-- Domain-neutral aggregation behavior.  Existing metadata receives explicit
-- compatibility defaults; callers may not infer behavior from dimension roles.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=214) THEN
    RAISE EXCEPTION 'MIGRATION_0215_PREDECESSOR_0214_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.member ADD COLUMN aggregation_operator text NOT NULL
  DEFAULT 'Add' CHECK(aggregation_operator IN
    ('Add','Subtract','Ignore','NeverAggregate','Formula'));

ALTER TABLE epm.relationship ADD COLUMN aggregation_operator_override text
  CHECK(aggregation_operator_override IS NULL OR
    aggregation_operator_override IN
      ('Add','Subtract','Ignore','NeverAggregate','Formula'));

ALTER TABLE epm.hierarchy_version ADD COLUMN membership_semantics text NOT NULL
  DEFAULT 'unique_member' CHECK(membership_semantics IN
    ('unique_member','placement'));

COMMENT ON COLUMN epm.member.aggregation_operator IS
  'Generic member default; placement and published-rule overrides have higher precedence.';
COMMENT ON COLUMN epm.relationship.aggregation_operator_override IS
  'Optional parent-child placement override; never silently applied to unique-member execution.';
COMMENT ON COLUMN epm.hierarchy_version.membership_semantics IS
  'Explicit hierarchy default. A sealed generic rule may override it.';

GRANT UPDATE(aggregation_operator) ON epm.member TO epm_runtime;
GRANT UPDATE(aggregation_operator_override) ON epm.relationship TO epm_runtime;
GRANT INSERT(membership_semantics) ON epm.hierarchy_version TO epm_runtime;
