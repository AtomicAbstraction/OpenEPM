-- Immutable draft definitions for the owner-selected dimensional policy.
-- A stored draft has no authorization effect.  No active pointer or default
-- policy is introduced by this migration.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=201) THEN
        RAISE EXCEPTION 'MIGRATION_0202_PREDECESSOR_0201_REQUIRED';
    END IF;
END $migration$;

CREATE TABLE epm.dimensional_security_policy_version (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    policy_version bigint NOT NULL CHECK (policy_version >= 1),
    policy_digest text NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    across_dimensions text NOT NULL CHECK (across_dimensions IN
        ('every_protected','any_protected')),
    within_dimension text NOT NULL CHECK (within_dimension IN
        ('any_tag','all_tags')),
    untagged_member text NOT NULL CHECK (untagged_member IN
        ('allow','deny')),
    untagged_deny_precedence text NOT NULL CHECK (
        untagged_deny_precedence IN ('absolute','dimension_result')),
    member_tag_cardinality text NOT NULL CHECK (
        member_tag_cardinality IN ('multiple','exactly_one_when_protected')),
    hierarchy_tags text NOT NULL CHECK (hierarchy_tags IN
        ('selected_member_only','effective_tags_resolved_by_server')),
    write_read_relationship text NOT NULL CHECK (
        write_read_relationship IN ('independent','require_read')),
    mixed_selection text NOT NULL CHECK (mixed_selection IN
        ('filter_reads_reject_writes','filter_reads_and_writes','reject_all')),
    administrator_treatment text NOT NULL CHECK (
        administrator_treatment IN ('require_assignment','bypass')),
    fact_side_authority text NOT NULL CHECK (
        fact_side_authority = 'derived_query_aid_only'),
    created_by_digest text NOT NULL CHECK (
        created_by_digest ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,policy_version),
    UNIQUE (workspace_id,application_id,policy_digest),
    FOREIGN KEY (workspace_id,application_id)
        REFERENCES epm.application_state(workspace_id,application_id)
        ON DELETE RESTRICT
);

ALTER TABLE epm.dimensional_security_policy_version ENABLE ROW LEVEL SECURITY;
CREATE POLICY dimensional_security_policy_runtime_read
    ON epm.dimensional_security_policy_version FOR SELECT TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY dimensional_security_policy_writer_scope
    ON epm.dimensional_security_policy_version TO epm_security
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY dimensional_security_policy_lifecycle_scope
    ON epm.dimensional_security_policy_version TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.dimensional_security_policy_version
    FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT ON epm.dimensional_security_policy_version TO epm_runtime;
GRANT SELECT,INSERT ON epm.dimensional_security_policy_version TO epm_security;
GRANT SELECT ON epm.dimensional_security_policy_version TO epm_lifecycle;

-- Extend exact owner-reset inventory in child-first order. The table has no
-- child records and must precede its application_state parent.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_pair text :=
  $pattern$'application_access_grant','workspace_lifecycle_receipt',$pattern$;
DECLARE new_pair text :=
  $pattern$'dimensional_security_policy_version','application_access_grant','workspace_lifecycle_receipt',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0202_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0202_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

-- Pin the reviewed post-0202 reset graph in the owner-only reset primitive.
-- This is deliberately separate from the inventory edit above so each
-- expected predecessor is checked before the function is replaced.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '9a442a6dbf353ec15f1dc1cf5a9a595d800e3bc91cab3432011837389071946a';
DECLARE new_fingerprint constant text :=
  'd3f570714c551d1f47e2498f74db7ee66b49197071bd0186ffbc60ab3a668e21';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0202_FINGERPRINT_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0202_FINGERPRINT_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;
