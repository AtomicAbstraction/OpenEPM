-- Complete the least-privilege boundary for atomic directory reconciliation.
--
-- Migration 0244 deliberately withheld DELETE while the current-state fence
-- was mutation-driven. A complete Keycloak snapshot must remove projection
-- rows that no longer exist, so the same governed provision role needs DELETE
-- on exactly the three replaceable projection tables. No business or identity
-- authority moves into PostgreSQL.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=244) THEN
        RAISE EXCEPTION 'MIGRATION_0245_PREDECESSOR_0244_REQUIRED';
    END IF;
END $migration$;

GRANT DELETE ON epm.identity_user_directory_state,
    epm.identity_group_directory_state,
    epm.identity_group_membership_state TO epm_provision;
