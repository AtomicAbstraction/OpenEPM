-- Reset deletion is owned exclusively by the reviewed migration-owner
-- SECURITY DEFINER primitive.  The workspace lifecycle credential needs
-- read-only inventory access to these records, never direct DELETE rights.
-- Migrations 0214 and 0217 accidentally reintroduced that stale privilege
-- pattern after migration 0166 had retired it globally.
REVOKE DELETE ON epm.sealed_cube_selection,
                 epm.application_rule_workflow_child,
                 epm.application_rule_workflow
  FROM epm_lifecycle;

DO $migration$
DECLARE
  role_name text;
  relation_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['epm_lifecycle','epm_lifecycle_login']
  LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
      FOR relation_name IN
        SELECT format('%I.%I',n.nspname,c.relname)
          FROM pg_class c
          JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname='epm' AND c.relkind IN ('r','p','v')
         ORDER BY c.relname
      LOOP
        IF has_table_privilege(role_name,relation_name,'DELETE') THEN
          RAISE EXCEPTION 'MIGRATION_0219_LIFECYCLE_DELETE_REMAINS:%:%',
            role_name,relation_name;
        END IF;
      END LOOP;
    END IF;
  END LOOP;
END
$migration$;
