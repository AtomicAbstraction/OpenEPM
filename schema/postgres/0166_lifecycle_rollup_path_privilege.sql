-- The workspace listener's lifecycle credential must never have direct table
-- deletion rights.  Reset deletion remains exclusively in the migration-owner
-- SECURITY DEFINER primitive, which already deletes all four tables below in
-- reviewed dependency order.  Migrations 0162 and 0163 granted these rights
-- while extending reset coverage; those grants are stale privilege residue.
REVOKE DELETE ON epm.inventory_unrealized_schedule_state,
                 epm.inventory_unrealized_schedule_version,
                 epm.rollup_placement_path_edge,
                 epm.rollup_placement_path
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
        SELECT format('%I.%I', n.nspname, c.relname)
          FROM pg_class c
          JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname='epm' AND c.relkind IN ('r','p','v')
         ORDER BY c.relname
      LOOP
        IF has_table_privilege(role_name,relation_name,'DELETE') THEN
          RAISE EXCEPTION 'MIGRATION_0166_LIFECYCLE_DELETE_REMAINS:%:%',
            role_name,relation_name;
        END IF;
      END LOOP;
    END IF;
  END LOOP;
END
$migration$;
