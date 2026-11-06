BEGIN;
DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=276) THEN
    RAISE EXCEPTION 'MIGRATION_0277_REQUIRES_0276';
  END IF;
END $migration$;

CREATE OR REPLACE FUNCTION epm.current_schema_version()
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, epm
AS $$
  SELECT COALESCE(max(version), 0)::integer FROM epm.schema_migration
$$;

REVOKE ALL ON FUNCTION epm.current_schema_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.current_schema_version() TO
  epm_access, epm_analyst, epm_lifecycle, epm_provision,
  epm_python_coordinator, epm_runtime, epm_security, epm_worker;
COMMIT;
