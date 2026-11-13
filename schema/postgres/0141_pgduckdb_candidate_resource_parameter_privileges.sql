-- The fixed candidate stage must set its two resource ceilings transaction
-- locally.  PostgreSQL 18 treats these pg_duckdb GUCs as superuser parameters;
-- grant only SET on the two bounded controls to the trusted runtime role.
-- No other pg_duckdb parameter or role is widened by this migration.

GRANT SET ON PARAMETER "duckdb.max_memory" TO epm_runtime;
GRANT SET ON PARAMETER "duckdb.max_temp_directory_size" TO epm_runtime;
