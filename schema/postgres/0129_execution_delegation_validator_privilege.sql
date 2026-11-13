-- epm_runtime owns no validator code, but PostgreSQL must be able to execute
-- this immutable CHECK helper when the approved delegation service inserts an
-- immutable version.  No table or mutation privilege is broadened.
DO $$
BEGIN
 IF has_function_privilege('epm_runtime',
      'epm.valid_execution_operation_scope(text[])','EXECUTE')
 THEN RAISE EXCEPTION 'RESET_0129_DEFINITION_MISMATCH'; END IF;
END $$;

GRANT EXECUTE ON FUNCTION epm.valid_execution_operation_scope(text[])
 TO epm_runtime;
