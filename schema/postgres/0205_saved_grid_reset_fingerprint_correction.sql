-- Correct the reviewed reset-graph fingerprint introduced with saved-grid
-- definitions. Migration 0204 added the correct child-first inventory entry,
-- but its manually recorded graph digest did not match the canonical
-- read-only inspector over the resulting schema. No table or business row is
-- changed here; this advances only the owner-reset admission fingerprint.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=204) THEN
        RAISE EXCEPTION 'MIGRATION_0205_PREDECESSOR_0204_REQUIRED';
    END IF;
END $migration$;

DO $migration$
DECLARE definition text; revised text;
DECLARE incorrect_fingerprint constant text :=
  '68c2dc7e39200d93437d551a1696e6ff5741789a889c41b5e969b62add77d983';
DECLARE reviewed_fingerprint constant text :=
  '4c976e4afb5c84849ee580683808d0371b3cf4d969fc2f22266524246e93451c';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(incorrect_fingerprint IN definition)=0 OR
     position(reviewed_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0205_FINGERPRINT_PREDECESSOR_MISMATCH';
  END IF;
  revised := replace(definition,incorrect_fingerprint,reviewed_fingerprint);
  IF revised=definition OR position(reviewed_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0205_FINGERPRINT_CORRECTION_FAILED';
  END IF;
  EXECUTE revised;
END $migration$;
