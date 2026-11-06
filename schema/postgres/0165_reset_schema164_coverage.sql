-- Forward-only reset coverage pin for the complete schema-164 relation/FK graph.
-- The owner-only function remains the qualified implementation accumulated by
-- migrations 0037-0163; only its fail-closed reviewed fingerprint is advanced.
DO $migration$
DECLARE
  definition text;
  old_fingerprint constant text :=
    '30a2efa926fe95d9d21d178d712a77ab8bb987f8ec9b334442aa3ae0981eb1aa';
  new_fingerprint constant text :=
    '56b75344dc664fe2bf602628e5ec9f7bc5bd4f789baec22d66d81adeb91cd20e';
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition) = 0 OR
     position(new_fingerprint IN definition) <> 0 THEN
    RAISE EXCEPTION 'MIGRATION_0165_RESET_FUNCTION_SOURCE_UNEXPECTED';
  END IF;
  definition := replace(definition, old_fingerprint, new_fingerprint);
  EXECUTE definition;
END
$migration$;

REVOKE ALL ON FUNCTION epm.delete_workspace_reset_owner_only(
  text,text,text,text,text) FROM PUBLIC;

DO $migration$
DECLARE
  definition text;
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(
    '56b75344dc664fe2bf602628e5ec9f7bc5bd4f789baec22d66d81adeb91cd20e'
    IN definition) = 0 OR position(
    '30a2efa926fe95d9d21d178d712a77ab8bb987f8ec9b334442aa3ae0981eb1aa'
    IN definition) <> 0 THEN
    RAISE EXCEPTION 'MIGRATION_0165_RESET_FUNCTION_PIN_FAILED';
  END IF;
END
$migration$;
