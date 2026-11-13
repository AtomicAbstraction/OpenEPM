-- A canonical plan digest identifies plan content, not one unique build.
-- Separate immutable builds may legitimately emit identical V2 plans while
-- retaining distinct source/environment/compiler identities through build_id.
DO $$
DECLARE constraint_name text;
BEGIN
 SELECT c.conname INTO constraint_name
 FROM pg_constraint c
 JOIN pg_class t ON t.oid=c.conrelid
 JOIN pg_namespace n ON n.oid=t.relnamespace
 WHERE n.nspname='epm' AND t.relname='python_plan_artifact'
   AND c.contype='u'
   AND pg_get_constraintdef(c.oid)='UNIQUE (workspace_id, application_id, plan_digest)';
 IF constraint_name IS NULL THEN
  RAISE EXCEPTION 'RESET_0133_DEFINITION_MISMATCH';
 END IF;
 EXECUTE format('ALTER TABLE epm.python_plan_artifact DROP CONSTRAINT %I',
                constraint_name);
END $$;

CREATE INDEX python_plan_artifact_digest_lookup
 ON epm.python_plan_artifact(workspace_id,application_id,plan_digest);
