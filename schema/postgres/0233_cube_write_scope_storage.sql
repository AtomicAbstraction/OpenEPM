-- Rename the active generic cube-write-scope storage in place.  Existing
-- rows, keys, RLS, privileges and immutable event history remain bound to the
-- same relation OIDs; no compatibility tables or views are introduced.
ALTER TABLE epm.planning_slice_lock RENAME TO cube_write_scope_lock;
ALTER TABLE epm.planning_lock_event RENAME TO cube_write_scope_lock_event;
ALTER TABLE epm.planning_submission RENAME TO cube_write_scope_submission;
ALTER TABLE epm.planning_submission_event
 RENAME TO cube_write_scope_submission_event;
ALTER TABLE epm.planning_assigned_submission
 RENAME TO cube_write_scope_assigned_submission;
ALTER TABLE epm.planning_assigned_reviewer
 RENAME TO cube_write_scope_assigned_reviewer;
ALTER TABLE epm.planning_assigned_review_event
 RENAME TO cube_write_scope_assigned_review_event;

-- Rename table-owned constraints and RLS policies. Constraint renames also
-- rename their backing indexes. The replacement order is longest-first.
DO $$
DECLARE r record;new_name text;
BEGIN
 FOR r IN
  SELECT c.relname table_name,x.conname object_name
  FROM pg_constraint x JOIN pg_class c ON c.oid=x.conrelid
  JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='epm' AND c.relname IN(
   'cube_write_scope_lock','cube_write_scope_lock_event',
   'cube_write_scope_submission','cube_write_scope_submission_event',
   'cube_write_scope_assigned_submission',
   'cube_write_scope_assigned_reviewer',
   'cube_write_scope_assigned_review_event')
 LOOP
  new_name:=replace(replace(replace(replace(replace(replace(replace(
   r.object_name,
   'planning_assigned_review_event','cube_write_scope_assigned_review_event'),
   'planning_assigned_submission','cube_write_scope_assigned_submission'),
   'planning_assigned_reviewer','cube_write_scope_assigned_reviewer'),
   'planning_submission_event','cube_write_scope_submission_event'),
   'planning_submission','cube_write_scope_submission'),
   'planning_lock_event','cube_write_scope_lock_event'),
   'planning_slice_lock','cube_write_scope_lock');
  IF length(new_name)>63 THEN
   new_name:=left(new_name,54)||'_'||substr(md5(new_name),1,8);
  END IF;
  IF new_name<>r.object_name THEN
   EXECUTE format('ALTER TABLE epm.%I RENAME CONSTRAINT %I TO %I',
                  r.table_name,r.object_name,new_name);
  END IF;
 END LOOP;
 FOR r IN
  SELECT tablename table_name,policyname object_name
  FROM pg_policies WHERE schemaname='epm'
   AND tablename IN(
    'cube_write_scope_lock','cube_write_scope_lock_event',
    'cube_write_scope_submission','cube_write_scope_submission_event',
    'cube_write_scope_assigned_submission',
    'cube_write_scope_assigned_reviewer',
    'cube_write_scope_assigned_review_event')
 LOOP
  new_name:=replace(replace(replace(replace(replace(replace(replace(
   r.object_name,
   'planning_assigned_review_event','cube_write_scope_assigned_review_event'),
   'planning_assigned_submission','cube_write_scope_assigned_submission'),
   'planning_assigned_reviewer','cube_write_scope_assigned_reviewer'),
   'planning_submission_event','cube_write_scope_submission_event'),
   'planning_submission','cube_write_scope_submission'),
   'planning_lock_event','cube_write_scope_lock_event'),
   'planning_slice','cube_write_scope_lock');
  IF length(new_name)>63 THEN
   new_name:=left(new_name,54)||'_'||substr(md5(new_name),1,8);
  END IF;
  IF new_name<>r.object_name THEN
   EXECUTE format('ALTER POLICY %I ON epm.%I RENAME TO %I',
                  r.object_name,r.table_name,new_name);
  END IF;
 END LOOP;
END $$;

ALTER INDEX epm.planning_slice_active RENAME TO cube_write_scope_active;
ALTER FUNCTION epm.validate_planning_lock_transition()
 RENAME TO validate_cube_write_scope_lock_transition;
ALTER FUNCTION epm.validate_planning_submission_transition()
 RENAME TO validate_cube_write_scope_submission_transition;
ALTER FUNCTION epm.validate_planning_assigned_chain()
 RENAME TO validate_cube_write_scope_assigned_chain;
ALTER TRIGGER planning_lock_transition ON epm.cube_write_scope_lock
 RENAME TO cube_write_scope_lock_transition;
ALTER TRIGGER planning_submission_transition
 ON epm.cube_write_scope_submission
 RENAME TO cube_write_scope_submission_transition;
ALTER TRIGGER planning_assigned_chain_submission
 ON epm.cube_write_scope_assigned_submission
 RENAME TO cube_write_scope_assigned_chain_submission;
ALTER TRIGGER planning_assigned_chain_reviewer
 ON epm.cube_write_scope_assigned_reviewer
 RENAME TO cube_write_scope_assigned_chain_reviewer;

-- Fact-table lock triggers keep their existing identities to preserve
-- operational diagnostics. Their trigger function is recompiled below
-- against the renamed lock relation.

-- PL/pgSQL bodies are stored as source text. Recompile every retained reset,
-- guard, escalation or trigger function which refers to a renamed relation.
DO $$
DECLARE r record;definition text;rewritten text;
BEGIN
 FOR r IN
  SELECT p.oid,p.oid::regprocedure identity
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='epm' AND p.prokind IN('f','p') AND (
   pg_get_functiondef(p.oid) LIKE '%planning_assigned_review_event%'
   OR pg_get_functiondef(p.oid) LIKE '%planning_assigned_submission%'
   OR pg_get_functiondef(p.oid) LIKE '%planning_assigned_reviewer%'
   OR pg_get_functiondef(p.oid) LIKE '%planning_submission_event%'
   OR pg_get_functiondef(p.oid) LIKE '%planning_submission%'
   OR pg_get_functiondef(p.oid) LIKE '%planning_lock_event%'
   OR pg_get_functiondef(p.oid) LIKE '%planning_slice_lock%')
 LOOP
  definition:=pg_get_functiondef(r.oid);
  rewritten:=replace(replace(replace(replace(replace(replace(replace(
   definition,
   'planning_assigned_review_event','cube_write_scope_assigned_review_event'),
   'planning_assigned_submission','cube_write_scope_assigned_submission'),
   'planning_assigned_reviewer','cube_write_scope_assigned_reviewer'),
   'planning_submission_event','cube_write_scope_submission_event'),
   'planning_submission','cube_write_scope_submission'),
   'planning_lock_event','cube_write_scope_lock_event'),
   'planning_slice_lock','cube_write_scope_lock');
  IF rewritten=definition THEN
   RAISE EXCEPTION 'CUBE_WRITE_SCOPE_FUNCTION_REWRITE_MISSING: %',r.identity;
  END IF;
  EXECUTE rewritten;
 END LOOP;
END $$;

REVOKE ALL ON FUNCTION epm.validate_cube_write_scope_lock_transition()
 FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.validate_cube_write_scope_submission_transition()
 FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.validate_cube_write_scope_assigned_chain()
 FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;

DO $$
DECLARE old_name text;new_name text;
BEGIN
 FOREACH old_name IN ARRAY ARRAY[
  'planning_slice_lock','planning_lock_event','planning_submission',
  'planning_submission_event','planning_assigned_submission',
  'planning_assigned_reviewer','planning_assigned_review_event'] LOOP
  IF to_regclass('epm.'||old_name) IS NOT NULL THEN
   RAISE EXCEPTION 'CUBE_WRITE_SCOPE_OLD_RELATION_REMAINS: %',old_name;
  END IF;
 END LOOP;
 FOREACH new_name IN ARRAY ARRAY[
  'cube_write_scope_lock','cube_write_scope_lock_event',
  'cube_write_scope_submission','cube_write_scope_submission_event',
  'cube_write_scope_assigned_submission',
  'cube_write_scope_assigned_reviewer',
  'cube_write_scope_assigned_review_event'] LOOP
  IF to_regclass('epm.'||new_name) IS NULL THEN
   RAISE EXCEPTION 'CUBE_WRITE_SCOPE_NEW_RELATION_MISSING: %',new_name;
  END IF;
 END LOOP;
 IF EXISTS(
  SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='epm' AND p.prokind IN('f','p') AND (
   pg_get_functiondef(p.oid) LIKE '%planning_assigned_review_event%'
   OR pg_get_functiondef(p.oid) LIKE '%planning_assigned_submission%'
   OR pg_get_functiondef(p.oid) LIKE '%planning_assigned_reviewer%'
   OR pg_get_functiondef(p.oid) LIKE '%planning_submission_event%'
   OR pg_get_functiondef(p.oid) LIKE '%planning_submission%'
   OR pg_get_functiondef(p.oid) LIKE '%planning_lock_event%'
   OR pg_get_functiondef(p.oid) LIKE '%planning_slice_lock%')) THEN
  RAISE EXCEPTION 'CUBE_WRITE_SCOPE_STALE_FUNCTION_REFERENCE';
 END IF;
END $$;
