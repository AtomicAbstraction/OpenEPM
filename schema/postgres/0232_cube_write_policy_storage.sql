-- Rename the active generic cube-write policy storage.  The data, keys, RLS,
-- privileges and immutable history remain in place; only the planning-era
-- physical vocabulary is retired.
ALTER TABLE epm.planning_workflow_policy_version
 RENAME TO cube_write_policy_version;
ALTER TABLE epm.planning_workflow_policy_state
 RENAME TO cube_write_policy_state;

-- Rename every table-owned catalog object which inherited the planning-era
-- prefix.  Constraint renames also rename their backing indexes.
DO $$
DECLARE r record;new_name text;
BEGIN
 FOR r IN
  SELECT c.relname table_name,x.conname object_name
  FROM pg_constraint x JOIN pg_class c ON c.oid=x.conrelid
  JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='epm' AND c.relname IN(
    'cube_write_policy_version','cube_write_policy_state')
    AND x.conname LIKE 'planning_workflow_policy%'
 LOOP
  new_name:=replace(r.object_name,'planning_workflow_policy',
                    'cube_write_policy');
  EXECUTE format('ALTER TABLE epm.%I RENAME CONSTRAINT %I TO %I',
                 r.table_name,r.object_name,new_name);
 END LOOP;
 FOR r IN
  SELECT tablename table_name,policyname object_name
  FROM pg_policies WHERE schemaname='epm'
    AND tablename IN('cube_write_policy_version','cube_write_policy_state')
    AND policyname LIKE 'planning_workflow_policy%'
 LOOP
  new_name:=replace(r.object_name,'planning_workflow_policy',
                    'cube_write_policy');
  EXECUTE format('ALTER POLICY %I ON epm.%I RENAME TO %I',
                 r.object_name,r.table_name,new_name);
 END LOOP;
END $$;

ALTER FUNCTION epm.planning_workflow_policy_version_immutable()
 RENAME TO cube_write_policy_version_immutable;
ALTER TRIGGER planning_workflow_policy_version_immutable
 ON epm.cube_write_policy_version
 RENAME TO cube_write_policy_version_immutable;

-- PL/pgSQL bodies are stored as source text.  Recompile every retained owner
-- reset or worker function which refers to the renamed relations; otherwise a
-- later reset/escalation would fail only when its lazy SQL expression runs.
DO $$
DECLARE r record;definition text;rewritten text;
BEGIN
 FOR r IN
  SELECT p.oid,p.oid::regprocedure identity
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='epm' AND p.prokind IN('f','p')
    AND (pg_get_functiondef(p.oid) LIKE '%epm.planning_workflow_policy_version%'
      OR pg_get_functiondef(p.oid) LIKE '%epm.planning_workflow_policy_state%'
      OR pg_get_functiondef(p.oid) LIKE '%''planning_workflow_policy_version''%'
      OR pg_get_functiondef(p.oid) LIKE '%''planning_workflow_policy_state''%')
 LOOP
  definition:=pg_get_functiondef(r.oid);
  rewritten:=replace(replace(definition,
    'planning_workflow_policy_version','cube_write_policy_version'),
    'planning_workflow_policy_state','cube_write_policy_state');
  IF rewritten=definition THEN
   RAISE EXCEPTION 'CUBE_WRITE_POLICY_FUNCTION_REWRITE_MISSING: %',r.identity;
  END IF;
  EXECUTE rewritten;
 END LOOP;
END $$;

-- The renamed immutable trigger function keeps the same fail-closed behavior
-- and executable privilege boundary.
REVOKE ALL ON FUNCTION epm.cube_write_policy_version_immutable()
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;

DO $$
BEGIN
 IF to_regclass('epm.planning_workflow_policy_version') IS NOT NULL
    OR to_regclass('epm.planning_workflow_policy_state') IS NOT NULL
    OR to_regclass('epm.cube_write_policy_version') IS NULL
    OR to_regclass('epm.cube_write_policy_state') IS NULL THEN
  RAISE EXCEPTION 'CUBE_WRITE_POLICY_STORAGE_RENAME_INCOMPLETE';
 END IF;
 IF EXISTS(
  SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='epm' AND p.prokind IN('f','p') AND (
    pg_get_functiondef(p.oid) LIKE '%epm.planning_workflow_policy_version%'
    OR pg_get_functiondef(p.oid) LIKE '%epm.planning_workflow_policy_state%'
    OR pg_get_functiondef(p.oid) LIKE '%''planning_workflow_policy_version''%'
    OR pg_get_functiondef(p.oid) LIKE '%''planning_workflow_policy_state''%')) THEN
  RAISE EXCEPTION 'CUBE_WRITE_POLICY_STALE_FUNCTION_REFERENCE';
 END IF;
END $$;
