BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=369) THEN
    RAISE EXCEPTION 'MIGRATION_0370_REQUIRES_0369';
  END IF;
END $migration$;

-- A workflow evidence link authenticates both the operation identity and its
-- committed revision.  Keep that four-column reference exact after the
-- replay-receipt/provenance split rather than weakening it to operation ID.
ALTER TABLE epm.operation_commit_provenance
  ADD CONSTRAINT operation_commit_provenance_operation_revision_key
  UNIQUE(workspace_id,application_id,operation_id,committed_revision);

-- Every current incoming receipt FK is durable business/history provenance,
-- not ownership of the replay payload.  Retarget the reviewed set in place,
-- preserving child columns, names, delete actions and deferral semantics.
-- The exact cardinalities fail closed if an unreviewed reference appears.
DO $retarget$
DECLARE item record; definition text; revised text; retargeted integer:=0;
BEGIN
  IF (SELECT count(*) FROM pg_constraint
      WHERE contype='f'
        AND confrelid='epm.operation_receipt'::regclass)<>35
     OR (SELECT count(*) FROM pg_constraint
         WHERE contype='f'
           AND confrelid='epm.operation_receipt'::regclass
           AND array_length(conkey,1)=3)<>34
     OR (SELECT count(*) FROM pg_constraint
         WHERE contype='f'
           AND confrelid='epm.operation_receipt'::regclass
           AND array_length(conkey,1)=4)<>1
     OR (SELECT count(*) FROM pg_constraint
         WHERE contype='f'
           AND confrelid='epm.operation_receipt'::regclass
           AND confdeltype='r')<>34
     OR (SELECT count(*) FROM pg_constraint
         WHERE contype='f'
           AND confrelid='epm.operation_receipt'::regclass
           AND confdeltype='c')<>1
     OR (SELECT count(*) FROM pg_constraint
         WHERE contype='f'
           AND confrelid='epm.operation_receipt'::regclass
           AND condeferrable AND condeferred)<>2 THEN
    RAISE EXCEPTION 'OPERATION_PROVENANCE_0370_REFERENCE_SET_DRIFT';
  END IF;

  FOR item IN
    SELECT con.oid,con.conname,n.nspname,c.relname
    FROM pg_constraint con
    JOIN pg_class c ON c.oid=con.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE con.contype='f'
      AND con.confrelid='epm.operation_receipt'::regclass
    ORDER BY n.nspname,c.relname,con.conname
  LOOP
    definition:=pg_get_constraintdef(item.oid,true);
    revised:=replace(definition,
      'REFERENCES epm.operation_receipt',
      'REFERENCES epm.operation_commit_provenance');
    IF revised=definition THEN
      RAISE EXCEPTION 'OPERATION_PROVENANCE_0370_DEFINITION_DRIFT: %',
        item.conname;
    END IF;
    EXECUTE format(
      'ALTER TABLE %I.%I DROP CONSTRAINT %I, ADD CONSTRAINT %I %s NOT VALID',
      item.nspname,item.relname,item.conname,item.conname,revised);
    EXECUTE format('ALTER TABLE %I.%I VALIDATE CONSTRAINT %I',
      item.nspname,item.relname,item.conname);
    retargeted:=retargeted+1;
  END LOOP;

  IF retargeted<>35
     OR EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f'
       AND confrelid='epm.operation_receipt'::regclass)
     OR (SELECT count(*) FROM pg_constraint WHERE contype='f'
       AND confrelid='epm.operation_commit_provenance'::regclass)<>35
     OR (SELECT count(*) FROM pg_constraint WHERE contype='f'
       AND confrelid='epm.operation_commit_provenance'::regclass
       AND confdeltype='r')<>34
     OR (SELECT count(*) FROM pg_constraint WHERE contype='f'
       AND confrelid='epm.operation_commit_provenance'::regclass
       AND confdeltype='c')<>1
     OR (SELECT count(*) FROM pg_constraint WHERE contype='f'
       AND confrelid='epm.operation_commit_provenance'::regclass
       AND condeferrable AND condeferred)<>2 THEN
    RAISE EXCEPTION 'OPERATION_PROVENANCE_0370_RETARGET_INCOMPLETE';
  END IF;
END $retarget$;

-- The reviewed FK graph changes parent identity but remains acyclic and keeps
-- the existing child-first lifecycle inventory valid.  Advance both exact
-- lifecycle graph pins; do not alter their relation inventory or ordering.
DO $lifecycle$
DECLARE definition text;
DECLARE previous constant text:=
  '3c31399aa62696d9d5de1cd1462bd2bc78e65a2bca1eb7bc122a4d6c1b6dd529';
DECLARE current_graph constant text:=
  'b8210a6a58ff42c7650b45fa56a0a0bbf79bab05a559e801781b39f12ed06429';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0370_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);

  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0370_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $lifecycle$;

COMMIT;
SELECT '0370 applied' AS migration;
