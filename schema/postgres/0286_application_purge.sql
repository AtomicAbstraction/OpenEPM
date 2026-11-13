BEGIN;
DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=285) THEN
    RAISE EXCEPTION 'MIGRATION_0286_REQUIRES_0285';
  END IF;
END $migration$;

-- Only terminal actor/target identity survives deletion. No old application
-- payload, row counts, source, definition, chat or artifact is retained here.
CREATE TABLE epm.application_purge_audit (
    target_workspace_id text NOT NULL,
    target_application_id text NOT NULL,
    target_created_at timestamptz NOT NULL,
    target_schema_epoch bigint NOT NULL CHECK (target_schema_epoch>=0),
    operation_id text NOT NULL CHECK (operation_id ~ '^[A-Za-z0-9._-]{8,128}$'),
    command_digest text NOT NULL CHECK (command_digest ~ '^[0-9a-f]{64}$'),
    actor_digest text NOT NULL CHECK (actor_digest ~ '^[0-9a-f]{64}$'),
    completed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (target_workspace_id,operation_id),
    UNIQUE (target_workspace_id,target_application_id,target_created_at)
);
ALTER TABLE epm.application_purge_audit ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON epm.application_purge_audit TO epm_lifecycle;
CREATE POLICY application_purge_audit_scope ON epm.application_purge_audit
    FOR SELECT TO epm_lifecycle
    USING (target_workspace_id=current_setting('epm.workspace_id',true));

CREATE FUNCTION epm.next_application_schema_epoch(p_workspace text,p_application text)
RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $function$
    SELECT COALESCE(max(target_schema_epoch)+1,0)
    FROM epm.application_purge_audit
    WHERE target_workspace_id=p_workspace AND target_application_id=p_application
$function$;
REVOKE ALL ON FUNCTION epm.next_application_schema_epoch(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.next_application_schema_epoch(text,text) TO epm_lifecycle;

-- This transaction/backend/application capability extends the established
-- projection cleanup guards without putting the containing workspace into
-- maintenance or granting ordinary clients any DELETE privilege.
CREATE FUNCTION epm.application_purge_allowed(p_workspace text,p_application text)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog AS $function$
  SELECT pg_has_role(session_user,'epm_lifecycle','member')
    AND pg_has_role(current_user,(SELECT relowner FROM pg_class
      WHERE oid='epm.operation_receipt'::regclass),'USAGE')
    AND current_setting('epm.application_purge_context',true)=
      jsonb_build_array(p_workspace,p_application,pg_current_xact_id()::text,pg_backend_pid())::text
    AND EXISTS(SELECT 1 FROM epm.application a JOIN epm.application_state s USING(workspace_id,application_id)
      WHERE a.workspace_id=p_workspace AND a.application_id=p_application
        AND a.status='Deleting' AND s.processing_mode='Deleting')
$function$;
REVOKE ALL ON FUNCTION epm.application_purge_allowed(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_purge_allowed(text,text) TO epm_runtime,epm_worker,epm_lifecycle;
DO $migration$
DECLARE definition text;
BEGIN
  SELECT pg_get_functiondef('epm.projection_cleanup_allowed(text,text,bigint,text)'::regprocedure) INTO definition;
  EXECUTE regexp_replace(definition,'\mBEGIN\M',
    'BEGIN IF epm.application_purge_allowed(w,a) THEN RETURN true; END IF;');
  SELECT pg_get_functiondef('epm.coordinate_layout_dimension_change()'::regprocedure) INTO definition;
  EXECUTE regexp_replace(definition,'\mBEGIN\M',
    'BEGIN IF TG_OP=''DELETE'' AND epm.application_purge_allowed(OLD.workspace_id,OLD.application_id) THEN RETURN NULL; END IF;');
END $migration$;

-- Compile one constant application-only inventory from the already reviewed
-- owner reset order. Resolve the existing logical projection names to their
-- physical backing tables so every retained generation is removed.
-- Runtime callers can never supply a relation or SQL expression.
DO $migration$
DECLARE definition text; body text; inventory text[]; selected text[]; item text;
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  body := split_part(split_part(definition,'FOREACH v_table IN ARRAY ARRAY[',2),']',1);
  IF body='' THEN RAISE EXCEPTION 'APPLICATION_PURGE_RESET_INVENTORY_MISSING'; END IF;
  EXECUTE 'SELECT ARRAY['||body||']::text[]' INTO inventory;
  FOREACH item IN ARRAY inventory LOOP
    item := CASE item WHEN 'numeric_cell_current' THEN 'numeric_cell_projection'
      WHEN 'text_cell_current' THEN 'text_cell_projection' WHEN 'line_detail_current' THEN 'line_detail_projection'
      WHEN 'generic_fact_current' THEN 'generic_fact_projection' WHEN 'coordinate_member' THEN 'coordinate_member_projection'
      WHEN 'coordinate_projection' THEN 'coordinate_projection_state' ELSE item END;
    IF EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=to_regclass('epm.'||item)
      AND a.attname='application_id' AND a.attnum>0 AND NOT a.attisdropped) THEN
      selected := array_append(selected,item);
    END IF;
  END LOOP;
  -- The reset intentionally retains global security audit; app purge retires
  -- application-associated history and retains only its terminal actor audit.
  selected := array_prepend('security_audit',selected);
  IF NOT ('application'=ANY(selected)) OR NOT ('application_state'=ANY(selected)) THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_INVENTORY_INCOMPLETE';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='epm' AND c.relkind IN ('r','p')
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='workspace_id' AND a.attnum>0 AND NOT a.attisdropped)
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='application_id' AND a.attnum>0 AND NOT a.attisdropped)
      AND c.relname <> ALL(selected)
  ) THEN RAISE EXCEPTION 'APPLICATION_PURGE_UNREVIEWED_SCOPED_RELATION'; END IF;
  EXECUTE format('CREATE FUNCTION epm.application_purge_relations() RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(selected)||'::text[]');
END $migration$;
REVOKE ALL ON FUNCTION epm.application_purge_relations() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_purge_relations() TO epm_lifecycle;

CREATE FUNCTION epm.application_purge_inventory(p_workspace text,p_application text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE item text; amount bigint; counts jsonb:='{}'; active jsonb:='{}'; lease_column text; target record;
BEGIN
  IF NOT pg_has_role(session_user,'epm_lifecycle','member')
     OR p_workspace IS DISTINCT FROM current_setting('epm.workspace_id',true)
     OR p_application IS DISTINCT FROM current_setting('epm.application_id',true) THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT a.name,a.created_at,a.status,s.schema_epoch,s.metadata_revision,s.data_revision,
    s.policy_revision,s.commit_revision,s.processing_mode INTO target
    FROM epm.application a JOIN epm.application_state s USING(workspace_id,application_id)
    WHERE a.workspace_id=p_workspace AND a.application_id=p_application FOR SHARE OF s;
  IF NOT FOUND THEN RAISE EXCEPTION 'APPLICATION_PURGE_TARGET_NOT_FOUND'; END IF;
  FOREACH item IN ARRAY epm.application_purge_relations() LOOP
    EXECUTE format('SELECT count(*) FROM epm.%I WHERE workspace_id=$1 AND application_id=$2',item)
      INTO amount USING p_workspace,p_application;
    counts := counts||jsonb_build_object(item,amount);
    FOR lease_column IN SELECT attname FROM pg_attribute WHERE attrelid=to_regclass('epm.'||item)
      AND attname IN ('lease_until','dispatch_lease_until') AND attnum>0 AND NOT attisdropped LOOP
      EXECUTE format('SELECT count(*) FROM epm.%I WHERE workspace_id=$1 AND application_id=$2 AND %I>clock_timestamp()',item,lease_column)
        INTO amount USING p_workspace,p_application;
      IF amount>0 THEN active:=active||jsonb_build_object(item||'.'||lease_column,amount); END IF;
    END LOOP;
  END LOOP;
  RETURN jsonb_build_object('rowCounts',counts,'activeLeases',active,'storage','postgresql','target',to_jsonb(target));
END $function$;
REVOKE ALL ON FUNCTION epm.application_purge_inventory(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_purge_inventory(text,text) TO epm_lifecycle;

CREATE FUNCTION epm.quiesce_application_purge(p_workspace text,p_application text,p_created_at timestamptz)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
  IF NOT pg_has_role(session_user,'epm_lifecycle','member')
     OR p_workspace IS DISTINCT FROM current_setting('epm.workspace_id',true)
     OR p_application IS DISTINCT FROM current_setting('epm.application_id',true) THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;
  UPDATE epm.application SET status='Deleting' WHERE workspace_id=p_workspace
    AND application_id=p_application AND created_at=p_created_at;
  IF NOT FOUND THEN RAISE EXCEPTION 'APPLICATION_PURGE_INCARNATION_CHANGED'; END IF;
  UPDATE epm.application_state SET processing_mode='Deleting'
    WHERE workspace_id=p_workspace AND application_id=p_application;
END $function$;
REVOKE ALL ON FUNCTION epm.quiesce_application_purge(text,text,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.quiesce_application_purge(text,text,timestamptz) TO epm_lifecycle;

CREATE FUNCTION epm.apply_application_purge(p_workspace text,p_application text,p_created_at timestamptz,
    p_operation text,p_command_digest text,p_actor_digest text,p_schema_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE prior epm.application_purge_audit%ROWTYPE; target record; item text; inventory jsonb;
BEGIN
  IF NOT pg_has_role(session_user,'epm_lifecycle','member')
     OR p_workspace IS DISTINCT FROM current_setting('epm.workspace_id',true)
     OR p_application IS DISTINCT FROM current_setting('epm.application_id',true)
     OR p_schema_fingerprint IS DISTINCT FROM '1163589cb3bd257c54c5c988a437cdfdfc00f63afee82189f11675d243460f77' THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO prior FROM epm.application_purge_audit
    WHERE target_workspace_id=p_workspace AND operation_id=p_operation;
  IF FOUND THEN
    IF prior.command_digest IS DISTINCT FROM p_command_digest OR prior.actor_digest IS DISTINCT FROM p_actor_digest
       OR prior.target_application_id IS DISTINCT FROM p_application OR prior.target_created_at IS DISTINCT FROM p_created_at THEN
      RAISE EXCEPTION 'IDEMPOTENCY_KEY_REUSED';
    END IF;
    RETURN jsonb_build_object('workspaceId',p_workspace,'applicationId',p_application,
      'createdAt',prior.target_created_at,'schemaEpoch',prior.target_schema_epoch,
      'operationId',p_operation,'status','Deleted');
  END IF;
  SELECT a.created_at,a.status,s.schema_epoch,s.processing_mode INTO target
    FROM epm.application a JOIN epm.application_state s USING(workspace_id,application_id)
    WHERE a.workspace_id=p_workspace AND a.application_id=p_application FOR UPDATE OF s;
  IF NOT FOUND OR target.created_at IS DISTINCT FROM p_created_at THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_INCARNATION_CHANGED';
  END IF;
  IF target.status<>'Deleting' OR target.processing_mode<>'Deleting' THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_QUIESCE_REQUIRED';
  END IF;
  inventory:=epm.application_purge_inventory(p_workspace,p_application);
  IF inventory->'activeLeases'<>'{}'::jsonb THEN RAISE EXCEPTION 'APPLICATION_PURGE_WORKERS_ACTIVE'; END IF;
  PERFORM set_config('epm.lifecycle_context','workspace_reset',true);
  PERFORM set_config('epm.application_purge_context',
    jsonb_build_array(p_workspace,p_application,pg_current_xact_id()::text,pg_backend_pid())::text,true);
  PERFORM set_config('epm.projection_cleanup_reset_context',
    jsonb_build_array(p_workspace,pg_current_xact_id()::text,pg_backend_pid())::text,true);
  FOREACH item IN ARRAY epm.application_purge_relations() LOOP
    EXECUTE format('DELETE FROM epm.%I WHERE workspace_id=$1 AND application_id=$2',item)
      USING p_workspace,p_application;
  END LOOP;
  -- These workspace receipts carry application scope in their fixed JSON
  -- contract, rather than physical application_id columns.
  DELETE FROM epm.workspace_lifecycle_receipt WHERE workspace_id=p_workspace AND result->>'applicationId'=p_application;
  DELETE FROM epm.security_operation_receipt WHERE workspace_id=p_workspace AND result->>'applicationId'=p_application;
  PERFORM set_config('epm.application_purge_context','',true);
  PERFORM set_config('epm.projection_cleanup_reset_context','',true);
  PERFORM set_config('epm.lifecycle_context','',true);
  INSERT INTO epm.application_purge_audit(target_workspace_id,target_application_id,target_created_at,
    target_schema_epoch,operation_id,command_digest,actor_digest)
    VALUES(p_workspace,p_application,p_created_at,target.schema_epoch,p_operation,p_command_digest,p_actor_digest);
  RETURN jsonb_build_object('workspaceId',p_workspace,'applicationId',p_application,
    'createdAt',p_created_at,'schemaEpoch',target.schema_epoch,'operationId',p_operation,'status','Deleted');
END $function$;
REVOKE ALL ON FUNCTION epm.apply_application_purge(text,text,timestamptz,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.apply_application_purge(text,text,timestamptz,text,text,text,text) TO epm_lifecycle;

DO $migration$
DECLARE definition text;
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
  IF position('390b2aa5ee922a4a76eb73158fd2ef0c6130c21d55bab95dcb19df77a597cefb' IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_RESET_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,'390b2aa5ee922a4a76eb73158fd2ef0c6130c21d55bab95dcb19df77a597cefb','1163589cb3bd257c54c5c988a437cdfdfc00f63afee82189f11675d243460f77');
END $migration$;
COMMIT;
