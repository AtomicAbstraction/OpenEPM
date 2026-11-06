-- Immutable policy versions may be removed only by the reviewed owner-reset
-- transaction capability. Ordinary DELETE and every UPDATE remain forbidden.
DO $$DECLARE w text;o text;a text;
BEGIN
 SELECT pg_get_functiondef('epm.planning_workflow_policy_version_immutable()'::regprocedure) INTO w;
 SELECT pg_get_functiondef('epm.planning_operation_policy_version_immutable()'::regprocedure) INTO o;
 SELECT pg_get_functiondef('epm.planning_assignment_version_immutable()'::regprocedure) INTO a;
 IF position('projection_cleanup_reset_context' in a)=0
 OR position('projection_cleanup_reset_context' in w)>0
 OR position('projection_cleanup_reset_context' in o)>0 THEN
  RAISE EXCEPTION 'RESET_0126_DEFINITION_MISMATCH';
 END IF;
END$$;

CREATE OR REPLACE FUNCTION epm.planning_workflow_policy_version_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' AND current_setting('epm.projection_cleanup_reset_context',true)=
    jsonb_build_array(OLD.workspace_id,pg_current_xact_id()::text,
                      pg_backend_pid())::text THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'PLANNING_WORKFLOW_POLICY_VERSION_IMMUTABLE'
   USING ERRCODE='23514';
END$$;

CREATE OR REPLACE FUNCTION epm.planning_operation_policy_version_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' AND current_setting('epm.projection_cleanup_reset_context',true)=
    jsonb_build_array(OLD.workspace_id,pg_current_xact_id()::text,
                      pg_backend_pid())::text THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'PLANNING_OPERATION_POLICY_VERSION_IMMUTABLE'
   USING ERRCODE='23514';
END$$;
