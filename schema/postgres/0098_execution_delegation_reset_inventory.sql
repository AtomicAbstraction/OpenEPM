-- Forward-only lifecycle inventory for execution delegations. Reset deletion
-- is dependency-safe through 0097 receipt/version/state cascades.
CREATE FUNCTION epm.execution_delegation_reset_inventory(p_workspace_id text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object(
  'execution_delegation_version',(SELECT count(*) FROM epm.execution_delegation_version WHERE workspace_id=p_workspace_id),
  'execution_delegation_state',(SELECT count(*) FROM epm.execution_delegation_state WHERE workspace_id=p_workspace_id))
 WHERE p_workspace_id=current_setting('epm.workspace_id',true)
$$;
REVOKE ALL ON FUNCTION epm.execution_delegation_reset_inventory(text) FROM PUBLIC,epm_runtime,epm_worker,epm_analyst;
GRANT EXECUTE ON FUNCTION epm.execution_delegation_reset_inventory(text) TO epm_lifecycle;
