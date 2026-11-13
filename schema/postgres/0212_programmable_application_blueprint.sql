-- Least-privilege bootstrap for the single programmable application model.
-- The lifecycle role cannot insert arbitrary metadata.  This fixed primitive
-- admits only the canonical six-axis blueprint into a new, empty application.

CREATE FUNCTION epm.initialize_programmable_application_blueprint(
  p_workspace text,p_application text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  application_kind text;
  metadata_revision bigint;
  data_revision bigint;
  policy_revision bigint;
  security_revision bigint;
  commit_revision bigint;
BEGIN
  IF NOT pg_has_role(session_user,'epm_lifecycle','member') THEN
    RAISE EXCEPTION 'PROGRAMMABLE_BLUEPRINT_LIFECYCLE_REQUIRED';
  END IF;
  IF p_workspace IS NULL OR length(p_workspace) NOT BETWEEN 1 AND 200
     OR p_application IS NULL OR length(p_application) NOT BETWEEN 1 AND 200
     OR current_setting('epm.workspace_id',true) IS DISTINCT FROM p_workspace
     OR current_setting('epm.application_id',true) IS DISTINCT FROM p_application THEN
    RAISE EXCEPTION 'PROGRAMMABLE_BLUEPRINT_SCOPE_INVALID';
  END IF;

  SELECT a.kind,s.metadata_revision,s.data_revision,s.policy_revision,
         s.security_revision,s.commit_revision
    INTO application_kind,metadata_revision,data_revision,policy_revision,
         security_revision,commit_revision
  FROM epm.application a
  JOIN epm.application_state s USING(workspace_id,application_id)
  WHERE a.workspace_id=p_workspace AND a.application_id=p_application
  FOR UPDATE OF a,s;
  IF NOT FOUND OR application_kind<>'multidimensional' THEN
    RAISE EXCEPTION 'PROGRAMMABLE_BLUEPRINT_APPLICATION_INVALID';
  END IF;
  IF metadata_revision<>0 OR data_revision<>0 OR policy_revision<>0
     OR security_revision<>0 OR commit_revision<>0 OR EXISTS(
       SELECT 1 FROM epm.dimension d
       WHERE d.workspace_id=p_workspace AND d.application_id=p_application) THEN
    RAISE EXCEPTION 'PROGRAMMABLE_BLUEPRINT_APPLICATION_NOT_EMPTY';
  END IF;

  INSERT INTO epm.dimension(
    workspace_id,application_id,dimension_id,name,model_role,
    semantic_role,density)
  VALUES
    (p_workspace,p_application,'Account','Account','Account','Context','Sparse'),
    (p_workspace,p_application,'Entity','Entity','Entity','Core entity','Sparse'),
    (p_workspace,p_application,'Year','Year','Year','Context','Sparse'),
    (p_workspace,p_application,'Period','Period','Period','Context','Sparse'),
    (p_workspace,p_application,'View','View','View','Context','Sparse'),
    (p_workspace,p_application,'Value','Value','Value','Context','Sparse');

  UPDATE epm.application_state
  SET metadata_revision=1,commit_revision=1
  WHERE workspace_id=p_workspace AND application_id=p_application;
END $$;

REVOKE ALL ON FUNCTION
  epm.initialize_programmable_application_blueprint(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  epm.initialize_programmable_application_blueprint(text,text) TO epm_lifecycle;
