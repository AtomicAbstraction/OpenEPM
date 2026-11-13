-- Fresh eight-axis applications with editable semantic descriptions.
-- The descriptor is a migration snapshot of multidimensional_roles.py.
-- The lifecycle verifies exact Python/SQL parity before creating any rows.
-- No existing application or business member is changed by this migration.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=281) THEN
    RAISE EXCEPTION 'MIGRATION_0282_PREDECESSOR_0281_REQUIRED';
  END IF;
END $migration$;

CREATE FUNCTION epm.programmable_application_blueprint()
RETURNS jsonb LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path=pg_catalog AS $function$
  SELECT $blueprint${
  "version": 2,
  "dimensions": [
    {
      "dimensionId": "Account",
      "name": "Account",
      "modelRole": "Account",
      "semanticRole": "Context",
      "density": "Sparse",
      "shortDescription": "Accounts, measures, KPIs and goals.",
      "detailedDescription": "Application-defined financial or statistical accounts, measures, key performance indicators and goals. Their calculations and aggregation behavior are defined explicitly by the application's rules."
    },
    {
      "dimensionId": "Entity",
      "name": "Entity",
      "modelRole": "Entity",
      "semanticRole": "Core entity",
      "density": "Sparse",
      "shortDescription": "Business objects and organizational units.",
      "detailedDescription": "The business objects or organizational units modeled by this application. Hierarchies describe their relationships; aggregation, consolidation and other behavior must be defined explicitly."
    },
    {
      "dimensionId": "Year",
      "name": "Year",
      "modelRole": "Year",
      "semanticRole": "Context",
      "density": "Sparse",
      "shortDescription": "Year-level time classification.",
      "detailedDescription": "The application's year-level time classification. Members and calendar relationships are defined by the application; no particular fiscal calendar is assumed."
    },
    {
      "dimensionId": "Period",
      "name": "Period",
      "modelRole": "Period",
      "semanticRole": "Context",
      "density": "Sparse",
      "shortDescription": "Periods in the application's timeline.",
      "detailedDescription": "Periods within the application's timeline or calendar. Their order, duration and relationship to years are defined by the application."
    },
    {
      "dimensionId": "View",
      "name": "View",
      "modelRole": "View",
      "semanticRole": "Context",
      "density": "Sparse",
      "shortDescription": "Interpretation or presentation of values.",
      "detailedDescription": "The application's interpretation or presentation of values. Any period, cumulative or other behavior is defined explicitly by its rules rather than inferred from a member name."
    },
    {
      "dimensionId": "Value",
      "name": "Value",
      "modelRole": "Value",
      "semanticRole": "Context",
      "density": "Sparse",
      "shortDescription": "Application-defined value categories or layers.",
      "detailedDescription": "Value categories or layers defined by the application. Their meaning and transformations are expressed by the model and its rules; no currency or accounting behavior is activated automatically."
    },
    {
      "dimensionId": "Scenario",
      "name": "Scenario",
      "modelRole": "Scenario",
      "semanticRole": "Context",
      "density": "Sparse",
      "shortDescription": "Application-defined alternatives and assumptions.",
      "detailedDescription": "Alternatives chosen by the application, such as Actual, Budget, Forecast or Simulation. These are examples rather than required members; the dimension does not create experimental applications."
    },
    {
      "dimensionId": "DataType",
      "name": "Data Type",
      "modelRole": "DataType",
      "semanticRole": "Context",
      "density": "Sparse",
      "shortDescription": "Application-defined information classification.",
      "detailedDescription": "A classification chosen by the application, such as numeric, text, commentary, source or input category. Members do not coerce stored values or replace the platform's numeric, text and supporting-detail validation."
    }
  ]
}$blueprint$::jsonb;
$function$;

REVOKE ALL ON FUNCTION epm.programmable_application_blueprint() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.programmable_application_blueprint() TO epm_lifecycle;

CREATE OR REPLACE FUNCTION epm.initialize_programmable_application_blueprint(
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
    semantic_role,density,short_description,detailed_description)
  SELECT p_workspace,p_application,d."dimensionId",d.name,d."modelRole",
    d."semanticRole",d.density,d."shortDescription",d."detailedDescription"
  FROM jsonb_to_recordset(epm.programmable_application_blueprint()->'dimensions')
    AS d("dimensionId" text,name text,"modelRole" text,"semanticRole" text,
         density text,"shortDescription" text,"detailedDescription" text);

  UPDATE epm.application_state
  SET metadata_revision=1,commit_revision=1
  WHERE workspace_id=p_workspace AND application_id=p_application;
END $$;

REVOKE ALL ON FUNCTION
  epm.initialize_programmable_application_blueprint(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  epm.initialize_programmable_application_blueprint(text,text) TO epm_lifecycle;
