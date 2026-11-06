-- Immutable planning forecast definitions; public routing and occurrences are
-- integrated separately and remain fail-closed until registered.
CREATE FUNCTION epm.forecast_definition_configuration_valid(c jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE k text; v jsonb; start_day date; cutoff date; end_day date;
BEGIN
 IF jsonb_typeof(c)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(c))<>14
 OR NOT c ?& ARRAY['name','scenarioDimension','actualMember','priorForecastMember','targetMember','yearDimension','periodDimension','filterMembers','mode','advancePeriods','horizonPeriods','windowStart','actualThrough','windowEndExclusive'] THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['name','scenarioDimension','actualMember','priorForecastMember','targetMember','yearDimension','periodDimension'] LOOP
  IF jsonb_typeof(c->k)<>'string' OR length(c->>k) NOT BETWEEN 1 AND 200 OR btrim(c->>k)<>c->>k OR (c->>k) ~ '[[:cntrl:]]' THEN RETURN false; END IF;
 END LOOP;
 IF c->>'mode' NOT IN ('seed','replace') OR jsonb_typeof(c->'mode')<>'string'
 OR c->>'scenarioDimension' IN (c->>'yearDimension',c->>'periodDimension') OR c->>'yearDimension'=c->>'periodDimension'
 OR c->>'actualMember' IN (c->>'priorForecastMember',c->>'targetMember') OR c->>'priorForecastMember'=c->>'targetMember' THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['advancePeriods','horizonPeriods'] LOOP
  IF jsonb_typeof(c->k)<>'number' OR (c->>k) !~ '^[1-9][0-9]?$' OR (c->>k)::int>36 THEN RETURN false; END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['windowStart','actualThrough','windowEndExclusive'] LOOP
  IF jsonb_typeof(c->k)<>'string' OR (c->>k) !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN RETURN false; END IF;
 END LOOP;
 start_day=(c->>'windowStart')::date; cutoff=(c->>'actualThrough')::date; end_day=(c->>'windowEndExclusive')::date;
 IF start_day>=end_day OR cutoff<start_day OR cutoff>end_day THEN RETURN false; END IF;
 IF jsonb_typeof(c->'filterMembers')<>'object' OR (SELECT count(*) FROM jsonb_object_keys(c->'filterMembers'))>29 THEN RETURN false; END IF;
 FOR k,v IN SELECT * FROM jsonb_each(c->'filterMembers') LOOP
  IF length(k) NOT BETWEEN 1 AND 200 OR btrim(k)<>k OR k ~ '[[:cntrl:]]' OR k IN (c->>'scenarioDimension',c->>'yearDimension',c->>'periodDimension') OR jsonb_typeof(v)<>'string' OR length(v#>>'{}') NOT BETWEEN 1 AND 200 OR btrim(v#>>'{}')<>v#>>'{}' OR (v#>>'{}') ~ '[[:cntrl:]]' THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION epm.forecast_definition_configuration_valid(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.forecast_definition_configuration_valid(jsonb) TO epm_runtime;
CREATE TABLE epm.planning_forecast_definition_version (
 workspace_id text NOT NULL, application_id text NOT NULL,
 definition_id text NOT NULL CHECK(definition_id ~ '^[A-Za-z0-9._-]{1,100}$'),
 version bigint NOT NULL CHECK(version>0), configuration jsonb NOT NULL CHECK(epm.forecast_definition_configuration_valid(configuration)),
 configuration_digest text NOT NULL CHECK(configuration_digest=encode(sha256(convert_to(configuration::text,'UTF8')),'hex')),
 actor_issuer text NOT NULL CHECK(length(actor_issuer) BETWEEN 1 AND 300),
 actor_subject text NOT NULL CHECK(length(actor_subject) BETWEEN 1 AND 300),
 operation_id text NOT NULL, created_revision bigint NOT NULL CHECK(created_revision>0),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,definition_id,version),
 CONSTRAINT forecast_definition_application_fkey FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
 CONSTRAINT forecast_definition_receipt_fkey FOREIGN KEY(workspace_id,application_id,operation_id) REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE epm.planning_forecast_definition_state (
 workspace_id text NOT NULL,application_id text NOT NULL,definition_id text NOT NULL,
 latest_version bigint NOT NULL CHECK(latest_version>0),active_version bigint CHECK(active_version>0 AND active_version<=latest_version),
 state_revision bigint NOT NULL CHECK(state_revision>0),
 PRIMARY KEY(workspace_id,application_id,definition_id),
 CONSTRAINT forecast_definition_latest_fkey FOREIGN KEY(workspace_id,application_id,definition_id,latest_version) REFERENCES epm.planning_forecast_definition_version(workspace_id,application_id,definition_id,version) ON DELETE RESTRICT,
 CONSTRAINT forecast_definition_active_fkey FOREIGN KEY(workspace_id,application_id,definition_id,active_version) REFERENCES epm.planning_forecast_definition_version(workspace_id,application_id,definition_id,version) ON DELETE RESTRICT
);
CREATE FUNCTION epm.forecast_definition_version_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE latest bigint;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'FORECAST_DEFINITION_IMMUTABLE' USING ERRCODE='23514'; END IF;
 IF current_setting('epm.workspace_id',true) IS DISTINCT FROM NEW.workspace_id OR current_setting('epm.application_id',true) IS DISTINCT FROM NEW.application_id THEN RAISE EXCEPTION 'FORECAST_DEFINITION_SCOPE_INVALID' USING ERRCODE='23514'; END IF;
 SELECT latest_version INTO latest FROM epm.planning_forecast_definition_state WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id AND definition_id=NEW.definition_id;
 IF NEW.version<>coalesce(latest,0)+1 THEN RAISE EXCEPTION 'FORECAST_DEFINITION_VERSION_INVALID' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER forecast_definition_version_guard BEFORE INSERT OR UPDATE ON epm.planning_forecast_definition_version FOR EACH ROW EXECUTE FUNCTION epm.forecast_definition_version_guard();
CREATE FUNCTION epm.forecast_definition_state_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
 IF current_setting('epm.workspace_id',true) IS DISTINCT FROM NEW.workspace_id OR current_setting('epm.application_id',true) IS DISTINCT FROM NEW.application_id THEN RAISE EXCEPTION 'FORECAST_DEFINITION_SCOPE_INVALID' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.latest_version<>1 OR NEW.state_revision<>1 OR NEW.active_version IS NOT NULL THEN RAISE EXCEPTION 'FORECAST_DEFINITION_STATE_INVALID' USING ERRCODE='23514'; END IF;
 ELSE
  IF ROW(NEW.workspace_id,NEW.application_id,NEW.definition_id) IS DISTINCT FROM ROW(OLD.workspace_id,OLD.application_id,OLD.definition_id) OR NEW.state_revision<>OLD.state_revision+1 OR NOT ((NEW.latest_version=OLD.latest_version+1 AND NEW.active_version IS NOT DISTINCT FROM OLD.active_version) OR (NEW.latest_version=OLD.latest_version AND NEW.active_version IS DISTINCT FROM OLD.active_version)) THEN RAISE EXCEPTION 'FORECAST_DEFINITION_STATE_INVALID' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER forecast_definition_state_guard BEFORE INSERT OR UPDATE ON epm.planning_forecast_definition_state FOR EACH ROW EXECUTE FUNCTION epm.forecast_definition_state_guard();
REVOKE ALL ON FUNCTION epm.forecast_definition_version_guard(),epm.forecast_definition_state_guard() FROM PUBLIC;
ALTER TABLE epm.planning_forecast_definition_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.planning_forecast_definition_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY forecast_definition_version_scope ON epm.planning_forecast_definition_version TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true)) WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY forecast_definition_state_scope ON epm.planning_forecast_definition_state TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true)) WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
REVOKE ALL ON epm.planning_forecast_definition_version,epm.planning_forecast_definition_state FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT ON epm.planning_forecast_definition_version TO epm_runtime;
GRANT SELECT,INSERT ON epm.planning_forecast_definition_state TO epm_runtime;
GRANT UPDATE(latest_version,active_version,state_revision) ON epm.planning_forecast_definition_state TO epm_runtime;
GRANT SELECT(workspace_id,application_id,definition_id,version)
    ON epm.planning_forecast_definition_version TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,definition_id,latest_version,active_version,state_revision)
    ON epm.planning_forecast_definition_state TO epm_lifecycle;
CREATE POLICY forecast_definition_version_lifecycle_inventory
    ON epm.planning_forecast_definition_version TO epm_lifecycle
    USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY forecast_definition_state_lifecycle_inventory
    ON epm.planning_forecast_definition_state TO epm_lifecycle
    USING(workspace_id=current_setting('epm.workspace_id',true));
