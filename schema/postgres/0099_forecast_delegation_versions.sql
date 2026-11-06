-- Bind every scheduled/occurrence execution to one immutable delegation.
-- Existing rows are accepted only when the current version is unambiguous and
-- matches the stored verified principal; otherwise this migration fails.
ALTER TABLE epm.planning_forecast_schedule_version ADD COLUMN delegation_version bigint;
ALTER TABLE epm.planning_forecast_occurrence ADD COLUMN delegation_version bigint;

UPDATE epm.planning_forecast_schedule_version f SET delegation_version=s.active_version
FROM epm.execution_delegation_state s JOIN epm.execution_delegation_version v
 ON (v.workspace_id,v.application_id,v.delegation_id,v.version)=
    (s.workspace_id,s.application_id,s.delegation_id,s.active_version)
WHERE (s.workspace_id,s.application_id,s.delegation_id)=
      (f.workspace_id,f.application_id,f.delegation_id)
 AND s.revoked_at IS NULL AND v.issuer=f.execution_issuer
 AND v.subject_id=f.execution_subject AND v.schedule_id=f.schedule_id
 AND v.schedule_version=f.version;
UPDATE epm.planning_forecast_occurrence f SET delegation_version=s.active_version
FROM epm.execution_delegation_state s JOIN epm.execution_delegation_version v
 ON (v.workspace_id,v.application_id,v.delegation_id,v.version)=
    (s.workspace_id,s.application_id,s.delegation_id,s.active_version)
WHERE (s.workspace_id,s.application_id,s.delegation_id)=
      (f.workspace_id,f.application_id,f.delegation_id)
 AND s.revoked_at IS NULL AND v.issuer=f.execution_issuer
 AND v.subject_id=f.execution_subject
 AND v.schedule_id IS NOT DISTINCT FROM f.schedule_id
 AND v.schedule_version IS NOT DISTINCT FROM f.schedule_version;

DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM epm.planning_forecast_schedule_version WHERE delegation_version IS NULL)
 OR EXISTS(SELECT 1 FROM epm.planning_forecast_occurrence WHERE delegation_version IS NULL)
 THEN RAISE EXCEPTION 'FORECAST_DELEGATION_BACKFILL_UNPROVEN'; END IF;
END $$;
ALTER TABLE epm.planning_forecast_schedule_version ALTER COLUMN delegation_version SET NOT NULL;
ALTER TABLE epm.planning_forecast_occurrence ALTER COLUMN delegation_version SET NOT NULL;
ALTER TABLE epm.planning_forecast_schedule_version ADD CONSTRAINT
 forecast_schedule_delegation_fkey FOREIGN KEY(workspace_id,application_id,
 delegation_id,delegation_version) REFERENCES epm.execution_delegation_version
 (workspace_id,application_id,delegation_id,version) ON DELETE RESTRICT;
ALTER TABLE epm.planning_forecast_occurrence ADD CONSTRAINT
 forecast_occurrence_delegation_fkey FOREIGN KEY(workspace_id,application_id,
 delegation_id,delegation_version) REFERENCES epm.execution_delegation_version
 (workspace_id,application_id,delegation_id,version) ON DELETE RESTRICT;
