DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=406) THEN
        RAISE EXCEPTION 'MIGRATION_0407_REQUIRES_0406';
    END IF;
END $migration$;

-- Every durable task producer projects its native lifecycle into epm.task in
-- the admission/update transaction. This includes validation builds without a
-- business job, human workflow occurrences and activities, schedule occurrences,
-- queries, transfers and ordered execution. Unknown statuses block by default.
CREATE INDEX task_authorization_migration_open
  ON epm.task(workspace_id,application_id,source_family)
  WHERE status NOT IN ('Succeeded','PartiallySucceeded','Failed','Interrupted');

CREATE FUNCTION epm.authorization_migration_active_work() RETURNS TABLE(family text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $body$
    WITH selected AS (SELECT current_setting('epm.workspace_id',true) workspace_id,
                             current_setting('epm.application_id',true) application_id),
    pending AS (
        SELECT DISTINCT t.source_family AS family FROM epm.task t
            JOIN selected USING(workspace_id,application_id)
            WHERE t.status NOT IN ('Succeeded','PartiallySucceeded','Failed','Interrupted')
        UNION ALL SELECT 'CalculationWorkRequest' WHERE EXISTS (
            SELECT 1 FROM epm.calculation_work_request JOIN selected USING(workspace_id,application_id)
            WHERE status NOT IN ('no_change','published','failed','cancelled'))
        UNION ALL SELECT 'CalculationWorkTask' WHERE EXISTS (
            SELECT 1 FROM epm.calculation_work_task JOIN selected USING(workspace_id,application_id)
            WHERE status NOT IN ('published','failed','cancelled'))
        UNION ALL SELECT 'ApplicationScheduleLease' WHERE EXISTS (
            SELECT 1 FROM epm.application_schedule_definition JOIN selected USING(workspace_id,application_id)
            WHERE dispatch_claimant IS NOT NULL AND dispatch_lease_until>statement_timestamp())
        UNION ALL SELECT 'PythonScheduleLease' WHERE EXISTS (
            SELECT 1 FROM epm.python_program_schedule_definition JOIN selected USING(workspace_id,application_id)
            WHERE dispatch_claimant IS NOT NULL AND dispatch_lease_until>statement_timestamp())
    ) SELECT pending.family FROM pending ORDER BY pending.family COLLATE "C"
$body$;
REVOKE ALL ON FUNCTION epm.authorization_migration_active_work() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.authorization_migration_active_work() TO epm_security;
