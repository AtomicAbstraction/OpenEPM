-- Bind every computed aggregate result to the dedicated authorization
-- revision.  Metadata and business-policy revisions do not advance for every
-- dimensional assignment/policy activation, so they cannot fence cached
-- analytical visibility by themselves.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=209) THEN
        RAISE EXCEPTION 'MIGRATION_0210_PREDECESSOR_0209_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.cube_aggregate_query
    ADD COLUMN source_security_revision bigint NULL;

-- Technical results created before this field existed were necessarily
-- produced while the old aggregate route admitted only applications without
-- an active dimensional policy.  Bind them to the application's revision at
-- upgrade; any later authorization change advances it and invalidates use.
UPDATE epm.cube_aggregate_query q
SET source_security_revision=s.security_revision
FROM epm.application_state s
WHERE q.workspace_id=s.workspace_id
  AND q.application_id=s.application_id
  AND q.source_commit_revision IS NOT NULL;

ALTER TABLE epm.cube_aggregate_query
    ADD CONSTRAINT cube_aggregate_query_security_revision_check CHECK
        (source_security_revision IS NULL OR source_security_revision>=0),
    ADD CONSTRAINT cube_aggregate_query_security_certificate_check CHECK
        ((source_commit_revision IS NULL)=(source_security_revision IS NULL));
