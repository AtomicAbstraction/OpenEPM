-- Bind every durable fact export request and artifact to the dedicated
-- dimensional-authorization revision.  Existing artifacts predate this
-- certificate and deliberately remain NULL/fail-closed instead of being
-- misrepresented as having been produced under today's grants.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=210) THEN
        RAISE EXCEPTION 'MIGRATION_0211_PREDECESSOR_0210_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.fact_export_producer_request
    ADD COLUMN security_revision bigint NULL,
    ADD CONSTRAINT fact_export_producer_security_revision_check CHECK
        (security_revision IS NULL OR security_revision>=0);

-- Work accepted before the certificate existed cannot safely continue or be
-- rerun: its already-checkpointed pages have no provable authorization pin.
-- Convert those rows before installing the active-state constraint so an
-- upgrade remains valid even when legacy work was in flight.
UPDATE epm.fact_export_producer_request
SET status='Failed', claimant=NULL, lease_until=NULL,
    error_code='EXPORT_SECURITY_CERTIFICATE_UNAVAILABLE',
    updated_at=transaction_timestamp()
WHERE security_revision IS NULL
  AND status IN ('Accepted','Reading','Prepared','Publishing');

ALTER TABLE epm.fact_export_producer_request
    ADD CONSTRAINT fact_export_producer_security_certificate_check CHECK
        (security_revision IS NOT NULL OR
         status IN ('Cancelled','Failed','Completed'));

ALTER TABLE epm.fact_export_artifact
    ADD COLUMN security_revision bigint NULL,
    ADD CONSTRAINT fact_export_artifact_security_revision_check CHECK
        (security_revision IS NULL OR security_revision>=0);

DO $migration$
DECLARE constraint_name text;
BEGIN
    SELECT c.conname INTO constraint_name
    FROM pg_constraint c
    WHERE c.conrelid='epm.fact_export_artifact'::regclass
      AND c.contype='c'
      AND pg_get_constraintdef(c.oid) LIKE '%contractVersion%'
    ORDER BY c.oid
    LIMIT 1;
    IF constraint_name IS NULL THEN
        RAISE EXCEPTION 'EXPORT_ARTIFACT_MANIFEST_CONSTRAINT_UNAVAILABLE';
    END IF;
    EXECUTE format('ALTER TABLE epm.fact_export_artifact DROP CONSTRAINT %I',
                   constraint_name);
END $migration$;

ALTER TABLE epm.fact_export_artifact
    ADD CONSTRAINT fact_export_artifact_manifest_security_check CHECK(
      manifest->>'status'='complete'
      AND manifest->'scope'->>'workspaceId'=workspace_id
      AND manifest->'scope'->>'applicationId'=application_id
      AND (manifest->>'snapshotRevision')~'^[0-9]+$'
      AND (manifest->>'snapshotRevision')::numeric=snapshot_revision
      AND (manifest->>'metadataRevision')~'^[0-9]+$'
      AND (manifest->>'metadataRevision')::numeric=metadata_revision
      AND (manifest->>'expiresAt')~'^[0-9]+$'
      AND (manifest->>'expiresAt')::numeric=expires_at_epoch
      AND (manifest->>'pageCount')~'^[0-9]+$'
      AND (manifest->>'pageCount')::numeric=page_count
      AND (manifest->>'totalRowCount')~'^[0-9]+$'
      AND (manifest->>'totalRowCount')::numeric=row_count
      AND (manifest->>'totalRowBytes')~'^[0-9]+$'
      AND (manifest->>'totalRowBytes')::numeric=row_bytes
      AND manifest->>'manifestDigest'=manifest_digest
      AND manifest->>'cumulativeDigest'=cumulative_digest
      AND manifest->'schema'='{"id":"openepm.fact-transfer-page","version":1,"coordinate":"stable-dimension-member-map","literalTypes":["AmountLiteral","TextLiteral","LineDetailLiteral"],"sourceReference":"required-stable-origin"}'::jsonb
      AND ((manifest->>'contractVersion'=
              'openepm-complete-export-manifest-v1'
            AND security_revision IS NULL
            AND NOT manifest ? 'securityRevision')
        OR (manifest->>'contractVersion'=
              'openepm-complete-export-manifest-v2'
            AND security_revision IS NOT NULL
            AND (manifest->>'securityRevision')~'^[0-9]+$'
            AND (manifest->>'securityRevision')::numeric=security_revision)));

DO $migration$
DECLARE constraint_name text;
BEGIN
    SELECT c.conname INTO constraint_name
    FROM pg_constraint c
    WHERE c.conrelid='epm.fact_export_payload_chunk'::regclass
      AND c.contype='c'
      AND pg_get_constraintdef(c.oid) LIKE '%contractVersion%'
    ORDER BY c.oid
    LIMIT 1;
    IF constraint_name IS NULL THEN
        RAISE EXCEPTION 'EXPORT_PAYLOAD_CHUNK_CONSTRAINT_UNAVAILABLE';
    END IF;
    EXECUTE format(
      'ALTER TABLE epm.fact_export_payload_chunk DROP CONSTRAINT %I',
      constraint_name);
END $migration$;

ALTER TABLE epm.fact_export_payload_chunk
    ADD CONSTRAINT fact_export_payload_chunk_versioned_check CHECK(
      chunk->>'contractVersion' IN (
        'openepm-export-payload-v1','openepm-export-payload-v2')
      AND chunk->>'artifactId'=artifact_id
      AND chunk->>'chunkDigest'=chunk_digest
      AND chunk->>'pageContentDigest'=page_content_digest
      AND (chunk->>'pageIndex')~'^[0-9]+$'
      AND (chunk->>'pageIndex')::numeric=page_index
      AND (chunk->>'chunkIndex')~'^[0-9]+$'
      AND (chunk->>'chunkIndex')::numeric=chunk_index
      AND (chunk->>'rowCount')~'^[0-9]+$'
      AND (chunk->>'rowCount')::numeric=row_count
      AND (chunk->>'rowBytes')~'^[0-9]+$'
      AND (chunk->>'rowBytes')::numeric=row_bytes
      AND chunk->'typeCounts'=type_counts
      AND (chunk->>'finalChunkForPage')::boolean=final_chunk_for_page
      AND jsonb_typeof(chunk->'rows')='array');

CREATE INDEX fact_export_producer_security_revision
    ON epm.fact_export_producer_request(
        workspace_id,application_id,security_revision,status);
CREATE INDEX fact_export_artifact_security_revision
    ON epm.fact_export_artifact(
        workspace_id,application_id,security_revision,artifact_id);
