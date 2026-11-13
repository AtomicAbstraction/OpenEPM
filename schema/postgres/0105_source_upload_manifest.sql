-- Immutable batch-level source/upload identity.  The manifest is attached by
-- fixed core code after facts.source.begin and before data is accepted.  It is
-- metadata only: retention state never deletes facts or source history.

ALTER TABLE epm.source_batch
    ADD COLUMN manifest_request_key text,
    ADD COLUMN manifest_origin_kind text,
    ADD COLUMN manifest_origin_ref text,
    ADD COLUMN manifest_schema_version text,
    ADD COLUMN manifest_schema jsonb,
    ADD COLUMN manifest_schema_digest text,
    ADD COLUMN manifest_content_digest text,
    ADD COLUMN manifest_digest text,
    ADD COLUMN manifest_creator_issuer text,
    ADD COLUMN manifest_creator_subject_id text,
    ADD COLUMN manifest_created_at timestamptz,
    ADD COLUMN manifest_retention_status text,
    ADD COLUMN manifest_retention_reason text,
    ADD COLUMN manifest_retention_issuer text,
    ADD COLUMN manifest_retention_subject_id text,
    ADD COLUMN manifest_retention_updated_at timestamptz,
    ADD CONSTRAINT source_batch_upload_manifest_shape CHECK (
      (manifest_digest IS NULL AND manifest_request_key IS NULL
        AND manifest_origin_kind IS NULL AND manifest_origin_ref IS NULL
        AND manifest_schema_version IS NULL AND manifest_schema IS NULL
        AND manifest_schema_digest IS NULL AND manifest_content_digest IS NULL
        AND manifest_creator_issuer IS NULL
        AND manifest_creator_subject_id IS NULL
        AND manifest_created_at IS NULL AND manifest_retention_status IS NULL
        AND manifest_retention_reason IS NULL
        AND manifest_retention_issuer IS NULL
        AND manifest_retention_subject_id IS NULL
        AND manifest_retention_updated_at IS NULL)
      OR
      (manifest_digest ~ '^[0-9a-f]{64}$'
        AND manifest_request_key ~ '^[A-Za-z0-9._-]{8,128}$'
        AND manifest_origin_kind IN
          ('file','mcp','notebook','schedule','system-generated')
        AND length(manifest_origin_ref) BETWEEN 1 AND 1000
        AND manifest_origin_ref !~ '[[:cntrl:]]'
        AND manifest_schema_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$'
        AND jsonb_typeof(manifest_schema)='object'
        AND octet_length(manifest_schema::text)<=65536
        AND manifest_schema_digest ~ '^[0-9a-f]{64}$'
        AND manifest_content_digest ~ '^[0-9a-f]{64}$'
        AND length(manifest_creator_issuer) BETWEEN 1 AND 300
        AND length(manifest_creator_subject_id) BETWEEN 1 AND 300
        AND manifest_created_at IS NOT NULL
        AND manifest_retention_status IN ('retained','held','expired')
        AND length(manifest_retention_reason) BETWEEN 1 AND 500
        AND length(manifest_retention_issuer) BETWEEN 1 AND 300
        AND length(manifest_retention_subject_id) BETWEEN 1 AND 300
        AND manifest_retention_updated_at IS NOT NULL)),
    ADD CONSTRAINT source_batch_upload_manifest_creator CHECK (
      manifest_digest IS NULL OR
      (manifest_creator_issuer=issuer AND
       manifest_creator_subject_id=subject_id)),
    ADD CONSTRAINT source_batch_upload_manifest_request_unique UNIQUE
      (workspace_id,application_id,manifest_creator_issuer,
       manifest_creator_subject_id,manifest_request_key);

CREATE INDEX source_batch_upload_manifest_retention
    ON epm.source_batch
      (workspace_id,application_id,manifest_retention_status,
       manifest_retention_updated_at)
    WHERE manifest_digest IS NOT NULL;

CREATE FUNCTION epm.source_batch_upload_manifest_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF TG_OP='INSERT' AND NEW.manifest_digest IS NOT NULL THEN
    RAISE EXCEPTION 'SOURCE_UPLOAD_MANIFEST_REQUIRES_ATTACH'
      USING ERRCODE='23514';
  ELSIF TG_OP='UPDATE' AND OLD.manifest_digest IS NOT NULL AND ROW(
      NEW.manifest_request_key,NEW.manifest_origin_kind,
      NEW.manifest_origin_ref,NEW.manifest_schema_version,
      NEW.manifest_schema,NEW.manifest_schema_digest,
      NEW.manifest_content_digest,NEW.manifest_digest,
      NEW.manifest_creator_issuer,NEW.manifest_creator_subject_id,
      NEW.manifest_created_at) IS DISTINCT FROM ROW(
      OLD.manifest_request_key,OLD.manifest_origin_kind,
      OLD.manifest_origin_ref,OLD.manifest_schema_version,
      OLD.manifest_schema,OLD.manifest_schema_digest,
      OLD.manifest_content_digest,OLD.manifest_digest,
      OLD.manifest_creator_issuer,OLD.manifest_creator_subject_id,
      OLD.manifest_created_at) THEN
    RAISE EXCEPTION 'SOURCE_UPLOAD_MANIFEST_IMMUTABLE' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER source_batch_upload_manifest_immutable
BEFORE INSERT OR UPDATE ON epm.source_batch FOR EACH ROW
EXECUTE FUNCTION epm.source_batch_upload_manifest_immutable();

REVOKE ALL ON FUNCTION epm.source_batch_upload_manifest_immutable()
    FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;

-- Replace the original table-wide UPDATE with the columns fixed core needs.
-- The immutable trigger is still a database boundary if runtime code attempts
-- to rewrite a previously attached manifest.
REVOKE UPDATE ON epm.source_batch FROM epm_runtime;
GRANT UPDATE(status,chunk_count,row_count,content_digest,receipt_revision,
    result,updated_at,manifest_request_key,manifest_origin_kind,
    manifest_origin_ref,manifest_schema_version,manifest_schema,
    manifest_schema_digest,manifest_content_digest,manifest_digest,
    manifest_creator_issuer,manifest_creator_subject_id,manifest_created_at,
    manifest_retention_status,manifest_retention_reason,
    manifest_retention_issuer,manifest_retention_subject_id,
    manifest_retention_updated_at) ON epm.source_batch TO epm_runtime;

-- Existing source_batch lifecycle RLS and reset deletion inventory cover the
-- new columns without adding a relation or changing the reviewed FK graph.
