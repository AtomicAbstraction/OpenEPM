DO $migration$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=407) THEN
   RAISE EXCEPTION 'MIGRATION_0408_REQUIRES_0407';
 END IF;
END $migration$;

-- Existing batches retain their original source and replay contract. A new
-- group-admitted batch records its fixed import shape at begin and the exact
-- accepted preview fingerprint in the same transaction as its fact receipt.
ALTER TABLE epm.source_batch
  ADD COLUMN group_numeric_import boolean NOT NULL DEFAULT false,
  ADD COLUMN publication_preview_digest text,
  ADD CONSTRAINT group_source_import_shape CHECK(
     NOT group_numeric_import OR
       (mode='merge' AND scope_all AND scope_members='{}'::jsonb
        AND period_selection IS NULL AND manifest_digest IS NULL)),
  ADD CONSTRAINT group_source_import_preview CHECK(
     (publication_preview_digest IS NOT NULL)=(group_numeric_import AND status='published')
     AND (publication_preview_digest IS NULL OR publication_preview_digest~'^[0-9a-f]{64}$'));
GRANT UPDATE(publication_preview_digest) ON epm.source_batch TO epm_runtime;

CREATE FUNCTION epm.group_source_publication_identity_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
BEGIN
  IF OLD.group_numeric_import IS DISTINCT FROM NEW.group_numeric_import
    OR (OLD.publication_preview_digest IS NOT NULL AND
        OLD.publication_preview_digest IS DISTINCT FROM NEW.publication_preview_digest) THEN
    RAISE EXCEPTION 'SOURCE_PUBLICATION_IDENTITY_IMMUTABLE' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $guard$;
REVOKE ALL ON FUNCTION epm.group_source_publication_identity_guard() FROM PUBLIC;
CREATE TRIGGER group_source_publication_identity_guard
  BEFORE UPDATE OF group_numeric_import,publication_preview_digest ON epm.source_batch
  FOR EACH ROW EXECUTE FUNCTION epm.group_source_publication_identity_guard();
