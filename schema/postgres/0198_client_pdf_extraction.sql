-- Store a bounded client-produced PDF extraction beside the immutable source
-- document. The fixed core validates and persists this payload but never
-- parses the PDF bytes on the application server.
ALTER TABLE epm.policy_source_artifact
    ADD COLUMN client_extraction_id text,
    ADD COLUMN client_extraction_sha256 text,
    ADD COLUMN client_extraction_bytes integer,
    ADD COLUMN client_extraction bytea,
    ADD CONSTRAINT policy_source_client_extraction_complete CHECK (
        num_nonnulls(client_extraction_id,client_extraction_sha256,
                     client_extraction_bytes,client_extraction) IN (0,4)),
    ADD CONSTRAINT policy_source_client_extraction_pdf CHECK (
        client_extraction_id IS NULL OR media_type='application/pdf'),
    ADD CONSTRAINT policy_source_client_extraction_id CHECK (
        client_extraction_id IS NULL OR
        client_extraction_id ~ '^[A-Za-z0-9._-]{8,128}$'),
    ADD CONSTRAINT policy_source_client_extraction_digest CHECK (
        client_extraction_sha256 IS NULL OR
        client_extraction_sha256 ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT policy_source_client_extraction_size CHECK (
        client_extraction_bytes IS NULL OR
        (client_extraction_bytes BETWEEN 1 AND 2097152 AND
         octet_length(client_extraction)=client_extraction_bytes));

CREATE UNIQUE INDEX policy_source_client_extraction_id_unique
    ON epm.policy_source_artifact
       (workspace_id,application_id,client_extraction_id)
    WHERE client_extraction_id IS NOT NULL;
