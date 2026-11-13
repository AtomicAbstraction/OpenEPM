-- Immutable technical artifacts for compiled import diagnostics and complete
-- paged exports. These records do not advance any business/data revision.

ALTER TABLE epm.source_batch ADD CONSTRAINT
 source_batch_manifest_identity_unique UNIQUE
 (workspace_id,application_id,batch_id,manifest_digest);

CREATE TABLE epm.source_import_diagnostic_artifact(
 workspace_id text NOT NULL,application_id text NOT NULL,
 artifact_id text NOT NULL CHECK(artifact_id ~ '^[0-9a-f]{32}$'),
 batch_id text NOT NULL,
 issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 300),
 subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 300),
 idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{8,128}$'),
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 source_manifest_digest text NOT NULL CHECK(source_manifest_digest ~ '^[0-9a-f]{64}$'),
 source_content_digest text NOT NULL CHECK(source_content_digest ~ '^[0-9a-f]{64}$'),
 source_schema_digest text NOT NULL CHECK(source_schema_digest ~ '^[0-9a-f]{64}$'),
 artifact_digest text NOT NULL CHECK(artifact_digest ~ '^[0-9a-f]{64}$'),
 artifact jsonb NOT NULL CHECK(jsonb_typeof(artifact)='object'
   AND octet_length(artifact::text)<=4194304),
 expires_at_epoch bigint NOT NULL CHECK(expires_at_epoch BETWEEN 1 AND 9223372036854775807),
 retention_status text NOT NULL DEFAULT 'retained'
   CHECK(retention_status IN ('retained','held','expired')),
 retention_reason text NOT NULL CHECK(length(retention_reason) BETWEEN 1 AND 500),
 retention_issuer text NOT NULL CHECK(length(retention_issuer) BETWEEN 1 AND 300),
 retention_subject_id text NOT NULL CHECK(length(retention_subject_id) BETWEEN 1 AND 300),
 retention_updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,artifact_id),
 UNIQUE(workspace_id,application_id,issuer,subject_id,idempotency_key),
 UNIQUE(workspace_id,application_id,batch_id),
 FOREIGN KEY(workspace_id,application_id,batch_id,source_manifest_digest)
  REFERENCES epm.source_batch(workspace_id,application_id,batch_id,manifest_digest)
  ON DELETE RESTRICT,
 CHECK(artifact->>'contractVersion'='openepm-source-import-diagnostics-v1'
   AND artifact->'sourceIdentity'->>'manifestDigest'=source_manifest_digest
   AND artifact->'sourceIdentity'->>'contentDigest'=source_content_digest
   AND artifact->'sourceIdentity'->>'schemaDigest'=source_schema_digest
   AND artifact->>'diagnosticsDigest'=artifact_digest
   AND jsonb_typeof(artifact->'diagnostics')='array'
   AND jsonb_typeof(artifact->'diagnosticCount')='number'
   AND jsonb_typeof(artifact->'observedCount')='number'
   AND jsonb_typeof(artifact->'errorCount')='number'
   AND jsonb_typeof(artifact->'warningCount')='number'
   AND jsonb_typeof(artifact->'truncated')='boolean'
   AND jsonb_typeof(artifact->'accepted')='boolean')
);

CREATE TABLE epm.fact_export_artifact(
 workspace_id text NOT NULL,application_id text NOT NULL,
 artifact_id text NOT NULL CHECK(artifact_id ~ '^[0-9a-f]{32}$'),
 issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 300),
 subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 300),
 idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{8,128}$'),
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 snapshot_revision bigint NOT NULL CHECK(snapshot_revision>=0),
 metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
 expires_at_epoch bigint NOT NULL CHECK(expires_at_epoch BETWEEN 1 AND 9223372036854775807),
 page_count integer NOT NULL CHECK(page_count BETWEEN 1 AND 100000),
 row_count bigint NOT NULL CHECK(row_count BETWEEN 0 AND 100000000),
 row_bytes bigint NOT NULL CHECK(row_bytes BETWEEN 0 AND 1099511627776),
 manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[0-9a-f]{64}$'),
 cumulative_digest text NOT NULL CHECK(cumulative_digest ~ '^[0-9a-f]{64}$'),
 manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object'
   AND octet_length(manifest::text)<=16777216),
 retention_status text NOT NULL DEFAULT 'retained'
   CHECK(retention_status IN ('retained','held','expired')),
 retention_reason text NOT NULL CHECK(length(retention_reason) BETWEEN 1 AND 500),
 retention_issuer text NOT NULL CHECK(length(retention_issuer) BETWEEN 1 AND 300),
 retention_subject_id text NOT NULL CHECK(length(retention_subject_id) BETWEEN 1 AND 300),
 retention_updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,artifact_id),
 UNIQUE(workspace_id,application_id,issuer,subject_id,idempotency_key),
 UNIQUE(workspace_id,application_id,manifest_digest),
 FOREIGN KEY(workspace_id,application_id)
  REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
 CHECK(manifest->>'contractVersion'='openepm-complete-export-manifest-v1'
   AND manifest->>'status'='complete'
   AND manifest->'scope'->>'workspaceId'=workspace_id
   AND manifest->'scope'->>'applicationId'=application_id
   AND (manifest->>'snapshotRevision') ~ '^[0-9]+$'
   AND (manifest->>'snapshotRevision')::numeric=snapshot_revision
   AND (manifest->>'metadataRevision') ~ '^[0-9]+$'
   AND (manifest->>'metadataRevision')::numeric=metadata_revision
   AND (manifest->>'expiresAt') ~ '^[0-9]+$'
   AND (manifest->>'expiresAt')::numeric=expires_at_epoch
   AND (manifest->>'pageCount') ~ '^[0-9]+$'
   AND (manifest->>'pageCount')::numeric=page_count
   AND (manifest->>'totalRowCount') ~ '^[0-9]+$'
   AND (manifest->>'totalRowCount')::numeric=row_count
   AND (manifest->>'totalRowBytes') ~ '^[0-9]+$'
   AND (manifest->>'totalRowBytes')::numeric=row_bytes
   AND manifest->>'manifestDigest'=manifest_digest
   AND manifest->>'cumulativeDigest'=cumulative_digest
   AND manifest->'schema'='{"id":"openepm.fact-transfer-page","version":1,"coordinate":"stable-dimension-member-map","literalTypes":["AmountLiteral","TextLiteral","LineDetailLiteral"],"sourceReference":"required-stable-origin"}'::jsonb)
);

CREATE INDEX source_import_diagnostic_retention ON
 epm.source_import_diagnostic_artifact(retention_status,expires_at_epoch,
  workspace_id,application_id);
CREATE INDEX fact_export_artifact_retention ON
 epm.fact_export_artifact(retention_status,expires_at_epoch,
  workspace_id,application_id);

CREATE FUNCTION epm.transfer_artifact_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['retention_status','retention_reason',
      'retention_issuer','retention_subject_id','retention_updated_at'])
    IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['retention_status','retention_reason',
      'retention_issuer','retention_subject_id','retention_updated_at']) THEN
  RAISE EXCEPTION 'TRANSFER_ARTIFACT_IMMUTABLE' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER source_import_diagnostic_immutable BEFORE UPDATE ON
 epm.source_import_diagnostic_artifact FOR EACH ROW
 EXECUTE FUNCTION epm.transfer_artifact_immutable();
CREATE TRIGGER fact_export_artifact_immutable BEFORE UPDATE ON
 epm.fact_export_artifact FOR EACH ROW
 EXECUTE FUNCTION epm.transfer_artifact_immutable();
REVOKE ALL ON FUNCTION epm.transfer_artifact_immutable() FROM PUBLIC,
 epm_runtime,epm_worker,epm_lifecycle,epm_analyst;

ALTER TABLE epm.source_import_diagnostic_artifact ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.fact_export_artifact ENABLE ROW LEVEL SECURITY;
CREATE POLICY source_import_diagnostic_runtime ON
 epm.source_import_diagnostic_artifact TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
CREATE POLICY fact_export_artifact_runtime ON epm.fact_export_artifact
 TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
CREATE POLICY source_import_diagnostic_lifecycle ON
 epm.source_import_diagnostic_artifact TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY fact_export_artifact_lifecycle ON epm.fact_export_artifact
 TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.source_import_diagnostic_artifact,
 epm.fact_export_artifact FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT SELECT,INSERT ON epm.source_import_diagnostic_artifact,
 epm.fact_export_artifact TO epm_runtime;
GRANT UPDATE(retention_status,retention_reason,retention_issuer,
 retention_subject_id,retention_updated_at)
 ON epm.source_import_diagnostic_artifact,epm.fact_export_artifact TO epm_runtime;
GRANT SELECT(workspace_id,application_id,artifact_id,batch_id,
 retention_status,expires_at_epoch) ON epm.source_import_diagnostic_artifact
 TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,artifact_id,retention_status,
 expires_at_epoch) ON epm.fact_export_artifact TO epm_lifecycle;

-- Register the new FK-safe deletion order with the owner-only exact reset.
DO $$
DECLARE v_old text := '36db585a34d01530ca050ce823779befdb8c0fa237d1d1e6aac804f25f1ac45e';
 v_new text := '4d5241f88afa0ed777a55862d48d831992d2d1d1cb0119d69681e4684e8c080d';
 v_definition text;v_replaced text;
 v_before text := '''layout_replacement_staged_coordinate'',''layout_replacement_generation'',''layout_replacement_request''';
 v_after text := '''source_import_diagnostic_artifact'',''fact_export_artifact'',''layout_replacement_staged_coordinate'',''layout_replacement_generation'',''layout_replacement_request''';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO v_definition;
 IF position(v_old in v_definition)=0 OR position(v_before in v_definition)=0
 THEN RAISE EXCEPTION 'RESET_0108_DEFINITION_MISMATCH'; END IF;
 v_replaced:=replace(replace(v_definition,v_old,v_new),v_before,v_after);
 EXECUTE v_replaced;
END $$;
