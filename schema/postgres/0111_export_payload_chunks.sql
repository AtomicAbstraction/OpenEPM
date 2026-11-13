-- Resumable immutable plaintext export payloads. This technical state does
-- not advance application business revisions and makes no encryption claim.

CREATE TABLE epm.fact_export_payload(
 workspace_id text NOT NULL,application_id text NOT NULL,
 artifact_id text NOT NULL CHECK(artifact_id ~ '^[0-9a-f]{32}$'),
 issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 300),
 subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 300),
 idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{8,128}$'),
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[0-9a-f]{64}$'),
 payload_digest text NOT NULL CHECK(payload_digest ~ '^[0-9a-f]{64}$'),
 expected_chunk_count integer NOT NULL CHECK(expected_chunk_count BETWEEN 1 AND 100000),
 row_count bigint NOT NULL CHECK(row_count BETWEEN 0 AND 100000000),
 row_bytes bigint NOT NULL CHECK(row_bytes BETWEEN 0 AND 1099511627776),
 type_counts jsonb NOT NULL CHECK(type_counts ?& ARRAY['amount','text','lineDetail']
   AND type_counts-ARRAY['amount','text','lineDetail']='{}'::jsonb),
 status text NOT NULL DEFAULT 'building' CHECK(status IN('building','complete')),
 storage_format text NOT NULL DEFAULT 'plaintext_json'
   CHECK(storage_format='plaintext_json'),
 encryption_claim boolean NOT NULL DEFAULT false CHECK(NOT encryption_claim),
 expires_at_epoch bigint NOT NULL CHECK(expires_at_epoch BETWEEN 1 AND 9223372036854775807),
 retention_status text NOT NULL DEFAULT 'retained'
   CHECK(retention_status IN('retained','held','expired')),
 retention_reason text NOT NULL CHECK(length(retention_reason) BETWEEN 1 AND 500),
 retention_issuer text NOT NULL CHECK(length(retention_issuer) BETWEEN 1 AND 300),
 retention_subject_id text NOT NULL CHECK(length(retention_subject_id) BETWEEN 1 AND 300),
 retention_updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 finalized_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,artifact_id),
 UNIQUE(workspace_id,application_id,issuer,subject_id,idempotency_key),
 FOREIGN KEY(workspace_id,application_id,artifact_id)
  REFERENCES epm.fact_export_artifact(workspace_id,application_id,artifact_id)
  ON DELETE RESTRICT,
 CHECK((status='building' AND finalized_at IS NULL)
    OR (status='complete' AND finalized_at IS NOT NULL)),
 CHECK((type_counts->>'amount') ~ '^[0-9]+$'
   AND (type_counts->>'text') ~ '^[0-9]+$'
   AND (type_counts->>'lineDetail') ~ '^[0-9]+$'
   AND (type_counts->>'amount')::numeric
      +(type_counts->>'text')::numeric
      +(type_counts->>'lineDetail')::numeric=row_count)
);

CREATE TABLE epm.fact_export_payload_chunk(
 workspace_id text NOT NULL,application_id text NOT NULL,
 artifact_id text NOT NULL,ordinal integer NOT NULL CHECK(ordinal>=0),
 page_index integer NOT NULL CHECK(page_index>=0),
 chunk_index integer NOT NULL CHECK(chunk_index>=0),
 chunk_digest text NOT NULL CHECK(chunk_digest ~ '^[0-9a-f]{64}$'),
 page_content_digest text NOT NULL CHECK(page_content_digest ~ '^[0-9a-f]{64}$'),
 row_count integer NOT NULL CHECK(row_count BETWEEN 0 AND 500),
 row_bytes integer NOT NULL CHECK(row_bytes BETWEEN 2 AND 8388608),
 type_counts jsonb NOT NULL CHECK(type_counts ?& ARRAY['amount','text','lineDetail']
   AND type_counts-ARRAY['amount','text','lineDetail']='{}'::jsonb),
 final_chunk_for_page boolean NOT NULL,
 storage_format text NOT NULL DEFAULT 'plaintext_json'
   CHECK(storage_format='plaintext_json'),
 encryption_claim boolean NOT NULL DEFAULT false CHECK(NOT encryption_claim),
 chunk jsonb NOT NULL CHECK(jsonb_typeof(chunk)='object'
   AND octet_length(chunk::text)<=9437184),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,artifact_id,ordinal),
 UNIQUE(workspace_id,application_id,artifact_id,page_index,chunk_index),
 FOREIGN KEY(workspace_id,application_id,artifact_id)
  REFERENCES epm.fact_export_payload(workspace_id,application_id,artifact_id)
  ON DELETE RESTRICT,
 CHECK(chunk->>'contractVersion'='openepm-export-payload-v1'
   AND chunk->>'artifactId'=artifact_id
   AND chunk->>'chunkDigest'=chunk_digest
   AND chunk->>'pageContentDigest'=page_content_digest
   AND (chunk->>'pageIndex') ~ '^[0-9]+$'
   AND (chunk->>'pageIndex')::numeric=page_index
   AND (chunk->>'chunkIndex') ~ '^[0-9]+$'
   AND (chunk->>'chunkIndex')::numeric=chunk_index
   AND (chunk->>'rowCount') ~ '^[0-9]+$'
   AND (chunk->>'rowCount')::numeric=row_count
   AND (chunk->>'rowBytes') ~ '^[0-9]+$'
   AND (chunk->>'rowBytes')::numeric=row_bytes
   AND chunk->'typeCounts'=type_counts
   AND (chunk->>'finalChunkForPage')::boolean=final_chunk_for_page
   AND jsonb_typeof(chunk->'rows')='array')
);

CREATE INDEX fact_export_payload_retention ON epm.fact_export_payload
 (retention_status,expires_at_epoch,workspace_id,application_id);

CREATE FUNCTION epm.export_payload_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='fact_export_payload_chunk' THEN
  RAISE EXCEPTION 'EXPORT_PAYLOAD_CHUNK_IMMUTABLE' USING ERRCODE='23514';
 END IF;
 IF (to_jsonb(NEW)-ARRAY['status','finalized_at','retention_status',
      'retention_reason','retention_issuer','retention_subject_id',
      'retention_updated_at']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['status','finalized_at','retention_status',
      'retention_reason','retention_issuer','retention_subject_id',
      'retention_updated_at']) THEN
  RAISE EXCEPTION 'EXPORT_PAYLOAD_IMMUTABLE' USING ERRCODE='23514';
 END IF;
 IF OLD.status='complete' AND NEW.status IS DISTINCT FROM OLD.status THEN
  RAISE EXCEPTION 'EXPORT_PAYLOAD_FINALIZED' USING ERRCODE='23514';
 END IF;
 IF OLD.retention_status='expired'
    AND NEW.retention_status IS DISTINCT FROM OLD.retention_status THEN
  RAISE EXCEPTION 'EXPORT_PAYLOAD_RETENTION_STALE' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER fact_export_payload_immutable BEFORE UPDATE ON
 epm.fact_export_payload FOR EACH ROW EXECUTE FUNCTION epm.export_payload_immutable();
CREATE TRIGGER fact_export_payload_chunk_immutable BEFORE UPDATE ON
 epm.fact_export_payload_chunk FOR EACH ROW EXECUTE FUNCTION epm.export_payload_immutable();
REVOKE ALL ON FUNCTION epm.export_payload_immutable() FROM PUBLIC,
 epm_runtime,epm_worker,epm_lifecycle,epm_analyst;

ALTER TABLE epm.fact_export_payload ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.fact_export_payload_chunk ENABLE ROW LEVEL SECURITY;
CREATE POLICY fact_export_payload_runtime ON epm.fact_export_payload TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
CREATE POLICY fact_export_payload_chunk_runtime ON epm.fact_export_payload_chunk TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
CREATE POLICY fact_export_payload_lifecycle ON epm.fact_export_payload TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY fact_export_payload_chunk_lifecycle ON epm.fact_export_payload_chunk TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.fact_export_payload,epm.fact_export_payload_chunk
 FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT SELECT,INSERT ON epm.fact_export_payload,epm.fact_export_payload_chunk TO epm_runtime;
GRANT UPDATE(status,finalized_at,retention_status,retention_reason,
 retention_issuer,retention_subject_id,retention_updated_at)
 ON epm.fact_export_payload TO epm_runtime;
GRANT SELECT(workspace_id,application_id,artifact_id,status,retention_status,
 expires_at_epoch) ON epm.fact_export_payload TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,artifact_id,ordinal)
 ON epm.fact_export_payload_chunk TO epm_lifecycle;

-- FK-safe exact reset registration; fingerprint is finalized by the live
-- migration qualification for this schema.
DO $$ DECLARE old text:='7ffba0dfc873a068e6e2572146420c926f334e77d1bacb6a5d27194de52c423b';
 new text:='0e91a3cfcdf49a82ff78839ae60febb8f718280a6de921b09f0cf5c620d7f5e5';d text;r text;
 b text:='''source_import_diagnostic_artifact'',''fact_export_artifact'',''layout_replacement_activation_coordinate''';
 a text:='''fact_export_payload_chunk'',''fact_export_payload'',''source_import_diagnostic_artifact'',''fact_export_artifact'',''layout_replacement_activation_coordinate''';
BEGIN SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)INTO d;
 IF position(old in d)=0 OR position(b in d)=0 THEN RAISE EXCEPTION 'RESET_0111_DEFINITION_MISMATCH';END IF;
 r:=replace(replace(d,old,new),b,a);EXECUTE r;END $$;
