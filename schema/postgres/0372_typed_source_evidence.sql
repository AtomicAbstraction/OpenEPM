BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=371) THEN
    RAISE EXCEPTION 'MIGRATION_0372_REQUIRES_0371';
  END IF;
END $migration$;

-- Source context is an application object graph, not an arbitrary JSON table.
-- Collections classify the business purpose, documents identify immutable
-- external source revisions, and records bind a typed classification plus an
-- optional full observation coordinate and closed source pointer.
CREATE TABLE epm.source_evidence_collection(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  collection_id text NOT NULL
    CHECK(collection_id~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200
    AND name=btrim(name) AND name!~'[[:cntrl:]]'),
  collection_kind text NOT NULL CHECK(collection_kind IN
    ('ObservationContext','SourceModel','SourceRecords')),
  description text NOT NULL DEFAULT '' CHECK(length(description)<=2000
    AND description!~'[[:cntrl:]]'),
  state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
  metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
  updated_issuer text NOT NULL CHECK(length(updated_issuer) BETWEEN 1 AND 300
    AND updated_issuer!~'[[:cntrl:]]'),
  updated_subject_id text NOT NULL CHECK(length(updated_subject_id) BETWEEN 1 AND 300
    AND updated_subject_id!~'[[:cntrl:]]'),
  updated_operation_id text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,collection_id),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,updated_operation_id)
    REFERENCES epm.operation_commit_provenance(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE epm.source_evidence_document(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  collection_id text NOT NULL,
  document_id text NOT NULL
    CHECK(document_id~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  title text NOT NULL CHECK(length(title) BETWEEN 1 AND 500
    AND title=btrim(title) AND title!~'[[:cntrl:]]'),
  media_type text NOT NULL CHECK(media_type~'^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}$'),
  source_uri text NOT NULL DEFAULT '' CHECK(length(source_uri)<=4096
    AND source_uri!~'[[:cntrl:]]'),
  source_revision text NOT NULL CHECK(length(source_revision) BETWEEN 1 AND 500
    AND source_revision!~'[[:cntrl:]]'),
  content_digest text NOT NULL CHECK(content_digest~'^[0-9a-f]{64}$'),
  state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
  metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
  updated_issuer text NOT NULL CHECK(length(updated_issuer) BETWEEN 1 AND 300
    AND updated_issuer!~'[[:cntrl:]]'),
  updated_subject_id text NOT NULL CHECK(length(updated_subject_id) BETWEEN 1 AND 300
    AND updated_subject_id!~'[[:cntrl:]]'),
  updated_operation_id text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,collection_id,document_id),
  FOREIGN KEY(workspace_id,application_id,collection_id)
    REFERENCES epm.source_evidence_collection(workspace_id,application_id,collection_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,updated_operation_id)
    REFERENCES epm.operation_commit_provenance(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE epm.source_evidence_record(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  collection_id text NOT NULL,
  record_id text NOT NULL
    CHECK(record_id~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  record_type text NOT NULL
    CHECK(record_type~'^[A-Za-z][A-Za-z0-9._:-]{0,99}$'),
  document_id text,
  observation_members jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK(jsonb_typeof(observation_members)='object'
      AND octet_length(observation_members::text)<=131072),
  source_pointer jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK(jsonb_typeof(source_pointer)='object'
      AND source_pointer-ARRAY['jsonPointer','page','line','column','cell','url']='{}'::jsonb
      AND octet_length(source_pointer::text)<=16384),
  properties jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK(jsonb_typeof(properties)='object'
      AND NOT (properties ?| ARRAY['collectionId','recordId','recordType','documentId',
        'observationMembers','sourcePointer','stateToken'])
      AND octet_length(properties::text)<=1048576),
  content_digest text NOT NULL CHECK(content_digest~'^[0-9a-f]{64}$'),
  state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
  metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
  updated_issuer text NOT NULL CHECK(length(updated_issuer) BETWEEN 1 AND 300
    AND updated_issuer!~'[[:cntrl:]]'),
  updated_subject_id text NOT NULL CHECK(length(updated_subject_id) BETWEEN 1 AND 300
    AND updated_subject_id!~'[[:cntrl:]]'),
  updated_operation_id text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,collection_id,record_id),
  FOREIGN KEY(workspace_id,application_id,collection_id)
    REFERENCES epm.source_evidence_collection(workspace_id,application_id,collection_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,collection_id,document_id)
    REFERENCES epm.source_evidence_document(workspace_id,application_id,collection_id,document_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,updated_operation_id)
    REFERENCES epm.operation_commit_provenance(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CHECK(document_id IS NULL OR document_id~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$')
);

CREATE INDEX source_evidence_document_collection
  ON epm.source_evidence_document(workspace_id,application_id,collection_id,document_id);
CREATE INDEX source_evidence_record_collection
  ON epm.source_evidence_record(workspace_id,application_id,collection_id,record_id);
CREATE INDEX source_evidence_record_document
  ON epm.source_evidence_record(workspace_id,application_id,collection_id,document_id)
  WHERE document_id IS NOT NULL;

ALTER TABLE epm.source_evidence_collection ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.source_evidence_document ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.source_evidence_record ENABLE ROW LEVEL SECURITY;

DO $policies$ DECLARE relation text; BEGIN
  FOREACH relation IN ARRAY ARRAY['source_evidence_collection',
      'source_evidence_document','source_evidence_record'] LOOP
    EXECUTE format('CREATE POLICY %I ON epm.%I TO epm_runtime '
      'USING(workspace_id=current_setting(''epm.workspace_id'',true) '
      'AND application_id=current_setting(''epm.application_id'',true)) '
      'WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) '
      'AND application_id=current_setting(''epm.application_id'',true))',
      relation||'_runtime_scope',relation);
    EXECUTE format('CREATE POLICY %I ON epm.%I TO epm_lifecycle '
      'USING(workspace_id=current_setting(''epm.workspace_id'',true))',
      relation||'_lifecycle_scope',relation);
  END LOOP;
END $policies$;

REVOKE ALL ON epm.source_evidence_collection,epm.source_evidence_document,
  epm.source_evidence_record FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,
  epm_security,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE,DELETE ON epm.source_evidence_collection,
  epm.source_evidence_document,epm.source_evidence_record TO epm_runtime;
GRANT SELECT ON epm.source_evidence_collection,epm.source_evidence_document,
  epm.source_evidence_record TO epm_lifecycle;

-- Register exact child-first deletion in both lifecycle owners and advance the
-- reviewed FK graph pin. Physical retirement is explicit, never cascade-only.
DO $lifecycle$
DECLARE definition text;revised text;inventory text[];idx integer;
DECLARE previous constant text:=
  'b8210a6a58ff42c7650b45fa56a0a0bbf79bab05a559e801781b39f12ed06429';
DECLARE current_graph constant text:=
  '6e1f5508abf72f98423b38f06736e3da5ab7982cbbac45dd22c00e1d355c5ff9';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0
     OR position('''operation_commit_provenance''' IN definition)=0
     OR position('''source_evidence_collection''' IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0372_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,'''operation_commit_provenance''',
    '''source_evidence_record'',''source_evidence_document'',''source_evidence_collection'',''operation_commit_provenance''');
  EXECUTE replace(revised,previous,current_graph);

  inventory:=epm.application_purge_relations();
  idx:=array_position(inventory,'operation_commit_provenance');
  IF idx IS NULL OR 'source_evidence_collection'=ANY(inventory) THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0372_INVENTORY_MISMATCH';
  END IF;
  inventory:=inventory[1:idx-1]||ARRAY['source_evidence_record',
    'source_evidence_document','source_evidence_collection']||inventory[idx:];
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
    'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');

  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0372_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $lifecycle$;

COMMIT;
SELECT '0372 applied' AS migration;
