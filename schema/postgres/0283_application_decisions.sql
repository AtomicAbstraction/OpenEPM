BEGIN;

DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=282) THEN
    RAISE EXCEPTION 'MIGRATION_0283_REQUIRES_0282';
  END IF;
END $migration$;

CREATE TABLE epm.application_decision_version (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    decision_id text NOT NULL CHECK (decision_id ~ '^[A-Za-z0-9._-]{1,100}$'),
    version integer NOT NULL CHECK (version>0),
    title text NOT NULL CHECK (octet_length(title) BETWEEN 1 AND 200 AND length(btrim(title))>0),
    decision_text text NOT NULL CHECK (octet_length(decision_text) BETWEEN 1 AND 8000 AND length(btrim(decision_text))>0),
    rationale text NOT NULL DEFAULT '' CHECK (octet_length(rationale)<=2000),
    source_reference text NOT NULL DEFAULT '' CHECK (octet_length(source_reference)<=1000),
    provenance text NOT NULL CHECK (provenance IN ('UserDecision','AgentInterpretation')),
    status text NOT NULL CHECK (status IN ('Active','Withdrawn')),
    content_digest text NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    created_operation_id text NOT NULL,
    created_revision bigint NOT NULL CHECK (created_revision>0),
    created_issuer text NOT NULL,
    created_subject_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,decision_id,version),
    FOREIGN KEY (workspace_id,application_id)
      REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,created_operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id) ON DELETE RESTRICT
);
CREATE INDEX application_decision_revision_idx ON epm.application_decision_version
    (workspace_id,application_id,created_revision DESC);
CREATE TABLE epm.application_decision_head (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    decision_id text NOT NULL,
    version integer NOT NULL,
    PRIMARY KEY (workspace_id,application_id,decision_id),
    FOREIGN KEY (workspace_id,application_id,decision_id,version)
      REFERENCES epm.application_decision_version(workspace_id,application_id,decision_id,version) ON DELETE RESTRICT
);

GRANT SELECT,INSERT ON epm.application_decision_version,epm.application_decision_head TO epm_runtime;
GRANT UPDATE (version) ON epm.application_decision_head TO epm_runtime;
GRANT SELECT ON epm.application_decision_version,epm.application_decision_head TO epm_lifecycle;
ALTER TABLE epm.application_decision_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.application_decision_head ENABLE ROW LEVEL SECURITY;
CREATE POLICY application_decision_version_scope ON epm.application_decision_version
    TO epm_runtime USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY application_decision_head_scope ON epm.application_decision_head
    TO epm_runtime USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY application_decision_version_lifecycle ON epm.application_decision_version
    FOR SELECT TO epm_lifecycle USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY application_decision_head_lifecycle ON epm.application_decision_head
    FOR SELECT TO epm_lifecycle USING (workspace_id=current_setting('epm.workspace_id',true));

CREATE FUNCTION epm.application_decision_version_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
  IF TG_OP='DELETE'
     AND current_setting('epm.lifecycle_context',true)='workspace_reset'
     AND pg_has_role(session_user,'epm_lifecycle','member') THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'APPLICATION_DECISION_VERSION_IMMUTABLE' USING ERRCODE='23514';
END $function$;
REVOKE ALL ON FUNCTION epm.application_decision_version_immutable()
    FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
CREATE TRIGGER application_decision_version_immutable
    BEFORE UPDATE OR DELETE ON epm.application_decision_version
    FOR EACH ROW EXECUTE FUNCTION epm.application_decision_version_immutable();

-- Both new relations are removed before their receipt/application parents.
-- Re-pin the reviewed reset graph; no compatibility reset path is retained.
DO $migration$
DECLARE definition text; revised text;
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position('''cf777fea26c62979a597561aed109311ecd2bf19b7d694df5db2e70cac6c8ca0''' IN definition)=0
     OR position('''python_environment_version'',''execution_delegation_version'',''operation_receipt''' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0283_PREDECESSOR_MISMATCH';
  END IF;
  revised := replace(definition,
    '''python_environment_version'',''execution_delegation_version'',''operation_receipt''',
    '''python_environment_version'',''execution_delegation_version'',''application_decision_head'',''application_decision_version'',''operation_receipt''');
  revised := replace(revised,
    'cf777fea26c62979a597561aed109311ecd2bf19b7d694df5db2e70cac6c8ca0',
    'c6b19e7612e2b7d2c536bf2326f9987e74ef01091ea1f0516f5d92f33c158379');
  EXECUTE revised;
END $migration$;

COMMIT;
