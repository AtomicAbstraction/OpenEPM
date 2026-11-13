BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=329) THEN
    RAISE EXCEPTION 'MIGRATION_0330_REQUIRES_0329';
  END IF;
END $migration$;

-- Approved acquisition variants and posted acquisition journals contain
-- digest-bound manifests over the old numbered policy identity.  Rewriting
-- those digests would fabricate approval evidence, so a populated deployment
-- must explicitly rebuild that development-only governance state first.
DO $migration$ BEGIN
  IF EXISTS(SELECT 1 FROM epm.policy_acquisition_case_bundle)
     OR EXISTS(SELECT 1 FROM epm.policy_acquisition_case_review)
     OR EXISTS(SELECT 1 FROM epm.policy_acquisition_approval)
     OR EXISTS(SELECT 1 FROM epm.policy_activation_event)
     OR EXISTS(SELECT 1 FROM epm.acquisition_journal) THEN
    RAISE EXCEPTION 'POLICY_0330_GOVERNANCE_REBUILD_REQUIRED';
  END IF;
END $migration$;

-- A policy id denotes one current accounting-policy definition.  Earlier
-- numbered drafts are product history and are deliberately not retained.
CREATE TABLE epm.policy_pack_definition_current (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  policy_id text NOT NULL CHECK(policy_id~'^[A-Za-z0-9._-]{1,100}$'),
  state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
  definition_digest text NOT NULL CHECK(definition_digest~'^[0-9a-f]{64}$'),
  family text NOT NULL CHECK(family IN ('IFRS','US_GAAP','CUSTOM')),
  effective_from date NOT NULL,
  effective_before date NOT NULL,
  required_elections jsonb NOT NULL CHECK(jsonb_typeof(required_elections)='array'),
  source_refs jsonb NOT NULL CHECK(jsonb_typeof(source_refs)='array'),
  created_operation_id text NOT NULL,
  created_revision bigint NOT NULL CHECK(created_revision>0),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,policy_id),
  UNIQUE(workspace_id,application_id,state_token),
  FOREIGN KEY(workspace_id,application_id,created_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT,
  CHECK(effective_from<effective_before)
);

WITH ranked AS (
  SELECT p.*,row_number() OVER(
    PARTITION BY workspace_id,application_id,policy_id
    ORDER BY version DESC,created_revision DESC,created_at DESC) AS ordinal
  FROM epm.policy_pack_draft p
)
INSERT INTO epm.policy_pack_definition_current(
  workspace_id,application_id,policy_id,state_token,definition_digest,family,
  effective_from,effective_before,required_elections,source_refs,
  created_operation_id,created_revision,created_at)
SELECT workspace_id,application_id,policy_id,
  encode(pg_catalog.sha256(convert_to(concat_ws(chr(31),'policy-definition',
    workspace_id,application_id,policy_id,version::text,
    clock_timestamp()::text,random()::text),'UTF8')),'hex'),
  encode(pg_catalog.sha256(convert_to(jsonb_build_object(
    'policyId',policy_id,'family',family,
    'effectiveFrom',effective_from::text,'effectiveBefore',effective_before::text,
    'requiredElections',required_elections,'sourceRefs',source_refs)::text,
    'UTF8')),'hex'),
  family,effective_from,effective_before,required_elections,source_refs,
  created_operation_id,created_revision,created_at
FROM ranked WHERE ordinal=1;

DROP TRIGGER reject_policy_draft_overlap ON epm.policy_pack_draft;
DROP FUNCTION epm.reject_policy_draft_overlap();
DROP TABLE epm.policy_pack_draft;
ALTER TABLE epm.policy_pack_definition_current RENAME TO policy_pack_draft;
CREATE INDEX policy_draft_effective ON epm.policy_pack_draft
  (workspace_id,application_id,family,effective_from,effective_before);

GRANT SELECT,INSERT ON epm.policy_pack_draft TO epm_runtime;
GRANT UPDATE(state_token,definition_digest,family,effective_from,
  effective_before,required_elections,source_refs,created_operation_id,
  created_revision,created_at) ON epm.policy_pack_draft TO epm_runtime;
ALTER TABLE epm.policy_pack_draft ENABLE ROW LEVEL SECURITY;
CREATE POLICY policy_draft_scope ON epm.policy_pack_draft TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));

-- Draft-save receipts are current operation evidence, not an object history
-- API.  Remove the retired numbered field from retained replay results.
CREATE FUNCTION epm.policy_0330_current_json(
  value jsonb,p_workspace text,p_application text) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $function$
DECLARE result jsonb; token text;
BEGIN
  IF jsonb_typeof(value)='array' THEN
    SELECT coalesce(jsonb_agg(epm.policy_0330_current_json(item,p_workspace,
      p_application) ORDER BY ordinal),'[]'::jsonb) INTO result
    FROM jsonb_array_elements(value) WITH ORDINALITY AS source(item,ordinal);
    RETURN result;
  END IF;
  IF jsonb_typeof(value)<>'object' THEN RETURN value; END IF;
  SELECT coalesce(jsonb_object_agg(key,
    epm.policy_0330_current_json(item,p_workspace,p_application)),
    '{}'::jsonb) INTO result FROM jsonb_each(value) AS source(key,item)
    WHERE key<>'policyVersion';
  IF value ? 'policyVersion' AND value ? 'policyId' THEN
    SELECT state_token INTO token FROM epm.policy_pack_draft
      WHERE workspace_id=p_workspace AND application_id=p_application
        AND policy_id=value->>'policyId';
    IF token IS NOT NULL THEN
      result=result||jsonb_build_object('policyStateToken',token);
    END IF;
  END IF;
  RETURN result;
END $function$;
ALTER TABLE epm.operation_receipt DISABLE TRIGGER USER;
UPDATE epm.operation_receipt
SET result=epm.policy_0330_current_json(
  CASE WHEN result ? 'policyId' AND result->>'status'='Draft'
            AND result ? 'version'
       THEN result-'version' ELSE result END,
  workspace_id,application_id)
WHERE (result ? 'policyId' AND result->>'status'='Draft' AND result ? 'version')
   OR result::text LIKE '%"policyVersion"%';
ALTER TABLE epm.operation_receipt ENABLE TRIGGER USER;
DROP FUNCTION epm.policy_0330_current_json(jsonb,text,text);
COMMIT;
