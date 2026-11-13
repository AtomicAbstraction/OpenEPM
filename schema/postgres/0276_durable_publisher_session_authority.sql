-- Persist the authentication epoch for every durable human publisher.  Rows
-- admitted before this contract cannot prove that their bearer session is
-- still current, so unsettled legacy work is quarantined fail closed.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=275) THEN
  RAISE EXCEPTION 'MIGRATION_0276_REQUIRES_0275';
 END IF;
END $$;

DO $migration$
DECLARE item record;
BEGIN
 FOR item IN SELECT * FROM (VALUES
   ('source_import_execution','token_issued_at','authority_kind'),
   ('cube_aggregate_query','token_issued_at','authority_kind'),
   ('fact_export_producer_request','token_issued_at','authority_kind'),
   ('python_program_build','token_issued_at','authority_kind'),
   ('python_program_workflow','token_issued_at','authority_kind'),
   ('application_rule_workflow','token_issued_at','authority_kind'),
   ('layout_replacement_activation','token_issued_at','authority_kind')
 ) AS values(table_name,epoch_column,kind_column) LOOP
  EXECUTE format('ALTER TABLE epm.%I ADD COLUMN %I bigint',
                 item.table_name,item.epoch_column);
  EXECUTE format('ALTER TABLE epm.%I ADD COLUMN %I text NOT NULL DEFAULT %L',
                 item.table_name,item.kind_column,'LegacyUnverified');
  EXECUTE format($sql$ALTER TABLE epm.%I ADD CONSTRAINT %I CHECK (
    (%I='HumanToken' AND %I>0)
    OR (%I='Technical' AND %I IS NULL AND issuer LIKE 'urn:openepm:%%')
    OR (%I='LegacyUnverified' AND %I IS NULL))$sql$,
    item.table_name,item.table_name||'_session_authority_valid',
    item.kind_column,item.epoch_column,item.kind_column,item.epoch_column,
    item.kind_column,item.epoch_column);
 END LOOP;
END $migration$;

UPDATE epm.source_import_execution SET status='Failed',
 error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',claimant=NULL,lease_until=NULL,
 updated_at=transaction_timestamp()
 WHERE status IN('Accepted','Claimed','Publishing');
UPDATE epm.cube_aggregate_query SET status='failed',
 error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',claimant=NULL,lease_until=NULL
 WHERE status IN('accepted','ready','running','computed','cancel_requested');
UPDATE epm.fact_export_producer_request SET status='Failed',
 error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',claimant=NULL,lease_until=NULL,
 updated_at=transaction_timestamp()
 WHERE status IN('Accepted','Reading','Prepared');
UPDATE epm.python_program_build SET status='failed',
 error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',claimant=NULL,lease_until=NULL,
 updated_at=transaction_timestamp()
 WHERE status IN('accepted','ready','running','cancel_requested');
UPDATE epm.python_program_workflow SET status='needs_inspection',
 result=coalesce(result,'{}'::jsonb)||
  jsonb_build_object('errorCode','TOKEN_ISSUE_TIME_UNAVAILABLE'),
 updated_at=transaction_timestamp()
 WHERE status IN('accepted','running','cancel_requested');
UPDATE epm.application_rule_workflow SET status='needs_inspection',
 worker_error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',claimant=NULL,
 lease_until=NULL,updated_at=transaction_timestamp()
 WHERE status IN('accepted','running','cancel_requested');
UPDATE epm.layout_replacement_activation SET status='Failed',
 error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',claimant=NULL,lease_until=NULL,
 updated_at=transaction_timestamp()
 WHERE status IN('Requested','Activating');

COMMENT ON COLUMN epm.source_import_execution.token_issued_at IS
 'Immutable OIDC iat for durable human execution; NULL only for bounded technical or quarantined legacy authority.';

-- Dispatchers need only the immutable session provenance added above.  Keep
-- worker access behind claim-bound SECURITY DEFINER functions so neither RLS
-- bypass nor broader business-payload SELECT privileges are introduced.
CREATE FUNCTION epm.cube_aggregate_worker_session_authority(
  p_workspace text,p_application text,p_query text,p_generation bigint,
  p_claimant text)
RETURNS TABLE(token_issued_at bigint,authority_kind text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT q.token_issued_at,q.authority_kind
 FROM epm.cube_aggregate_query q
 WHERE q.workspace_id=p_workspace AND q.application_id=p_application
   AND q.query_id=p_query AND q.claim_generation=p_generation
   AND (q.status='computed' OR (q.status='running'
     AND q.claimant=p_claimant AND q.lease_until>clock_timestamp()))
$$;

CREATE FUNCTION epm.export_producer_worker_session_authority(
  p_workspace text,p_application text,p_request text,p_generation bigint,
  p_claimant text)
RETURNS TABLE(token_issued_at bigint,authority_kind text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT r.token_issued_at,r.authority_kind
 FROM epm.fact_export_producer_request r
 WHERE r.workspace_id=p_workspace AND r.application_id=p_application
   AND r.request_id=p_request AND r.claim_generation=p_generation
   AND r.status='Reading' AND r.claimant=p_claimant
   AND r.lease_until>clock_timestamp()
$$;

CREATE FUNCTION epm.python_workflow_worker_session_authority(
  p_workspace text,p_application text,p_workflow text,p_generation bigint,
  p_claimant text)
RETURNS TABLE(token_issued_at bigint,authority_kind text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT w.token_issued_at,w.authority_kind
 FROM epm.python_program_workflow w
 WHERE w.workspace_id=p_workspace AND w.application_id=p_application
   AND w.workflow_id=p_workflow AND w.claim_generation=p_generation
   AND w.status IN('accepted','running','cancel_requested')
   AND w.claimant=p_claimant AND w.lease_until>clock_timestamp()
$$;

CREATE FUNCTION epm.application_rule_worker_session_authority(
  p_workspace text,p_application text,p_workflow text,p_generation bigint,
  p_claimant text)
RETURNS TABLE(token_issued_at bigint,authority_kind text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT w.token_issued_at,w.authority_kind
 FROM epm.application_rule_workflow w
 WHERE w.workspace_id=p_workspace AND w.application_id=p_application
   AND w.workflow_id=p_workflow AND w.claim_generation=p_generation
   AND w.status IN('accepted','running','cancel_requested')
   AND w.claimant=p_claimant AND w.lease_until>clock_timestamp()
$$;

REVOKE ALL ON FUNCTION
 epm.cube_aggregate_worker_session_authority(text,text,text,bigint,text),
 epm.export_producer_worker_session_authority(text,text,text,bigint,text),
 epm.python_workflow_worker_session_authority(text,text,text,bigint,text),
 epm.application_rule_worker_session_authority(text,text,text,bigint,text)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
 epm.cube_aggregate_worker_session_authority(text,text,text,bigint,text),
 epm.export_producer_worker_session_authority(text,text,text,bigint,text),
 epm.python_workflow_worker_session_authority(text,text,text,bigint,text),
 epm.application_rule_worker_session_authority(text,text,text,bigint,text)
 TO epm_worker;

DROP FUNCTION epm.layout_replacement_activation_authority_request(
 text,text,text,text,text,text,text,text,text,jsonb,text[],text);
CREATE FUNCTION epm.layout_replacement_activation_authority_request(
 w text,a text,aid text,rid text,ikey text,rdigest text,
 issuer_name text,subject_name text,vdigest text,decisions jsonb,
 admitted_groups text[],scope_digest text,issued_at bigint,kind text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,epm AS $$
DECLARE outcome jsonb;
BEGIN
 IF admitted_groups IS NULL OR cardinality(admitted_groups)>100
    OR array_position(admitted_groups,NULL) IS NOT NULL
    OR scope_digest IS NULL OR scope_digest!~'^[0-9a-f]{64}$'
    OR NOT ((kind='HumanToken' AND issued_at>0)
      OR (kind='Technical' AND issued_at IS NULL
          AND issuer_name LIKE 'urn:openepm:%')) THEN
  RAISE EXCEPTION 'LAYOUT_ACTIVATION_AUTHORIZATION_SCOPE_INVALID';
 END IF;
 outcome:=epm.layout_replacement_activation_request(
   w,a,aid,rid,ikey,rdigest,issuer_name,subject_name,vdigest,decisions);
 UPDATE epm.layout_replacement_activation x
 SET verified_groups=admitted_groups,authorization_scope_digest=scope_digest,
     token_issued_at=issued_at,authority_kind=kind
 WHERE x.workspace_id=w AND x.application_id=a AND x.activation_id=aid
   AND x.authorization_scope_digest IS NULL;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'LAYOUT_ACTIVATION_AUTHORIZATION_SCOPE_CONFLICT';
 END IF;
 RETURN outcome;
END $$;
REVOKE ALL ON FUNCTION epm.layout_replacement_activation_authority_request(
 text,text,text,text,text,text,text,text,text,jsonb,text[],text,bigint,text)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_activation_authority_request(
 text,text,text,text,text,text,text,text,text,jsonb,text[],text,bigint,text)
 TO epm_runtime;

CREATE OR REPLACE FUNCTION epm.layout_replacement_activation_current_admin(
 w text,a text,aid text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE x epm.layout_replacement_activation%ROWTYPE;current_groups text[];
BEGIN
 SELECT * INTO x FROM epm.layout_replacement_activation
 WHERE workspace_id=w AND application_id=a AND activation_id=aid;
 IF NOT FOUND OR x.authorization_scope_digest IS NULL
    OR x.authority_kind='LegacyUnverified'
    OR (x.authority_kind='HumanToken' AND NOT
      epm.identity_subject_session_valid(x.issuer,x.subject_id,
                                         x.token_issued_at))
    OR (x.authority_kind='Technical' AND
      (x.token_issued_at IS NOT NULL OR x.issuer NOT LIKE 'urn:openepm:%')) THEN
  RETURN false;
 END IF;
 current_groups:=epm.current_identity_groups(
   x.issuer,x.subject_id,x.verified_groups);
 RETURN EXISTS(SELECT 1 FROM epm.workspace_access_grant g
   WHERE g.workspace_id=w AND g.issuer=x.issuer
     AND g.subject_id=x.subject_id AND g.role='Administrator')
 OR EXISTS(SELECT 1 FROM epm.application_access_grant g
   WHERE g.workspace_id=w AND g.application_id=a AND g.issuer=x.issuer
     AND g.subject_id=x.subject_id AND g.role='Administrator')
 OR EXISTS(SELECT 1 FROM epm.workspace_group_access_grant g
   WHERE g.workspace_id=w AND g.issuer=x.issuer
     AND g.group_id=ANY(current_groups) AND g.role='Administrator')
 OR EXISTS(SELECT 1 FROM epm.application_group_access_grant g
   WHERE g.workspace_id=w AND g.application_id=a AND g.issuer=x.issuer
     AND g.group_id=ANY(current_groups) AND g.role='Administrator');
END $$;
