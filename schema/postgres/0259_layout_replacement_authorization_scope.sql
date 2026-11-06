-- Bind private populated-layout replacement work to current group authority.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=258) THEN
        RAISE EXCEPTION 'MIGRATION_0259_PREDECESSOR_0258_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.layout_replacement_request
    ADD COLUMN verified_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.layout_replacement_request
    ADD CONSTRAINT layout_replacement_verified_groups_check CHECK (
        cardinality(verified_groups)<=100
        AND array_position(verified_groups,NULL) IS NULL),
    ADD CONSTRAINT layout_replacement_authorization_scope_digest_check CHECK (
        authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

COMMENT ON COLUMN epm.layout_replacement_request.verified_groups IS
    'Immutable verified group upper bound admitted with this replacement';
COMMENT ON COLUMN epm.layout_replacement_request.authorization_scope_digest IS
    'Exact server-derived dimensional authorization scope at admission';

CREATE FUNCTION epm.layout_replacement_current_admin(
 p_workspace text,p_application text,p_request text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,epm AS $$
DECLARE request epm.layout_replacement_request%ROWTYPE;
DECLARE current_groups text[];
BEGIN
 SELECT * INTO request FROM epm.layout_replacement_request
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND request_id=p_request;
 IF NOT FOUND OR request.authorization_scope_digest IS NULL
    OR NOT epm.identity_subject_active(request.issuer,request.subject_id) THEN
  RETURN false;
 END IF;
 current_groups:=epm.current_identity_groups(
  request.issuer,request.subject_id,request.verified_groups);
 RETURN EXISTS(SELECT 1 FROM epm.workspace_access_grant g
     WHERE g.workspace_id=p_workspace AND g.issuer=request.issuer
       AND g.subject_id=request.subject_id AND g.role='Administrator')
   OR EXISTS(SELECT 1 FROM epm.application_access_grant g
     WHERE g.workspace_id=p_workspace AND g.application_id=p_application
       AND g.issuer=request.issuer AND g.subject_id=request.subject_id
       AND g.role='Administrator')
   OR EXISTS(SELECT 1 FROM epm.workspace_group_access_grant g
     WHERE g.workspace_id=p_workspace AND g.issuer=request.issuer
       AND g.group_id=ANY(current_groups) AND g.role='Administrator')
   OR EXISTS(SELECT 1 FROM epm.application_group_access_grant g
     WHERE g.workspace_id=p_workspace AND g.application_id=p_application
       AND g.issuer=request.issuer AND g.group_id=ANY(current_groups)
       AND g.role='Administrator');
END $$;

CREATE FUNCTION epm.layout_replacement_authority_claim(
 p_workspace text,p_application text,p_request text,p_claimant text,
 p_lease_seconds integer)
RETURNS TABLE(request_id text,generation_id text,plan jsonb,
 claim_generation bigint,issuer text,subject_id text,verified_groups text[],
 authorization_scope_digest text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
 OR p_lease_seconds NOT BETWEEN 30 AND 300 THEN
  RAISE EXCEPTION 'LAYOUT_REPLACEMENT_CLAIM_INVALID' USING ERRCODE='22023';
 END IF;
 RETURN QUERY UPDATE epm.layout_replacement_request r SET status='Staging',
  claim_generation=r.claim_generation+1,claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  updated_at=transaction_timestamp()
 WHERE r.workspace_id=p_workspace AND r.application_id=p_application
  AND r.request_id=p_request AND r.status='Accepted'
  AND r.authorization_scope_digest IS NOT NULL
  AND epm.layout_replacement_current_admin(
    p_workspace,p_application,p_request)
 RETURNING r.request_id,r.target_generation_id,r.plan,r.claim_generation,
  r.issuer,r.subject_id,r.verified_groups,r.authorization_scope_digest;
END $$;

CREATE FUNCTION epm.layout_replacement_materialization_authority_claim(
 p_workspace text,p_application text,p_request text,p_claimant text,
 p_seconds integer)
RETURNS TABLE(request_id text,generation_id text,claim_generation bigint,
 next_chunk integer,issuer text,subject_id text,verified_groups text[],
 authorization_scope_digest text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF length(p_claimant) NOT BETWEEN 1 AND 200
 OR p_seconds NOT BETWEEN 30 AND 300 THEN
  RAISE EXCEPTION 'LAYOUT_MATERIALIZATION_CLAIM_INVALID'
    USING ERRCODE='22023';
 END IF;
 INSERT INTO epm.layout_replacement_materialization(
  workspace_id,application_id,request_id,generation_id)
 SELECT r.workspace_id,r.application_id,r.request_id,r.target_generation_id
 FROM epm.layout_replacement_request r WHERE r.workspace_id=p_workspace
 AND r.application_id=p_application AND r.request_id=p_request
 AND r.status='Staged' AND r.authorization_scope_digest IS NOT NULL
 AND epm.layout_replacement_current_admin(
   p_workspace,p_application,p_request)
 ON CONFLICT DO NOTHING;
 RETURN QUERY UPDATE epm.layout_replacement_materialization m
 SET status='Running',claim_generation=m.claim_generation+1,
  claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_seconds),
  updated_at=transaction_timestamp()
 FROM epm.layout_replacement_request r WHERE m.workspace_id=p_workspace
  AND m.application_id=p_application AND m.request_id=p_request
  AND m.status='Ready' AND r.workspace_id=m.workspace_id
  AND r.application_id=m.application_id AND r.request_id=m.request_id
  AND r.status='Staged' AND r.authorization_scope_digest IS NOT NULL
  AND epm.layout_replacement_current_admin(
    p_workspace,p_application,p_request)
 RETURNING m.request_id,m.generation_id,m.claim_generation,m.next_chunk,
  r.issuer,r.subject_id,r.verified_groups,r.authorization_scope_digest;
END $$;

REVOKE ALL ON FUNCTION
 epm.layout_replacement_current_admin(text,text,text),
 epm.layout_replacement_authority_claim(text,text,text,text,integer),
 epm.layout_replacement_materialization_authority_claim(text,text,text,text,integer),
 epm.layout_replacement_worker_claim(text,text,text,text,integer),
 epm.layout_replacement_materialization_claim(text,text,text,text,integer)
 FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle,epm_security,epm_access;
GRANT EXECUTE ON FUNCTION
 epm.layout_replacement_authority_claim(text,text,text,text,integer),
 epm.layout_replacement_materialization_authority_claim(text,text,text,text,integer)
 TO epm_worker;
