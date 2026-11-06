-- Bind the populated-layout atomic activation to the current verified
-- Keycloak-group identity and dimensional authorization scope.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=257) THEN
        RAISE EXCEPTION 'MIGRATION_0258_PREDECESSOR_0257_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.layout_replacement_activation
    ADD COLUMN verified_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.layout_replacement_activation
    ADD CONSTRAINT layout_activation_verified_groups_check CHECK (
        cardinality(verified_groups)<=100
        AND array_position(verified_groups,NULL) IS NULL),
    ADD CONSTRAINT layout_activation_authorization_scope_digest_check CHECK (
        authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

COMMENT ON COLUMN epm.layout_replacement_activation.verified_groups IS
    'Immutable verified group upper bound admitted with this activation';
COMMENT ON COLUMN epm.layout_replacement_activation.authorization_scope_digest IS
    'Exact server-derived dimensional authorization scope at admission';

CREATE FUNCTION epm.layout_replacement_activation_authority_request(
    w text,a text,aid text,rid text,ikey text,rdigest text,
    issuer_name text,subject_name text,vdigest text,decisions jsonb,
    admitted_groups text[],scope_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,epm AS $$
DECLARE outcome jsonb;
BEGIN
  IF admitted_groups IS NULL OR cardinality(admitted_groups)>100
     OR array_position(admitted_groups,NULL) IS NOT NULL
     OR scope_digest IS NULL OR scope_digest!~'^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'LAYOUT_ACTIVATION_AUTHORIZATION_SCOPE_INVALID';
  END IF;
  outcome:=epm.layout_replacement_activation_request(
    w,a,aid,rid,ikey,rdigest,issuer_name,subject_name,vdigest,decisions);
  UPDATE epm.layout_replacement_activation x
    SET verified_groups=admitted_groups,
        authorization_scope_digest=scope_digest
    WHERE x.workspace_id=w AND x.application_id=a
      AND x.activation_id=aid
      AND (x.authorization_scope_digest IS NULL
        OR (x.verified_groups=admitted_groups
          AND x.authorization_scope_digest=scope_digest));
  IF NOT FOUND THEN
    RAISE EXCEPTION 'LAYOUT_ACTIVATION_AUTHORIZATION_SCOPE_CONFLICT';
  END IF;
  RETURN outcome;
END $$;

CREATE FUNCTION epm.layout_replacement_activation_authority_claim(
    w text,a text,aid text,claimant_name text,seconds integer)
RETURNS TABLE(activation_id text,claim_generation bigint,issuer text,
    subject_id text,verified_groups text[],authorization_scope_digest text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
BEGIN
  RETURN QUERY UPDATE epm.layout_replacement_activation x
    SET status='Activating',claim_generation=x.claim_generation+1,
        claimant=claimant_name,
        lease_until=clock_timestamp()+make_interval(secs=>seconds),
        updated_at=transaction_timestamp()
    WHERE x.workspace_id=w AND x.application_id=a
      AND x.activation_id=aid AND x.status='Requested'
      AND seconds BETWEEN 30 AND 300
      AND x.authorization_scope_digest IS NOT NULL
    RETURNING x.activation_id,x.claim_generation,x.issuer,x.subject_id,
      x.verified_groups,x.authorization_scope_digest;
END $$;

CREATE FUNCTION epm.layout_replacement_activation_current_admin(
    w text,a text,aid text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE x epm.layout_replacement_activation%ROWTYPE;
DECLARE current_groups text[];
BEGIN
  SELECT * INTO x FROM epm.layout_replacement_activation
    WHERE workspace_id=w AND application_id=a AND activation_id=aid;
  IF NOT FOUND OR x.authorization_scope_digest IS NULL
     OR NOT epm.identity_subject_active(x.issuer,x.subject_id) THEN
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

DO $migration$
DECLARE definition text; revised text;
DECLARE old_check text :=
  $pattern$OR (NOT EXISTS(SELECT 1 FROM epm.workspace_access_grant WHERE workspace_id=w AND issuer=x.issuer AND subject_id=x.subject_id AND role='Administrator')
      AND NOT EXISTS(SELECT 1 FROM epm.application_access_grant WHERE workspace_id=w AND application_id=a AND issuer=x.issuer AND subject_id=x.subject_id AND role='Administrator'))$pattern$;
DECLARE new_check text :=
  $pattern$OR NOT epm.layout_replacement_activation_current_admin(w,a,aid)$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.layout_replacement_activation_publish(text,text,text,text,bigint)'::regprocedure)
    INTO definition;
  IF position(old_check IN definition)=0 OR position(new_check IN definition)>0 THEN
    RAISE EXCEPTION 'LAYOUT_ACTIVATION_AUTHORIZATION_DEFINITION_MISMATCH';
  END IF;
  revised:=replace(definition,old_check,new_check);
  IF revised=definition OR position(new_check IN revised)=0 THEN
    RAISE EXCEPTION 'LAYOUT_ACTIVATION_AUTHORIZATION_REWRITE_FAILED';
  END IF;
  EXECUTE revised;
END $migration$;

REVOKE ALL ON FUNCTION
  epm.layout_replacement_activation_authority_request(text,text,text,text,text,text,text,text,text,jsonb,text[],text),
  epm.layout_replacement_activation_authority_claim(text,text,text,text,integer),
  epm.layout_replacement_activation_current_admin(text,text,text)
  FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle,epm_security,epm_access;
GRANT EXECUTE ON FUNCTION
  epm.layout_replacement_activation_authority_request(text,text,text,text,text,text,text,text,text,jsonb,text[],text)
  TO epm_runtime;
GRANT EXECUTE ON FUNCTION
  epm.layout_replacement_activation_authority_claim(text,text,text,text,integer)
  TO epm_worker;
