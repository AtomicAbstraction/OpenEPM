BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=375) THEN
    RAISE EXCEPTION 'MIGRATION_0376_REQUIRES_0375';
  END IF;
END $migration$;

-- A source-owned definition normally cannot detach from its source.  Permit
-- only the table owner, reached through the exact SECURITY DEFINER transition
-- below, to convert a MemberList to fixed Configuration ownership.  Runtime
-- retains no direct UPDATE or DELETE authority that can exercise this branch.
DO $guard$
DECLARE definition text;previous text;replacement text;
BEGIN
  SELECT pg_get_functiondef(
    'epm.current_definition_owner_guard()'::regprocedure) INTO definition;
  previous:=$old$IF OLD.ownership_state='Source' AND (NEW.ownership_state<>'Source'
   OR NEW.source_program_id IS DISTINCT FROM OLD.source_program_id) THEN
   RAISE EXCEPTION 'DEFINITION_SOURCE_ASSOCIATION_IMMUTABLE' USING ERRCODE='23514';
  END IF;$old$;
  replacement:=$new$IF OLD.ownership_state='Source' AND (NEW.ownership_state<>'Source'
   OR NEW.source_program_id IS DISTINCT FROM OLD.source_program_id) AND NOT (
    TG_TABLE_NAME='member_list_definition'
    AND NEW.ownership_state='Configuration'
    AND NEW.source_program_id IS NULL AND NEW.source_token IS NULL
    AND NEW.source_digest IS NULL AND NEW.source_build_id IS NULL
    AND NEW.current_certificate->>'acceptance'='FixedValidation'
    AND NEW.current_certificate->>'compilerVersion'='openepm-fixed-definition-v1'
    AND current_user=pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid=TG_RELID))
   ) THEN
   RAISE EXCEPTION 'DEFINITION_SOURCE_ASSOCIATION_IMMUTABLE' USING ERRCODE='23514';
  END IF;$new$;
  IF position(previous IN definition)=0 OR position(replacement IN definition)>0 THEN
    RAISE EXCEPTION 'MEMBER_LIST_0376_OWNER_GUARD_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,replacement);
END $guard$;

CREATE FUNCTION epm.member_list_adopt_configuration(
  p_workspace_id text,p_application_id text,p_list_id text,
  p_expected_list_token text,p_expected_canonical_digest text,
  p_source_program_id text,p_expected_source_state_token text,
  p_expected_source_token text,p_expected_source_digest text,
  p_new_list_token text,p_fixed_certificate jsonb,p_operation_id text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,epm AS $function$
DECLARE affected integer;
BEGIN
  IF p_workspace_id IS NULL OR p_workspace_id=''
     OR p_application_id IS NULL OR p_application_id=''
     OR p_workspace_id<>current_setting('epm.workspace_id',true)
     OR p_application_id<>current_setting('epm.application_id',true)
     OR p_list_id IS NULL OR p_list_id!~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'
     OR p_source_program_id IS NULL
     OR p_source_program_id!~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'
     OR p_expected_list_token!~'^[0-9a-f]{64}$'
     OR p_expected_canonical_digest!~'^[0-9a-f]{64}$'
     OR p_expected_source_state_token!~'^[0-9a-f]{64}$'
     OR p_expected_source_token!~'^[0-9a-f]{64}$'
     OR p_expected_source_digest!~'^[0-9a-f]{64}$'
     OR p_new_list_token!~'^[0-9a-f]{64}$'
     OR p_fixed_certificate IS NULL
     OR p_operation_id IS NULL OR p_operation_id!~'^[A-Za-z0-9._-]{8,128}$' THEN
    RAISE EXCEPTION 'MEMBER_LIST_CONFIGURATION_ADOPTION_ARGUMENT_INVALID';
  END IF;
  IF current_setting('transaction_isolation')<>'read committed' THEN
    RAISE EXCEPTION 'MEMBER_LIST_CONFIGURATION_ADOPTION_REQUIRES_READ_COMMITTED';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM epm.operation_receipt r
      WHERE (r.workspace_id,r.application_id,r.operation_id)=
        (p_workspace_id,p_application_id,p_operation_id)
        AND r.result->>'listId'=p_list_id
        AND r.result->>'ownershipState'='Configuration'
        AND r.result->>'retiredSourceProgramId'=p_source_program_id
        AND r.result->>'stateToken'=p_new_list_token) THEN
    RAISE EXCEPTION 'MEMBER_LIST_CONFIGURATION_ADOPTION_RECEIPT_REQUIRED';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM epm.python_program_definition s
      WHERE (s.workspace_id,s.application_id,s.program_id,s.state_token,
             s.source_token,s.source_digest)=
        (p_workspace_id,p_application_id,p_source_program_id,
         p_expected_source_state_token,p_expected_source_token,
         p_expected_source_digest)
        AND s.declared_output=jsonb_build_object('kind','MemberList',
          'definitionId',p_list_id,'dimensionId',(SELECT l.dimension_id
            FROM epm.member_list_definition l WHERE
              (l.workspace_id,l.application_id,l.list_id)=
              (p_workspace_id,p_application_id,p_list_id)))) THEN
    RETURN false;
  END IF;
  UPDATE epm.member_list_definition l SET
    ownership_state='Configuration',source_program_id=NULL,source_token=NULL,
    source_digest=NULL,source_build_id=NULL,state_token=p_new_list_token,
    current_certificate=p_fixed_certificate,updated_operation_id=p_operation_id,
    updated_at=transaction_timestamp()
   WHERE (l.workspace_id,l.application_id,l.list_id,l.state_token,
          l.canonical_digest,l.ownership_state,l.source_program_id,
          l.source_token,l.source_digest)=
     (p_workspace_id,p_application_id,p_list_id,p_expected_list_token,
      p_expected_canonical_digest,'Source',p_source_program_id,
      p_expected_source_token,p_expected_source_digest);
  GET DIAGNOSTICS affected=ROW_COUNT;
  IF affected<>1 THEN RETURN false;END IF;
  DELETE FROM epm.python_program_definition s
   WHERE (s.workspace_id,s.application_id,s.program_id,s.state_token,
          s.source_token,s.source_digest)=
     (p_workspace_id,p_application_id,p_source_program_id,
      p_expected_source_state_token,p_expected_source_token,
      p_expected_source_digest);
  GET DIAGNOSTICS affected=ROW_COUNT;
  IF affected<>1 THEN
    RAISE EXCEPTION 'MEMBER_LIST_CONFIGURATION_ADOPTION_SOURCE_DELETE_MISMATCH';
  END IF;
  SET CONSTRAINTS ALL IMMEDIATE;
  RETURN true;
END $function$;

REVOKE ALL ON FUNCTION epm.member_list_adopt_configuration(
  text,text,text,text,text,text,text,text,text,text,jsonb,text)
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT EXECUTE ON FUNCTION epm.member_list_adopt_configuration(
  text,text,text,text,text,text,text,text,text,text,jsonb,text) TO epm_runtime;

COMMIT;
SELECT '0376 applied' AS migration;
