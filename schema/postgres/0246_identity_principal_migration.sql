-- Governed one-to-one migration of current authorization from a retired
-- identity authority to Keycloak. Historical receipts, events, sealed plans
-- and completed work are deliberately never rewritten.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=245) THEN
        RAISE EXCEPTION 'MIGRATION_0246_PREDECESSOR_0245_REQUIRED';
    END IF;
END $migration$;

CREATE TABLE epm.identity_principal_migration (
    migration_id text PRIMARY KEY
        CHECK (migration_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
    old_issuer text NOT NULL CHECK (length(old_issuer) BETWEEN 1 AND 300
        AND old_issuer=btrim(old_issuer) AND old_issuer !~ '[[:cntrl:]]'),
    old_subject_id text NOT NULL CHECK (length(old_subject_id) BETWEEN 1 AND 300
        AND old_subject_id=btrim(old_subject_id)
        AND old_subject_id !~ '[[:cntrl:]]'),
    new_issuer text NOT NULL CHECK (length(new_issuer) BETWEEN 1 AND 300
        AND new_issuer=btrim(new_issuer) AND new_issuer !~ '[[:cntrl:]]'),
    new_subject_id text NOT NULL CHECK (length(new_subject_id) BETWEEN 1 AND 300
        AND new_subject_id=btrim(new_subject_id)
        AND new_subject_id !~ '[[:cntrl:]]'),
    preview_digest text NOT NULL CHECK (preview_digest ~ '^[0-9a-f]{64}$'),
    actor_digest text NOT NULL CHECK (actor_digest ~ '^[0-9a-f]{64}$'),
    effect_summary jsonb NOT NULL CHECK (jsonb_typeof(effect_summary)='object'
        AND octet_length(effect_summary::text)<=65536),
    applied_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE(old_issuer,old_subject_id),
    UNIQUE(new_issuer,new_subject_id),
    CHECK ((old_issuer,old_subject_id)<>(new_issuer,new_subject_id))
);

CREATE FUNCTION epm.identity_principal_migration_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN
    RAISE EXCEPTION 'IDENTITY_PRINCIPAL_MIGRATION_IMMUTABLE'
        USING ERRCODE='23514';
END$$;
CREATE TRIGGER identity_principal_migration_immutable
    BEFORE UPDATE OR DELETE ON epm.identity_principal_migration
    FOR EACH ROW EXECUTE FUNCTION epm.identity_principal_migration_immutable();
REVOKE ALL ON FUNCTION epm.identity_principal_migration_immutable()
    FROM PUBLIC,epm_provision,epm_runtime,epm_access,epm_security,
         epm_worker,epm_lifecycle;

ALTER TABLE epm.identity_principal_migration ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON epm.identity_principal_migration FROM PUBLIC,epm_provision,
    epm_runtime,epm_access,epm_security,epm_worker,epm_lifecycle;

CREATE FUNCTION epm.identity_principal_migration_preview(
    actor_issuer text,actor_subject text,old_issuer text,old_subject text,
    new_issuer text,new_subject text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
#variable_conflict use_variable
DECLARE summary jsonb;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.platform_operator_grant g
        WHERE g.issuer=actor_issuer AND g.subject_id=actor_subject) THEN
        RAISE EXCEPTION 'PLATFORM_OPERATOR_REQUIRED' USING ERRCODE='42501';
    END IF;
    IF old_issuer IS NULL OR old_subject IS NULL OR new_issuer IS NULL
       OR new_subject IS NULL OR old_issuer<>btrim(old_issuer)
       OR old_subject<>btrim(old_subject) OR new_issuer<>btrim(new_issuer)
       OR new_subject<>btrim(new_subject)
       OR length(old_issuer) NOT BETWEEN 1 AND 300
       OR length(old_subject) NOT BETWEEN 1 AND 300
       OR length(new_issuer) NOT BETWEEN 1 AND 300
       OR length(new_subject) NOT BETWEEN 1 AND 300
       OR (old_issuer,old_subject)=(new_issuer,new_subject) THEN
        RAISE EXCEPTION 'IDENTITY_PRINCIPAL_MIGRATION_ARGUMENTS_INVALID'
            USING ERRCODE='22023';
    END IF;
    SELECT jsonb_build_object(
      'platformOperatorGrants',(SELECT count(*) FROM epm.platform_operator_grant
        WHERE issuer=old_issuer AND subject_id=old_subject),
      'workspaceGrants',(SELECT count(*) FROM epm.workspace_access_grant
        WHERE issuer=old_issuer AND subject_id=old_subject),
      'applicationGrants',(SELECT count(*) FROM epm.application_access_grant
        WHERE issuer=old_issuer AND subject_id=old_subject),
      'dimensionalAssignments',(SELECT count(*) FROM epm.application_access_grant
        WHERE issuer=old_issuer AND subject_id=old_subject
          AND (read_security_tags<>'{}'::jsonb
            OR write_security_tags<>'{}'::jsonb)),
      'ruleGrants',(SELECT count(*) FROM epm.rule_access_grant
        WHERE issuer=old_issuer AND subject_id=old_subject),
      'historicalReceiptReferences',(SELECT count(*) FROM epm.operation_receipt
        WHERE (provenance->>'issuer'=old_issuer
           AND provenance->>'subjectId'=old_subject)
           OR (provenance IS NULL AND actor_id=old_subject)),
      'outstandingJobs',(SELECT count(*) FROM epm.job
        WHERE issuer=old_issuer AND subject_id=old_subject
          AND status IN ('accepted','ready','running','staged',
                         'cancel_requested','needs_inspection')),
      'outstandingTaskReferences',(SELECT count(*) FROM epm.task
        WHERE issuer=old_issuer AND subject_id=old_subject
          AND status IN ('Accepted','Waiting','Running','InterruptRequested',
                         'NeedsInspection')),
      'activeDelegations',(SELECT count(*)
        FROM epm.execution_delegation_state s
        JOIN epm.execution_delegation_version v
          ON (v.workspace_id,v.application_id,v.delegation_id,v.version)=
             (s.workspace_id,s.application_id,s.delegation_id,s.active_version)
        WHERE s.active_version IS NOT NULL AND s.revoked_at IS NULL
          AND v.issuer=old_issuer AND v.subject_id=old_subject),
      'targetDirectoryUsers',(SELECT count(*)
        FROM epm.identity_user_directory_state
        WHERE issuer=new_issuer AND subject_id=new_subject
          AND status='Active'),
      'targetCollisions',(
        (SELECT count(*) FROM epm.platform_operator_grant
          WHERE issuer=new_issuer AND subject_id=new_subject)+
        (SELECT count(*) FROM epm.workspace_access_grant
          WHERE issuer=new_issuer AND subject_id=new_subject)+
        (SELECT count(*) FROM epm.application_access_grant
          WHERE issuer=new_issuer AND subject_id=new_subject)+
        (SELECT count(*) FROM epm.rule_access_grant
          WHERE issuer=new_issuer AND subject_id=new_subject)),
      'priorMappings',(SELECT count(*) FROM epm.identity_principal_migration
        WHERE (identity_principal_migration.old_issuer=old_issuer
           AND identity_principal_migration.old_subject_id=old_subject)
           OR (identity_principal_migration.new_issuer=new_issuer
           AND identity_principal_migration.new_subject_id=new_subject)),
      'workspaces',COALESCE((SELECT jsonb_agg(workspace_id ORDER BY workspace_id)
        FROM (SELECT workspace_id FROM epm.workspace_access_grant
               WHERE issuer=old_issuer AND subject_id=old_subject
              UNION SELECT workspace_id FROM epm.application_access_grant
               WHERE issuer=old_issuer AND subject_id=old_subject
              UNION SELECT workspace_id FROM epm.rule_access_grant
               WHERE issuer=old_issuer AND subject_id=old_subject) scopes),'[]'::jsonb)
    ) INTO summary;
    RETURN summary;
END$$;

CREATE FUNCTION epm.identity_principal_migration_apply(
    migration_id text,actor_issuer text,actor_subject text,
    old_issuer text,old_subject text,new_issuer text,new_subject text,
    expected_summary jsonb,preview_digest text,actor_digest text,
    target_digest text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
#variable_conflict use_variable
DECLARE current_summary jsonb;workspace_name text;result jsonb;
BEGIN
    IF migration_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'
       OR preview_digest !~ '^[0-9a-f]{64}$'
       OR actor_digest !~ '^[0-9a-f]{64}$'
       OR target_digest !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(expected_summary)<>'object' THEN
        RAISE EXCEPTION 'IDENTITY_PRINCIPAL_MIGRATION_APPLY_INVALID'
            USING ERRCODE='22023';
    END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended('epm.identity.principal-migration',0));
    current_summary:=epm.identity_principal_migration_preview(
        actor_issuer,actor_subject,old_issuer,old_subject,
        new_issuer,new_subject);
    IF current_summary<>expected_summary THEN
        RAISE EXCEPTION 'IDENTITY_PRINCIPAL_MIGRATION_PREVIEW_STALE'
            USING ERRCODE='40001';
    END IF;
    IF (current_summary->>'outstandingJobs')::bigint<>0
       OR (current_summary->>'outstandingTaskReferences')::bigint<>0
       OR (current_summary->>'activeDelegations')::bigint<>0 THEN
        RAISE EXCEPTION 'IDENTITY_PRINCIPAL_MIGRATION_ACTIVE_WORK'
            USING ERRCODE='55006';
    END IF;
    IF (current_summary->>'targetDirectoryUsers')::bigint<>1 THEN
        RAISE EXCEPTION 'IDENTITY_PRINCIPAL_MIGRATION_TARGET_NOT_CURRENT'
            USING ERRCODE='23503';
    END IF;
    IF (current_summary->>'targetCollisions')::bigint<>0
       OR (current_summary->>'priorMappings')::bigint<>0 THEN
        RAISE EXCEPTION 'IDENTITY_PRINCIPAL_MIGRATION_AMBIGUOUS'
            USING ERRCODE='23505';
    END IF;
    FOR workspace_name IN SELECT value#>>'{}'
      FROM jsonb_array_elements(current_summary->'workspaces') LOOP
        PERFORM pg_advisory_xact_lock(hashtextextended(
          'epm.security.workspace:'||workspace_name,0));
    END LOOP;
    -- Recheck after every workspace fence is held.
    IF epm.identity_principal_migration_preview(actor_issuer,actor_subject,
       old_issuer,old_subject,new_issuer,new_subject)<>current_summary THEN
        RAISE EXCEPTION 'IDENTITY_PRINCIPAL_MIGRATION_PREVIEW_STALE'
            USING ERRCODE='40001';
    END IF;
    INSERT INTO epm.platform_operator_grant(issuer,subject_id,granted_at)
      SELECT new_issuer,new_subject,granted_at
      FROM epm.platform_operator_grant
      WHERE issuer=old_issuer AND subject_id=old_subject;
    INSERT INTO epm.workspace_access_grant
      (issuer,subject_id,workspace_id,role,granted_at)
      SELECT new_issuer,new_subject,workspace_id,role,granted_at
      FROM epm.workspace_access_grant
      WHERE issuer=old_issuer AND subject_id=old_subject;
    INSERT INTO epm.application_access_grant
      (issuer,subject_id,workspace_id,application_id,role,granted_at,
       read_security_tags,write_security_tags)
      SELECT new_issuer,new_subject,workspace_id,application_id,role,granted_at,
             read_security_tags,write_security_tags
      FROM epm.application_access_grant
      WHERE issuer=old_issuer AND subject_id=old_subject;
    INSERT INTO epm.rule_access_grant
      (issuer,subject_id,workspace_id,application_id,can_design,can_publish,
       can_run,granted_at)
      SELECT new_issuer,new_subject,workspace_id,application_id,can_design,
             can_publish,can_run,granted_at
      FROM epm.rule_access_grant
      WHERE issuer=old_issuer AND subject_id=old_subject;
    DELETE FROM epm.rule_access_grant
      WHERE issuer=old_issuer AND subject_id=old_subject;
    DELETE FROM epm.application_access_grant
      WHERE issuer=old_issuer AND subject_id=old_subject;
    DELETE FROM epm.workspace_access_grant
      WHERE issuer=old_issuer AND subject_id=old_subject;
    DELETE FROM epm.platform_operator_grant
      WHERE issuer=old_issuer AND subject_id=old_subject;
    INSERT INTO epm.identity_principal_migration
      (migration_id,old_issuer,old_subject_id,new_issuer,new_subject_id,
       preview_digest,actor_digest,effect_summary)
      VALUES(migration_id,old_issuer,old_subject,new_issuer,new_subject,
             preview_digest,actor_digest,current_summary);
    result:=jsonb_build_object('migrationId',migration_id,'status','Applied',
       'previewDigest',preview_digest,'effects',current_summary,
       'historyRewritten',false);
    INSERT INTO epm.security_audit(actor_id,action,target_digest,outcome,detail)
      VALUES(actor_digest,'identity.principal-migration.apply',target_digest,
             'Accepted',jsonb_build_object('migrationId',migration_id,
              'previewDigest',preview_digest,'historyRewritten',false));
    RETURN result;
END$$;

REVOKE ALL ON FUNCTION epm.identity_principal_migration_preview(
    text,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.identity_principal_migration_apply(
    text,text,text,text,text,text,text,jsonb,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.identity_principal_migration_preview(
    text,text,text,text,text,text) TO epm_provision;
GRANT EXECUTE ON FUNCTION epm.identity_principal_migration_apply(
    text,text,text,text,text,text,text,jsonb,text,text,text) TO epm_provision;

COMMENT ON TABLE epm.identity_principal_migration IS
    'Immutable audit of governed current-authority migration; historical business records are not rewritten';
