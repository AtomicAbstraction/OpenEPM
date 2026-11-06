-- Explicit Administrator cleanup of a referenced recovery generation.
-- Canonical history and the active generation are never cleanup targets.
CREATE TABLE epm.projection_cleanup_manifest (
    workspace_id text NOT NULL, application_id text NOT NULL, job_id text NOT NULL,
    rebuild_job_id text NOT NULL,
    generation_kind text NOT NULL CHECK(generation_kind IN ('abandoned','retired')),
    target_generation bigint NOT NULL CHECK(target_generation>=0),
    schema_epoch bigint NOT NULL CHECK(schema_epoch>=0),
    recovery_program_digest text NOT NULL CHECK(recovery_program_digest~'^[0-9a-f]{64}$'),
    phase text NOT NULL DEFAULT 'numeric' CHECK(phase IN ('numeric','text','detail','generic','members','projection','publish','published')),
    counters jsonb NOT NULL DEFAULT '{}', certificates jsonb NOT NULL DEFAULT '{}',
    quantum_count bigint NOT NULL DEFAULT 0,
    last_checkpoint_claimant text, last_checkpoint_generation bigint, last_checkpoint_digest text,
    context_xid text, context_pid integer, context_claim bigint,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,job_id),
    CONSTRAINT projection_cleanup_manifest_job_fkey FOREIGN KEY(workspace_id,application_id,job_id)
        REFERENCES epm.job(workspace_id,application_id,job_id) ON DELETE CASCADE,
    CONSTRAINT projection_cleanup_manifest_rebuild_fkey FOREIGN KEY(workspace_id,application_id,rebuild_job_id)
        REFERENCES epm.projection_recovery_manifest(workspace_id,application_id,job_id) ON DELETE RESTRICT
);
ALTER TABLE epm.projection_cleanup_manifest ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON epm.projection_cleanup_manifest FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;

-- Read-only technical resolution, never a deletion capability. Fixed Python
-- checks the verified actor's Administrator grant before invoking this resolver.
CREATE FUNCTION epm.projection_cleanup_target(w text,a text,rid text,kind text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE r epm.projection_recovery_manifest%ROWTYPE; j epm.job%ROWTYPE;
    s epm.application_state%ROWTYPE; target bigint;
BEGIN
    IF current_setting('epm.workspace_id',true) IS DISTINCT FROM w
       OR current_setting('epm.application_id',true) IS DISTINCT FROM a THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_SCOPE_INVALID' USING ERRCODE='23514';
    END IF;
    IF rid IS NULL OR rid!~'^[0-9a-f]{32}$' OR kind IS NULL OR kind NOT IN ('abandoned','retired') THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_TARGET_INVALID' USING ERRCODE='23514';
    END IF;
    SELECT * INTO r FROM epm.projection_recovery_manifest WHERE workspace_id=w AND application_id=a AND job_id=rid;
    SELECT * INTO j FROM epm.job WHERE workspace_id=w AND application_id=a AND job_id=rid;
    SELECT * INTO s FROM epm.application_state WHERE workspace_id=w AND application_id=a;
    IF r.job_id IS NULL OR j.job_id IS NULL OR s.application_id IS NULL
       OR j.function_name<>'facts.projections.rebuild' OR j.compiler_version<>'fact-projections-rebuild-v2' THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_TARGET_INVALID' USING ERRCODE='23514';
    END IF;
    IF kind='retired' THEN
        IF r.phase<>'published' OR j.status<>'published' OR NOT EXISTS(
            SELECT 1 FROM epm.operation_receipt o WHERE o.workspace_id=w AND o.application_id=a
            AND o.operation_id=rid AND o.sealed AND o.command_digest=j.program_digest
            AND o.actor_id=j.subject_id AND o.committed_revision=j.receipt_revision) THEN
            RAISE EXCEPTION 'PROJECTION_CLEANUP_TARGET_INVALID' USING ERRCODE='23514';
        END IF;
        target:=r.original_generation;
    ELSE
        IF j.status NOT IN ('failed','cancelled') OR r.phase='published' OR EXISTS(
            SELECT 1 FROM epm.operation_receipt o WHERE o.workspace_id=w AND o.application_id=a AND o.operation_id=rid) THEN
            RAISE EXCEPTION 'PROJECTION_CLEANUP_TARGET_INVALID' USING ERRCODE='23514';
        END IF;
        target:=r.target_generation;
    END IF;
    IF target=s.active_projection_generation THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_TARGET_ACTIVE' USING ERRCODE='23514';
    END IF;
    RETURN jsonb_build_object('rebuildJobId',rid,'generationKind',kind,'targetGeneration',target,
        'recoveryProgramDigest',j.program_digest,'schemaEpoch',s.schema_epoch);
END $$;
REVOKE ALL ON FUNCTION epm.projection_cleanup_target(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.projection_cleanup_target(text,text,text,text) TO epm_runtime;

-- Invoker identity must stay intact. Runtime cannot turn a GUC into owner
-- authority. Reset has a separate transaction/workspace capability, set only
-- inside the reviewed owner-only reset primitive in migration83.
CREATE FUNCTION epm.projection_cleanup_allowed(w text,a text,target bigint,required_phase text DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE m epm.projection_cleanup_manifest%ROWTYPE; current_generation bigint; capability jsonb;
BEGIN
    IF coalesce(current_setting('epm.projection_cleanup_context',true),'')=''
       AND coalesce(current_setting('epm.projection_cleanup_reset_context',true),'')='' THEN RETURN false; END IF;
    IF NOT pg_has_role(current_user,(SELECT relowner FROM pg_class
        WHERE oid='epm.operation_receipt'::regclass),'USAGE') THEN RETURN false; END IF;
    IF current_setting('epm.projection_cleanup_reset_context',true)=
        jsonb_build_array(w,pg_current_xact_id()::text,pg_backend_pid())::text
       AND EXISTS(SELECT 1 FROM epm.workspace WHERE workspace_id=w AND status='Maintenance') THEN RETURN true; END IF;
    IF coalesce(current_setting('epm.projection_cleanup_context',true),'')='' THEN RETURN false; END IF;
    capability:=current_setting('epm.projection_cleanup_context',true)::jsonb;
    SELECT * INTO m FROM epm.projection_cleanup_manifest x WHERE x.workspace_id=w AND x.application_id=a
        AND x.job_id=capability->>2 AND x.target_generation=target AND (required_phase IS NULL OR x.phase=required_phase)
        AND x.context_xid=pg_current_xact_id()::text AND x.context_pid=pg_backend_pid()
        AND current_setting('epm.projection_cleanup_context',true)=jsonb_build_array(
            w,a,x.job_id,target,x.context_claim,x.context_xid,x.context_pid)::text;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT active_projection_generation INTO current_generation FROM epm.application_state
        WHERE workspace_id=w AND application_id=a;
    IF current_generation IS NULL OR current_generation=target THEN RETURN false; END IF;
    IF NOT EXISTS(SELECT 1 FROM epm.job j WHERE j.workspace_id=w AND j.application_id=a
        AND j.job_id=m.job_id AND j.status='running' AND j.claim_generation=m.context_claim
        AND j.lease_until>clock_timestamp()) THEN
        RAISE EXCEPTION 'STALE_WORKER_FENCE' USING ERRCODE='23514';
    END IF;
    RETURN true;
END $$;
REVOKE ALL ON FUNCTION epm.projection_cleanup_allowed(text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.projection_cleanup_allowed(text,text,bigint,text) TO epm_runtime,epm_lifecycle;

CREATE FUNCTION epm.projection_inactive_delete_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE required_phase text;
BEGIN
    required_phase:=CASE TG_TABLE_NAME WHEN 'numeric_cell_projection' THEN 'numeric'
        WHEN 'text_cell_projection' THEN 'text' WHEN 'line_detail_projection' THEN 'detail'
        WHEN 'generic_fact_projection' THEN 'generic' WHEN 'coordinate_member_projection' THEN 'members'
        ELSE 'projection' END;
    IF EXISTS(SELECT 1 FROM projection_removed p LEFT JOIN epm.application_state s USING(workspace_id,application_id)
        WHERE CASE WHEN p.projection_generation IS DISTINCT FROM s.active_projection_generation THEN NOT
            epm.projection_cleanup_allowed(p.workspace_id,p.application_id,p.projection_generation,required_phase) ELSE false END) THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_DELETE_FORBIDDEN' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION epm.projection_inactive_delete_guard() FROM PUBLIC;
DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY ARRAY['numeric_cell_projection','text_cell_projection','line_detail_projection',
        'generic_fact_projection','coordinate_member_projection','coordinate_projection_state'] LOOP
        EXECUTE format('CREATE TRIGGER projection_inactive_delete_guard AFTER DELETE ON epm.%I
            REFERENCING OLD TABLE AS projection_removed FOR EACH STATEMENT EXECUTE FUNCTION epm.projection_inactive_delete_guard()',t);
    END LOOP;
END $$;

CREATE FUNCTION epm.projection_generations_cleanup_step(w text,a text,jid text,claimant_name text,generation integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE s epm.application_state%ROWTYPE; j epm.job%ROWTYPE;
    m epm.projection_cleanup_manifest%ROWTYPE; p jsonb; resolved jsonb;
    physical text; ordering text; next_phase text; deleted bigint:=0; serialized_bytes bigint:=0;
    revision bigint; output jsonb;
BEGIN
    IF current_setting('epm.workspace_id',true) IS DISTINCT FROM w
       OR current_setting('epm.application_id',true) IS DISTINCT FROM a THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_SCOPE_INVALID' USING ERRCODE='23514';
    END IF;
    PERFORM pg_advisory_xact_lock_shared(hashtextextended('epm.security.workspace:'||w,0));
    SELECT * INTO s FROM epm.application_state WHERE workspace_id=w AND application_id=a FOR UPDATE;
    SELECT * INTO j FROM epm.job WHERE workspace_id=w AND application_id=a AND job_id=jid;
    IF s.application_id IS NULL OR j.job_id IS NULL OR j.function_name<>'facts.projections.cleanup'
       OR j.compiler_version<>'projection-generations-cleanup-v1'
       OR j.plan_digest<>'b264fe3557ae52e85b2ee89a757e153d926bd0721947e4727781233bf2019f29'
       OR j.resource_class<>'long' THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_JOB_INVALID' USING ERRCODE='23514';
    END IF;
    IF j.status<>'running' OR j.claimant IS DISTINCT FROM claimant_name
       OR j.claim_generation IS DISTINCT FROM generation
       OR j.lease_until IS NULL OR j.lease_until<=clock_timestamp() THEN
        RAISE EXCEPTION 'STALE_WORKER_FENCE' USING ERRCODE='23514';
    END IF;
    p:=j.normalized_program;
    IF p->>'function' IS DISTINCT FROM 'facts.projections.cleanup' OR p->>'version' IS DISTINCT FROM '1'
       OR p-ARRAY['version','function','reason','rebuildJobId','generationKind','targetGeneration','recoveryProgramDigest','schemaEpoch']<>'{}'::jsonb
       OR jsonb_typeof(p->'reason') IS DISTINCT FROM 'string'
       OR length(p->>'reason') NOT BETWEEN 1 AND 500 OR (p->>'reason')~'^[[:space:]]|[[:space:]]$'
       OR jsonb_typeof(p->'rebuildJobId') IS DISTINCT FROM 'string' OR (p->>'rebuildJobId')!~'^[0-9a-f]{32}$'
       OR jsonb_typeof(p->'generationKind') IS DISTINCT FROM 'string' OR p->>'generationKind' NOT IN ('abandoned','retired')
       OR jsonb_typeof(p->'recoveryProgramDigest') IS DISTINCT FROM 'string' OR (p->>'recoveryProgramDigest')!~'^[0-9a-f]{64}$'
       OR jsonb_typeof(p->'targetGeneration') IS DISTINCT FROM 'number'
       OR jsonb_typeof(p->'schemaEpoch') IS DISTINCT FROM 'number'
       OR (p->>'targetGeneration')!~'^(0|[1-9][0-9]*)$'
       OR (p->>'schemaEpoch')!~'^(0|[1-9][0-9]*)$' THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_JOB_INVALID' USING ERRCODE='23514';
    END IF;
    IF j.program_digest IS DISTINCT FROM encode(sha256(convert_to(
        '{"function":"facts.projections.cleanup","generationKind":'||(p->'generationKind')::text||
        ',"reason":'||(p->'reason')::text||',"rebuildJobId":'||(p->'rebuildJobId')::text||
        ',"recoveryProgramDigest":'||(p->'recoveryProgramDigest')::text||',"schemaEpoch":'||(p->>'schemaEpoch')||
        ',"targetGeneration":'||(p->>'targetGeneration')||',"version":1}','UTF8')),'hex') THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_JOB_INVALID' USING ERRCODE='23514';
    END IF;
    IF s.commit_open OR s.schema_epoch<>(p->>'schemaEpoch')::bigint THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_SCHEMA_CHANGED' USING ERRCODE='23514';
    END IF;
    IF s.processing_mode<>'Active'
       OR NOT EXISTS(SELECT 1 FROM epm.workspace WHERE workspace_id=w AND status='Active')
       OR NOT EXISTS(SELECT 1 FROM epm.application WHERE workspace_id=w AND application_id=a AND status='Active') THEN
        RAISE EXCEPTION 'APPLICATION_NOT_WRITABLE' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM epm.workspace_access_grant WHERE workspace_id=w AND issuer=j.issuer
          AND subject_id=j.subject_id AND role='Administrator')
       AND NOT EXISTS(SELECT 1 FROM epm.application_access_grant WHERE workspace_id=w AND application_id=a
          AND issuer=j.issuer AND subject_id=j.subject_id AND role='Administrator') THEN
        RAISE EXCEPTION 'APPLICATION_GRANT_REQUIRED' USING ERRCODE='23514';
    END IF;
    resolved:=epm.projection_cleanup_target(w,a,p->>'rebuildJobId',p->>'generationKind');
    IF (resolved->>'targetGeneration')::bigint<>(p->>'targetGeneration')::bigint
       OR resolved->>'recoveryProgramDigest' IS DISTINCT FROM p->>'recoveryProgramDigest' THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_TARGET_INVALID' USING ERRCODE='23514';
    END IF;
    SELECT * INTO m FROM epm.projection_cleanup_manifest WHERE workspace_id=w AND application_id=a AND job_id=jid FOR UPDATE;
    IF NOT FOUND THEN
        INSERT INTO epm.projection_cleanup_manifest(workspace_id,application_id,job_id,rebuild_job_id,generation_kind,
            target_generation,schema_epoch,recovery_program_digest)
        VALUES(w,a,jid,p->>'rebuildJobId',p->>'generationKind',(p->>'targetGeneration')::bigint,
            (p->>'schemaEpoch')::bigint,p->>'recoveryProgramDigest') RETURNING * INTO m;
    END IF;
    IF ROW(m.rebuild_job_id,m.generation_kind,m.target_generation,m.schema_epoch,m.recovery_program_digest)
        IS DISTINCT FROM ROW(p->>'rebuildJobId',p->>'generationKind',(p->>'targetGeneration')::bigint,
            (p->>'schemaEpoch')::bigint,p->>'recoveryProgramDigest') THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_JOB_INVALID' USING ERRCODE='23514';
    END IF;
    IF m.target_generation=s.active_projection_generation THEN
        RAISE EXCEPTION 'PROJECTION_CLEANUP_TARGET_ACTIVE' USING ERRCODE='23514';
    END IF;
    UPDATE epm.projection_cleanup_manifest SET context_xid=pg_current_xact_id()::text,
        context_pid=pg_backend_pid(),context_claim=generation WHERE workspace_id=w AND application_id=a AND job_id=jid;
    PERFORM set_config('epm.projection_cleanup_context',jsonb_build_array(w,a,jid,m.target_generation,
        generation,pg_current_xact_id()::text,pg_backend_pid())::text,true);
    IF m.phase<>'publish' THEN
        physical:=CASE m.phase WHEN 'numeric' THEN 'numeric_cell_projection' WHEN 'text' THEN 'text_cell_projection'
            WHEN 'detail' THEN 'line_detail_projection' WHEN 'generic' THEN 'generic_fact_projection'
            WHEN 'members' THEN 'coordinate_member_projection' WHEN 'projection' THEN 'coordinate_projection_state' END;
        ordering:=CASE m.phase WHEN 'generic' THEN 'table_id,series_key'
            WHEN 'members' THEN 'coordinate_id,dimension_id' ELSE 'coordinate_id' END;
        next_phase:=CASE m.phase WHEN 'numeric' THEN 'text' WHEN 'text' THEN 'detail' WHEN 'detail' THEN 'generic'
            WHEN 'generic' THEN 'members' WHEN 'members' THEN 'projection' WHEN 'projection' THEN 'publish' END;
        IF physical IS NULL THEN RAISE EXCEPTION 'PROJECTION_CLEANUP_JOB_INVALID' USING ERRCODE='23514'; END IF;
        -- LIMIT is inside a materialized relation before the byte window. The
        -- window/count never sees the entire retained generation.
        EXECUTE format('WITH candidates AS MATERIALIZED (
            SELECT ctid AS tid,octet_length(to_jsonb(p)::text)::bigint AS row_bytes FROM epm.%I p
            WHERE workspace_id=$1 AND application_id=$2 AND projection_generation=$3
            ORDER BY %s LIMIT 128), budget AS MATERIALIZED (
            SELECT tid,row_bytes,row_number() OVER(ORDER BY tid) AS ordinal,
                sum(row_bytes) OVER(ORDER BY tid ROWS UNBOUNDED PRECEDING) AS bytes FROM candidates),
            picked AS MATERIALIZED (SELECT tid,row_bytes FROM budget WHERE bytes<=1048576 OR ordinal=1),
            removed AS (DELETE FROM epm.%I d USING picked p WHERE d.ctid=p.tid
                AND d.workspace_id=$1 AND d.application_id=$2 AND d.projection_generation=$3 RETURNING d.ctid)
            SELECT (SELECT count(*) FROM removed),(SELECT coalesce(sum(row_bytes),0) FROM picked)',physical,ordering,physical)
            INTO deleted,serialized_bytes USING w,a,m.target_generation;
        SET CONSTRAINTS epm.generic_projection_complete IMMEDIATE;
        SET CONSTRAINTS epm.generic_projection_complete DEFERRED;
        m.counters:=m.counters||jsonb_build_object(m.phase,coalesce((m.counters->>m.phase)::bigint,0)+deleted);
        IF deleted=0 THEN
            m.certificates:=m.certificates||jsonb_build_object(m.phase,true);
            m.phase:=next_phase;
        END IF;
    END IF;
    m.quantum_count:=m.quantum_count+1;
    SELECT * INTO j FROM epm.job WHERE workspace_id=w AND application_id=a AND job_id=jid FOR UPDATE;
    IF j.status<>'running' OR j.claimant IS DISTINCT FROM claimant_name
       OR j.claim_generation IS DISTINCT FROM generation
       OR j.lease_until IS NULL OR j.lease_until<=clock_timestamp() THEN
        RAISE EXCEPTION 'STALE_WORKER_FENCE' USING ERRCODE='23514';
    END IF;
    UPDATE epm.projection_cleanup_manifest SET phase=m.phase,counters=m.counters,certificates=m.certificates,
        quantum_count=m.quantum_count,updated_at=clock_timestamp() WHERE workspace_id=w AND application_id=a AND job_id=jid;
    IF m.phase='publish' AND physical IS NULL THEN
        IF m.certificates<>'{"numeric":true,"text":true,"detail":true,"generic":true,"members":true,"projection":true}'::jsonb THEN
            RAISE EXCEPTION 'PROJECTION_CLEANUP_JOB_INVALID' USING ERRCODE='23514';
        END IF;
        revision:=s.commit_revision+1;
        output:=jsonb_build_object('committedRevision',revision,'rebuildJobId',m.rebuild_job_id,
            'generationKind',m.generation_kind,'targetGeneration',m.target_generation,'reason',p->>'reason',
            'projections',m.counters,'historyPreserved',true,'activeGenerationRetained',true);
        UPDATE epm.application_state SET commit_revision=revision WHERE workspace_id=w AND application_id=a;
        INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result)
            VALUES(w,a,jid,j.program_digest,j.subject_id,revision,output);
        UPDATE epm.projection_cleanup_manifest SET phase='published',context_xid=NULL,context_pid=NULL,context_claim=NULL
            WHERE workspace_id=w AND application_id=a AND job_id=jid;
        UPDATE epm.job SET status='published',receipt_revision=revision,result=output,error_code=NULL,
            claimant=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE workspace_id=w AND application_id=a AND job_id=jid;
    ELSE
        output:=jsonb_build_object('status','ready','checkpoint',true,'phase',m.phase,'deletedRows',deleted,
            'serializedBytes',serialized_bytes,'targetGeneration',m.target_generation,'quantumCount',m.quantum_count);
        UPDATE epm.projection_cleanup_manifest SET context_xid=NULL,context_pid=NULL,context_claim=NULL,
            last_checkpoint_claimant=claimant_name,last_checkpoint_generation=generation,last_checkpoint_digest=j.program_digest
            WHERE workspace_id=w AND application_id=a AND job_id=jid;
        UPDATE epm.job SET status='ready',claimant=NULL,lease_until=NULL,error_code=NULL,result=output,
            attempts=greatest(attempts-1,0),updated_at=clock_timestamp() WHERE workspace_id=w AND application_id=a AND job_id=jid;
    END IF;
    PERFORM set_config('epm.projection_cleanup_context','',true);
    RETURN output;
END $$;
REVOKE ALL ON FUNCTION epm.projection_generations_cleanup_step(text,text,text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.projection_generations_cleanup_step(text,text,text,text,integer) TO epm_runtime;

CREATE FUNCTION epm.projection_cleanup_checkpoint_matches(w text,a text,jid text,
    claimant_name text,generation integer,program_digest text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
BEGIN
    IF current_setting('epm.workspace_id',true) IS DISTINCT FROM w
        OR current_setting('epm.application_id',true) IS DISTINCT FROM a THEN RETURN false; END IF;
    RETURN EXISTS(SELECT 1 FROM epm.projection_cleanup_manifest m JOIN epm.job j USING(workspace_id,application_id,job_id)
        WHERE m.workspace_id=w AND m.application_id=a AND m.job_id=jid AND j.status='ready'
        AND j.function_name='facts.projections.cleanup' AND j.compiler_version='projection-generations-cleanup-v1'
        AND j.program_digest=projection_cleanup_checkpoint_matches.program_digest
        AND m.last_checkpoint_digest=j.program_digest AND m.last_checkpoint_claimant=claimant_name
        AND m.last_checkpoint_generation=generation AND j.claim_generation=generation);
END $$;
REVOKE ALL ON FUNCTION epm.projection_cleanup_checkpoint_matches(text,text,text,text,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.projection_cleanup_checkpoint_matches(text,text,text,text,integer,text) TO epm_worker;

-- Existing active paths are unchanged; only certified cleanup/reset deletes differ.
CREATE OR REPLACE FUNCTION epm.fact_detail_delete_matches() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM fact_deleted d WHERE NOT
        epm.projection_cleanup_allowed(d.workspace_id,d.application_id,d.projection_generation,'detail')) THEN RETURN NULL; END IF;
    -- Reset deletes history before projections under its existing privileged
    -- manifest workflow. Runtime cannot delete immutable detail history.
    IF EXISTS(SELECT 1 FROM fact_deleted c JOIN LATERAL(
        SELECT * FROM epm.line_detail_event e WHERE e.workspace_id=c.workspace_id AND e.application_id=c.application_id
          AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC LIMIT 1)e ON true
        LEFT JOIN epm.operation_receipt r ON r.workspace_id=e.workspace_id AND r.application_id=e.application_id AND r.operation_id=e.operation_id
        WHERE e.present OR (coalesce(r.sealed,true) AND NOT epm.fact_reconstruction_allowed(c.workspace_id,c.application_id))) THEN
        RAISE EXCEPTION 'FACT_DETAIL_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION epm.generic_fact_projection_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE e epm.generic_fact_event%ROWTYPE;
BEGIN
    IF TG_OP='DELETE' AND epm.projection_cleanup_allowed(OLD.workspace_id,OLD.application_id,
        OLD.projection_generation,'generic') THEN RETURN NULL; END IF;
    IF TG_OP<>'DELETE' AND epm.staged_projection_allowed(NEW.workspace_id,NEW.application_id,
        NEW.projection_generation,'generic') THEN
        SELECT * INTO e FROM epm.generic_fact_event WHERE workspace_id=NEW.workspace_id
            AND application_id=NEW.application_id AND table_id=NEW.table_id AND series_key=NEW.series_key
            ORDER BY committed_revision DESC LIMIT 1;
        IF e.event_id IS NULL OR e.action='Delete' OR ROW(NEW.value,NEW.change_id,NEW.last_revision)
            IS DISTINCT FROM ROW(e.after_value,e.resulting_change_id,e.committed_revision) THEN
            RAISE EXCEPTION 'GENERIC_FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
        END IF;
        RETURN NULL;
    END IF;
    IF TG_OP='DELETE' THEN
        PERFORM epm.fact_scope_check(OLD.workspace_id,OLD.application_id);
        IF epm.fact_reconstruction_allowed(OLD.workspace_id,OLD.application_id) THEN
            PERFORM epm.generic_fact_projection_check(OLD.workspace_id,OLD.application_id,OLD.table_id,OLD.series_key);
            RETURN NULL;
        END IF;
        IF NOT EXISTS(SELECT 1 FROM epm.generic_fact_event WHERE workspace_id=OLD.workspace_id
            AND application_id=OLD.application_id AND table_id=OLD.table_id AND series_key=OLD.series_key)
           AND pg_has_role(current_user,(SELECT relowner FROM pg_class
               WHERE oid='epm.operation_receipt'::regclass),'USAGE') THEN RETURN NULL; END IF;
        IF NOT EXISTS(SELECT 1 FROM epm.generic_fact_event WHERE workspace_id=OLD.workspace_id
            AND application_id=OLD.application_id AND table_id=OLD.table_id AND series_key=OLD.series_key
            AND action='Delete' AND committed_revision>OLD.last_revision) THEN
            RAISE EXCEPTION 'GENERIC_FACT_DELETE_EVENT_REQUIRED' USING ERRCODE='23514';
        END IF;
        PERFORM epm.generic_fact_projection_check(OLD.workspace_id,OLD.application_id,OLD.table_id,OLD.series_key);
    ELSE
        PERFORM epm.generic_fact_projection_check(NEW.workspace_id,NEW.application_id,NEW.table_id,NEW.series_key);
    END IF;
    RETURN NULL;
END $$;
