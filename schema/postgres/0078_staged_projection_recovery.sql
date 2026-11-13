-- Versioned staged reconstruction. Canonical history is never rewritten.
-- No runtime role can read/write manifests or choose a target generation.
CREATE TABLE epm.projection_recovery_manifest (
    workspace_id text NOT NULL, application_id text NOT NULL, job_id text NOT NULL,
    target_generation bigint NOT NULL CHECK(target_generation>0),
    original_generation bigint NOT NULL CHECK(original_generation>=0),
    source_commit_revision bigint NOT NULL, schema_epoch bigint NOT NULL,
    metadata_revision bigint NOT NULL, data_revision bigint NOT NULL, policy_revision bigint NOT NULL,
    coordinate_highwater bigint NOT NULL,
    phase text NOT NULL CHECK(phase IN ('coordinates','numeric','text','detail','generic','activate','published')),
    coordinate_cursor bigint NOT NULL DEFAULT 0, revision_cursor bigint NOT NULL DEFAULT 0,
    ordinal_cursor integer NOT NULL DEFAULT 0,
    table_cursor text NOT NULL DEFAULT '', key_cursor text NOT NULL DEFAULT '',
    carry jsonb, counters jsonb NOT NULL DEFAULT '{}', certificates jsonb NOT NULL DEFAULT '{}',
    quantum_count bigint NOT NULL DEFAULT 0,
    last_checkpoint_claimant text, last_checkpoint_generation bigint, last_checkpoint_digest text,
    context_xid text, context_pid integer, context_claim bigint,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,job_id),
    UNIQUE(workspace_id,application_id,target_generation),
    CONSTRAINT projection_recovery_manifest_job_fkey FOREIGN KEY(workspace_id,application_id,job_id)
        REFERENCES epm.job(workspace_id,application_id,job_id) ON DELETE CASCADE
);
ALTER TABLE epm.projection_recovery_manifest ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON epm.projection_recovery_manifest FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;

-- Existing replay indexes order revisions DESC inside each key. Dedicated ASC
-- folds avoid sorting an unbounded hot key merely to retrieve its next128 rows.
CREATE INDEX numeric_event_recovery_fold ON epm.numeric_fact_event
    (workspace_id,application_id,coordinate_id,committed_revision,line_ordinal);
CREATE INDEX text_event_recovery_fold ON epm.text_fact_event
    (workspace_id,application_id,coordinate_id,committed_revision,line_ordinal);
CREATE INDEX detail_event_recovery_fold ON epm.line_detail_event
    (workspace_id,application_id,coordinate_id,committed_revision);
CREATE INDEX generic_event_recovery_fold ON epm.generic_fact_event
    (workspace_id,application_id,table_id,series_key,committed_revision);

-- Invoker identity is essential: making this helper SECURITY DEFINER would turn
-- a caller-controlled setting into authority. Runtime callers return before any
-- access to private storage. The capability dies at transaction/backend end.
CREATE FUNCTION epm.staged_projection_allowed(w text,a text,target bigint,allowed_phase text DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE m epm.projection_recovery_manifest%ROWTYPE;
BEGIN
    IF coalesce(current_setting('epm.staged_projection_context',true),'')='' THEN RETURN false; END IF;
    IF NOT pg_has_role(current_user,(SELECT relowner FROM pg_class
        WHERE oid='epm.operation_receipt'::regclass),'USAGE') THEN RETURN false; END IF;
    SELECT m0.* INTO m FROM epm.projection_recovery_manifest m0
        JOIN epm.job j USING(workspace_id,application_id,job_id)
        WHERE m0.workspace_id=w AND m0.application_id=a AND m0.target_generation=target
        AND m0.target_generation<>m0.original_generation
        AND (allowed_phase IS NULL OR m0.phase=allowed_phase)
        AND m0.context_xid=pg_current_xact_id()::text AND m0.context_pid=pg_backend_pid()
        AND current_setting('epm.staged_projection_context',true)=jsonb_build_array(
            w,a,m0.job_id,target,m0.context_claim,m0.context_xid,m0.context_pid)::text;
    IF NOT FOUND THEN RETURN false; END IF;
    IF NOT EXISTS(SELECT 1 FROM epm.job j WHERE j.workspace_id=w AND j.application_id=a
        AND j.job_id=m.job_id AND j.status='running' AND j.claim_generation=m.context_claim
        AND j.lease_until>clock_timestamp()) THEN
        RAISE EXCEPTION 'STALE_WORKER_FENCE' USING ERRCODE='23514';
    END IF;
    RETURN true;
END $$;
REVOKE ALL ON FUNCTION epm.staged_projection_allowed(text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.staged_projection_allowed(text,text,bigint,text) TO epm_runtime,epm_lifecycle;

CREATE FUNCTION epm.projection_inactive_write_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE required_phase text;
BEGIN
    required_phase:=CASE TG_TABLE_NAME WHEN 'numeric_cell_projection' THEN 'numeric'
        WHEN 'text_cell_projection' THEN 'text' WHEN 'line_detail_projection' THEN 'detail'
        WHEN 'generic_fact_projection' THEN 'generic' ELSE 'coordinates' END;
    IF EXISTS(SELECT 1 FROM projection_written p LEFT JOIN epm.application_state s USING(workspace_id,application_id)
        WHERE CASE WHEN p.projection_generation IS DISTINCT FROM s.active_projection_generation THEN NOT
        epm.staged_projection_allowed(p.workspace_id,p.application_id,p.projection_generation,required_phase) ELSE false END) THEN
        RAISE EXCEPTION 'RECONSTRUCTION_INACTIVE_WRITE_FORBIDDEN' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' THEN
        IF EXISTS(SELECT 1 FROM projection_prior p LEFT JOIN epm.application_state s USING(workspace_id,application_id)
            WHERE CASE WHEN p.projection_generation IS DISTINCT FROM s.active_projection_generation THEN NOT
            epm.staged_projection_allowed(p.workspace_id,p.application_id,p.projection_generation,required_phase) ELSE false END) THEN
            RAISE EXCEPTION 'RECONSTRUCTION_INACTIVE_WRITE_FORBIDDEN' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION epm.projection_inactive_write_guard() FROM PUBLIC;
DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY ARRAY['numeric_cell_projection','text_cell_projection','line_detail_projection',
        'generic_fact_projection','coordinate_member_projection','coordinate_projection_state'] LOOP
        EXECUTE format('CREATE TRIGGER projection_inactive_insert_guard AFTER INSERT ON epm.%I
            REFERENCING NEW TABLE AS projection_written FOR EACH STATEMENT EXECUTE FUNCTION epm.projection_inactive_write_guard()',t);
        EXECUTE format('CREATE TRIGGER projection_inactive_update_guard AFTER UPDATE ON epm.%I
            REFERENCING NEW TABLE AS projection_written OLD TABLE AS projection_prior
            FOR EACH STATEMENT EXECUTE FUNCTION epm.projection_inactive_write_guard()',t);
    END LOOP;
END $$;

CREATE OR REPLACE FUNCTION epm.projection_generation_pointer_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.active_projection_generation<>0 THEN
            RAISE EXCEPTION 'PROJECTION_GENERATION_ACTIVATION_REQUIRED' USING ERRCODE='23514';
        END IF;
    ELSIF NEW.active_projection_generation IS DISTINCT FROM OLD.active_projection_generation THEN
        IF NOT epm.staged_projection_allowed(NEW.workspace_id,NEW.application_id,
            NEW.active_projection_generation,'activate') THEN
            RAISE EXCEPTION 'PROJECTION_GENERATION_ACTIVATION_REQUIRED' USING ERRCODE='23514';
        END IF;
        IF NOT EXISTS(
            SELECT 1 FROM epm.projection_recovery_manifest m WHERE m.workspace_id=NEW.workspace_id
            AND m.application_id=NEW.application_id AND m.target_generation=NEW.active_projection_generation
            AND m.original_generation=OLD.active_projection_generation
            AND m.source_commit_revision=OLD.commit_revision
            AND m.schema_epoch=OLD.schema_epoch AND m.metadata_revision=OLD.metadata_revision
            AND m.data_revision=OLD.data_revision AND m.policy_revision=OLD.policy_revision
            AND m.certificates='{"coordinates":true,"numeric":true,"text":true,"detail":true,"generic":true}'::jsonb
            AND NEW.commit_revision=OLD.commit_revision+1
            AND NEW.schema_epoch=OLD.schema_epoch AND NEW.metadata_revision=OLD.metadata_revision
            AND NEW.data_revision=OLD.data_revision AND NEW.policy_revision=OLD.policy_revision) THEN
            RAISE EXCEPTION 'PROJECTION_GENERATION_ACTIVATION_REQUIRED' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION epm.projection_recovery_receipt(w text,a text,op text,rev bigint,head bigint,actor text DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF rev>head OR NOT EXISTS(SELECT 1 FROM epm.operation_receipt r
        WHERE r.workspace_id=w AND r.application_id=a AND r.operation_id=op
        AND r.sealed AND r.committed_revision=rev AND (actor IS NULL OR r.actor_id=actor)) THEN
        RAISE EXCEPTION 'RECONSTRUCTION_RECEIPT_INVALID' USING ERRCODE='23514';
    END IF;
END $$;
REVOKE ALL ON FUNCTION epm.projection_recovery_receipt(text,text,text,bigint,bigint,text) FROM PUBLIC;

CREATE FUNCTION epm.fact_projections_rebuild_step(w text,a text,jid text,claimant_name text,generation integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE s epm.application_state%ROWTYPE; j epm.job%ROWTYPE;
    m epm.projection_recovery_manifest%ROWTYPE; layout epm.coordinate_layout%ROWTYPE;
    e record; previous jsonb; p jsonb; output jsonb; revision bigint; highwater bigint;
    processed integer:=0; bytes_used bigint:=0; event_bytes bigint; exhausted boolean:=true;
    next_phase text; counter_name text; numeric_present boolean; numeric_amount numeric;
BEGIN
    IF current_setting('epm.workspace_id',true) IS DISTINCT FROM w
       OR current_setting('epm.application_id',true) IS DISTINCT FROM a THEN
        RAISE EXCEPTION 'RECONSTRUCTION_SCOPE_INVALID' USING ERRCODE='23514';
    END IF;
    PERFORM pg_advisory_xact_lock_shared(hashtextextended('epm.security.workspace:'||w,0));
    SELECT * INTO s FROM epm.application_state WHERE workspace_id=w AND application_id=a FOR UPDATE;
    SELECT * INTO j FROM epm.job WHERE workspace_id=w AND application_id=a AND job_id=jid;
    IF s.application_id IS NULL OR j.job_id IS NULL OR j.function_name<>'facts.projections.rebuild'
       OR j.compiler_version<>'fact-projections-rebuild-v2'
       OR j.plan_digest<>'bdb24ea0001349b4f4b2778486cfcf01856ede90cf8a0b297807e56162c4aea8'
       OR j.resource_class<>'long' THEN
        RAISE EXCEPTION 'RECONSTRUCTION_JOB_INVALID' USING ERRCODE='23514';
    END IF;
    IF j.status<>'running' OR j.claimant IS DISTINCT FROM claimant_name
       OR j.claim_generation IS DISTINCT FROM generation
       OR j.lease_until IS NULL OR j.lease_until<=clock_timestamp() THEN
        RAISE EXCEPTION 'STALE_WORKER_FENCE' USING ERRCODE='23514';
    END IF;
    p:=j.normalized_program;
    IF p->>'function' IS DISTINCT FROM 'facts.projections.rebuild' OR p->'version' IS DISTINCT FROM '2'::jsonb
       OR p-ARRAY['version','function','reason','sourceCommitRevision','schemaEpoch']<>'{}'::jsonb
       OR jsonb_typeof(p->'reason') IS DISTINCT FROM 'string'
       OR length(p->>'reason') NOT BETWEEN 1 AND 500 OR (p->>'reason')~'^[[:space:]]|[[:space:]]$'
       OR jsonb_typeof(p->'sourceCommitRevision') IS DISTINCT FROM 'number'
       OR jsonb_typeof(p->'schemaEpoch') IS DISTINCT FROM 'number'
       OR (p->>'sourceCommitRevision')!~'^(0|[1-9][0-9]*)$'
       OR (p->>'schemaEpoch')!~'^(0|[1-9][0-9]*)$' THEN
        RAISE EXCEPTION 'RECONSTRUCTION_JOB_INVALID' USING ERRCODE='23514';
    END IF;
    IF j.program_digest IS DISTINCT FROM encode(sha256(convert_to(
        '{"function":"facts.projections.rebuild","reason":'||(p->'reason')::text||
        ',"schemaEpoch":'||(p->>'schemaEpoch')||',"sourceCommitRevision":'||
        (p->>'sourceCommitRevision')||',"version":2}', 'UTF8')),'hex') THEN
        RAISE EXCEPTION 'RECONSTRUCTION_JOB_INVALID' USING ERRCODE='23514';
    END IF;
    IF s.commit_open OR s.commit_revision<>(p->>'sourceCommitRevision')::bigint
       OR s.schema_epoch<>(p->>'schemaEpoch')::bigint
       OR s.metadata_revision<>j.expected_metadata_revision OR s.data_revision<>j.expected_data_revision
       OR s.policy_revision<>j.expected_policy_revision THEN
        RAISE EXCEPTION 'STALE_RECONSTRUCTION_SOURCE' USING ERRCODE='23514';
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
    SELECT coalesce((SELECT coordinate_id FROM epm.coordinate WHERE workspace_id=w AND application_id=a
        ORDER BY coordinate_id DESC LIMIT 1),0) INTO highwater;
    SELECT * INTO m FROM epm.projection_recovery_manifest
        WHERE workspace_id=w AND application_id=a AND job_id=jid FOR UPDATE;
    IF NOT FOUND THEN
        INSERT INTO epm.projection_recovery_manifest(workspace_id,application_id,job_id,target_generation,
            original_generation,source_commit_revision,schema_epoch,metadata_revision,data_revision,policy_revision,
            coordinate_highwater,phase)
        VALUES(w,a,jid,greatest(s.active_projection_generation,coalesce((SELECT target_generation
            FROM epm.projection_recovery_manifest WHERE workspace_id=w AND application_id=a
            ORDER BY target_generation DESC LIMIT 1),0))+1,s.active_projection_generation,s.commit_revision,
            s.schema_epoch,s.metadata_revision,s.data_revision,s.policy_revision,highwater,'coordinates')
        RETURNING * INTO m;
        IF EXISTS(SELECT 1 FROM epm.numeric_cell_projection WHERE workspace_id=w AND application_id=a AND projection_generation=m.target_generation)
            OR EXISTS(SELECT 1 FROM epm.text_cell_projection WHERE workspace_id=w AND application_id=a AND projection_generation=m.target_generation)
            OR EXISTS(SELECT 1 FROM epm.line_detail_projection WHERE workspace_id=w AND application_id=a AND projection_generation=m.target_generation)
            OR EXISTS(SELECT 1 FROM epm.generic_fact_projection WHERE workspace_id=w AND application_id=a AND projection_generation=m.target_generation)
            OR EXISTS(SELECT 1 FROM epm.coordinate_member_projection WHERE workspace_id=w AND application_id=a AND projection_generation=m.target_generation)
            OR EXISTS(SELECT 1 FROM epm.coordinate_projection_state WHERE workspace_id=w AND application_id=a AND projection_generation=m.target_generation) THEN
            RAISE EXCEPTION 'RECONSTRUCTION_TARGET_NOT_EMPTY' USING ERRCODE='23514';
        END IF;
    END IF;
    IF ROW(m.original_generation,m.source_commit_revision,m.schema_epoch,m.metadata_revision,m.data_revision,
        m.policy_revision,m.coordinate_highwater) IS DISTINCT FROM ROW(s.active_projection_generation,
        s.commit_revision,s.schema_epoch,s.metadata_revision,s.data_revision,s.policy_revision,highwater) THEN
        RAISE EXCEPTION 'STALE_RECONSTRUCTION_SOURCE' USING ERRCODE='23514';
    END IF;
    UPDATE epm.projection_recovery_manifest SET context_xid=pg_current_xact_id()::text,
        context_pid=pg_backend_pid(),context_claim=generation WHERE workspace_id=w AND application_id=a AND job_id=jid;
    PERFORM set_config('epm.staged_projection_context',jsonb_build_array(w,a,jid,m.target_generation,
        generation,pg_current_xact_id()::text,pg_backend_pid())::text,true);
    -- Existing statement guards still compare canonical latest events exactly.
    -- Inactive row writes additionally require the target/phase-bound capability.
    PERFORM set_config('epm.fact_reconstruction_context',
        jsonb_build_array(w,a,pg_current_xact_id()::text,pg_backend_pid())::text,true);

    IF m.phase='coordinates' THEN
        SELECT * INTO layout FROM epm.coordinate_layout WHERE workspace_id=w AND application_id=a AND schema_epoch=m.schema_epoch;
        IF layout.schema_epoch IS NULL AND highwater>0 THEN
            RAISE EXCEPTION 'RECONSTRUCTION_LAYOUT_INVALID' USING ERRCODE='23514';
        END IF;
        FOR e IN SELECT * FROM epm.coordinate WHERE workspace_id=w AND application_id=a
            AND coordinate_id>m.coordinate_cursor AND coordinate_id<=m.coordinate_highwater
            ORDER BY coordinate_id LIMIT 128 LOOP
            event_bytes:=octet_length(to_jsonb(e)::text);
            IF processed>0 AND bytes_used+event_bytes>1048576 THEN exhausted:=false; EXIT; END IF;
            IF ARRAY(SELECT key FROM jsonb_object_keys(e.members) keys(key) ORDER BY key COLLATE "C")
                IS DISTINCT FROM layout.dimensions THEN
                RAISE EXCEPTION 'COORDINATE_LAYOUT_GRAIN_MISMATCH' USING ERRCODE='23514';
            END IF;
            INSERT INTO epm.coordinate_member_projection(workspace_id,application_id,projection_generation,coordinate_id,dimension_id,member_id)
                SELECT w,a,m.target_generation,e.coordinate_id,key,value FROM jsonb_each_text(e.members);
            INSERT INTO epm.coordinate_projection_state(workspace_id,application_id,projection_generation,coordinate_id,schema_epoch,
                entity_member,account_member,scenario_member,year_member,period_member,value_member,view_member,icp_member,data_type_member,custom_members)
            VALUES(w,a,m.target_generation,e.coordinate_id,m.schema_epoch,
                e.members->>(layout.role_dimensions->>'Entity'),e.members->>(layout.role_dimensions->>'Account'),
                e.members->>(layout.role_dimensions->>'Scenario'),e.members->>(layout.role_dimensions->>'Year'),
                e.members->>(layout.role_dimensions->>'Period'),e.members->>(layout.role_dimensions->>'Value'),
                e.members->>(layout.role_dimensions->>'View'),e.members->>(layout.role_dimensions->>'ICP'),
                e.members->>(layout.role_dimensions->>'DataType'),
                ARRAY(SELECT e.members->>axis FROM unnest(layout.custom_dimensions) WITH ORDINALITY axes(axis,position) ORDER BY position));
            m.coordinate_cursor:=e.coordinate_id; processed:=processed+1; bytes_used:=bytes_used+event_bytes;
        END LOOP;
        counter_name:='coordinateRows'; next_phase:='numeric';
    ELSIF m.phase='numeric' THEN
        FOR e IN SELECT * FROM epm.numeric_fact_event WHERE workspace_id=w AND application_id=a
            AND ROW(coordinate_id,committed_revision,line_ordinal)>ROW(m.coordinate_cursor,m.revision_cursor,m.ordinal_cursor)
            ORDER BY coordinate_id,committed_revision,line_ordinal LIMIT 128 LOOP
            event_bytes:=octet_length(to_jsonb(e)::text);
            IF processed>0 AND bytes_used+event_bytes>1048576 THEN exhausted:=false; EXIT; END IF;
            previous:=m.carry;
            PERFORM epm.projection_recovery_receipt(w,a,e.operation_id,e.committed_revision,m.source_commit_revision);
            IF e.present IS DISTINCT FROM (e.kind<>'clear') OR e.delta IS DISTINCT FROM
                coalesce(e.resulting_amount,0)-coalesce((previous->>'resulting_amount')::numeric,0) THEN
                RAISE EXCEPTION 'RECONSTRUCTION_NUMERIC_LINEAGE_INVALID' USING ERRCODE='23514';
            END IF;
            m.carry:=to_jsonb(e);
            IF NOT EXISTS(SELECT 1 FROM epm.numeric_fact_event WHERE workspace_id=w AND application_id=a
                AND coordinate_id=e.coordinate_id AND ROW(committed_revision,line_ordinal)>ROW(e.committed_revision,e.line_ordinal)) THEN
                INSERT INTO epm.numeric_cell_projection(workspace_id,application_id,projection_generation,coordinate_id,present,amount,change_id,last_revision)
                    VALUES(w,a,m.target_generation,e.coordinate_id,e.present,e.resulting_amount,e.change_id,e.committed_revision);
                m.carry:=NULL;
                m.counters:=m.counters||jsonb_build_object('numericRows',coalesce((m.counters->>'numericRows')::bigint,0)+1);
            END IF;
            m.coordinate_cursor:=e.coordinate_id; m.revision_cursor:=e.committed_revision; m.ordinal_cursor:=e.line_ordinal;
            processed:=processed+1; bytes_used:=bytes_used+event_bytes;
        END LOOP;
        counter_name:='numericEvents'; next_phase:='text';
    ELSIF m.phase='text' THEN
        FOR e IN SELECT * FROM epm.text_fact_event WHERE workspace_id=w AND application_id=a
            AND ROW(coordinate_id,committed_revision,line_ordinal)>ROW(m.coordinate_cursor,m.revision_cursor,m.ordinal_cursor)
            ORDER BY coordinate_id,committed_revision,line_ordinal LIMIT 128 LOOP
            event_bytes:=octet_length(to_jsonb(e)::text);
            IF processed>0 AND bytes_used+event_bytes>1048576 THEN exhausted:=false; EXIT; END IF;
            previous:=m.carry;
            PERFORM epm.projection_recovery_receipt(w,a,e.operation_id,e.committed_revision,m.source_commit_revision);
            IF e.present IS DISTINCT FROM (e.kind<>'clear')
                OR e.prior_present IS DISTINCT FROM coalesce((previous->>'present')::boolean,false)
                OR e.prior_value IS DISTINCT FROM previous->>'resulting_value' THEN
                RAISE EXCEPTION 'RECONSTRUCTION_TEXT_LINEAGE_INVALID' USING ERRCODE='23514';
            END IF;
            m.carry:=to_jsonb(e);
            IF NOT EXISTS(SELECT 1 FROM epm.text_fact_event WHERE workspace_id=w AND application_id=a
                AND coordinate_id=e.coordinate_id AND ROW(committed_revision,line_ordinal)>ROW(e.committed_revision,e.line_ordinal)) THEN
                IF e.present AND EXISTS(SELECT 1 FROM epm.numeric_cell_projection WHERE workspace_id=w AND application_id=a
                    AND projection_generation=m.target_generation AND coordinate_id=e.coordinate_id AND present) THEN
                    RAISE EXCEPTION 'RECONSTRUCTION_VALUE_TYPE_CONFLICT' USING ERRCODE='23514';
                END IF;
                INSERT INTO epm.text_cell_projection(workspace_id,application_id,projection_generation,coordinate_id,present,text_value,change_id,last_revision)
                    VALUES(w,a,m.target_generation,e.coordinate_id,e.present,e.resulting_value,e.change_id,e.committed_revision);
                m.carry:=NULL;
                m.counters:=m.counters||jsonb_build_object('textRows',coalesce((m.counters->>'textRows')::bigint,0)+1);
            END IF;
            m.coordinate_cursor:=e.coordinate_id; m.revision_cursor:=e.committed_revision; m.ordinal_cursor:=e.line_ordinal;
            processed:=processed+1; bytes_used:=bytes_used+event_bytes;
        END LOOP;
        counter_name:='textEvents'; next_phase:='detail';
    ELSIF m.phase='detail' THEN
        FOR e IN SELECT * FROM epm.line_detail_event WHERE workspace_id=w AND application_id=a
            AND ROW(coordinate_id,committed_revision)>ROW(m.coordinate_cursor,m.revision_cursor)
            ORDER BY coordinate_id,committed_revision LIMIT 128 LOOP
            event_bytes:=octet_length(to_jsonb(e)::text);
            IF processed>0 AND bytes_used+event_bytes>1048576 THEN exhausted:=false; EXIT; END IF;
            previous:=m.carry;
            PERFORM epm.projection_recovery_receipt(w,a,e.operation_id,e.committed_revision,m.source_commit_revision);
            IF e.prior_items IS DISTINCT FROM (CASE WHEN (previous->>'present')::boolean THEN previous->'items' ELSE NULL END)
                OR e.prior_total IS DISTINCT FROM (CASE WHEN (previous->>'present')::boolean THEN (previous->>'total')::numeric ELSE NULL END)
                OR e.total IS DISTINCT FROM (SELECT coalesce(sum((x->>'amount')::numeric),0) FROM jsonb_array_elements(e.items)x) THEN
                RAISE EXCEPTION 'RECONSTRUCTION_DETAIL_LINEAGE_INVALID' USING ERRCODE='23514';
            END IF;
            IF e.present THEN
                SELECT present,resulting_amount INTO numeric_present,numeric_amount FROM epm.numeric_fact_event
                    WHERE workspace_id=w AND application_id=a AND coordinate_id=e.coordinate_id
                    AND committed_revision<=e.committed_revision ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1;
                IF NOT coalesce(numeric_present,false) OR numeric_amount IS DISTINCT FROM e.total THEN
                    RAISE EXCEPTION 'RECONSTRUCTION_DETAIL_HISTORY_TOTAL_CONFLICT' USING ERRCODE='23514';
                END IF;
            END IF;
            m.carry:=to_jsonb(e);
            IF NOT EXISTS(SELECT 1 FROM epm.line_detail_event WHERE workspace_id=w AND application_id=a
                AND coordinate_id=e.coordinate_id AND committed_revision>e.committed_revision) THEN
                IF e.present THEN
                    IF NOT EXISTS(SELECT 1 FROM epm.numeric_cell_projection WHERE workspace_id=w AND application_id=a
                        AND projection_generation=m.target_generation AND coordinate_id=e.coordinate_id AND present AND amount=e.total) THEN
                        RAISE EXCEPTION 'RECONSTRUCTION_DETAIL_TOTAL_CONFLICT' USING ERRCODE='23514';
                    END IF;
                    INSERT INTO epm.line_detail_projection(workspace_id,application_id,projection_generation,coordinate_id,items,total,change_id,last_revision)
                        VALUES(w,a,m.target_generation,e.coordinate_id,e.items,e.total,e.change_id,e.committed_revision);
                    m.counters:=m.counters||jsonb_build_object('detailRows',coalesce((m.counters->>'detailRows')::bigint,0)+1);
                END IF;
                m.carry:=NULL;
            END IF;
            m.coordinate_cursor:=e.coordinate_id; m.revision_cursor:=e.committed_revision;
            processed:=processed+1; bytes_used:=bytes_used+event_bytes;
        END LOOP;
        counter_name:='detailEvents'; next_phase:='generic';
    ELSIF m.phase='generic' THEN
        FOR e IN SELECT * FROM epm.generic_fact_event WHERE workspace_id=w AND application_id=a
            AND ROW(table_id,series_key,committed_revision)>ROW(m.table_cursor,m.key_cursor,m.revision_cursor)
            ORDER BY table_id,series_key,committed_revision LIMIT 128 LOOP
            event_bytes:=octet_length(to_jsonb(e)::text);
            IF processed>0 AND bytes_used+event_bytes>1048576 THEN exhausted:=false; EXIT; END IF;
            previous:=m.carry;
            PERFORM epm.projection_recovery_receipt(w,a,e.operation_id,e.committed_revision,m.source_commit_revision,e.actor_id);
            IF e.before_value IS DISTINCT FROM (CASE WHEN previous->>'action'<>'Delete' THEN previous->'after_value' ELSE NULL END)
                OR e.before_change_id IS DISTINCT FROM (CASE WHEN previous->>'action'<>'Delete' THEN previous->>'resulting_change_id' ELSE '' END)
                OR (e.action='Create') IS DISTINCT FROM (previous IS NULL OR previous->>'action'='Delete')
                OR e.resulting_change_id!~'^[0-9a-f]{32}$'
                OR (e.action='Delete' AND e.after_value IS NOT NULL)
                OR (e.action<>'Delete' AND (e.after_value IS NULL OR e.after_value='null'::jsonb)) THEN
                RAISE EXCEPTION 'RECONSTRUCTION_GENERIC_LINEAGE_INVALID' USING ERRCODE='23514';
            END IF;
            m.carry:=to_jsonb(e);
            IF NOT EXISTS(SELECT 1 FROM epm.generic_fact_event WHERE workspace_id=w AND application_id=a
                AND table_id=e.table_id AND series_key=e.series_key AND committed_revision>e.committed_revision) THEN
                IF e.action<>'Delete' THEN
                    INSERT INTO epm.generic_fact_projection(workspace_id,application_id,projection_generation,table_id,series_key,value,change_id,last_revision,updated_at)
                        VALUES(w,a,m.target_generation,e.table_id,e.series_key,e.after_value,e.resulting_change_id,e.committed_revision,e.created_at);
                    m.counters:=m.counters||jsonb_build_object('genericRows',coalesce((m.counters->>'genericRows')::bigint,0)+1);
                END IF;
                m.carry:=NULL;
            END IF;
            m.table_cursor:=e.table_id; m.key_cursor:=e.series_key; m.revision_cursor:=e.committed_revision;
            processed:=processed+1; bytes_used:=bytes_used+event_bytes;
        END LOOP;
        counter_name:='genericEvents'; next_phase:='activate';
    ELSIF m.phase<>'activate' THEN
        RAISE EXCEPTION 'RECONSTRUCTION_MANIFEST_INVALID' USING ERRCODE='23514';
    END IF;

    -- Flush row checks before changing phase or dropping the capability. Works
    -- both with default deferred constraints and callers requesting IMMEDIATE.
    SET CONSTRAINTS epm.generic_projection_complete IMMEDIATE;
    SET CONSTRAINTS epm.generic_projection_complete DEFERRED;
    IF m.phase<>'activate' THEN
        m.counters:=m.counters||jsonb_build_object(counter_name,coalesce((m.counters->>counter_name)::bigint,0)+processed);
        -- A completely empty next range is the durable exhaustion certificate.
        -- A full128 batch or byte stop deliberately yields without guessing.
        IF processed=0 AND exhausted THEN
            IF m.carry IS NOT NULL THEN RAISE EXCEPTION 'RECONSTRUCTION_CARRY_INVALID' USING ERRCODE='23514'; END IF;
            m.certificates:=m.certificates||jsonb_build_object(m.phase,true);
            m.phase:=next_phase; m.coordinate_cursor:=0; m.revision_cursor:=0; m.ordinal_cursor:=0;
            m.table_cursor:=''; m.key_cursor:='';
        END IF;
    END IF;
    m.quantum_count:=m.quantum_count+1;
    -- Keep job unlocked through all source reads/writes so cancellation,
    -- heartbeat and takeover can race; their last committed decision wins here.
    SELECT * INTO j FROM epm.job WHERE workspace_id=w AND application_id=a AND job_id=jid FOR UPDATE;
    IF j.status<>'running' OR j.claimant IS DISTINCT FROM claimant_name
       OR j.claim_generation IS DISTINCT FROM generation
       OR j.lease_until IS NULL OR j.lease_until<=clock_timestamp() THEN
        RAISE EXCEPTION 'STALE_WORKER_FENCE' USING ERRCODE='23514';
    END IF;
    UPDATE epm.projection_recovery_manifest SET phase=m.phase,coordinate_cursor=m.coordinate_cursor,
        revision_cursor=m.revision_cursor,ordinal_cursor=m.ordinal_cursor,table_cursor=m.table_cursor,key_cursor=m.key_cursor,
        carry=m.carry,counters=m.counters,certificates=m.certificates,quantum_count=m.quantum_count,
        updated_at=clock_timestamp() WHERE workspace_id=w AND application_id=a AND job_id=jid;
    IF m.phase='activate' AND processed=0 AND next_phase IS NULL THEN
        IF m.certificates<>'{"coordinates":true,"numeric":true,"text":true,"detail":true,"generic":true}'::jsonb THEN
            RAISE EXCEPTION 'RECONSTRUCTION_CERTIFICATE_INVALID' USING ERRCODE='23514';
        END IF;
        revision:=s.commit_revision+1;
        output:=jsonb_build_object('committedRevision',revision,'sourceCommitRevision',s.commit_revision,
            'schemaEpoch',s.schema_epoch,'reason',p->>'reason','projections',m.counters,
            'targetGeneration',m.target_generation,'historyPreserved',true);
        UPDATE epm.application_state SET active_projection_generation=m.target_generation,commit_revision=revision
            WHERE workspace_id=w AND application_id=a;
        INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result)
            VALUES(w,a,jid,j.program_digest,j.subject_id,revision,output);
        UPDATE epm.projection_recovery_manifest SET phase='published',context_xid=NULL,context_pid=NULL,context_claim=NULL
            WHERE workspace_id=w AND application_id=a AND job_id=jid;
        UPDATE epm.job SET status='published',receipt_revision=revision,result=output,error_code=NULL,
            claimant=NULL,lease_until=NULL,updated_at=clock_timestamp()
            WHERE workspace_id=w AND application_id=a AND job_id=jid;
    ELSE
        output:=jsonb_build_object('status','ready','checkpoint',true,'phase',m.phase,
            'processedEvents',processed,'targetGeneration',m.target_generation,'quantumCount',m.quantum_count);
        UPDATE epm.projection_recovery_manifest SET context_xid=NULL,context_pid=NULL,context_claim=NULL,
            last_checkpoint_claimant=claimant_name,last_checkpoint_generation=generation,last_checkpoint_digest=j.program_digest
            WHERE workspace_id=w AND application_id=a AND job_id=jid;
        UPDATE epm.job SET status='ready',claimant=NULL,lease_until=NULL,error_code=NULL,
            result=output,attempts=greatest(attempts-1,0),updated_at=clock_timestamp()
            WHERE workspace_id=w AND application_id=a AND job_id=jid;
    END IF;
    PERFORM set_config('epm.staged_projection_context','',true);
    PERFORM set_config('epm.fact_reconstruction_context','',true);
    RETURN output;
END $$;
REVOKE ALL ON FUNCTION epm.fact_projections_rebuild_step(text,text,text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.fact_projections_rebuild_step(text,text,text,text,integer) TO epm_runtime;

-- A cleared successful claim is only replayable with its private committed
-- checkpoint proof. A later worker's claim never authenticates the old worker.
CREATE FUNCTION epm.fact_projection_rebuild_checkpoint_matches(w text,a text,jid text,
    claimant_name text,generation integer,program_digest text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
BEGIN
    IF current_setting('epm.workspace_id',true) IS DISTINCT FROM w
        OR current_setting('epm.application_id',true) IS DISTINCT FROM a THEN RETURN false; END IF;
    RETURN EXISTS(SELECT 1 FROM epm.projection_recovery_manifest m JOIN epm.job j
        USING(workspace_id,application_id,job_id)
        WHERE m.workspace_id=w AND m.application_id=a AND m.job_id=jid AND j.status='ready'
        AND j.function_name='facts.projections.rebuild' AND j.compiler_version='fact-projections-rebuild-v2'
        AND j.program_digest=fact_projection_rebuild_checkpoint_matches.program_digest
        AND m.last_checkpoint_digest=j.program_digest AND m.last_checkpoint_claimant=claimant_name
        AND m.last_checkpoint_generation=generation AND j.claim_generation=generation);
END $$;
REVOKE ALL ON FUNCTION epm.fact_projection_rebuild_checkpoint_matches(text,text,text,text,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.fact_projection_rebuild_checkpoint_matches(text,text,text,text,integer,text) TO epm_worker;

-- Only the generic deferred check previously read the active view. Staged rows
-- instead match the latest immutable event directly in their private generation.
-- The original active path (including early SET CONSTRAINTS) stays unchanged.
CREATE OR REPLACE FUNCTION epm.generic_fact_projection_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE e epm.generic_fact_event%ROWTYPE;
BEGIN
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
