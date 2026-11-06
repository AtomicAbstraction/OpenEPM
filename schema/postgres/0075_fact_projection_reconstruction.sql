-- Fixed source-only reconstruction. No repair values, SQL, owner credentials or
-- general trigger bypass are exposed to the application runtime.
CREATE FUNCTION epm.fact_reconstruction_allowed(w text,a text) RETURNS boolean
LANGUAGE sql SET search_path=pg_catalog,epm AS $$
    SELECT CASE WHEN pg_has_role(current_user,(SELECT relowner FROM pg_class
        WHERE oid='epm.operation_receipt'::regclass),'USAGE') THEN
        coalesce(current_setting('epm.fact_reconstruction_context',true)=
            jsonb_build_array(w,a,pg_current_xact_id()::text,pg_backend_pid())::text,false)
        ELSE false END
$$;
REVOKE ALL ON FUNCTION epm.fact_reconstruction_allowed(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.fact_reconstruction_allowed(text,text) TO epm_runtime,epm_lifecycle;

-- Validate all retained history independently of damaged current projections.
-- This function has no runtime EXECUTE privilege and accepts no replacement data.
CREATE FUNCTION epm.fact_reconstruction_validate(w text,a text,head bigint) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM (
        SELECT workspace_id,application_id,operation_id,committed_revision FROM epm.numeric_fact_event
        WHERE workspace_id=w AND application_id=a
        UNION ALL SELECT workspace_id,application_id,operation_id,committed_revision FROM epm.text_fact_event
        WHERE workspace_id=w AND application_id=a
        UNION ALL SELECT workspace_id,application_id,operation_id,committed_revision FROM epm.line_detail_event
        WHERE workspace_id=w AND application_id=a
        UNION ALL SELECT workspace_id,application_id,operation_id,committed_revision FROM epm.generic_fact_event
        WHERE workspace_id=w AND application_id=a)e
        LEFT JOIN epm.operation_receipt r USING(workspace_id,application_id,operation_id)
        WHERE r.operation_id IS NULL OR NOT r.sealed OR e.committed_revision<>r.committed_revision
          OR e.committed_revision>head)
       OR EXISTS(SELECT 1 FROM epm.generic_fact_event e JOIN epm.operation_receipt r
          USING(workspace_id,application_id,operation_id) WHERE e.workspace_id=w AND e.application_id=a
          AND e.actor_id<>r.actor_id) THEN
        RAISE EXCEPTION 'RECONSTRUCTION_RECEIPT_INVALID' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH h AS (SELECT *,lag(resulting_amount) OVER chain AS previous_amount
        FROM epm.numeric_fact_event WHERE workspace_id=w AND application_id=a
        WINDOW chain AS(PARTITION BY coordinate_id ORDER BY committed_revision,line_ordinal))
        SELECT 1 FROM h WHERE present IS DISTINCT FROM (kind<>'clear')
          OR delta IS DISTINCT FROM coalesce(resulting_amount,0)-coalesce(previous_amount,0)) THEN
        RAISE EXCEPTION 'RECONSTRUCTION_NUMERIC_LINEAGE_INVALID' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH h AS (SELECT *,lag(present) OVER chain AS previous_present,
          lag(resulting_value) OVER chain AS previous_value FROM epm.text_fact_event
        WHERE workspace_id=w AND application_id=a
        WINDOW chain AS(PARTITION BY coordinate_id ORDER BY committed_revision,line_ordinal))
        SELECT 1 FROM h WHERE present IS DISTINCT FROM (kind<>'clear')
          OR prior_present IS DISTINCT FROM coalesce(previous_present,false)
          OR prior_value IS DISTINCT FROM previous_value) THEN
        RAISE EXCEPTION 'RECONSTRUCTION_TEXT_LINEAGE_INVALID' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH h AS (SELECT *,lag(present) OVER chain AS previous_present,
          lag(items) OVER chain AS previous_items,lag(total) OVER chain AS previous_total
        FROM epm.line_detail_event WHERE workspace_id=w AND application_id=a
        WINDOW chain AS(PARTITION BY coordinate_id ORDER BY committed_revision))
        SELECT 1 FROM h WHERE prior_items IS DISTINCT FROM
            CASE WHEN previous_present THEN previous_items ELSE NULL END
          OR prior_total IS DISTINCT FROM CASE WHEN previous_present THEN previous_total ELSE NULL END
          OR total IS DISTINCT FROM (SELECT coalesce(sum((x->>'amount')::numeric),0)
              FROM jsonb_array_elements(items)x)) THEN
        RAISE EXCEPTION 'RECONSTRUCTION_DETAIL_LINEAGE_INVALID' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH h AS (SELECT *,lag(action) OVER chain AS previous_action,
          lag(after_value) OVER chain AS previous_value,lag(resulting_change_id) OVER chain AS previous_id
        FROM epm.generic_fact_event WHERE workspace_id=w AND application_id=a
        WINDOW chain AS(PARTITION BY table_id,series_key ORDER BY committed_revision))
        SELECT 1 FROM h WHERE before_value IS DISTINCT FROM
            CASE WHEN previous_action<>'Delete' THEN previous_value ELSE NULL END
          OR before_change_id IS DISTINCT FROM CASE WHEN previous_action<>'Delete' THEN previous_id ELSE '' END
          OR (action='Create') IS DISTINCT FROM (previous_action IS NULL OR previous_action='Delete')
          OR resulting_change_id!~'^[0-9a-f]{32}$'
          OR (action='Delete' AND after_value IS NOT NULL)
          OR (action<>'Delete' AND (after_value IS NULL OR after_value='null'::jsonb))) THEN
        RAISE EXCEPTION 'RECONSTRUCTION_GENERIC_LINEAGE_INVALID' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH n AS (SELECT DISTINCT ON(coordinate_id) coordinate_id,present FROM epm.numeric_fact_event
          WHERE workspace_id=w AND application_id=a ORDER BY coordinate_id,committed_revision DESC,line_ordinal DESC),
        t AS (SELECT DISTINCT ON(coordinate_id) coordinate_id,present FROM epm.text_fact_event
          WHERE workspace_id=w AND application_id=a ORDER BY coordinate_id,committed_revision DESC,line_ordinal DESC)
        SELECT 1 FROM n JOIN t USING(coordinate_id) WHERE n.present AND t.present) THEN
        RAISE EXCEPTION 'RECONSTRUCTION_VALUE_TYPE_CONFLICT' USING ERRCODE='23514';
    END IF;
    IF EXISTS(SELECT 1 FROM epm.line_detail_event d LEFT JOIN LATERAL(
        SELECT present,resulting_amount FROM epm.numeric_fact_event n
        WHERE n.workspace_id=d.workspace_id AND n.application_id=d.application_id AND n.coordinate_id=d.coordinate_id
          AND n.committed_revision<=d.committed_revision
        ORDER BY n.committed_revision DESC,n.line_ordinal DESC LIMIT 1)n ON true
        WHERE d.workspace_id=w AND d.application_id=a AND d.present
          AND (NOT coalesce(n.present,false) OR n.resulting_amount IS DISTINCT FROM d.total)) THEN
        RAISE EXCEPTION 'RECONSTRUCTION_DETAIL_HISTORY_TOTAL_CONFLICT' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH d AS(SELECT DISTINCT ON(coordinate_id) coordinate_id,present,total
        FROM epm.line_detail_event WHERE workspace_id=w AND application_id=a
        ORDER BY coordinate_id,committed_revision DESC),
        n AS(SELECT DISTINCT ON(coordinate_id) coordinate_id,present,resulting_amount
        FROM epm.numeric_fact_event WHERE workspace_id=w AND application_id=a
        ORDER BY coordinate_id,committed_revision DESC,line_ordinal DESC)
        SELECT 1 FROM d LEFT JOIN n USING(coordinate_id) WHERE d.present
          AND (NOT coalesce(n.present,false) OR n.resulting_amount IS DISTINCT FROM d.total)) THEN
        RAISE EXCEPTION 'RECONSTRUCTION_DETAIL_TOTAL_CONFLICT' USING ERRCODE='23514';
    END IF;
END $$;
REVOKE ALL ON FUNCTION epm.fact_reconstruction_validate(text,text,bigint) FROM PUBLIC;

CREATE FUNCTION epm.fact_projections_rebuild(w text,a text,jid text,claimant_name text,generation integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE s epm.application_state%ROWTYPE; j epm.job%ROWTYPE; p jsonb;
    output jsonb; counts jsonb:='{}'; affected bigint; revision bigint;
BEGIN
    -- Check caller scope even under definer identity. The caller cannot create
    -- a valid context by setting a GUC: invoker guards also require owner identity.
    IF current_setting('epm.workspace_id',true) IS DISTINCT FROM w
       OR current_setting('epm.application_id',true) IS DISTINCT FROM a THEN
        RAISE EXCEPTION 'RECONSTRUCTION_SCOPE_INVALID' USING ERRCODE='23514';
    END IF;
    PERFORM pg_advisory_xact_lock_shared(hashtextextended('epm.security.workspace:'||w,0));
    SELECT * INTO s FROM epm.application_state WHERE workspace_id=w AND application_id=a FOR UPDATE;
    SELECT * INTO j FROM epm.job WHERE workspace_id=w AND application_id=a AND job_id=jid;
    IF s.application_id IS NULL OR j.job_id IS NULL OR j.function_name<>'facts.projections.rebuild'
       OR j.compiler_version<>'fact-projections-rebuild-v1'
       OR j.plan_digest<>'e8b2d3005d3d668c1bd65a419d96b049b6fcb35a81d1d26f649c16d4a5d9504c'
       OR j.resource_class<>'long' THEN
        RAISE EXCEPTION 'RECONSTRUCTION_JOB_INVALID' USING ERRCODE='23514';
    END IF;
    IF j.status<>'running' OR j.claimant IS DISTINCT FROM claimant_name
       OR j.claim_generation IS DISTINCT FROM generation
       OR j.lease_until IS NULL OR j.lease_until<=clock_timestamp() THEN
        RAISE EXCEPTION 'STALE_WORKER_FENCE' USING ERRCODE='23514';
    END IF;
    p:=j.normalized_program;
    IF p->>'function' IS DISTINCT FROM 'facts.projections.rebuild' OR p->>'version' IS DISTINCT FROM '1'
       OR p-ARRAY['version','function','reason','sourceCommitRevision','schemaEpoch']<>'{}'::jsonb
       OR jsonb_typeof(p->'reason') IS DISTINCT FROM 'string'
       OR length(p->>'reason') NOT BETWEEN 1 AND 500 OR (p->>'reason')~'^[[:space:]]|[[:space:]]$'
       OR jsonb_typeof(p->'sourceCommitRevision') IS DISTINCT FROM 'number'
       OR jsonb_typeof(p->'schemaEpoch') IS DISTINCT FROM 'number'
       OR (p->>'sourceCommitRevision')!~'^(0|[1-9][0-9]*)$'
       OR (p->>'schemaEpoch')!~'^(0|[1-9][0-9]*)$' THEN
        RAISE EXCEPTION 'RECONSTRUCTION_JOB_INVALID' USING ERRCODE='23514';
    END IF;
    -- Canonical UTF-8 serialization matches the fixed Python compiler's sorted
    -- JSON keys. JSON string escaping stays native; never remove whitespace from
    -- inside a reason or accept an arbitrary stored receipt digest.
    IF j.program_digest IS DISTINCT FROM encode(sha256(convert_to(
        '{"function":"facts.projections.rebuild","reason":'||(p->'reason')::text||
        ',"schemaEpoch":'||(p->>'schemaEpoch')||',"sourceCommitRevision":'||
        (p->>'sourceCommitRevision')||',"version":1}', 'UTF8')),'hex') THEN
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
    PERFORM epm.fact_reconstruction_validate(w,a,s.commit_revision);
    PERFORM set_config('epm.fact_reconstruction_context',
        jsonb_build_array(w,a,pg_current_xact_id()::text,pg_backend_pid())::text,true);

    -- Membership is also derived. Missing or misassigned rows otherwise leave
    -- indexed readers/calculations wrong even after amounts are reconstructed.
    INSERT INTO epm.coordinate_member(workspace_id,application_id,coordinate_id,dimension_id,member_id)
    SELECT w,a,c.coordinate_id,pair.key,pair.value FROM epm.coordinate c
    CROSS JOIN LATERAL jsonb_each_text(c.members) pair
    WHERE c.workspace_id=w AND c.application_id=a
    ON CONFLICT(workspace_id,application_id,coordinate_id,dimension_id) DO UPDATE SET member_id=excluded.member_id;
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('coordinateMemberRows',affected);
    DELETE FROM epm.coordinate_member m USING epm.coordinate c
    WHERE m.workspace_id=w AND m.application_id=a AND c.workspace_id=w AND c.application_id=a
      AND m.coordinate_id=c.coordinate_id AND (c.members->>m.dimension_id) IS DISTINCT FROM m.member_id;
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('coordinateMemberRemoved',affected);

    -- Current tables are derived, not sources. Preserve original event IDs,
    -- committed revisions and cleared numeric/text CAS tombstones.
    INSERT INTO epm.numeric_cell_current(workspace_id,application_id,coordinate_id,present,amount,change_id,last_revision)
    SELECT DISTINCT ON(coordinate_id) w,a,coordinate_id,present,resulting_amount,change_id,committed_revision
    FROM epm.numeric_fact_event WHERE workspace_id=w AND application_id=a
    ORDER BY coordinate_id,committed_revision DESC,line_ordinal DESC
    ON CONFLICT(workspace_id,application_id,coordinate_id) DO UPDATE SET
        present=excluded.present,amount=excluded.amount,change_id=excluded.change_id,last_revision=excluded.last_revision;
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('numericRows',affected);
    DELETE FROM epm.numeric_cell_current c WHERE c.workspace_id=w AND c.application_id=a
      AND NOT EXISTS(SELECT 1 FROM epm.numeric_fact_event e WHERE e.workspace_id=w AND e.application_id=a
          AND e.coordinate_id=c.coordinate_id);
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('numericRemoved',affected);

    INSERT INTO epm.text_cell_current(workspace_id,application_id,coordinate_id,present,text_value,change_id,last_revision)
    SELECT DISTINCT ON(coordinate_id) w,a,coordinate_id,present,resulting_value,change_id,committed_revision
    FROM epm.text_fact_event WHERE workspace_id=w AND application_id=a
    ORDER BY coordinate_id,committed_revision DESC,line_ordinal DESC
    ON CONFLICT(workspace_id,application_id,coordinate_id) DO UPDATE SET
        present=excluded.present,text_value=excluded.text_value,change_id=excluded.change_id,last_revision=excluded.last_revision;
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('textRows',affected);
    DELETE FROM epm.text_cell_current c WHERE c.workspace_id=w AND c.application_id=a
      AND NOT EXISTS(SELECT 1 FROM epm.text_fact_event e WHERE e.workspace_id=w AND e.application_id=a
          AND e.coordinate_id=c.coordinate_id);
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('textRemoved',affected);

    WITH latest AS(SELECT DISTINCT ON(coordinate_id) * FROM epm.line_detail_event
        WHERE workspace_id=w AND application_id=a ORDER BY coordinate_id,committed_revision DESC)
    INSERT INTO epm.line_detail_current(workspace_id,application_id,coordinate_id,items,total,change_id,last_revision)
    SELECT w,a,coordinate_id,items,total,change_id,committed_revision FROM latest WHERE present
    ON CONFLICT(workspace_id,application_id,coordinate_id) DO UPDATE SET
        items=excluded.items,total=excluded.total,change_id=excluded.change_id,last_revision=excluded.last_revision;
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('detailRows',affected);
    DELETE FROM epm.line_detail_current c WHERE c.workspace_id=w AND c.application_id=a
      AND NOT EXISTS(SELECT 1 FROM (SELECT present FROM epm.line_detail_event e
          WHERE e.workspace_id=w AND e.application_id=a AND e.coordinate_id=c.coordinate_id
          ORDER BY committed_revision DESC LIMIT 1)latest WHERE present);
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('detailRemoved',affected);

    WITH latest AS(SELECT DISTINCT ON(table_id,series_key) * FROM epm.generic_fact_event
        WHERE workspace_id=w AND application_id=a ORDER BY table_id,series_key,committed_revision DESC)
    INSERT INTO epm.generic_fact_current(workspace_id,application_id,table_id,series_key,value,change_id,last_revision,updated_at)
    SELECT w,a,table_id,series_key,after_value,resulting_change_id,committed_revision,created_at
    FROM latest WHERE action<>'Delete'
    ON CONFLICT(workspace_id,application_id,table_id,series_key) DO UPDATE SET
        value=excluded.value,change_id=excluded.change_id,last_revision=excluded.last_revision,updated_at=excluded.updated_at;
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('genericRows',affected);
    DELETE FROM epm.generic_fact_current c WHERE c.workspace_id=w AND c.application_id=a
      AND NOT EXISTS(SELECT 1 FROM (SELECT action FROM epm.generic_fact_event e
          WHERE e.workspace_id=w AND e.application_id=a AND e.table_id=c.table_id AND e.series_key=c.series_key
          ORDER BY committed_revision DESC LIMIT 1)latest WHERE action<>'Delete');
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('genericRemoved',affected);
    PERFORM epm.coordinate_projection_build(w,a);

    -- Flush checks while owner/context is valid, then close the privilege window
    -- before returning to fixed Python. No event/receipt seal is reopened.
    SET CONSTRAINTS epm.generic_projection_complete IMMEDIATE;
    SET CONSTRAINTS epm.generic_projection_complete DEFERRED;
    PERFORM set_config('epm.fact_reconstruction_context','',true);

    -- Cancellation, heartbeat and takeover may proceed until this final fence.
    SELECT * INTO j FROM epm.job WHERE workspace_id=w AND application_id=a AND job_id=jid FOR UPDATE;
    IF j.status<>'running' OR j.claimant IS DISTINCT FROM claimant_name
       OR j.claim_generation IS DISTINCT FROM generation
       OR j.lease_until IS NULL OR j.lease_until<=clock_timestamp() THEN
        RAISE EXCEPTION 'STALE_WORKER_FENCE' USING ERRCODE='23514';
    END IF;
    revision:=s.commit_revision+1;
    output:=jsonb_build_object('committedRevision',revision,'sourceCommitRevision',s.commit_revision,
        'schemaEpoch',s.schema_epoch,'reason',p->>'reason','projections',counts,'historyPreserved',true);
    UPDATE epm.application_state SET commit_revision=revision WHERE workspace_id=w AND application_id=a;
    INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result)
        VALUES(w,a,jid,j.program_digest,j.subject_id,revision,output);
    UPDATE epm.job SET status='published',receipt_revision=revision,result=output,
        claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
        WHERE workspace_id=w AND application_id=a AND job_id=jid;
    RETURN output;
END $$;
REVOKE ALL ON FUNCTION epm.fact_projections_rebuild(text,text,text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.fact_projections_rebuild(text,text,text,text,integer) TO epm_runtime;


-- Existing ordinary guards retain exact canonical matching. Only sealed-receipt
-- and projection-mutation epoch restrictions admit this owner/scope/XID/backend
-- context; event/receipt guards remain unchanged. Planning locks themselves never
-- change, and journal writes are never exempted.
CREATE OR REPLACE FUNCTION epm.fact_projection_matches() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF TG_TABLE_NAME='numeric_cell_current' THEN
        IF EXISTS(SELECT 1 FROM fact_projected c LEFT JOIN LATERAL(
            SELECT * FROM epm.numeric_fact_event e WHERE e.workspace_id=c.workspace_id AND e.application_id=c.application_id
              AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)e ON true
            LEFT JOIN epm.operation_receipt r ON r.workspace_id=e.workspace_id AND r.application_id=e.application_id AND r.operation_id=e.operation_id
            WHERE e.event_id IS NULL OR (coalesce(r.sealed,true) AND NOT epm.fact_reconstruction_allowed(c.workspace_id,c.application_id)) OR ROW(c.present,c.amount,c.change_id,c.last_revision)
              IS DISTINCT FROM ROW(e.present,e.resulting_amount,e.change_id,e.committed_revision)) THEN
            RAISE EXCEPTION 'FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
        END IF;
    ELSIF TG_TABLE_NAME='text_cell_current' THEN
        IF EXISTS(SELECT 1 FROM fact_projected c LEFT JOIN LATERAL(
            SELECT * FROM epm.text_fact_event e WHERE e.workspace_id=c.workspace_id AND e.application_id=c.application_id
              AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)e ON true
            LEFT JOIN epm.operation_receipt r ON r.workspace_id=e.workspace_id AND r.application_id=e.application_id AND r.operation_id=e.operation_id
            WHERE e.event_id IS NULL OR (coalesce(r.sealed,true) AND NOT epm.fact_reconstruction_allowed(c.workspace_id,c.application_id)) OR ROW(c.present,c.text_value,c.change_id,c.last_revision)
              IS DISTINCT FROM ROW(e.present,e.resulting_value,e.change_id,e.committed_revision)) THEN
            RAISE EXCEPTION 'FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
        END IF;
    ELSE
        IF EXISTS(SELECT 1 FROM fact_projected c LEFT JOIN LATERAL(
            SELECT * FROM epm.line_detail_event e WHERE e.workspace_id=c.workspace_id AND e.application_id=c.application_id
              AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC LIMIT 1)e ON true
            LEFT JOIN epm.operation_receipt r ON r.workspace_id=e.workspace_id AND r.application_id=e.application_id AND r.operation_id=e.operation_id
            WHERE e.event_id IS NULL OR (coalesce(r.sealed,true) AND NOT epm.fact_reconstruction_allowed(c.workspace_id,c.application_id)) OR NOT e.present OR ROW(c.items,c.total,c.change_id,c.last_revision)
              IS DISTINCT FROM ROW(e.items,e.total,e.change_id,e.committed_revision)) THEN
            RAISE EXCEPTION 'FACT_DETAIL_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION epm.fact_detail_delete_matches() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
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

CREATE OR REPLACE FUNCTION epm.reject_locked_fact_write()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM affected_rows point
        JOIN epm.coordinate c ON c.workspace_id=point.workspace_id
        AND c.application_id=point.application_id
        AND c.coordinate_id=point.coordinate_id
        JOIN epm.planning_slice_lock l
        ON l.workspace_id=point.workspace_id
        AND l.application_id=point.application_id
        AND l.status='Locked'
        AND (l.scope_all OR c.members @> l.scope_members)
        AND NOT (TG_TABLE_NAME IN ('numeric_cell_current','text_cell_current','line_detail_current')
            AND epm.fact_reconstruction_allowed(point.workspace_id,point.application_id))
        LIMIT 1) THEN
        RAISE EXCEPTION 'PLANNING_SLICE_LOCKED'
            USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' THEN
        IF EXISTS (
            SELECT 1 FROM prior_rows point
            JOIN epm.coordinate c ON c.workspace_id=point.workspace_id
            AND c.application_id=point.application_id
            AND c.coordinate_id=point.coordinate_id
            JOIN epm.planning_slice_lock l
            ON l.workspace_id=point.workspace_id
            AND l.application_id=point.application_id
            AND l.status='Locked'
            AND (l.scope_all OR c.members @> l.scope_members)
        AND NOT (TG_TABLE_NAME IN ('numeric_cell_current','text_cell_current','line_detail_current')
            AND epm.fact_reconstruction_allowed(point.workspace_id,point.application_id))
            LIMIT 1) THEN
            RAISE EXCEPTION 'PLANNING_SLICE_LOCKED'
                USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION epm.generic_fact_write_open() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    -- Serialize with the same short application publication gate as fixed core.
    PERFORM 1 FROM epm.application_state s WHERE EXISTS(SELECT 1 FROM generic_inserted i
       WHERE i.workspace_id=s.workspace_id AND i.application_id=s.application_id) FOR UPDATE;
    IF TG_TABLE_NAME='generic_fact_event' THEN
        IF EXISTS(SELECT 1 FROM generic_inserted i JOIN epm.operation_receipt r
           USING(workspace_id,application_id,operation_id) WHERE r.sealed) THEN
            RAISE EXCEPTION 'GENERIC_FACT_OPERATION_SEALED' USING ERRCODE='23514';
        END IF;
        IF EXISTS(SELECT 1 FROM generic_inserted i LEFT JOIN epm.application_state s
           USING(workspace_id,application_id) WHERE s.commit_revision IS NULL OR NOT
           (i.committed_revision=s.commit_revision+1 OR
             (i.committed_revision=s.commit_revision AND s.commit_open))) THEN
            RAISE EXCEPTION 'GENERIC_FACT_REVISION_INVALID' USING ERRCODE='23514';
        END IF;
        IF EXISTS(SELECT 1 FROM generic_inserted i WHERE
           i.resulting_change_id!~'^[0-9a-f]{32}$' OR
           (i.action='Create' AND (i.before_value IS NOT NULL OR i.before_change_id<>'')) OR
           (i.action IN ('Update','Delete') AND
             (i.before_value IS NULL OR i.before_value='null'::jsonb OR i.before_change_id!~'^[0-9a-f]{32}$')) OR
           (i.action='Delete' AND i.after_value IS NOT NULL) OR
           (i.action<>'Delete' AND (i.after_value IS NULL OR i.after_value='null'::jsonb))) THEN
            RAISE EXCEPTION 'GENERIC_FACT_EVENT_SHAPE_INVALID' USING ERRCODE='23514';
        END IF;
    ELSE
        IF EXISTS(SELECT 1 FROM generic_inserted i LEFT JOIN epm.application_state s
           USING(workspace_id,application_id) WHERE s.commit_revision IS NULL OR NOT
           (epm.fact_reconstruction_allowed(i.workspace_id,i.application_id) OR (i.last_revision=s.commit_revision+1 OR
             (i.last_revision=s.commit_revision AND s.commit_open)))) THEN
            RAISE EXCEPTION 'GENERIC_FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION epm.generic_fact_projection_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        PERFORM epm.fact_scope_check(OLD.workspace_id,OLD.application_id);
        IF epm.fact_reconstruction_allowed(OLD.workspace_id,OLD.application_id) THEN
            PERFORM epm.generic_fact_projection_check(OLD.workspace_id,OLD.application_id,OLD.table_id,OLD.series_key);
            RETURN NULL;
        END IF;
        -- The reviewed owner-only reset deletes history before projections.
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
