-- Generation-backed derived storage. Existing canonical events and receipt/CAS
-- meaning are unchanged. Generation zero preserves populated legacy state.
-- This foundation does NOT expose an unvalidated activation or staging API.
ALTER TABLE epm.application_state ADD COLUMN active_projection_generation bigint NOT NULL DEFAULT 0
    CHECK(active_projection_generation>=0);
CREATE FUNCTION epm.active_projection_generation() RETURNS bigint
LANGUAGE sql STABLE SET search_path=pg_catalog,epm AS $$
    SELECT active_projection_generation FROM epm.application_state
    WHERE workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true)
$$;
REVOKE ALL ON FUNCTION epm.active_projection_generation() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.active_projection_generation() TO epm_runtime,epm_analyst,epm_lifecycle;
CREATE FUNCTION epm.projection_generation_pointer_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF (TG_OP='INSERT' AND NEW.active_projection_generation<>0)
       OR (TG_OP='UPDATE' AND NEW.active_projection_generation IS DISTINCT FROM OLD.active_projection_generation) THEN
        RAISE EXCEPTION 'PROJECTION_GENERATION_ACTIVATION_REQUIRED' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.projection_generation_pointer_guard() FROM PUBLIC;
CREATE TRIGGER projection_generation_pointer_guard BEFORE INSERT OR UPDATE ON epm.application_state
    FOR EACH ROW EXECUTE FUNCTION epm.projection_generation_pointer_guard();

ALTER TABLE epm.numeric_cell_current RENAME TO numeric_cell_projection;
ALTER TABLE epm.numeric_cell_projection ADD COLUMN projection_generation bigint NOT NULL DEFAULT 0 CHECK(projection_generation>=0);
ALTER TABLE epm.numeric_cell_projection DROP CONSTRAINT numeric_cell_current_pkey;
ALTER TABLE epm.numeric_cell_projection ADD PRIMARY KEY(workspace_id,application_id,projection_generation,coordinate_id);
-- A restrictive policy combines with existing scope policies; they cannot OR
-- their way around inactive-generation protection. No caller GUC authorizes it.
CREATE POLICY projection_active_generation ON epm.numeric_cell_projection AS RESTRICTIVE TO epm_runtime,epm_analyst
    USING(projection_generation=(SELECT epm.active_projection_generation()))
    WITH CHECK(projection_generation=(SELECT epm.active_projection_generation()));

ALTER TABLE epm.text_cell_current RENAME TO text_cell_projection;
ALTER TABLE epm.text_cell_projection ADD COLUMN projection_generation bigint NOT NULL DEFAULT 0 CHECK(projection_generation>=0);
ALTER TABLE epm.text_cell_projection DROP CONSTRAINT text_cell_current_pkey;
ALTER TABLE epm.text_cell_projection ADD PRIMARY KEY(workspace_id,application_id,projection_generation,coordinate_id);
-- A restrictive policy combines with existing scope policies; they cannot OR
-- their way around inactive-generation protection. No caller GUC authorizes it.
CREATE POLICY projection_active_generation ON epm.text_cell_projection AS RESTRICTIVE TO epm_runtime,epm_analyst
    USING(projection_generation=(SELECT epm.active_projection_generation()))
    WITH CHECK(projection_generation=(SELECT epm.active_projection_generation()));

ALTER TABLE epm.line_detail_current RENAME TO line_detail_projection;
ALTER TABLE epm.line_detail_projection ADD COLUMN projection_generation bigint NOT NULL DEFAULT 0 CHECK(projection_generation>=0);
ALTER TABLE epm.line_detail_projection DROP CONSTRAINT line_detail_current_pkey;
ALTER TABLE epm.line_detail_projection ADD PRIMARY KEY(workspace_id,application_id,projection_generation,coordinate_id);
-- A restrictive policy combines with existing scope policies; they cannot OR
-- their way around inactive-generation protection. No caller GUC authorizes it.
CREATE POLICY projection_active_generation ON epm.line_detail_projection AS RESTRICTIVE TO epm_runtime,epm_analyst
    USING(projection_generation=(SELECT epm.active_projection_generation()))
    WITH CHECK(projection_generation=(SELECT epm.active_projection_generation()));

ALTER TABLE epm.generic_fact_current RENAME TO generic_fact_projection;
ALTER TABLE epm.generic_fact_projection ADD COLUMN projection_generation bigint NOT NULL DEFAULT 0 CHECK(projection_generation>=0);
ALTER TABLE epm.generic_fact_projection DROP CONSTRAINT generic_fact_current_pkey;
ALTER TABLE epm.generic_fact_projection ADD PRIMARY KEY(workspace_id,application_id,projection_generation,table_id,series_key);
-- A restrictive policy combines with existing scope policies; they cannot OR
-- their way around inactive-generation protection. No caller GUC authorizes it.
CREATE POLICY projection_active_generation ON epm.generic_fact_projection AS RESTRICTIVE TO epm_runtime,epm_analyst
    USING(projection_generation=(SELECT epm.active_projection_generation()))
    WITH CHECK(projection_generation=(SELECT epm.active_projection_generation()));

ALTER TABLE epm.coordinate_member RENAME TO coordinate_member_projection;
ALTER TABLE epm.coordinate_member_projection ADD COLUMN projection_generation bigint NOT NULL DEFAULT 0 CHECK(projection_generation>=0);
ALTER TABLE epm.coordinate_member_projection DROP CONSTRAINT coordinate_member_pkey;
ALTER TABLE epm.coordinate_member_projection ADD PRIMARY KEY(workspace_id,application_id,projection_generation,coordinate_id,dimension_id);
-- A restrictive policy combines with existing scope policies; they cannot OR
-- their way around inactive-generation protection. No caller GUC authorizes it.
CREATE POLICY projection_active_generation ON epm.coordinate_member_projection AS RESTRICTIVE TO epm_runtime,epm_analyst
    USING(projection_generation=(SELECT epm.active_projection_generation()))
    WITH CHECK(projection_generation=(SELECT epm.active_projection_generation()));

ALTER TABLE epm.coordinate_projection RENAME TO coordinate_projection_state;
ALTER TABLE epm.coordinate_projection_state ADD COLUMN projection_generation bigint NOT NULL DEFAULT 0 CHECK(projection_generation>=0);
ALTER TABLE epm.coordinate_projection_state DROP CONSTRAINT coordinate_projection_pkey;
ALTER TABLE epm.coordinate_projection_state ADD PRIMARY KEY(workspace_id,application_id,projection_generation,coordinate_id);
-- A restrictive policy combines with existing scope policies; they cannot OR
-- their way around inactive-generation protection. No caller GUC authorizes it.
CREATE POLICY projection_active_generation ON epm.coordinate_projection_state AS RESTRICTIVE TO epm_runtime,epm_analyst
    USING(projection_generation=(SELECT epm.active_projection_generation()))
    WITH CHECK(projection_generation=(SELECT epm.active_projection_generation()));

DO $$ DECLARE item record; columns_sql text; BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('numeric_cell_current','numeric_cell_projection'),
        ('text_cell_current','text_cell_projection'),
        ('line_detail_current','line_detail_projection'),
        ('generic_fact_current','generic_fact_projection'),
        ('coordinate_member','coordinate_member_projection'),
        ('coordinate_projection','coordinate_projection_state')
    ) AS names(logical_name,physical_name) LOOP
        SELECT string_agg(format('p.%I',attname),',' ORDER BY attnum) INTO columns_sql
          FROM pg_attribute WHERE attrelid=format('epm.%I',item.physical_name)::regclass
            AND attnum>0 AND NOT attisdropped AND attname<>'projection_generation';
        EXECUTE format('CREATE VIEW epm.%I WITH(security_invoker=true,security_barrier=true) AS
            SELECT %s FROM epm.%I p JOIN epm.application_state s USING(workspace_id,application_id)
            WHERE p.projection_generation=s.active_projection_generation',item.logical_name,columns_sql,item.physical_name);
        EXECUTE format('GRANT SELECT ON epm.%I TO epm_runtime,epm_analyst',item.logical_name);
    END LOOP;
END $$;
-- Existing supporting-detail transactions lock their current numeric/detail
-- rows after fencing application state. PostgreSQL requires UPDATE privilege
-- on a view for SELECT FOR UPDATE, even though this join view cannot be a DML
-- target. A single column privilege permits row locking without a write route.
GRANT UPDATE(workspace_id) ON epm.numeric_cell_current,epm.text_cell_current,epm.line_detail_current TO epm_runtime;
-- Keep indexed filtering selective as retained generations accumulate.
DROP INDEX epm.coordinate_member_lookup;
CREATE INDEX coordinate_member_lookup ON epm.coordinate_member_projection
    (workspace_id,application_id,projection_generation,dimension_id,member_id,coordinate_id);
DROP INDEX epm.coordinate_projection_entity;
CREATE INDEX coordinate_projection_entity ON epm.coordinate_projection_state
    (workspace_id,application_id,projection_generation,fact_table_id,schema_epoch,entity_member,coordinate_id);
DROP INDEX epm.coordinate_projection_account;
CREATE INDEX coordinate_projection_account ON epm.coordinate_projection_state
    (workspace_id,application_id,projection_generation,fact_table_id,schema_epoch,account_member,coordinate_id);
DROP INDEX epm.coordinate_projection_scenario;
CREATE INDEX coordinate_projection_scenario ON epm.coordinate_projection_state
    (workspace_id,application_id,projection_generation,fact_table_id,schema_epoch,scenario_member,coordinate_id);
DROP INDEX epm.coordinate_projection_year;
CREATE INDEX coordinate_projection_year ON epm.coordinate_projection_state
    (workspace_id,application_id,projection_generation,fact_table_id,schema_epoch,year_member,coordinate_id);
DROP INDEX epm.coordinate_projection_period;
CREATE INDEX coordinate_projection_period ON epm.coordinate_projection_state
    (workspace_id,application_id,projection_generation,fact_table_id,schema_epoch,period_member,coordinate_id);
DROP INDEX epm.coordinate_projection_value;
CREATE INDEX coordinate_projection_value ON epm.coordinate_projection_state
    (workspace_id,application_id,projection_generation,fact_table_id,schema_epoch,value_member,coordinate_id);
DROP INDEX epm.coordinate_projection_view;
CREATE INDEX coordinate_projection_view ON epm.coordinate_projection_state
    (workspace_id,application_id,projection_generation,fact_table_id,schema_epoch,view_member,coordinate_id);
DROP INDEX epm.coordinate_projection_icp;
CREATE INDEX coordinate_projection_icp ON epm.coordinate_projection_state
    (workspace_id,application_id,projection_generation,fact_table_id,schema_epoch,icp_member,coordinate_id);
DROP INDEX epm.coordinate_projection_data_type;
CREATE INDEX coordinate_projection_data_type ON epm.coordinate_projection_state
    (workspace_id,application_id,projection_generation,fact_table_id,schema_epoch,data_type_member,coordinate_id);

-- Rebind fact_projection_matches to the generation-backed storage while preserving its public contract.
CREATE OR REPLACE FUNCTION epm.fact_projection_matches() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF TG_TABLE_NAME='numeric_cell_projection' THEN
        IF EXISTS(SELECT 1 FROM fact_projected c LEFT JOIN LATERAL(
            SELECT * FROM epm.numeric_fact_event e WHERE e.workspace_id=c.workspace_id AND e.application_id=c.application_id
              AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)e ON true
            LEFT JOIN epm.operation_receipt r ON r.workspace_id=e.workspace_id AND r.application_id=e.application_id AND r.operation_id=e.operation_id
            WHERE e.event_id IS NULL OR (coalesce(r.sealed,true) AND NOT epm.fact_reconstruction_allowed(c.workspace_id,c.application_id)) OR ROW(c.present,c.amount,c.change_id,c.last_revision)
              IS DISTINCT FROM ROW(e.present,e.resulting_amount,e.change_id,e.committed_revision)) THEN
            RAISE EXCEPTION 'FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
        END IF;
    ELSIF TG_TABLE_NAME='text_cell_projection' THEN
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

-- Rebind reject_locked_fact_write to the generation-backed storage while preserving its public contract.
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
        AND NOT (TG_TABLE_NAME IN ('numeric_cell_projection','text_cell_projection','line_detail_projection')
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
        AND NOT (TG_TABLE_NAME IN ('numeric_cell_projection','text_cell_projection','line_detail_projection')
            AND epm.fact_reconstruction_allowed(point.workspace_id,point.application_id))
            LIMIT 1) THEN
            RAISE EXCEPTION 'PLANNING_SLICE_LOCKED'
                USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;

-- Rebind generic_fact_projection_check to the generation-backed storage while preserving its public contract.
CREATE OR REPLACE FUNCTION epm.generic_fact_projection_check(w text,a text,t text,k text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE e epm.generic_fact_event%ROWTYPE; c record;
BEGIN
    PERFORM epm.fact_scope_check(w,a);
    SELECT * INTO e FROM epm.generic_fact_event WHERE workspace_id=w AND application_id=a
      AND table_id=t AND series_key=k ORDER BY committed_revision DESC LIMIT 1;
    SELECT * INTO c FROM epm.generic_fact_current WHERE workspace_id=w AND application_id=a
      AND table_id=t AND series_key=k;
    IF (e.event_id IS NULL AND c.series_key IS NOT NULL)
       OR (e.action='Delete' AND c.series_key IS NOT NULL)
       OR (e.action<>'Delete' AND (c.series_key IS NULL OR
           ROW(c.value,c.change_id,c.last_revision) IS DISTINCT FROM
           ROW(e.after_value,e.resulting_change_id,e.committed_revision))) THEN
        RAISE EXCEPTION 'GENERIC_FACT_PROJECTION_INCONSISTENT' USING ERRCODE='23514';
    END IF;
END $$;

-- Rebind generic_fact_projection_complete to the generation-backed storage while preserving its public contract.
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

-- Rebind coordinate_projection_build to the generation-backed storage while preserving its public contract.
CREATE OR REPLACE FUNCTION epm.coordinate_projection_build(w text,a text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
BEGIN
    PERFORM 1 FROM epm.application_state WHERE workspace_id=w AND application_id=a FOR UPDATE;
    IF EXISTS(SELECT 1 FROM epm.coordinate c JOIN epm.application_state s USING(workspace_id,application_id)
        JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch)
        WHERE c.workspace_id=w AND c.application_id=a
        AND ARRAY(SELECT key FROM jsonb_object_keys(c.members) keys(key) ORDER BY key COLLATE "C")<>l.dimensions) THEN
        RAISE EXCEPTION 'COORDINATE_LAYOUT_GRAIN_MISMATCH' USING ERRCODE='23514';
    END IF;
    INSERT INTO epm.coordinate_projection_state(projection_generation,workspace_id,application_id,coordinate_id,schema_epoch,
        entity_member,account_member,scenario_member,year_member,period_member,value_member,view_member,icp_member,data_type_member,custom_members)
    SELECT s.active_projection_generation,c.workspace_id,c.application_id,c.coordinate_id,l.schema_epoch,
        c.members->>(l.role_dimensions->>'Entity'),c.members->>(l.role_dimensions->>'Account'),
        c.members->>(l.role_dimensions->>'Scenario'),c.members->>(l.role_dimensions->>'Year'),
        c.members->>(l.role_dimensions->>'Period'),c.members->>(l.role_dimensions->>'Value'),
        c.members->>(l.role_dimensions->>'View'),c.members->>(l.role_dimensions->>'ICP'),c.members->>(l.role_dimensions->>'DataType'),
        ARRAY(SELECT c.members->>axis FROM unnest(l.custom_dimensions) WITH ORDINALITY axes(axis,position) ORDER BY position)
    FROM epm.coordinate c JOIN epm.application_state s USING(workspace_id,application_id)
    JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch)
    WHERE c.workspace_id=w AND c.application_id=a
    ON CONFLICT(workspace_id,application_id,projection_generation,coordinate_id) DO UPDATE SET
        schema_epoch=excluded.schema_epoch,entity_member=excluded.entity_member,account_member=excluded.account_member,
        scenario_member=excluded.scenario_member,year_member=excluded.year_member,period_member=excluded.period_member,
        value_member=excluded.value_member,view_member=excluded.view_member,icp_member=excluded.icp_member,
        data_type_member=excluded.data_type_member,custom_members=excluded.custom_members;
END $$;

-- Rebind coordinate_project_inserted to the generation-backed storage while preserving its public contract.
CREATE OR REPLACE FUNCTION epm.coordinate_project_inserted() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
BEGIN
    PERFORM 1 FROM epm.application_state s
        JOIN (SELECT DISTINCT workspace_id,application_id FROM coordinate_inserted) c USING(workspace_id,application_id)
        ORDER BY s.workspace_id,s.application_id FOR UPDATE OF s;
    IF EXISTS(SELECT 1 FROM coordinate_inserted c JOIN epm.application_state s USING(workspace_id,application_id)
        JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch)
        WHERE ARRAY(SELECT key FROM jsonb_object_keys(c.members) keys(key) ORDER BY key COLLATE "C")<>l.dimensions) THEN
        RAISE EXCEPTION 'COORDINATE_LAYOUT_GRAIN_MISMATCH' USING ERRCODE='23514';
    END IF;
    INSERT INTO epm.coordinate_projection_state(projection_generation,workspace_id,application_id,coordinate_id,schema_epoch,
        entity_member,account_member,scenario_member,year_member,period_member,value_member,view_member,icp_member,data_type_member,custom_members)
    SELECT s.active_projection_generation,c.workspace_id,c.application_id,c.coordinate_id,l.schema_epoch,
        c.members->>(l.role_dimensions->>'Entity'),c.members->>(l.role_dimensions->>'Account'),
        c.members->>(l.role_dimensions->>'Scenario'),c.members->>(l.role_dimensions->>'Year'),
        c.members->>(l.role_dimensions->>'Period'),c.members->>(l.role_dimensions->>'Value'),
        c.members->>(l.role_dimensions->>'View'),c.members->>(l.role_dimensions->>'ICP'),c.members->>(l.role_dimensions->>'DataType'),
        ARRAY(SELECT c.members->>axis FROM unnest(l.custom_dimensions) WITH ORDINALITY axes(axis,position) ORDER BY position)
    FROM coordinate_inserted c JOIN epm.application_state s USING(workspace_id,application_id)
    JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch);
    RETURN NULL;
END $$;

-- Rebind fact_projections_rebuild to the generation-backed storage while preserving its public contract.
CREATE OR REPLACE FUNCTION epm.fact_projections_rebuild(w text,a text,jid text,claimant_name text,generation integer)
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
    INSERT INTO epm.coordinate_member_projection(projection_generation,workspace_id,application_id,coordinate_id,dimension_id,member_id)
    SELECT (SELECT active_projection_generation FROM epm.application_state WHERE workspace_id=w AND application_id=a),w,a,c.coordinate_id,pair.key,pair.value FROM epm.coordinate c
    CROSS JOIN LATERAL jsonb_each_text(c.members) pair
    WHERE c.workspace_id=w AND c.application_id=a
    ON CONFLICT(workspace_id,application_id,projection_generation,coordinate_id,dimension_id) DO UPDATE SET member_id=excluded.member_id;
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('coordinateMemberRows',affected);
    DELETE FROM epm.coordinate_member_projection m USING epm.coordinate c
    WHERE m.workspace_id=w AND m.application_id=a AND m.projection_generation=(SELECT active_projection_generation FROM epm.application_state WHERE workspace_id=w AND application_id=a) AND c.workspace_id=w AND c.application_id=a
      AND m.coordinate_id=c.coordinate_id AND (c.members->>m.dimension_id) IS DISTINCT FROM m.member_id;
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('coordinateMemberRemoved',affected);

    -- Current tables are derived, not sources. Preserve original event IDs,
    -- committed revisions and cleared numeric/text CAS tombstones.
    INSERT INTO epm.numeric_cell_projection(projection_generation,workspace_id,application_id,coordinate_id,present,amount,change_id,last_revision)
    SELECT DISTINCT ON(coordinate_id) (SELECT active_projection_generation FROM epm.application_state WHERE workspace_id=w AND application_id=a),w,a,coordinate_id,present,resulting_amount,change_id,committed_revision
    FROM epm.numeric_fact_event WHERE workspace_id=w AND application_id=a
    ORDER BY coordinate_id,committed_revision DESC,line_ordinal DESC
    ON CONFLICT(workspace_id,application_id,projection_generation,coordinate_id) DO UPDATE SET
        present=excluded.present,amount=excluded.amount,change_id=excluded.change_id,last_revision=excluded.last_revision;
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('numericRows',affected);
    DELETE FROM epm.numeric_cell_projection c WHERE c.workspace_id=w AND c.application_id=a AND c.projection_generation=(SELECT active_projection_generation FROM epm.application_state WHERE workspace_id=w AND application_id=a)
      AND NOT EXISTS(SELECT 1 FROM epm.numeric_fact_event e WHERE e.workspace_id=w AND e.application_id=a
          AND e.coordinate_id=c.coordinate_id);
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('numericRemoved',affected);

    INSERT INTO epm.text_cell_projection(projection_generation,workspace_id,application_id,coordinate_id,present,text_value,change_id,last_revision)
    SELECT DISTINCT ON(coordinate_id) (SELECT active_projection_generation FROM epm.application_state WHERE workspace_id=w AND application_id=a),w,a,coordinate_id,present,resulting_value,change_id,committed_revision
    FROM epm.text_fact_event WHERE workspace_id=w AND application_id=a
    ORDER BY coordinate_id,committed_revision DESC,line_ordinal DESC
    ON CONFLICT(workspace_id,application_id,projection_generation,coordinate_id) DO UPDATE SET
        present=excluded.present,text_value=excluded.text_value,change_id=excluded.change_id,last_revision=excluded.last_revision;
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('textRows',affected);
    DELETE FROM epm.text_cell_projection c WHERE c.workspace_id=w AND c.application_id=a AND c.projection_generation=(SELECT active_projection_generation FROM epm.application_state WHERE workspace_id=w AND application_id=a)
      AND NOT EXISTS(SELECT 1 FROM epm.text_fact_event e WHERE e.workspace_id=w AND e.application_id=a
          AND e.coordinate_id=c.coordinate_id);
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('textRemoved',affected);

    WITH latest AS(SELECT DISTINCT ON(coordinate_id) * FROM epm.line_detail_event
        WHERE workspace_id=w AND application_id=a ORDER BY coordinate_id,committed_revision DESC)
    INSERT INTO epm.line_detail_projection(projection_generation,workspace_id,application_id,coordinate_id,items,total,change_id,last_revision)
    SELECT (SELECT active_projection_generation FROM epm.application_state WHERE workspace_id=w AND application_id=a),w,a,coordinate_id,items,total,change_id,committed_revision FROM latest WHERE present
    ON CONFLICT(workspace_id,application_id,projection_generation,coordinate_id) DO UPDATE SET
        items=excluded.items,total=excluded.total,change_id=excluded.change_id,last_revision=excluded.last_revision;
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('detailRows',affected);
    DELETE FROM epm.line_detail_projection c WHERE c.workspace_id=w AND c.application_id=a AND c.projection_generation=(SELECT active_projection_generation FROM epm.application_state WHERE workspace_id=w AND application_id=a)
      AND NOT EXISTS(SELECT 1 FROM (SELECT present FROM epm.line_detail_event e
          WHERE e.workspace_id=w AND e.application_id=a AND e.coordinate_id=c.coordinate_id
          ORDER BY committed_revision DESC LIMIT 1)latest WHERE present);
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('detailRemoved',affected);

    WITH latest AS(SELECT DISTINCT ON(table_id,series_key) * FROM epm.generic_fact_event
        WHERE workspace_id=w AND application_id=a ORDER BY table_id,series_key,committed_revision DESC)
    INSERT INTO epm.generic_fact_projection(projection_generation,workspace_id,application_id,table_id,series_key,value,change_id,last_revision,updated_at)
    SELECT (SELECT active_projection_generation FROM epm.application_state WHERE workspace_id=w AND application_id=a),w,a,table_id,series_key,after_value,resulting_change_id,committed_revision,created_at
    FROM latest WHERE action<>'Delete'
    ON CONFLICT(workspace_id,application_id,projection_generation,table_id,series_key) DO UPDATE SET
        value=excluded.value,change_id=excluded.change_id,last_revision=excluded.last_revision,updated_at=excluded.updated_at;
    GET DIAGNOSTICS affected=ROW_COUNT; counts:=counts||jsonb_build_object('genericRows',affected);
    DELETE FROM epm.generic_fact_projection c WHERE c.workspace_id=w AND c.application_id=a AND c.projection_generation=(SELECT active_projection_generation FROM epm.application_state WHERE workspace_id=w AND application_id=a)
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

-- Rebind delete_workspace_reset_owner_only to the generation-backed storage while preserving its public contract.
CREATE OR REPLACE FUNCTION epm.delete_workspace_reset_owner_only(
    p_workspace_id text, p_operation_id text, p_manifest_digest text,
    p_schema_fingerprint text, p_actor_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog AS $$
DECLARE
    v_prior epm.workspace_reset_receipt%ROWTYPE;
    v_status text;
    v_table text;
    v_physical text;
    v_deleted bigint;
    v_counts jsonb := '{}'::jsonb;
    v_apps jsonb;
    v_result jsonb;
BEGIN
    IF p_workspace_id IS NULL OR p_workspace_id = '' OR
       p_workspace_id <> current_setting('epm.workspace_id',true) OR
       p_operation_id IS NULL OR
       p_operation_id !~ '^[A-Za-z0-9._-]{8,128}$' OR
       p_manifest_digest IS NULL OR
       p_manifest_digest !~ '^[0-9a-f]{64}$' OR
       p_schema_fingerprint IS NULL OR
       p_schema_fingerprint <> '10802758c8fc28a6074e2f7bccaec4c7d825a29ebba8ddcc18da49d94577c979' OR
       p_actor_digest IS NULL OR
       p_actor_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'RESET_DELETE_ARGUMENTS_INVALID';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'RESET_REQUIRES_READ_COMMITTED';
    END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended('epm.security.workspace:' || p_workspace_id,0));
    SELECT * INTO v_prior FROM epm.workspace_reset_receipt
        WHERE target_workspace_id=p_workspace_id
        AND operation_id=p_operation_id;
    IF FOUND THEN
        IF v_prior.manifest_digest<>p_manifest_digest OR
           v_prior.schema_fingerprint<>p_schema_fingerprint OR
           v_prior.actor_digest<>p_actor_digest THEN
            RAISE EXCEPTION 'IDEMPOTENCY_KEY_REUSED';
        END IF;
        RETURN v_prior.result;
    END IF;
    SELECT status INTO v_status FROM epm.workspace
        WHERE workspace_id=p_workspace_id FOR UPDATE;
    IF v_status IS DISTINCT FROM 'Maintenance' THEN
        RAISE EXCEPTION 'WORKSPACE_NOT_IN_MAINTENANCE';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.job WHERE workspace_id=p_workspace_id
        AND status IN ('accepted','ready','running','staged',
                       'cancel_requested','needs_inspection')) THEN
        RAISE EXCEPTION 'UNSETTLED_OR_INSPECTION_JOBS';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.expression_rule_sequence
        WHERE workspace_id=p_workspace_id
          AND status IN ('accepted','running','cancel_requested')) THEN
        RAISE EXCEPTION 'UNSETTLED_RULE_SEQUENCES';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.full_aggregate_sequence
        WHERE workspace_id=p_workspace_id
          AND status IN ('accepted','running','cancel_requested')) THEN
        RAISE EXCEPTION 'UNSETTLED_FULL_SEQUENCES';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.source_batch
        WHERE workspace_id=p_workspace_id
        AND status IN ('staging','ready')) THEN
        RAISE EXCEPTION 'UNPUBLISHED_SOURCE_BATCHES';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.job j
        JOIN epm.operation_receipt r
          ON r.workspace_id=j.workspace_id
         AND r.application_id=j.application_id
         AND r.operation_id=j.job_id
        WHERE j.workspace_id=p_workspace_id
        AND j.status<>'published') THEN
        RAISE EXCEPTION 'JOB_RECEIPT_REQUIRES_INSPECTION';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.source_batch b
        JOIN epm.operation_receipt r
          ON r.workspace_id=b.workspace_id
         AND r.application_id=b.application_id
         AND r.operation_id=b.batch_id
        WHERE b.workspace_id=p_workspace_id
        AND b.status<>'published') THEN
        RAISE EXCEPTION 'SOURCE_BATCH_RECEIPT_REQUIRES_INSPECTION';
    END IF;
    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),
                    '[]'::jsonb) INTO v_apps
        FROM epm.application WHERE workspace_id=p_workspace_id;

    -- The order is pinned to the reviewed 0074 FK graph. All names are
    -- constants; callers cannot supply a table or SQL fragment.
    -- Self-referential journal FKs are removed by table-wide DELETE statements.
    FOREACH v_table IN ARRAY ARRAY[
        'coordinate_projection','coordinate_layout',
        'generic_fact_event','generic_fact_current',
        'rollup_source_lineage','ownership_value_event',
        'ownership_value_current','allocation_basis_lineage','relationship',
        'planning_submission_event','manual_journal_line',
        'hierarchy_closure','hierarchy_active','expression_rule_publication','coordinate_member',
        'calendar_period_event','calendar_period_current',
        'ic_elimination_line','ic_elimination_publication',
        'calculation_result','calculation_publication',
        'text_fact_event','text_cell_current','source_batch_row',
        'source_batch_chunk','semantic_column','policy_pack_draft',
        'acquisition_journal_line','acquisition_journal',
        'policy_activation_current','policy_activation_event',
        'policy_acquisition_approval','policy_acquisition_case_review',
        'policy_acquisition_case_bundle','policy_source_artifact',
        'planning_submission','planning_lock_event','planning_copy_origin',
        'numeric_fact_event','numeric_cell_current','member',
        'manual_journal','line_detail_event','line_detail_current',
        'job_event','job_dependency','hierarchy_version',
        'ic_elimination_withdrawal','ic_elimination_generation',
        'calculation_generation','source_batch','planning_slice_lock',
        'expression_rule_version','operation_receipt','job_event_cursor','job','generic_fact_table','expression_rule_sequence',
        'full_aggregate_sequence','dimension',
        'coordinate','rule_access_grant','application_state',
        'application_access_grant','workspace_lifecycle_receipt',
        'workspace_access_grant','security_operation_receipt',
        'application','worker_workspace_dispatch','workspace']
    LOOP
        v_physical := CASE v_table WHEN 'numeric_cell_current' THEN 'numeric_cell_projection' WHEN 'text_cell_current' THEN 'text_cell_projection' WHEN 'line_detail_current' THEN 'line_detail_projection' WHEN 'generic_fact_current' THEN 'generic_fact_projection' WHEN 'coordinate_member' THEN 'coordinate_member_projection' WHEN 'coordinate_projection' THEN 'coordinate_projection_state' ELSE v_table END;
        EXECUTE format('DELETE FROM epm.%I WHERE workspace_id=$1',v_physical)
            USING p_workspace_id;
        GET DIAGNOSTICS v_deleted = ROW_COUNT;
        v_counts := v_counts || jsonb_build_object(v_table,v_deleted);
    END LOOP;

    v_result := jsonb_build_object(
        'workspaceId',p_workspace_id,
        'operationId',p_operation_id,
        'status','Deleted',
        'manifestDigest',p_manifest_digest,
        'schemaFingerprint',p_schema_fingerprint,
        'applicationIds',v_apps,
        'deletedCounts',v_counts);
    INSERT INTO epm.workspace_reset_receipt
        (target_workspace_id,operation_id,manifest_digest,
         schema_fingerprint,actor_digest,result)
        VALUES (p_workspace_id,p_operation_id,p_manifest_digest,
                p_schema_fingerprint,p_actor_digest,v_result);
    INSERT INTO epm.security_audit
        (actor_id,action,workspace_id,target_digest,outcome,detail)
        VALUES (p_actor_digest,'workspace.reset.apply',p_workspace_id,
                p_manifest_digest,'Accepted',
                jsonb_build_object('operationId',p_operation_id,
                                   'schemaFingerprint',p_schema_fingerprint,
                                   'applicationIds',v_apps,
                                   'deletedCounts',v_counts));
    RETURN v_result;
END $$;
