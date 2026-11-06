-- Committed hierarchy versions are complete and sealed; cursor/member-set pins
-- must not change through a later runtime INSERT into their closure rows.
ALTER TABLE epm.hierarchy_version ADD COLUMN sealed boolean NOT NULL DEFAULT true;
ALTER TABLE epm.hierarchy_version ALTER COLUMN sealed SET DEFAULT false;

CREATE FUNCTION epm.hierarchy_publication_complete(w text,a text,d text,v bigint) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,epm AS $$
    SELECT EXISTS(SELECT 1 FROM epm.hierarchy_version h
      JOIN epm.application_state s USING(workspace_id,application_id)
      JOIN epm.operation_receipt r ON r.workspace_id=h.workspace_id
        AND r.application_id=h.application_id AND r.operation_id=h.operation_id
      WHERE h.workspace_id=w AND h.application_id=a AND h.dimension_id=d AND h.version=v
        AND h.metadata_revision=s.metadata_revision AND r.result->>'kind'='hierarchy.build'
        AND (r.result->>'version')::bigint=h.version
        AND (r.result->>'closureCount')::bigint=(SELECT count(*) FROM epm.hierarchy_closure c
          WHERE c.workspace_id=w AND c.application_id=a AND c.dimension_id=d AND c.version=v))
$$;
-- Historical versions may have older metadata; validate their original receipt
-- and completeness without requiring them to match the current metadata head.
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM epm.hierarchy_version h LEFT JOIN epm.operation_receipt r
       ON r.workspace_id=h.workspace_id AND r.application_id=h.application_id AND r.operation_id=h.operation_id
       WHERE r.operation_id IS NULL OR r.result->>'kind' IS DISTINCT FROM 'hierarchy.build'
       OR (r.result->>'version')::bigint IS DISTINCT FROM h.version
       OR (r.result->>'closureCount')::bigint IS DISTINCT FROM (SELECT count(*) FROM epm.hierarchy_closure c
         WHERE c.workspace_id=h.workspace_id AND c.application_id=h.application_id
           AND c.dimension_id=h.dimension_id AND c.version=h.version)) THEN
        RAISE EXCEPTION 'HIERARCHY_LEGACY_VERSION_INCOMPLETE' USING ERRCODE='23514';
    END IF;
END $$;

CREATE FUNCTION epm.hierarchy_version_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF TG_OP='INSERT' THEN NEW.sealed=false; RETURN NEW; END IF;
    IF OLD.sealed OR NOT NEW.sealed OR
       (to_jsonb(NEW)-'sealed') IS DISTINCT FROM (to_jsonb(OLD)-'sealed') THEN
        RAISE EXCEPTION 'HIERARCHY_VERSION_SEALED' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM epm.hierarchy_active p WHERE p.workspace_id=NEW.workspace_id
        AND p.application_id=NEW.application_id AND p.dimension_id=NEW.dimension_id AND p.version=NEW.version)
       OR NOT epm.hierarchy_publication_complete(NEW.workspace_id,NEW.application_id,NEW.dimension_id,NEW.version) THEN
        RAISE EXCEPTION 'HIERARCHY_VERSION_UNPUBLISHED' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER hierarchy_version_guard BEFORE INSERT OR UPDATE ON epm.hierarchy_version
    FOR EACH ROW EXECUTE FUNCTION epm.hierarchy_version_guard();

CREATE FUNCTION epm.hierarchy_closure_open() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM hierarchy_inserted i JOIN epm.hierarchy_version h
        USING(workspace_id,application_id,dimension_id,version) WHERE h.sealed) THEN
        RAISE EXCEPTION 'HIERARCHY_VERSION_SEALED' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER hierarchy_closure_open AFTER INSERT ON epm.hierarchy_closure
    REFERENCING NEW TABLE AS hierarchy_inserted FOR EACH STATEMENT EXECUTE FUNCTION epm.hierarchy_closure_open();

CREATE FUNCTION epm.hierarchy_activate_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE published boolean;
BEGIN
    SELECT sealed INTO published FROM epm.hierarchy_version WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id AND dimension_id=NEW.dimension_id AND version=NEW.version;
    IF published IS NULL OR NOT epm.hierarchy_publication_complete(NEW.workspace_id,NEW.application_id,NEW.dimension_id,NEW.version) THEN
        RAISE EXCEPTION 'HIERARCHY_VERSION_INCOMPLETE' USING ERRCODE='23514';
    END IF;
    IF published AND (TG_OP='INSERT' OR OLD.version<>NEW.version) THEN
        RAISE EXCEPTION 'HIERARCHY_VERSION_SEALED' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER hierarchy_activate_complete BEFORE INSERT OR UPDATE ON epm.hierarchy_active
    FOR EACH ROW EXECUTE FUNCTION epm.hierarchy_activate_complete();

CREATE FUNCTION epm.hierarchy_seal_active() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    UPDATE epm.hierarchy_version SET sealed=true WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id AND dimension_id=NEW.dimension_id AND version=NEW.version AND NOT sealed;
    RETURN NULL;
END $$;
CREATE TRIGGER hierarchy_seal_active AFTER INSERT OR UPDATE ON epm.hierarchy_active
    FOR EACH ROW EXECUTE FUNCTION epm.hierarchy_seal_active();

CREATE FUNCTION epm.hierarchy_version_must_seal() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM epm.hierarchy_version h WHERE h.workspace_id=NEW.workspace_id
      AND h.application_id=NEW.application_id AND h.dimension_id=NEW.dimension_id AND h.version=NEW.version AND NOT h.sealed) THEN
        RAISE EXCEPTION 'HIERARCHY_VERSION_UNPUBLISHED' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER hierarchy_version_must_seal AFTER INSERT ON epm.hierarchy_version
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION epm.hierarchy_version_must_seal();

REVOKE ALL ON FUNCTION epm.hierarchy_publication_complete(text,text,text,bigint),
    epm.hierarchy_version_guard(),epm.hierarchy_closure_open(),epm.hierarchy_activate_complete(),
    epm.hierarchy_seal_active(),epm.hierarchy_version_must_seal() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.hierarchy_publication_complete(text,text,text,bigint),
    epm.hierarchy_version_guard(),epm.hierarchy_closure_open(),epm.hierarchy_activate_complete(),
    epm.hierarchy_seal_active(),epm.hierarchy_version_must_seal() TO epm_runtime;
-- Only false->true with a complete current active publication is allowed by
-- the header guard. This column grant cannot unseal or edit version metadata.
GRANT UPDATE(sealed) ON epm.hierarchy_version TO epm_runtime;
