BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=370) THEN
    RAISE EXCEPTION 'MIGRATION_0371_REQUIRES_0370';
  END IF;
END $migration$;

-- Decode only the compact expiry carried by the fixed server's oa1 identity.
-- HMAC authentication remains application-core responsibility; this decoder
-- exists solely to derive deterministic retention from an already admitted ID.
CREATE FUNCTION epm.operation_admission_expiry(p_operation_id text)
RETURNS timestamptz LANGUAGE plpgsql IMMUTABLE STRICT
SET search_path=pg_catalog AS $$
DECLARE encoded text; alphabet constant text:='0123456789abcdefghijklmnopqrstuvwxyz';
DECLARE position integer; digit integer; seconds numeric:=0;
BEGIN
  IF p_operation_id!~'^oa1_[0-9a-z]{1,13}_[0-9a-f]{32}_[A-Za-z0-9_-]{43}$' THEN
    RETURN NULL;
  END IF;
  encoded:=split_part(p_operation_id,'_',2);
  FOR position IN 1..length(encoded) LOOP
    digit:=strpos(alphabet,substr(encoded,position,1))-1;
    IF digit<0 THEN RETURN NULL; END IF;
    seconds:=seconds*36+digit;
    IF seconds>253402300799 THEN RETURN NULL; END IF;
  END LOOP;
  RETURN to_timestamp(seconds::double precision);
END $$;
REVOKE ALL ON FUNCTION epm.operation_admission_expiry(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.operation_admission_expiry(text) TO epm_runtime;

ALTER TABLE epm.operation_receipt
  ADD COLUMN replay_expires_at timestamptz;

CREATE FUNCTION epm.operation_receipt_retention_set() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE admitted_until timestamptz;
BEGIN
  admitted_until:=epm.operation_admission_expiry(NEW.operation_id);
  IF left(NEW.operation_id,4)='oa1_' AND admitted_until IS NULL THEN
    RAISE EXCEPTION 'SIGNED_OPERATION_ID_INVALID' USING ERRCODE='23514';
  END IF;
  NEW.replay_expires_at:=CASE WHEN admitted_until IS NULL THEN NULL
    ELSE admitted_until+interval '24 hours' END;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.operation_receipt_retention_set() FROM PUBLIC;

CREATE TRIGGER a0_operation_receipt_retention
BEFORE INSERT OR UPDATE OF operation_id ON epm.operation_receipt
FOR EACH ROW EXECUTE FUNCTION epm.operation_receipt_retention_set();

UPDATE epm.operation_receipt
SET replay_expires_at=epm.operation_admission_expiry(operation_id)+interval '24 hours'
WHERE epm.operation_admission_expiry(operation_id) IS NOT NULL;

ALTER TABLE epm.operation_receipt ADD CONSTRAINT operation_receipt_retention_exact
CHECK ((left(operation_id,4)<>'oa1_' AND replay_expires_at IS NULL)
    OR (left(operation_id,4)='oa1_' AND replay_expires_at=
        epm.operation_admission_expiry(operation_id)+interval '24 hours'));

CREATE INDEX operation_receipt_replay_expiry
ON epm.operation_receipt(replay_expires_at,workspace_id,application_id,operation_id)
WHERE replay_expires_at IS NOT NULL AND sealed;

-- Cleanup is lifecycle-owned, bounded and deterministic.  Raw membership is
-- a redundant transaction-time reconciliation index, not lasting provenance;
-- business events and operation_commit_provenance deliberately remain.
CREATE FUNCTION epm.cleanup_expired_operation_receipts(
  p_before timestamptz,p_limit integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record; removed integer:=0;
BEGIN
  IF NOT pg_has_role(session_user,'epm_lifecycle','member') THEN
    RAISE EXCEPTION 'OPERATION_RECEIPT_CLEANUP_LIFECYCLE_REQUIRED';
  END IF;
  IF p_before IS NULL OR p_limit IS NULL OR p_limit<1 OR p_limit>10000 THEN
    RAISE EXCEPTION 'OPERATION_RECEIPT_CLEANUP_ARGUMENT_INVALID'
      USING ERRCODE='22023';
  END IF;
  FOR candidate IN
    SELECT workspace_id,application_id,operation_id
    FROM epm.operation_receipt
    WHERE replay_expires_at IS NOT NULL AND replay_expires_at<=p_before
      AND sealed AND left(operation_id,4)='oa1_'
    ORDER BY replay_expires_at,workspace_id,application_id,operation_id
    FOR UPDATE SKIP LOCKED LIMIT p_limit
  LOOP
    DELETE FROM epm.raw_operation_membership
    WHERE workspace_id=candidate.workspace_id
      AND application_id=candidate.application_id
      AND operation_id=candidate.operation_id;
    DELETE FROM epm.operation_receipt
    WHERE workspace_id=candidate.workspace_id
      AND application_id=candidate.application_id
      AND operation_id=candidate.operation_id
      AND replay_expires_at<=p_before AND sealed;
    IF FOUND THEN removed:=removed+1; END IF;
  END LOOP;
  RETURN removed;
END $$;
REVOKE ALL ON FUNCTION epm.cleanup_expired_operation_receipts(timestamptz,integer)
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_access,epm_security,epm_provision;
GRANT EXECUTE ON FUNCTION epm.cleanup_expired_operation_receipts(timestamptz,integer)
  TO epm_lifecycle;

COMMIT;
SELECT '0371 applied' AS migration;
