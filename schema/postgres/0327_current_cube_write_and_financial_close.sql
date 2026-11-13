BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=326) THEN
    RAISE EXCEPTION 'MIGRATION_0327_REQUIRES_0326';
  END IF;
END $migration$;

-- Locks, submissions and financial closes are current state machines.  Their
-- event rows retain accounting/audit chronology, while mutable currentness is
-- fenced by an opaque token rather than a user-visible numeric version.
DROP TRIGGER cube_write_scope_lock_transition ON epm.cube_write_scope_lock;
DROP TRIGGER cube_write_scope_submission_transition
  ON epm.cube_write_scope_submission;
DROP TRIGGER financial_period_close_transition ON epm.financial_period_close;

ALTER TABLE epm.cube_write_scope_lock ADD COLUMN state_token text;
ALTER TABLE epm.cube_write_scope_submission ADD COLUMN state_token text;
ALTER TABLE epm.financial_period_close ADD COLUMN state_token text;

UPDATE epm.cube_write_scope_lock SET state_token=encode(pg_catalog.sha256(
  convert_to(concat_ws(chr(31),'cube-write-lock',workspace_id,application_id,
    lock_id,version::text,clock_timestamp()::text,random()::text),'UTF8')),'hex');
UPDATE epm.cube_write_scope_submission SET state_token=encode(pg_catalog.sha256(
  convert_to(concat_ws(chr(31),'cube-write-submission',workspace_id,
    application_id,lock_id,version::text,clock_timestamp()::text,
    random()::text),'UTF8')),'hex');
UPDATE epm.financial_period_close SET state_token=encode(pg_catalog.sha256(
  convert_to(concat_ws(chr(31),'financial-close',workspace_id,application_id,
    close_id,version::text,clock_timestamp()::text,random()::text),'UTF8')),'hex');

DO $migration$ DECLARE relation_name text;constraint_row record;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY['cube_write_scope_lock',
    'cube_write_scope_submission','financial_period_close'] LOOP
    FOR constraint_row IN SELECT conname FROM pg_constraint
      WHERE conrelid=('epm.'||relation_name)::regclass
        AND pg_get_constraintdef(oid) ~ 'version'
    LOOP
      EXECUTE format('ALTER TABLE epm.%I DROP CONSTRAINT %I',
                     relation_name,constraint_row.conname);
    END LOOP;
  END LOOP;
END $migration$;

ALTER TABLE epm.cube_write_scope_lock
  ALTER COLUMN state_token SET NOT NULL,
  DROP COLUMN version,
  ADD CONSTRAINT cube_write_scope_lock_state_token_check
    CHECK(state_token~'^[0-9a-f]{64}$'),
  ADD CONSTRAINT cube_write_scope_lock_state_token_unique
    UNIQUE(workspace_id,application_id,state_token),
  ADD CONSTRAINT cube_write_scope_lock_current_status_check
    CHECK((status='Locked')=(reopened_revision IS NULL));
ALTER TABLE epm.cube_write_scope_submission
  ALTER COLUMN state_token SET NOT NULL,
  DROP COLUMN version,
  ADD CONSTRAINT cube_write_scope_submission_state_token_check
    CHECK(state_token~'^[0-9a-f]{64}$'),
  ADD CONSTRAINT cube_write_scope_submission_state_token_unique
    UNIQUE(workspace_id,application_id,state_token),
  ADD CONSTRAINT cube_write_scope_submission_current_status_check CHECK(
    (status='Submitted' AND approved_revision IS NULL AND reopened_revision IS NULL)
    OR (status='Approved' AND approved_revision>submitted_revision
        AND reopened_revision IS NULL)
    OR (status='Reopened' AND reopened_revision>submitted_revision
        AND (approved_revision IS NULL OR reopened_revision>approved_revision)));
ALTER TABLE epm.financial_period_close
  ALTER COLUMN state_token SET NOT NULL,
  DROP COLUMN version,
  ADD CONSTRAINT financial_period_close_state_token_check
    CHECK(state_token~'^[0-9a-f]{64}$'),
  ADD CONSTRAINT financial_period_close_state_token_unique
    UNIQUE(workspace_id,application_id,state_token),
  ADD CONSTRAINT financial_period_close_current_status_check CHECK(
    (status='Closed' AND reopen_issuer IS NULL AND reopen_subject_id IS NULL
      AND reopen_reason IS NULL AND reopened_revision IS NULL)
    OR (status='Reopened' AND reopen_issuer IS NOT NULL
      AND reopen_subject_id IS NOT NULL AND reopen_reason IS NOT NULL
      AND reopened_revision>closed_revision));

CREATE OR REPLACE FUNCTION epm.validate_cube_write_scope_lock_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.status<>'Locked' OR NEW.reopened_revision IS NOT NULL THEN
      RAISE EXCEPTION 'PLANNING_LOCK_INITIAL_STATE_INVALID';
    END IF;
  ELSIF OLD.status<>'Locked' OR NEW.status<>'Open'
      OR NEW.state_token=OLD.state_token OR NEW.reopened_revision IS NULL
      OR NEW.reopened_revision<=OLD.locked_revision THEN
    RAISE EXCEPTION 'PLANNING_LOCK_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END $function$;
CREATE TRIGGER cube_write_scope_lock_transition BEFORE INSERT OR UPDATE
  ON epm.cube_write_scope_lock FOR EACH ROW
  EXECUTE FUNCTION epm.validate_cube_write_scope_lock_transition();

CREATE OR REPLACE FUNCTION epm.validate_cube_write_scope_submission_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.status<>'Submitted' THEN
      RAISE EXCEPTION 'PLANNING_SUBMISSION_INITIAL_STATE_INVALID';
    END IF;
  ELSIF NEW.state_token=OLD.state_token OR NOT (
      (OLD.status='Submitted' AND NEW.status='Approved'
        AND NEW.approved_revision IS NOT NULL)
      OR (OLD.status IN('Submitted','Approved') AND NEW.status='Reopened'
        AND NEW.reopened_revision IS NOT NULL)) THEN
    RAISE EXCEPTION 'PLANNING_SUBMISSION_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END $function$;
CREATE TRIGGER cube_write_scope_submission_transition BEFORE INSERT OR UPDATE
  ON epm.cube_write_scope_submission FOR EACH ROW
  EXECUTE FUNCTION epm.validate_cube_write_scope_submission_transition();

CREATE OR REPLACE FUNCTION epm.validate_financial_period_close_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.status<>'Closed' OR NEW.reopened_revision IS NOT NULL THEN
      RAISE EXCEPTION 'FINANCIAL_CLOSE_INITIAL_STATE_INVALID';
    END IF;
  ELSIF OLD.status<>'Closed' OR NEW.status<>'Reopened'
      OR NEW.state_token=OLD.state_token OR NEW.reopened_revision IS NULL
      OR NEW.reopened_revision<=OLD.closed_revision THEN
    RAISE EXCEPTION 'FINANCIAL_CLOSE_TRANSITION_INVALID';
  END IF;
  RETURN NEW;
END $function$;
CREATE TRIGGER financial_period_close_transition BEFORE INSERT OR UPDATE
  ON epm.financial_period_close FOR EACH ROW
  EXECUTE FUNCTION epm.validate_financial_period_close_transition();

GRANT UPDATE(state_token) ON epm.cube_write_scope_lock,
  epm.cube_write_scope_submission,epm.financial_period_close TO epm_runtime;

-- Retained idempotency receipts remain replayable but no longer disclose the
-- retired numeric state locators.
ALTER TABLE epm.operation_receipt DISABLE TRIGGER USER;
UPDATE epm.operation_receipt SET result=(result-'version'-'lockVersion'
  -'submissionVersion'-'expectedVersion')
WHERE result ?| ARRAY['version','lockVersion','submissionVersion',
                      'expectedVersion'];
ALTER TABLE epm.operation_receipt ENABLE TRIGGER USER;

COMMIT;
