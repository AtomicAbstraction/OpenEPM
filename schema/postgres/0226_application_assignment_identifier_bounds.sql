-- PostgreSQL's regular-expression repetition ceiling is lower than the
-- assignment contract's 300-character identifier bound.  Preserve the exact
-- public contract with an explicit length check and an unbounded character
-- class instead of silently narrowing accepted identifiers.

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=225) THEN
    RAISE EXCEPTION 'MIGRATION_0226_PREDECESSOR_0225_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.application_assignment_version
  DROP CONSTRAINT application_assignment_version_assignment_set_id_check,
  ADD CONSTRAINT application_assignment_version_assignment_set_id_check
    CHECK(length(assignment_set_id) BETWEEN 1 AND 300
      AND assignment_set_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$');

ALTER TABLE epm.application_assignment_state
  DROP CONSTRAINT application_assignment_state_assignment_set_id_check,
  ADD CONSTRAINT application_assignment_state_assignment_set_id_check
    CHECK(length(assignment_set_id) BETWEEN 1 AND 300
      AND assignment_set_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$');
