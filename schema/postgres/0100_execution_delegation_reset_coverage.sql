-- Forward-only replacement of the reviewed owner reset primitive.  Preserve
-- the complete 0092 body while making two exact, fail-closed substitutions:
-- the reviewed schema fingerprint and the FK-safe delegation deletion order.
DO $$
DECLARE
 v_old text := '9d50597e7cf94398036460386fd50b636183348da5c405e49a4545824b62015d';
 v_new text := '0d2a3c4cac9b49c4b4585163d628dbc8604050f5cee8ca73d3cf7579710d7430';
 v_before text := '''expression_rule_version'',''raw_operation_membership'',''operation_receipt''';
 v_after text := '''expression_rule_version'',''raw_operation_membership'',''execution_delegation_state'',''execution_delegation_version'',''operation_receipt''';
 v_definition text;
 v_replaced text;
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO v_definition;
 IF length(v_definition)-length(replace(v_definition,v_old,''))<>length(v_old)
 OR length(v_definition)-length(replace(v_definition,v_before,''))<>length(v_before)
 THEN RAISE EXCEPTION 'RESET_0092_DEFINITION_MISMATCH'; END IF;
 v_replaced := replace(replace(v_definition,v_old,v_new),v_before,v_after);
 IF v_replaced=v_definition THEN RAISE EXCEPTION 'RESET_0100_REPLACEMENT_FAILED'; END IF;
 EXECUTE v_replaced;
END $$;

-- The replaced constant-name loop deletes and counts state before immutable
-- versions and both before their owning operation receipts.
