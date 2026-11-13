-- The populated-layout trigger refreshes layout history after dimension
-- deletion.  Owner reset must therefore remove coordinates first, allow that
-- trigger to rebuild its transient current layout, and remove every layout
-- immediately afterwards.  No FK, trigger, or ordinary history rule changes.
DO $$
DECLARE
    definition text;
    revised text;
    early_pair text := $pattern$'coordinate_projection','coordinate_layout',$pattern$;
    old_tail text := $pattern$'full_aggregate_sequence','dimension',
        'coordinate','rule_access_grant','application_state',$pattern$;
    new_tail text := $pattern$'full_aggregate_sequence','coordinate','dimension',
        'coordinate_layout','rule_access_grant','application_state',$pattern$;
BEGIN
    SELECT pg_get_functiondef(
        'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
      INTO definition;
    IF position(early_pair IN definition)=0
       OR position(old_tail IN definition)=0
       OR position(new_tail IN definition)>0 THEN
        RAISE EXCEPTION 'RESET_0127_DEFINITION_MISMATCH';
    END IF;
    revised := replace(definition,early_pair,$pattern$'coordinate_projection',$pattern$);
    revised := replace(revised,old_tail,new_tail);
    IF revised=definition
       OR position(early_pair IN revised)>0
       OR position(old_tail IN revised)>0
       OR position(new_tail IN revised)=0 THEN
        RAISE EXCEPTION 'RESET_0127_DEFINITION_MISMATCH';
    END IF;
    EXECUTE revised;
END $$;
