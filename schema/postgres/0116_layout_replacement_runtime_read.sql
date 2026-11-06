-- Public replacement status may reveal only a scoped bounded staged count.
-- Runtime intentionally retains no direct access to private staged mappings.
CREATE FUNCTION epm.layout_replacement_staged_count(
    p_workspace text,p_application text,p_request text)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $$
DECLARE v_generation text;
DECLARE v_expected integer;
DECLARE v_count bigint;
BEGIN
    IF p_workspace IS DISTINCT FROM current_setting('epm.workspace_id',true)
       OR p_application IS DISTINCT FROM current_setting(
           'epm.application_id',true) THEN
        RAISE EXCEPTION 'LAYOUT_REPLACEMENT_SCOPE_INVALID'
            USING ERRCODE='42501';
    END IF;
    SELECT r.target_generation_id,r.expected_coordinate_count
      INTO v_generation,v_expected
      FROM epm.layout_replacement_request r
     WHERE r.workspace_id=p_workspace AND r.application_id=p_application
       AND r.request_id=p_request;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT count(*) INTO v_count
      FROM epm.layout_replacement_staged_coordinate c
     WHERE c.workspace_id=p_workspace AND c.application_id=p_application
       AND c.generation_id=v_generation;
    IF v_count>v_expected OR v_count>100000 THEN
        RAISE EXCEPTION 'LAYOUT_REPLACEMENT_STAGED_COUNT_INVALID';
    END IF;
    RETURN v_count::integer;
END $$;

REVOKE ALL ON FUNCTION epm.layout_replacement_staged_count(
    text,text,text) FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_staged_count(
    text,text,text) TO epm_runtime;

-- Fixed-core validation needs the exact immutable mapping, but never an
-- unscoped table capability.  Bind it to the accepted request generation and
-- reject incomplete/oversized private stages before returning any row.
CREATE FUNCTION epm.layout_replacement_staged_mapping(
    p_workspace text,p_application text,p_request text)
RETURNS TABLE(source_coordinate_id bigint,target_members jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
ROWS 100000
AS $$
DECLARE v_generation text;
DECLARE v_expected integer;
DECLARE v_count bigint;
BEGIN
    IF p_workspace IS DISTINCT FROM current_setting('epm.workspace_id',true)
       OR p_application IS DISTINCT FROM current_setting(
           'epm.application_id',true) THEN
        RAISE EXCEPTION 'LAYOUT_REPLACEMENT_SCOPE_INVALID'
            USING ERRCODE='42501';
    END IF;
    SELECT r.target_generation_id,r.expected_coordinate_count
      INTO v_generation,v_expected
      FROM epm.layout_replacement_request r
     WHERE r.workspace_id=p_workspace AND r.application_id=p_application
       AND r.request_id=p_request;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT count(*) INTO v_count
      FROM epm.layout_replacement_staged_coordinate c
     WHERE c.workspace_id=p_workspace AND c.application_id=p_application
       AND c.generation_id=v_generation;
    IF v_count<>v_expected OR v_count>100000 THEN
        RAISE EXCEPTION 'LAYOUT_REPLACEMENT_STAGED_MAPPING_INVALID';
    END IF;
    RETURN QUERY
    SELECT c.source_coordinate_id,c.target_members
      FROM epm.layout_replacement_staged_coordinate c
     WHERE c.workspace_id=p_workspace AND c.application_id=p_application
       AND c.generation_id=v_generation
     ORDER BY c.source_coordinate_id;
END $$;

REVOKE ALL ON FUNCTION epm.layout_replacement_staged_mapping(
    text,text,text) FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_staged_mapping(
    text,text,text) TO epm_runtime;
