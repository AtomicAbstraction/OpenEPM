-- Deterministic server-side coordinate keys and provenance for numeric
-- scenario copy preparation. Publication uses the fixed source-batch path.

CREATE FUNCTION epm.coordinate_series_key(members jsonb)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
    SELECT encode(sha256(convert_to('[' || string_agg(
        '[' || to_json(axis)::text || ',' || to_json(member)::text || ']',
        ',' ORDER BY axis COLLATE "C") || ']', 'UTF8')), 'hex')
    FROM jsonb_each_text(members) AS item(axis,member)
$$;
REVOKE ALL ON FUNCTION epm.coordinate_series_key(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.coordinate_series_key(jsonb) TO epm_runtime;

CREATE TABLE epm.planning_copy_origin (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    batch_id text NOT NULL,
    normalized_program jsonb NOT NULL
        CHECK (jsonb_typeof(normalized_program)='object'),
    source_data_revision bigint NOT NULL CHECK (source_data_revision>=0),
    source_row_count bigint NOT NULL CHECK (source_row_count BETWEEN 0 AND 100000),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,batch_id),
    FOREIGN KEY (workspace_id,application_id,batch_id)
        REFERENCES epm.source_batch(workspace_id,application_id,batch_id)
        ON DELETE RESTRICT
);
GRANT SELECT,INSERT ON epm.planning_copy_origin TO epm_runtime;
ALTER TABLE epm.planning_copy_origin ENABLE ROW LEVEL SECURITY;
CREATE POLICY planning_copy_origin_scope ON epm.planning_copy_origin
    TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
