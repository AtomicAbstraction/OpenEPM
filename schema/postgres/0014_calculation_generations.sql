-- Immutable set-based calculation output and atomic publication pointer.
-- Numeric input facts remain a separate authoritative source layer.

CREATE FUNCTION epm.round_half_even(value numeric, places integer)
RETURNS numeric LANGUAGE plpgsql IMMUTABLE STRICT
SET search_path=pg_catalog AS $$
DECLARE scale numeric;
DECLARE shifted numeric;
DECLARE base numeric;
DECLARE remainder numeric;
BEGIN
    IF places < 0 OR places > 12 THEN
        RAISE EXCEPTION 'ROUNDING_SCALE_UNSUPPORTED';
    END IF;
    scale := power(10::numeric, places);
    shifted := abs(value) * scale;
    base := trunc(shifted);
    remainder := shifted - base;
    IF remainder > 0.5 OR (remainder = 0.5 AND mod(base,2) <> 0) THEN
        base := base + 1;
    END IF;
    RETURN sign(value) * base / scale;
END $$;
REVOKE ALL ON FUNCTION epm.round_half_even(numeric,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.round_half_even(numeric,integer) TO epm_runtime;

CREATE TABLE epm.calculation_generation (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    generation_id text NOT NULL CHECK (generation_id ~ '^[0-9a-f]{32}$'),
    job_id text NOT NULL,
    result_key text NOT NULL
        CHECK (result_key ~ '^[A-Za-z0-9._-]{8,128}$'),
    source_commit_revision bigint NOT NULL CHECK (source_commit_revision >= 0),
    source_metadata_revision bigint NOT NULL CHECK (source_metadata_revision >= 0),
    source_policy_revision bigint NOT NULL CHECK (source_policy_revision >= 0),
    factor numeric(20,12) NOT NULL,
    row_count integer NOT NULL CHECK (row_count BETWEEN 0 AND 500),
    published_revision bigint NOT NULL CHECK (published_revision > 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,generation_id),
    UNIQUE (workspace_id,application_id,job_id),
    FOREIGN KEY (workspace_id,application_id,job_id)
        REFERENCES epm.job(workspace_id,application_id,job_id)
        ON DELETE RESTRICT
);

CREATE TABLE epm.calculation_result (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    generation_id text NOT NULL,
    coordinate_id bigint NOT NULL,
    source_amount numeric(28,8) NOT NULL,
    source_change_id text NOT NULL,
    amount numeric(28,8) NOT NULL,
    PRIMARY KEY (workspace_id,application_id,generation_id,coordinate_id),
    FOREIGN KEY (workspace_id,application_id,generation_id)
        REFERENCES epm.calculation_generation
        (workspace_id,application_id,generation_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,coordinate_id)
        REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
        ON DELETE RESTRICT
);
CREATE INDEX calculation_result_coordinate ON epm.calculation_result
    (workspace_id,application_id,coordinate_id,generation_id);

CREATE TABLE epm.calculation_publication (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    result_key text NOT NULL
        CHECK (result_key ~ '^[A-Za-z0-9._-]{8,128}$'),
    generation_id text NOT NULL,
    published_revision bigint NOT NULL CHECK (published_revision > 0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,result_key),
    FOREIGN KEY (workspace_id,application_id,generation_id)
        REFERENCES epm.calculation_generation
        (workspace_id,application_id,generation_id)
        ON DELETE RESTRICT
);

GRANT SELECT,INSERT ON epm.calculation_generation,
    epm.calculation_result TO epm_runtime;
GRANT SELECT,INSERT,UPDATE ON epm.calculation_publication TO epm_runtime;
ALTER TABLE epm.calculation_generation ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.calculation_result ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.calculation_publication ENABLE ROW LEVEL SECURITY;
CREATE POLICY calculation_generation_scope ON epm.calculation_generation
    TO epm_runtime USING
    (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true))
    WITH CHECK
    (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true));
CREATE POLICY calculation_result_scope ON epm.calculation_result
    TO epm_runtime USING
    (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true))
    WITH CHECK
    (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true));
CREATE POLICY calculation_publication_scope ON epm.calculation_publication
    TO epm_runtime USING
    (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true))
    WITH CHECK
    (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true));
