-- Generic application metadata. No finance-specific dimension is mandatory.
-- All references carry both application keys; public IDs remain text.

CREATE TABLE epm.dimension (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    dimension_id text NOT NULL CHECK (length(dimension_id) BETWEEN 1 AND 200),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    short_description text NOT NULL DEFAULT '',
    detailed_description text NOT NULL DEFAULT '',
    semantic_role text NOT NULL DEFAULT 'Context'
        CHECK (semantic_role IN ('Core entity', 'Context')),
    density text NOT NULL DEFAULT 'Sparse'
        CHECK (density IN ('Dense', 'Sparse')),
    model_role text CHECK (model_role IN
        ('Scenario','Year','Period','View','Entity','Value','Account',
         'ICP','Currency','DataType','Custom')),
    status text NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active','Inactive')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id, dimension_id),
    FOREIGN KEY (workspace_id, application_id)
        REFERENCES epm.application_state(workspace_id, application_id)
        ON DELETE RESTRICT
);
CREATE UNIQUE INDEX dimension_name_per_application
    ON epm.dimension(workspace_id, application_id, lower(name));

CREATE TABLE epm.member (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    dimension_id text NOT NULL,
    member_id text NOT NULL CHECK (length(member_id) BETWEEN 1 AND 200),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    short_description text NOT NULL DEFAULT '',
    detailed_description text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active','Inactive')),
    density text NOT NULL DEFAULT 'Sparse'
        CHECK (density IN ('Dense','Sparse')),
    custom_values jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(custom_values) = 'object'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id, dimension_id, member_id),
    UNIQUE (workspace_id, application_id, member_id),
    FOREIGN KEY (workspace_id, application_id, dimension_id)
        REFERENCES epm.dimension(workspace_id, application_id, dimension_id)
        ON DELETE RESTRICT
);
CREATE UNIQUE INDEX member_name_per_dimension
    ON epm.member(workspace_id, application_id, dimension_id, lower(name));

CREATE TABLE epm.relationship (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    relationship_id text NOT NULL CHECK (length(relationship_id) BETWEEN 1 AND 200),
    dimension_id text NOT NULL,
    parent_member_id text NOT NULL,
    child_member_id text NOT NULL,
    semantic_tag text NOT NULL DEFAULT '',
    detailed_description text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active','Inactive')),
    custom_values jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(custom_values) = 'object'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id, relationship_id),
    UNIQUE (workspace_id, application_id, dimension_id,
            parent_member_id, child_member_id),
    FOREIGN KEY (workspace_id, application_id, dimension_id, parent_member_id)
        REFERENCES epm.member(workspace_id, application_id, dimension_id, member_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id, application_id, dimension_id, child_member_id)
        REFERENCES epm.member(workspace_id, application_id, dimension_id, member_id)
        ON DELETE RESTRICT,
    CHECK (parent_member_id <> child_member_id)
);
CREATE INDEX relationship_children
    ON epm.relationship(workspace_id, application_id, dimension_id,
                        parent_member_id, status);

CREATE FUNCTION epm.reject_relationship_cycle() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- Serialize competing edge edits in one application. Without this lock,
    -- opposite edges can both pass a visibility-only cycle check.
    PERFORM 1 FROM epm.application_state
        WHERE workspace_id = NEW.workspace_id
          AND application_id = NEW.application_id FOR UPDATE;
    IF NEW.status = 'Active' AND EXISTS (
        WITH RECURSIVE reachable(member_id) AS (
            SELECT NEW.child_member_id
            UNION
            SELECT r.child_member_id FROM epm.relationship r
            JOIN reachable p ON p.member_id = r.parent_member_id
            WHERE r.workspace_id = NEW.workspace_id
              AND r.application_id = NEW.application_id
              AND r.dimension_id = NEW.dimension_id
              AND r.status = 'Active'
              AND r.relationship_id <> NEW.relationship_id
        )
        SELECT 1 FROM reachable WHERE member_id = NEW.parent_member_id
    ) THEN
        RAISE EXCEPTION 'RELATIONSHIP_CYCLE' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER reject_relationship_cycle
    BEFORE INSERT OR UPDATE
    ON epm.relationship FOR EACH ROW
    EXECUTE FUNCTION epm.reject_relationship_cycle();

CREATE TABLE epm.semantic_column (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    dimension_id text NOT NULL,
    scope text NOT NULL CHECK (scope IN ('Member','Relationship')),
    slot integer NOT NULL CHECK (slot BETWEEN 1 AND 30),
    display_name text NOT NULL DEFAULT '',
    semantic_definition text NOT NULL DEFAULT '',
    population_guidance text NOT NULL DEFAULT '',
    restrictions text NOT NULL DEFAULT '',
    properties jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(properties) = 'object'),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id, dimension_id, scope, slot),
    FOREIGN KEY (workspace_id, application_id, dimension_id)
        REFERENCES epm.dimension(workspace_id, application_id, dimension_id)
        ON DELETE RESTRICT,
    CHECK (scope <> 'Relationship' OR slot <= 20)
);

GRANT SELECT ON epm.dimension, epm.member, epm.relationship,
    epm.semantic_column TO epm_runtime, epm_analyst;
GRANT INSERT, UPDATE, DELETE ON epm.dimension, epm.member,
    epm.relationship, epm.semantic_column TO epm_runtime;
GRANT UPDATE (metadata_revision, commit_revision)
    ON epm.application_state TO epm_runtime;

ALTER TABLE epm.dimension ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.member ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.relationship ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.semantic_column ENABLE ROW LEVEL SECURITY;

CREATE POLICY dimension_scope ON epm.dimension TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY member_scope ON epm.member TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY relationship_scope ON epm.relationship TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY semantic_column_scope ON epm.semantic_column
    TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
