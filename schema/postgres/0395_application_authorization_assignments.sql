-- Stage scope-qualified assignments without changing any existing application's
-- active evaluator. The cutover must use a reviewed application transition.
DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=394) THEN
        RAISE EXCEPTION 'MIGRATION_0395_REQUIRES_0394';
    END IF;
END $migration$;

ALTER TABLE epm.application ADD COLUMN authorization_model text NOT NULL
    DEFAULT 'legacy' CHECK (authorization_model IN ('legacy','group_assignments'));

CREATE TABLE epm.application_authorization_role (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    role_id text NOT NULL CHECK (role_id ~ '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$'),
    role_name text NOT NULL CHECK (length(btrim(role_name)) BETWEEN 1 AND 160),
    revision bigint NOT NULL CHECK (revision > 0),
    actions text[] NOT NULL CHECK (array_ndims(actions)=1 AND
        cardinality(actions) BETWEEN 1 AND 256 AND array_position(actions,NULL) IS NULL),
    PRIMARY KEY (workspace_id,application_id,role_id),
    FOREIGN KEY (workspace_id,application_id) REFERENCES epm.application ON DELETE CASCADE
);

CREATE TABLE epm.application_authorization_scope (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    scope_id text NOT NULL CHECK (scope_id ~ '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$'),
    scope_name text NOT NULL CHECK (length(btrim(scope_name)) BETWEEN 1 AND 160),
    revision bigint NOT NULL CHECK (revision > 0),
    scope_kind text NOT NULL,
    selector jsonb NOT NULL CHECK (jsonb_typeof(selector)='object'),
    CHECK (CASE scope_kind
        WHEN 'entire_application' THEN selector='{}'::jsonb
        WHEN 'dimension_tags' THEN selector<>'{}'::jsonb
            AND epm.valid_dimensional_security_tag_map(selector)
        WHEN 'exact_object' THEN selector ?& ARRAY['objectType','objectId']
            AND selector - 'objectType' - 'objectId'='{}'::jsonb
            AND jsonb_typeof(selector->'objectType')='string'
            AND jsonb_typeof(selector->'objectId')='string'
            AND length(selector->>'objectType') BETWEEN 1 AND 100
            AND length(selector->>'objectId') BETWEEN 1 AND 300
        ELSE false END),
    PRIMARY KEY (workspace_id,application_id,scope_id),
    FOREIGN KEY (workspace_id,application_id) REFERENCES epm.application ON DELETE CASCADE
);

CREATE TABLE epm.application_authorization_assignment (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    assignment_id text NOT NULL CHECK (assignment_id ~ '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$'),
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300),
    group_id text NOT NULL CHECK (epm.valid_authorization_group_id(group_id)),
    role_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    PRIMARY KEY (workspace_id,application_id,assignment_id),
    FOREIGN KEY (workspace_id,application_id,role_id)
        REFERENCES epm.application_authorization_role ON DELETE CASCADE
);
CREATE INDEX application_authorization_group_lookup ON epm.application_authorization_assignment
    (issuer,group_id,workspace_id,application_id);

CREATE TABLE epm.application_authorization_assignment_scope (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    assignment_id text NOT NULL,
    action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.-]{1,126}$'),
    scope_id text NOT NULL,
    PRIMARY KEY (workspace_id,application_id,assignment_id,action,scope_id),
    FOREIGN KEY (workspace_id,application_id,assignment_id)
        REFERENCES epm.application_authorization_assignment ON DELETE CASCADE,
    FOREIGN KEY (workspace_id,application_id,scope_id)
        REFERENCES epm.application_authorization_scope ON DELETE CASCADE
);
CREATE INDEX application_authorization_scope_usage ON epm.application_authorization_assignment_scope
    (workspace_id,application_id,scope_id);

-- Role revocation removes an action from this relation even when an old
-- assignment still references it. Never aggregate privileges across axes.
CREATE VIEW epm.application_authorization_privilege WITH (security_invoker=true) AS
SELECT a.workspace_id,a.application_id,a.issuer,a.group_id,a.assignment_id,
       a.revision AS assignment_revision,r.role_id,r.role_name,r.revision AS role_revision,
       b.action,s.scope_id,s.scope_name,s.revision AS scope_revision,s.scope_kind,s.selector
FROM epm.application_authorization_assignment a
JOIN epm.application_authorization_role r USING (workspace_id,application_id,role_id)
JOIN epm.application_authorization_assignment_scope b USING (workspace_id,application_id,assignment_id)
JOIN epm.application_authorization_scope s USING (workspace_id,application_id,scope_id)
WHERE b.action=ANY(r.actions);

DO $policies$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['application_authorization_role',
        'application_authorization_scope','application_authorization_assignment',
        'application_authorization_assignment_scope']
    LOOP
        EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',table_name);
        EXECUTE format('CREATE POLICY scoped_read ON epm.%I FOR SELECT
            TO epm_runtime,epm_security,epm_worker USING (
            workspace_id=current_setting(''epm.workspace_id'',true)
            AND application_id=current_setting(''epm.application_id'',true))',table_name);
        EXECUTE format('CREATE POLICY router_read ON epm.%I FOR SELECT
            TO epm_access USING (true)',table_name);
        EXECUTE format('CREATE POLICY scoped_management ON epm.%I FOR ALL TO epm_security
            USING (workspace_id=current_setting(''epm.workspace_id'',true)
                AND application_id=current_setting(''epm.application_id'',true))
            WITH CHECK (workspace_id=current_setting(''epm.workspace_id'',true)
                AND application_id=current_setting(''epm.application_id'',true))',table_name);
        EXECUTE format('REVOKE ALL ON epm.%I FROM PUBLIC',table_name);
        EXECUTE format('GRANT SELECT ON epm.%I TO epm_runtime,epm_access,epm_security,epm_worker',table_name);
        EXECUTE format('GRANT INSERT,UPDATE,DELETE ON epm.%I TO epm_security',table_name);
    END LOOP;
END $policies$;
REVOKE ALL ON epm.application_authorization_privilege FROM PUBLIC;
GRANT SELECT ON epm.application_authorization_privilege TO epm_runtime,epm_access,epm_security,epm_worker;
