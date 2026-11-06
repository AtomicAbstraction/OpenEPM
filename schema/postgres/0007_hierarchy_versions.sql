-- Versioned, application-scoped hierarchy selection index. Each closure row
-- counts graph paths but does not decide financial aggregation treatment.

CREATE TABLE epm.hierarchy_version (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    dimension_id text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    metadata_revision bigint NOT NULL CHECK (metadata_revision >= 0),
    operation_id text NOT NULL,
    built_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id, dimension_id, version),
    FOREIGN KEY (workspace_id, application_id, dimension_id)
        REFERENCES epm.dimension(workspace_id, application_id, dimension_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id, application_id, operation_id)
        REFERENCES epm.operation_receipt(workspace_id, application_id, operation_id)
        ON DELETE RESTRICT
);

CREATE TABLE epm.hierarchy_closure (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    dimension_id text NOT NULL,
    version bigint NOT NULL,
    ancestor_member_id text NOT NULL,
    descendant_member_id text NOT NULL,
    min_depth integer NOT NULL CHECK (min_depth >= 0),
    path_count bigint NOT NULL CHECK (path_count > 0),
    PRIMARY KEY (workspace_id, application_id, dimension_id, version,
                 ancestor_member_id, descendant_member_id),
    FOREIGN KEY (workspace_id, application_id, dimension_id, version)
        REFERENCES epm.hierarchy_version(
            workspace_id, application_id, dimension_id, version)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id, application_id, dimension_id,
                 ancestor_member_id)
        REFERENCES epm.member(workspace_id, application_id, dimension_id,
                              member_id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id, application_id, dimension_id,
                 descendant_member_id)
        REFERENCES epm.member(workspace_id, application_id, dimension_id,
                              member_id) ON DELETE RESTRICT
);
CREATE INDEX hierarchy_closure_descendant
    ON epm.hierarchy_closure(workspace_id, application_id, dimension_id,
                             version, descendant_member_id,
                             ancestor_member_id);

CREATE TABLE epm.hierarchy_active (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    dimension_id text NOT NULL,
    version bigint NOT NULL,
    activated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id, dimension_id),
    FOREIGN KEY (workspace_id, application_id, dimension_id, version)
        REFERENCES epm.hierarchy_version(
            workspace_id, application_id, dimension_id, version)
        ON DELETE RESTRICT
);

GRANT SELECT ON epm.hierarchy_version, epm.hierarchy_closure,
    epm.hierarchy_active TO epm_runtime, epm_analyst;
GRANT INSERT ON epm.hierarchy_version, epm.hierarchy_closure,
    epm.hierarchy_active TO epm_runtime;
GRANT UPDATE ON epm.hierarchy_active TO epm_runtime;

ALTER TABLE epm.hierarchy_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.hierarchy_closure ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.hierarchy_active ENABLE ROW LEVEL SECURITY;

CREATE POLICY hierarchy_version_scope ON epm.hierarchy_version
    TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY hierarchy_closure_scope ON epm.hierarchy_closure
    TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY hierarchy_active_scope ON epm.hierarchy_active
    TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
