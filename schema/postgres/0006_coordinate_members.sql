-- Typed coordinate membership makes each fact point refer to scoped members.
-- The fixed core also checks that the coordinate spans every active dimension.

CREATE TABLE epm.coordinate_member (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    coordinate_id bigint NOT NULL,
    dimension_id text NOT NULL,
    member_id text NOT NULL,
    PRIMARY KEY (workspace_id, application_id, coordinate_id, dimension_id),
    FOREIGN KEY (workspace_id, application_id, coordinate_id)
        REFERENCES epm.coordinate(workspace_id, application_id, coordinate_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id, application_id, dimension_id, member_id)
        REFERENCES epm.member(workspace_id, application_id, dimension_id, member_id)
        ON DELETE RESTRICT
);
CREATE INDEX coordinate_member_lookup
    ON epm.coordinate_member(workspace_id, application_id,
                             dimension_id, member_id, coordinate_id);

GRANT SELECT ON epm.coordinate_member TO epm_runtime, epm_analyst;
GRANT INSERT ON epm.coordinate_member TO epm_runtime;
ALTER TABLE epm.coordinate_member ENABLE ROW LEVEL SECURITY;
CREATE POLICY coordinate_member_scope ON epm.coordinate_member
    TO epm_runtime, epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
