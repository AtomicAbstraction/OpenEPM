-- Preserve the exact relationship placement selected by a bounded planning
-- rollup. Parent/child snapshots retain historical interpretation if the
-- active relationship is later deactivated; legacy unique-member rows remain
-- null and retain their existing hierarchy-version lineage.

ALTER TABLE epm.rollup_source_lineage
    ADD COLUMN placement_relationship_id text,
    ADD COLUMN placement_parent_member_id text,
    ADD COLUMN placement_child_member_id text;

ALTER TABLE epm.rollup_source_lineage
    ADD CONSTRAINT rollup_source_placement_shape CHECK (
        (placement_relationship_id IS NULL
         AND placement_parent_member_id IS NULL
         AND placement_child_member_id IS NULL)
        OR
        (source_selection='hierarchy'
         AND placement_relationship_id IS NOT NULL
         AND placement_parent_member_id IS NOT NULL
         AND placement_child_member_id IS NOT NULL)),
    ADD CONSTRAINT rollup_source_placement_relationship_fk FOREIGN KEY
        (workspace_id,application_id,placement_relationship_id)
        REFERENCES epm.relationship
        (workspace_id,application_id,relationship_id)
        ON DELETE RESTRICT;

CREATE INDEX rollup_source_placement ON epm.rollup_source_lineage
    (workspace_id,application_id,placement_relationship_id,generation_id)
    WHERE placement_relationship_id IS NOT NULL;
