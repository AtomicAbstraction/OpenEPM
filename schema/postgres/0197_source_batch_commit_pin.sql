-- New source batches retain the immutable-history boundary corresponding to
-- their authored data revision.  Historical rows remain nullable and retain
-- their stricter global data-revision publication rule.

ALTER TABLE epm.source_batch
    ADD COLUMN expected_commit_revision bigint,
    ADD CONSTRAINT source_batch_expected_commit_revision_check
        CHECK (expected_commit_revision IS NULL
               OR expected_commit_revision >= 0);
