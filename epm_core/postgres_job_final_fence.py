"""Shared final publication fence for fixed durable job publishers."""
from psycopg.types.json import Jsonb


def finish_published_job(db, scope, claim, *, revision, result):
    """Publish only while the exact DB-clock lease and claim still own the job.

    Callers invoke this as their final statement in the same transaction as
    generation, result, pointer, state and receipt effects.  A zero row count
    raises so the transaction rolls every prior effect back atomically.
    """
    completed = db.execute('''UPDATE epm.job SET status='published',
        receipt_revision=%s,result=%s,claimant=NULL,lease_until=NULL,
        updated_at=transaction_timestamp()
        WHERE workspace_id=%s AND application_id=%s AND job_id=%s
        AND status='running' AND claim_generation=%s AND claimant=%s
        AND lease_until>clock_timestamp()''',
        (revision, Jsonb(result), scope.workspace_id, scope.application_id,
         claim['job_id'], claim['claim_generation'],
         claim['claimant'])).rowcount
    if completed != 1:
        raise ValueError('STALE_WORKER_FINAL_FENCE')

