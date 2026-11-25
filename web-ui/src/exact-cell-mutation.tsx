import { useEffect, useRef, useState } from "react";
import {
  ApiError,
  isDefiniteEffectRefusal,
  prepareAdmittedProgramEffect,
  replayAdmittedEffect,
  request,
  type AdmittedEffectPacket,
} from "./api";
import { usePreservedDraft, type DraftRecoveryLease } from "./unsaved-work";
import { ReceiptInspector } from "./ReceiptInspector";
import { transferAction } from "./data-transfer-action";
import type { ApplicationCatalog, Scope } from "./types";

type Program = Record<string, unknown>;
export type MutationPreview = {
  previewToken: string;
  programDigest: string;
  revisionVector: Record<string, number>;
  detail?: {
    coordinate: Record<string, string>;
    replacement: "complete_set";
    itemCount: number;
    present: true;
    total: { type: "AmountLiteral"; decimal: string };
  };
};
type Outcome = {
  jobId: string;
  status: string;
  committedRevision: number | null;
};
type Pending = {
  owner: string;
  packet: AdmittedEffectPacket;
  outcome: Outcome | null;
  uncertain: boolean;
};
type MutationAttempt = {
  context: string;
  phase: "preview" | "submit" | "reconcile" | "inspect";
  controller: AbortController;
};
const states = new Set([
  "accepted",
  "ready",
  "running",
  "staged",
  "published",
  "failed",
  "cancel_requested",
  "cancelled",
  "needs_inspection",
  "stale",
]);
const terminal = (outcome: Outcome | null) =>
  Boolean(
    outcome &&
      (["failed", "cancelled", "stale"].includes(outcome.status) ||
        (outcome.status === "published" && outcome.committedRevision !== null)),
  );

const stalePreviewCodes = new Set([
  "STALE_OR_MISMATCHED_V2_PREVIEW",
  "STALE_METADATA_REVISION",
  "STALE_DATA_REVISION",
  "STALE_POLICY_REVISION",
]);
const draftConflictCodes = new Set([
  ...stalePreviewCodes,
  "STALE_CELL_CHANGE_ID",
  "STALE_DETAIL_CHANGE_ID",
]);
const submissionRefusalCodes = new Set([
  "APPLICATION_GRANT_REQUIRED",
  "APPLICATION_UNAVAILABLE",
  "APPLICATION_NOT_WRITABLE",
  "WORKSPACE_NOT_WRITABLE",
  "APPLICATION_CAPABILITY_DISABLED",
  "PROGRAM_VALIDATION_FAILED",
  "OPERATION_ADMISSION_EXPIRED",
  ...stalePreviewCodes,
]);

export function exactMutationOutcome(
  value: unknown,
  expectedJobId?: string,
  requireReceipt = expectedJobId !== undefined,
): Outcome {
  const row = value as Record<string, unknown> | null;
  const jobId = row?.jobId ?? row?.job_id;
  if (
    !row ||
    typeof jobId !== "string" ||
    !/^[0-9a-f]{32}$/.test(jobId) ||
    (expectedJobId && jobId !== expectedJobId) ||
    typeof row.status !== "string" ||
    !states.has(row.status)
  )
    throw new Error("INVALID_MUTATION_OUTCOME");
  const revision = row.receipt_revision;
  if (
    revision != null &&
    (!Number.isSafeInteger(revision) ||
      Number(revision) < 1 ||
      !["published", "needs_inspection"].includes(row.status))
  )
    throw new Error("INVALID_MUTATION_RECEIPT");
  if (requireReceipt && row.status === "published" && revision == null)
    throw new Error("MUTATION_COMMIT_EVIDENCE_UNAVAILABLE");
  return {
    jobId,
    status: row.status,
    committedRevision:
      row.status === "published" && revision != null ? Number(revision) : null,
  };
}

/** Presentation state only: fixed Python owns preview, replay, policy and effects. */
export function useExactCellMutation(
  scope: Scope | null,
  context: string,
  editor: string,
  program: Program | null,
  owner: string,
) {
  const [review, setReview] = useState<{
    context: string;
    key: string;
    value: MutationPreview;
  } | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [missingSubmission, setMissingSubmission] = useState<{
    context: string;
    operationId: string;
  } | null>(null);
  const [attempt, setAttempt] = useState<MutationAttempt | null>(null);
  const [failure, setFailure] = useState<{
    context: string;
    message: string;
  } | null>(null);
  const activeContext = JSON.stringify([
    scope?.workspaceId,
    scope?.applicationId,
    owner,
    context,
  ]);
  const active = useRef(activeContext);
  active.current = activeContext;
  const inFlight = useRef<MutationAttempt | null>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    const previous = inFlight.current;
    if (previous && previous.context !== activeContext)
      previous.controller.abort();
  }, [activeContext]);
  const phase = attempt?.context === activeContext ? attempt.phase : null;
  const programKey = JSON.stringify(program);
  const activeProgram = useRef(programKey);
  activeProgram.current = programKey;
  const currentReview =
    review?.context === activeContext && review.key === programKey
      ? review.value
      : null;
  const scopeMatches =
    !pending ||
    (pending.owner === owner &&
      pending.packet.body.workspaceId === scope?.workspaceId &&
      pending.packet.body.applicationId === scope?.applicationId);
  const currentPending = scopeMatches ? pending : null;
  const canRetry =
    Boolean(currentPending?.uncertain) &&
    missingSubmission?.context === activeContext &&
    missingSubmission.operationId ===
      currentPending?.packet.body.idempotencyKey;
  const frozen = Boolean(currentPending && !terminal(currentPending.outcome));
  const recovery = usePreservedDraft(
    scope?.workspaceId || "none",
    scope?.applicationId || "none",
    editor,
    "Unresolved exact cell mutation",
    frozen,
    { pending: currentPending },
    (draft) => {
      setPending(draft.pending);
      setReview(null);
    },
  );

  function begin(phase: MutationAttempt["phase"]) {
    const previous = inFlight.current;
    if (
      previous?.context === activeContext &&
      !previous.controller.signal.aborted
    )
      return null;
    previous?.controller.abort();
    const attempt = {
      context: activeContext,
      phase,
      controller: new AbortController(),
    };
    inFlight.current = attempt;
    setAttempt(attempt);
    setFailure(null);
    return attempt;
  }

  function ownsResponse(attempt: MutationAttempt) {
    return (
      active.current === attempt.context &&
      inFlight.current === attempt &&
      !attempt.controller.signal.aborted
    );
  }

  function reportFailure(
    attempt: MutationAttempt,
    reason: unknown,
    fallback: string,
  ) {
    if (mounted.current && ownsResponse(attempt)) {
      const conflict = isDefiniteEffectRefusal(
        reason,
        attempt.phase === "preview" ? draftConflictCodes : stalePreviewCodes,
      );
      setFailure({
        context: attempt.context,
        message:
          conflict &&
          (attempt.phase === "preview" || attempt.phase === "submit")
            ? "This edit needs a fresh preview. Reread the current values and preview the edit again."
            : reason instanceof Error
              ? reason.message
              : fallback,
      });
    }
  }

  function finish(attempt: MutationAttempt) {
    if (inFlight.current !== attempt) return;
    inFlight.current = null;
    if (mounted.current) setAttempt(null);
  }

  async function preview() {
    if (!scope || !program || frozen) return;
    const attempt = begin("preview");
    if (!attempt) return;
    const captured = structuredClone(program);
    setReview(null);
    try {
      const value = await request<MutationPreview>(
        "/api/preview",
        {
          ...scope,
          program: captured,
        },
        attempt.controller.signal,
      );
      if (!mounted.current || !ownsResponse(attempt)) return;
      if (
        typeof value.previewToken !== "string" ||
        value.previewToken.length < 16 ||
        typeof value.programDigest !== "string" ||
        !/^[0-9a-f]{64}$/.test(value.programDigest) ||
        !value.revisionVector ||
        Object.values(value.revisionVector).some(
          (pin) => !Number.isSafeInteger(pin) || pin < 0,
        )
      )
        throw new Error("INVALID_MUTATION_PREVIEW");
      if (captured.function === "facts.line-detail.replace") {
        const args = captured.arguments as {
          coordinate: unknown;
          items: unknown[];
        };
        const detail = value.detail;
        if (
          !detail ||
          detail.replacement !== "complete_set" ||
          detail.present !== true ||
          detail.itemCount !== args.items.length ||
          detail.total?.type !== "AmountLiteral" ||
          typeof detail.total.decimal !== "string" ||
          !/^-?\d+(?:\.\d+)?$/.test(detail.total.decimal) ||
          JSON.stringify(Object.entries(detail.coordinate).sort()) !==
            JSON.stringify(Object.entries(args.coordinate as object).sort())
        )
          throw new Error("INVALID_DETAIL_PREVIEW_EVIDENCE");
      }
      setReview({
        context: attempt.context,
        key: JSON.stringify(captured),
        value,
      });
    } catch (reason) {
      reportFailure(attempt, reason, "Unable to preview mutation");
    } finally {
      finish(attempt);
    }
  }

  async function send(
    packet: AdmittedEffectPacket,
    previouslyUncertain: boolean,
    attempt: MutationAttempt,
    expectedLease: DraftRecoveryLease | null,
  ) {
    const unresolved = { owner, packet, outcome: null, uncertain: true };
    // Reserve the exact packet before dispatch. A capacity or competing-owner
    // failure cannot send an effect whose recovery intent would be lost.
    const lease = recovery.retain({ pending: unresolved }, expectedLease);
    setPending(unresolved);
    try {
      const value = await replayAdmittedEffect<unknown>(
        packet,
        attempt.controller.signal,
      );
      if (!ownsResponse(attempt)) return;
      const outcome = exactMutationOutcome(value);
      const accepted = { owner, packet, outcome, uncertain: false };
      if (terminal(outcome)) recovery.release(lease, { pending: null });
      else recovery.retain({ pending: accepted }, lease);
      if (!mounted.current) return;
      setPending(accepted);
      setReview(null);
    } catch (reason) {
      if (!ownsResponse(attempt)) return;
      if (
        !previouslyUncertain &&
        isDefiniteEffectRefusal(reason, submissionRefusalCodes)
      ) {
        recovery.release(lease, { pending: null });
        if (mounted.current) {
          setPending(null);
          setReview(null);
        }
      }
      reportFailure(attempt, reason, "Mutation outcome unknown");
    }
  }

  async function submit() {
    if (!scope || !program || !currentReview || frozen) return;
    const attempt = begin("submit");
    if (!attempt) return;
    try {
      const packet = await prepareAdmittedProgramEffect(
        "/api/submit",
        {
          ...scope,
          program,
          dependsOnJobIds: [],
          confirmed: true,
          previewToken: currentReview.previewToken,
        },
        `${editor}-${crypto.randomUUID()}`,
        attempt.controller.signal,
      );
      if (
        !mounted.current ||
        !ownsResponse(attempt) ||
        activeProgram.current !== programKey
      )
        return;
      await send(packet, false, attempt, null);
    } catch (reason) {
      reportFailure(attempt, reason, "Unable to admit mutation");
    } finally {
      finish(attempt);
    }
  }

  async function retrySubmission() {
    if (!currentPending?.uncertain || !canRetry) return;
    const attempt = begin("reconcile");
    if (!attempt) return;
    try {
      if (!recovery.lease) throw new Error("DRAFT_RECOVERY_LEASE_REQUIRED");
      await send(currentPending.packet, true, attempt, recovery.lease);
    } catch (reason) {
      reportFailure(attempt, reason, "Unable to retain mutation recovery");
    } finally {
      finish(attempt);
    }
  }

  async function readOutcome() {
    const job = currentPending?.outcome;
    if (!scope || !currentPending || terminal(job || null)) return;
    const attempt = begin("inspect");
    if (!attempt) return;
    const captured = currentPending;
    const operationId = captured.packet.body.idempotencyKey;
    setMissingSubmission(null);
    try {
      if (!recovery.lease) throw new Error("DRAFT_RECOVERY_LEASE_REQUIRED");
      // This read owns a new recovery revision. A prior mounted instance's
      // response cannot replace or settle it while the current read is pending.
      const lease = recovery.retain({ pending: captured }, recovery.lease);
      const result = await request<unknown>(
        "/api/job",
        {
          ...scope,
          ...(job ? { jobId: job.jobId } : { operationId }),
        },
        attempt.controller.signal,
      );
      if (!ownsResponse(attempt)) return;
      const outcome = exactMutationOutcome(result, job?.jobId, true);
      if (terminal(outcome)) recovery.release(lease, { pending: null });
      else
        recovery.retain(
          { pending: { ...captured, outcome, uncertain: false } },
          lease,
        );
      if (mounted.current)
        setPending({ ...captured, outcome, uncertain: false });
    } catch (reason) {
      if (
        !job &&
        reason instanceof ApiError &&
        reason.code === "JOB_UNAVAILABLE"
      ) {
        if (mounted.current && ownsResponse(attempt))
          setMissingSubmission({ context: attempt.context, operationId });
      } else {
        reportFailure(attempt, reason, "Unable to read mutation outcome");
      }
    } finally {
      finish(attempt);
    }
  }
  return {
    review: currentReview,
    pending: currentPending,
    frozen,
    busy: phase !== null,
    phase,
    error: failure?.context === activeContext ? failure.message : "",
    preview,
    submit,
    canRetry,
    retrySubmission,
    readOutcome,
  };
}

function outcomeStatus(
  pending: Pending,
  phase: MutationAttempt["phase"] | null,
  canRetry: boolean,
) {
  if (phase === "submit")
    return "Waiting for acknowledgement of the exact mutation…";
  if (phase === "reconcile") return "Retrying the original submission…";
  if (phase === "inspect") return "Reading current mutation status…";
  if (pending.uncertain)
    return canRetry
      ? "The original submission is still unconfirmed. Check again or retry the exact original request."
      : "Mutation outcome unknown. Check the original status before making a different change.";
  const outcome = pending.outcome;
  if (outcome?.committedRevision != null)
    return `Committed at revision ${outcome.committedRevision}.`;
  if (outcome?.status === "needs_inspection")
    return "This mutation needs inspection. Check the original job and receipt before making another change.";
  if (outcome?.status === "cancel_requested")
    return "Cancellation requested. Check this mutation again for its final status.";
  return `Request status: ${outcome?.status}. This is not a confirmed value change.`;
}

export function ExactMutationOutcome({
  mutation,
  scope,
  catalog,
  refresh,
}: {
  mutation: ReturnType<typeof useExactCellMutation>;
  scope: Scope;
  catalog: ApplicationCatalog | null;
  refresh?: () => void;
}) {
  const [receiptJobId, setReceiptJobId] = useState<string | null>(null);
  const pending = mutation.pending;
  if (!pending) return null;
  const outcome = pending.outcome;
  const committed = outcome?.committedRevision != null;
  const inspection = outcome?.status === "needs_inspection";
  const canInspectReceipt = Boolean(
    (committed || inspection) &&
      catalog?.functions["application.operation.receipt.read"],
  );
  return (
    <section aria-label="Exact mutation outcome">
      <p role="status">
        {outcomeStatus(pending, mutation.phase, mutation.canRetry)}
      </p>
      <button
        {...transferAction(
          mutation.busy || terminal(outcome),
          mutation.readOutcome,
        )}
      >
        {pending.uncertain
          ? "Check original mutation status"
          : "Refresh mutation status"}
      </button>
      {pending.uncertain && mutation.canRetry && (
        <button {...transferAction(mutation.busy, mutation.retrySubmission)}>
          Retry exact submission
        </button>
      )}
      {!pending.uncertain && (
        <>
          {canInspectReceipt && outcome && (
            <button
              type="button"
              onClick={() => setReceiptJobId(outcome.jobId)}
            >
              Inspect mutation receipt
            </button>
          )}
          {committed && refresh && (
            <button {...transferAction(mutation.busy, refresh)}>
              Read committed cell
            </button>
          )}
        </>
      )}
      {canInspectReceipt && outcome && receiptJobId === outcome.jobId && (
        <ReceiptInspector
          scope={scope}
          catalog={catalog}
          operationId={outcome.jobId}
          close={() => setReceiptJobId(null)}
        />
      )}
    </section>
  );
}
