import { useLayoutEffect, useRef, useState } from "react";
import { ApiError, readProgram } from "./api";
import { useGovernedEffectRecovery } from "./governed-effect-recovery";
import {
  LayoutCancellation,
  layoutWorkState,
  useLayoutCancellation,
  type LayoutWorkState,
} from "./LayoutCancellation";
import { useStableMutationIntentKey } from "./mutation-intent";
import type { ApplicationCatalog, Scope } from "./types";

import {
  activationAcknowledgement,
  activationOutcome,
  activationRead,
  activationRequest,
  identifier,
  layoutReplacementRead,
  reviewReplacement,
  type Acknowledgement,
  type ActivationReview,
  type LayoutActivationTarget,
  type Outcome,
} from "./layout-activation-contract";

const staleReviews = new Set([
  "LAYOUT_ACTIVATION_VALIDATION_STALE",
  "LAYOUT_ACTIVATION_STALE",
  "LAYOUT_DEPENDENCY_CERTIFICATE_STALE",
  "LAYOUT_SOURCE_INVENTORY_STALE",
  "STALE_LAYOUT_DEPENDENCIES",
  "LAYOUT_DEPENDENCY_INVENTORY_MISMATCH",
]);
const definiteRefusals = new Set([
  ...staleReviews,
  "APPLICATION_PROGRAM_INVALID",
  "APPLICATION_NOT_WRITABLE",
  "METADATA_ACTION_CONFIRMATION_REQUIRED",
  "OPERATION_ADMISSION_REQUIRED",
  "OPERATION_ADMISSION_MISMATCH",
  "REQUEST_TOO_LARGE",
  "LAYOUT_ACTIVATION_REQUEST_INVALID",
  "LAYOUT_ACTIVATION_REQUEST_CONFLICT",
  "LAYOUT_ACTIVATION_AUTHORIZATION_SCOPE_CHANGED",
  "LAYOUT_ACTIVATION_IDEMPOTENCY_CONFLICT",
  "LAYOUT_ACTIVATION_CONFLICTING_WORK",
  "LAYOUT_ACTIVATION_DECISION_INVALID",
  "LAYOUT_DEPENDENCY_LIMIT",
  "LAYOUT_DEPENDENCY_CERTIFICATE_LIMIT",
  "LAYOUT_DEPENDENCY_COMPATIBILITY_UNPROVEN",
  "LAYOUT_DEPENDENCY_CERTIFICATE_REQUIRED",
]);

function disposition(message: string) {
  if (staleReviews.has(message))
    return "The model or its dependencies changed after validation. Read the replacement and obtain a fresh private validation before requesting activation.";
  if (message === "LAYOUT_ACTIVATION_REQUEST_CONFLICT")
    return "An activation conflicts with this request. Check layout activation tasks in Monitor before trying again.";
  if (message === "LAYOUT_DEPENDENCY_CERTIFICATE_REQUIRED")
    return "This validation certificate cannot authorize activation. Request a freshly reviewed private replacement.";
  return message;
}

type Observation =
  | {
      kind: "review";
      result: ActivationReview | null;
      work: LayoutWorkState | null;
    }
  | { kind: "outcome"; result: Outcome }
  | { kind: "loading" }
  | { kind: "error"; message: string };

export function LayoutActivation({
  scope,
  catalog,
  target,
  replacementState,
  onReplacementChanged,
}: {
  scope: Scope;
  catalog: ApplicationCatalog | null;
  target: LayoutActivationTarget;
  replacementState?: LayoutWorkState | null;
  onReplacementChanged?: () => void;
}) {
  const owner = JSON.stringify([
    scope.workspaceId,
    scope.applicationId,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
    target.kind,
    target.id,
  ]);
  const canReview = Boolean(
    target.kind === "replacement" &&
      catalog?.applicationAccess.subjectId &&
      catalog.functions[layoutReplacementRead] &&
      catalog.functions[activationRequest] &&
      catalog.functions[activationRead],
  );
  const canRead = Boolean(catalog?.functions[activationRead]);
  const canReadReplacement = Boolean(catalog?.functions[layoutReplacementRead]);
  const context = JSON.stringify([
    owner,
    target.kind === "replacement" ? target.generationId : null,
    catalog?.revisions,
    catalog?.applicationAccess.role,
    canReview,
    canRead,
    canReadReplacement,
  ]);
  const [entry, setEntry] = useState<{ context: string; value: Observation }>();
  const [saved, setSaved] = useState<{
    owner: string;
    result: Acknowledgement;
    review: ActivationReview;
  }>();
  const [linked, setLinked] = useState<{
    owner: string;
    activationId: string;
  }>();
  const [page, setPage] = useState(0);
  const controller = useRef<AbortController | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const keyFor = useStableMutationIntentKey("layout-activation");
  const recovery = useGovernedEffectRecovery<ActivationReview, Acknowledgement>(
    target.kind === "replacement" ? scope : undefined,
    catalog,
    context,
    {
      path: "/api/metadata-action",
      tool: "execute_v2_metadata_program",
      editor: `metadata-layout-activation:${target.id}`,
      pendingLabel: "Layout activation with an unconfirmed outcome",
      functions: [activationRequest],
      subject: "layout activation",
      closePrompt:
        "Close this unconfirmed activation? Check layout activation tasks in Monitor before preparing another request.",
      initialRefusal: (reason) =>
        reason instanceof ApiError &&
        (reason.kind === "authorization" ||
          ([400, 409, 413, 422].includes(reason.status) &&
            definiteRefusals.has(reason.code))),
      result: activationAcknowledgement,
    },
    (review, result) => {
      setEntry(undefined);
      setSaved({ owner, result, review });
    },
  );
  const acknowledged = saved?.owner === owner ? saved : undefined;
  const activationId =
    target.kind === "activation"
      ? target.id
      : (acknowledged?.result.activationId ??
        (linked?.owner === owner ? linked.activationId : undefined));
  const readContext = JSON.stringify([context, activationId]);
  const observation = entry?.context === readContext ? entry.value : undefined;
  const review = observation?.kind === "review" ? observation.result : null;
  const loading = observation?.kind === "loading";
  const currentWork = activationId
    ? observation?.kind === "outcome"
      ? observation.result
      : null
    : observation?.kind === "review"
      ? observation.work
      : observation
        ? null
        : (replacementState ?? null);
  const cancellation = useLayoutCancellation({
    scope,
    catalog,
    context: readContext,
    kind: activationId ? "activation" : "replacement",
    id: activationId ?? target.id,
    state: currentWork,
    onRefreshNeeded: () => {
      setEntry(undefined);
      if (!activationId) onReplacementChanged?.();
    },
  });
  const cancelling = cancellation.pending || cancellation.busy;

  useLayoutEffect(() => () => controller.current?.abort(), [readContext]);

  if (
    !identifier(target.id) ||
    (activationId
      ? !canRead
      : !canReadReplacement || (!canReview && !cancellation.canControl))
  )
    return null;

  async function inspect() {
    if (loading || recovery.busy || recovery.pending || cancelling) return;
    controller.current?.abort();
    const next = new AbortController();
    controller.current = next;
    setEntry({ context: readContext, value: { kind: "loading" } });
    setPage(0);
    try {
      let value: Observation;
      if (activationId) {
        const reply = await readProgram<unknown>(
          scope,
          activationRead,
          { activationId },
          next.signal,
        );
        value = {
          kind: "outcome",
          result: activationOutcome(reply, activationId, target, acknowledged),
        };
      } else if (target.kind === "replacement") {
        const reply = await readProgram<unknown>(
          scope,
          layoutReplacementRead,
          { requestId: target.id },
          next.signal,
        );
        const result = reviewReplacement(reply, target);
        if (result.activationId) {
          if (!next.signal.aborted) {
            setEntry(undefined);
            setLinked({ owner, activationId: result.activationId });
          }
          return;
        }
        value = {
          kind: "review",
          result: result.review,
          work: layoutWorkState(reply, "replacement", target.id),
        };
      } else return;
      if (!next.signal.aborted) setEntry({ context: readContext, value });
    } catch (reason) {
      if (!next.signal.aborted)
        setEntry({
          context: readContext,
          value: {
            kind: "error",
            message:
              reason instanceof ApiError
                ? reason.message
                : "The server did not confirm this layout activation state.",
          },
        });
    }
  }

  function submit() {
    if (
      !review ||
      !canReview ||
      activationId ||
      recovery.busy ||
      recovery.pending ||
      cancelling ||
      cancellation.result?.status === "Cancelled" ||
      !window.confirm(
        "Request activation of this validated layout? Activation publishes the new layout for this application.",
      )
    )
      return;
    const idempotencyKey = keyFor([owner, review]);
    heading.current?.focus();
    setEntry(undefined);
    void recovery.submit(
      {
        workspaceId: scope.workspaceId,
        applicationId: scope.applicationId,
        confirmed: true,
        idempotencyKey,
        program: {
          languageVersion: 2,
          function: activationRequest,
          arguments: { ...review, idempotencyKey },
        },
      },
      review,
    );
  }

  const pending = recovery.pending || recovery.busy;
  const outcome =
    observation?.kind === "outcome" ? observation.result : undefined;
  return (
    <section
      className="layout-activation-review"
      aria-label="Layout activation"
    >
      <h3 ref={heading} tabIndex={-1}>
        Layout activation
      </h3>
      {!recovery.busy && !recovery.pending && (
        <LayoutCancellation
          action={cancellation}
          refreshAvailable={Boolean(currentWork)}
        />
      )}
      {!cancelling &&
        (pending ? (
          <>
            <p role="status">
              {recovery.busy
                ? "Checking the activation request…"
                : recovery.message ||
                  "The original layout activation is unconfirmed."}
            </p>
            {recovery.retryReady && (
              <button
                type="button"
                disabled={recovery.busy}
                onClick={() => {
                  heading.current?.focus();
                  void recovery.retry();
                }}
              >
                Check original activation
              </button>
            )}
            {recovery.reviewedProgram && (
              <button
                type="button"
                disabled={recovery.busy}
                onClick={() => void recovery.copyOriginal()}
              >
                Copy original activation for MCP
              </button>
            )}
            {recovery.canCloseRecovery && (
              <button
                type="button"
                disabled={recovery.busy}
                onClick={() => {
                  if (recovery.closeRecovery()) heading.current?.focus();
                }}
              >
                Close unconfirmed activation
              </button>
            )}
          </>
        ) : (
          <>
            {activationId && (
              <p>
                Activation <code>{activationId}</code>
              </p>
            )}
            {acknowledged && !outcome && (
              <p role="status">
                Acknowledged as {acknowledged.result.status}. Read the
                activation status to confirm publication.
              </p>
            )}
            {outcome && (
              <p role="status">
                {outcome.status}
                {outcome.errorCode && ` · ${outcome.errorCode}`}
              </p>
            )}
            {outcome?.receipt && (
              <div role="status">
                <strong>
                  Layout published at revision{" "}
                  {outcome.receipt.committedRevision}.
                </strong>
                <p>
                  Schema epoch {outcome.receipt.schemaEpoch} · Projection
                  generation {outcome.receipt.projectionGeneration}.
                </p>
                {outcome.receipt.addedDimensionId && (
                  <p>Added dimension {outcome.receipt.addedDimensionId}.</p>
                )}
              </div>
            )}
            {observation?.kind === "review" && !review && (
              <p role="status">
                {observation.work?.status === "Cancelled"
                  ? "This replacement is cancelled."
                  : "This replacement has no eligible activation review. Read it again after private validation."}
              </p>
            )}
            <button
              type="button"
              aria-disabled={loading || undefined}
              onClick={() => void inspect()}
            >
              {activationId
                ? "Read activation status"
                : canReview
                  ? "Review layout activation"
                  : "Read replacement work"}
            </button>
            {loading && (
              <p role="status">Reading current activation evidence…</p>
            )}
            {observation?.kind === "error" && (
              <p role="alert">{observation.message}</p>
            )}
            {!observation && recovery.message && (
              <p role="alert">{disposition(recovery.message)}</p>
            )}
            {review &&
              canReview &&
              cancellation.result?.status !== "Cancelled" && (
                <>
                  <p>
                    Validated layout <code>{review.targetGenerationId}</code>
                  </p>
                  <p>
                    Certificate <code>{review.validationDigest}</code>
                  </p>
                  <p>
                    Source revision {review.expectedPins.sourceCommitRevision} ·
                    Schema epoch {review.expectedPins.schemaEpoch}.
                  </p>
                  <p>
                    {review.dependencyDecisions.length} retained dependency
                    decisions.
                  </p>
                  {review.dependencyDecisions.length > 0 && (
                    <details>
                      <summary>Read retained dependency decisions</summary>
                      <ul>
                        {review.dependencyDecisions
                          .slice(page * 25, page * 25 + 25)
                          .map((item) => (
                            <li key={JSON.stringify([item.kind, item.id])}>
                              {item.kind} {item.id} · {item.decision}
                            </li>
                          ))}
                      </ul>
                      {review.dependencyDecisions.length > 25 && (
                        <>
                          <button
                            type="button"
                            disabled={page === 0}
                            onClick={() => setPage(page - 1)}
                          >
                            Previous decisions
                          </button>
                          <button
                            type="button"
                            disabled={
                              (page + 1) * 25 >=
                              review.dependencyDecisions.length
                            }
                            onClick={() => setPage(page + 1)}
                          >
                            Next decisions
                          </button>
                        </>
                      )}
                    </details>
                  )}
                  <p>
                    Activation publishes the shared layout. Rebuild decisions
                    require separate follow-up work.
                  </p>
                  <button type="button" onClick={submit}>
                    Request activation
                  </button>
                </>
              )}
          </>
        ))}
    </section>
  );
}
