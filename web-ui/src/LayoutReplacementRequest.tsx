import { useLayoutEffect, useRef, useState } from "react";
import { ApiError, readProgram } from "./api";
import { useGovernedEffectRecovery } from "./governed-effect-recovery";
import { LayoutActivation } from "./LayoutActivation";
import { layoutWorkState, type LayoutWorkState } from "./LayoutCancellation";
import { layoutReplacementRead } from "./layout-activation-contract";
import { useStableMutationIntentKey } from "./mutation-intent";
import type { ApplicationCatalog, Scope } from "./types";

export const layoutReplacementRequest =
  "metadata.layout.populated.replace.request";
const maxRequestBytes = 10_000_000;
const signedAdmissionLength = 94;

export type ReviewedLayoutReplacement = {
  dimensionName: string;
  plan: Record<string, unknown>;
  preview: {
    planDigest: string;
    previewDigest: string;
    impact: { coordinates: number };
  };
  dependencyDecisions: {
    kind: "rule" | "publication";
    id: string;
    decision: "Invalidate" | "Rebuild";
  }[];
  expectedDependencyDigest: string;
};

const statuses = [
  "Accepted",
  "Staging",
  "Staged",
  "Validated",
  "ValidationFailed",
  "Failed",
  "Cancelled",
] as const;
type Status = (typeof statuses)[number];
type Acknowledgement = {
  requestId: string;
  targetGenerationId: string;
  status: Status;
};
type RequestDetails = {
  dimensionName: string;
  planDigest: string;
  previewDigest: string;
  coordinateCount: number;
};
type Progress = {
  status: Status;
  work: LayoutWorkState | null;
  stagedCoordinateCount: number;
  materialization: null | {
    status: "Ready" | "Running" | "Complete" | "Failed";
  };
  certificate: null | { activationEligible: boolean };
};

const definitiveRefusals = new Set([
  "APPLICATION_PROGRAM_INVALID",
  "APPLICATION_NOT_WRITABLE",
  "OPERATION_ADMISSION_REQUIRED",
  "OPERATION_ADMISSION_MISMATCH",
  "METADATA_ACTION_CONFIRMATION_REQUIRED",
  "REQUEST_TOO_LARGE",
  "STALE_LAYOUT_PINS",
  "STALE_LAYOUT_DEPENDENCIES",
  "LAYOUT_CHANGED_DURING_PREVIEW",
  "LAYOUT_PREVIEW_AUTHORIZATION_CHANGED",
  "LAYOUT_REPLACEMENT_AUTHORIZATION_SCOPE_CHANGED",
  "LAYOUT_REPLACEMENT_PREVIEW_MISMATCH",
  "LAYOUT_REPLACEMENT_IDEMPOTENCY_CONFLICT",
  "LAYOUT_SOURCE_INVENTORY_STALE",
  "LAYOUT_DEPENDENCY_INVENTORY_MISMATCH",
  "LAYOUT_DEPENDENCY_COMPATIBILITY_UNPROVEN",
  "LAYOUT_DEPENDENCY_CERTIFICATE_LIMIT",
  "LAYOUT_DEPENDENCY_LIMIT",
  "LAYOUT_REPLACEMENT_DEPENDENCY_DECISIONS_INVALID",
  "LAYOUT_REVIEWED_DEPENDENCY_DIGEST_INVALID",
]);

function isStatus(value: unknown): value is Status {
  return (
    typeof value === "string" && statuses.some((status) => status === value)
  );
}

function acknowledgement(value: unknown): Acknowledgement | null {
  const reply = value as {
    languageVersion?: unknown;
    function?: unknown;
    result?: Partial<Acknowledgement> & { duplicate?: unknown };
  } | null;
  const result = reply?.result;
  if (
    reply?.languageVersion !== 2 ||
    reply.function !== layoutReplacementRequest ||
    !result ||
    typeof result.duplicate !== "boolean" ||
    typeof result.requestId !== "string" ||
    !/^[0-9a-f]{32}$/.test(result.requestId) ||
    typeof result.targetGenerationId !== "string" ||
    !/^[0-9a-f]{32}$/.test(result.targetGenerationId) ||
    !isStatus(result.status) ||
    (!result.duplicate && result.status !== "Accepted")
  )
    return null;
  return {
    requestId: result.requestId,
    targetGenerationId: result.targetGenerationId,
    status: result.status,
  };
}

const protocol = {
  path: "/api/metadata-action",
  tool: "execute_v2_metadata_program",
  editor: "metadata-layout-replacement-effect",
  pendingLabel: "Layout replacement with an unconfirmed outcome",
  functions: [layoutReplacementRequest],
  subject: "layout replacement",
  closePrompt:
    "Close this unconfirmed request? Check layout replacement builds in Monitor before preparing another request.",
  initialRefusal(reason: unknown) {
    return (
      reason instanceof ApiError &&
      (reason.kind === "authorization" ||
        ([400, 409, 413, 422].includes(reason.status) &&
          definitiveRefusals.has(reason.code)))
    );
  },
  result: acknowledgement,
};

export function useLayoutReplacementRequest(
  scope: Scope | undefined,
  catalog: ApplicationCatalog | null,
) {
  const [savedRequest, setSavedRequest] = useState<{
    owner: string;
    details: RequestDetails;
    acknowledgement: Acknowledgement;
  }>();
  const [error, setError] = useState("");
  const owner = JSON.stringify([
    scope?.workspaceId,
    scope?.applicationId,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
  ]);
  const context = JSON.stringify([
    owner,
    catalog?.revisions,
    catalog?.applicationAccess.role,
  ]);
  const keyFor = useStableMutationIntentKey("layout-replacement");
  const recovery = useGovernedEffectRecovery<RequestDetails, Acknowledgement>(
    scope,
    catalog,
    context,
    protocol,
    (details, result) => {
      setSavedRequest({ owner, details, acknowledgement: result });
    },
  );
  const recorded =
    catalog?.functions[layoutReplacementRead] && savedRequest?.owner === owner
      ? savedRequest
      : undefined;
  const canSubmit = Boolean(
    scope &&
      catalog?.applicationAccess.subjectId &&
      catalog.functions[layoutReplacementRequest] &&
      catalog.functions[layoutReplacementRead],
  );

  useLayoutEffect(() => {
    setError("");
  }, [context]);

  function submit(intent: ReviewedLayoutReplacement) {
    if (!scope || !canSubmit || recorded || recovery.pending || recovery.busy)
      return;
    const {
      dimensionName,
      plan,
      preview,
      dependencyDecisions,
      expectedDependencyDigest,
    } = intent;
    const coordinateCount = preview.impact.coordinates;
    const details = {
      dimensionName,
      planDigest: preview.planDigest,
      previewDigest: preview.previewDigest,
      coordinateCount,
    };
    const idempotencyKey = keyFor([
      owner,
      preview.previewDigest,
      expectedDependencyDigest,
      dependencyDecisions,
    ]);
    const body = {
      workspaceId: scope.workspaceId,
      applicationId: scope.applicationId,
      confirmed: true,
      idempotencyKey,
      program: {
        languageVersion: 2,
        function: layoutReplacementRequest,
        arguments: {
          plan,
          preview,
          dependencyDecisions,
          expectedDependencyDigest,
          idempotencyKey,
        },
      },
    };
    setError("");
    const bytes = new TextEncoder().encode(
      JSON.stringify({
        ...body,
        idempotencyKey: "x".repeat(signedAdmissionLength),
      }),
    ).length;
    if (bytes > maxRequestBytes) {
      setError(
        "This reviewed mapping exceeds the browser request limit. Download the review for your MCP client.",
      );
      return;
    }
    if (
      !window.confirm(
        `Request private replacement for ${dimensionName}? Activation is a separate step.`,
      )
    )
      return;
    return recovery.submit(body, details);
  }

  return {
    ...recovery,
    canSubmit,
    recorded,
    context,
    message:
      error ||
      ([
        "STALE_LAYOUT_DEPENDENCIES",
        "STALE_LAYOUT_PINS",
        "LAYOUT_CHANGED_DURING_PREVIEW",
        "LAYOUT_SOURCE_INVENTORY_STALE",
      ].includes(recovery.message)
        ? "The model or its dependencies changed. Refresh the layout and review the replacement again."
        : recovery.message),
    submit,
    closeRecorded: () => setSavedRequest(undefined),
  };
}

function readProgress(
  value: unknown,
  request: NonNullable<
    ReturnType<typeof useLayoutReplacementRequest>["recorded"]
  >,
): Progress {
  const result = value as
    | ({
        requestId?: unknown;
        targetGenerationId?: unknown;
        planDigest?: unknown;
        previewDigest?: unknown;
        expectedCoordinateCount?: unknown;
        activationId?: unknown;
      } & Partial<Progress>)
    | null;
  const { acknowledgement, details } = request;
  if (
    !result ||
    result.requestId !== acknowledgement.requestId ||
    result.targetGenerationId !== acknowledgement.targetGenerationId ||
    result.planDigest !== details.planDigest ||
    result.previewDigest !== details.previewDigest ||
    result.expectedCoordinateCount !== details.coordinateCount ||
    !isStatus(result.status) ||
    typeof result.stagedCoordinateCount !== "number" ||
    !Number.isSafeInteger(result.stagedCoordinateCount) ||
    result.stagedCoordinateCount < 0 ||
    result.stagedCoordinateCount > details.coordinateCount ||
    !(
      result.materialization === null ||
      (result.materialization &&
        ["Ready", "Running", "Complete", "Failed"].includes(
          result.materialization.status,
        ))
    ) ||
    !(
      result.certificate === null ||
      (result.certificate &&
        typeof result.certificate.activationEligible === "boolean")
    )
  )
    throw new Error(
      "The server did not confirm the status of this replacement request.",
    );
  return {
    status: result.status,
    work: result.activationId
      ? null
      : layoutWorkState(value, "replacement", acknowledgement.requestId),
    stagedCoordinateCount: result.stagedCoordinateCount,
    materialization: result.materialization,
    certificate: result.certificate,
  };
}

export function LayoutReplacementRequestStatus({
  scope,
  catalog,
  operation,
  onClose,
}: {
  scope: Scope | undefined;
  catalog: ApplicationCatalog | null;
  operation: ReturnType<typeof useLayoutReplacementRequest>;
  onClose: () => void;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  const controller = useRef<AbortController | null>(null);
  const [observation, setObservation] = useState<{
    context: string;
    value: "loading" | Progress;
  }>();
  const [readError, setReadError] = useState("");
  const request = operation.recorded;
  const context = JSON.stringify([
    operation.context,
    request?.acknowledgement.requestId,
  ]);
  const value =
    observation?.context === context ? observation.value : undefined;
  const loading = value === "loading";
  const progress = value && value !== "loading" ? value : undefined;
  useLayoutEffect(() => {
    heading.current?.focus();
  }, [request?.acknowledgement.requestId, operation.pending]);
  useLayoutEffect(() => {
    setReadError("");
    return () => controller.current?.abort();
  }, [context]);

  async function inspect() {
    if (!request || !scope || loading) return;
    controller.current?.abort();
    const next = new AbortController();
    controller.current = next;
    setObservation({ context, value: "loading" });
    setReadError("");
    try {
      const result = await readProgram<unknown>(
        scope,
        layoutReplacementRead,
        { requestId: request.acknowledgement.requestId },
        next.signal,
      );
      if (!next.signal.aborted)
        setObservation({ context, value: readProgress(result, request) });
    } catch (reason) {
      if (!next.signal.aborted)
        setReadError(
          reason instanceof Error
            ? reason.message
            : "Could not read the replacement status.",
        );
    } finally {
      if (!next.signal.aborted)
        setObservation((current) =>
          current?.context === context && current.value === "loading"
            ? undefined
            : current,
        );
    }
  }

  return (
    <section
      className="metadata-layout-review"
      aria-label="Layout replacement request"
    >
      <h3 ref={heading} tabIndex={-1}>
        Layout replacement request
      </h3>
      {request ? (
        <>
          <p>
            {request.details.dimensionName} · Request{" "}
            <code>{request.acknowledgement.requestId}</code>
          </p>
          <p>Accepted for private work. Activation is a separate step.</p>
          <p role="status">
            {loading ? (
              "Reading current replacement status…"
            ) : progress ? (
              <>
                {progress.status} ·{" "}
                {progress.stagedCoordinateCount.toLocaleString()} of{" "}
                {request.details.coordinateCount.toLocaleString()} coordinates
                staged
                {progress.materialization &&
                  ` · Materialization ${progress.materialization.status.toLowerCase()}`}
              </>
            ) : (
              <>Acknowledged status {request.acknowledgement.status}</>
            )}
          </p>
          {progress?.status === "Validated" &&
            progress.certificate?.activationEligible && (
              <p>
                The validation certificate reports eligibility for a separate
                activation review.
              </p>
            )}
          <button
            type="button"
            disabled={loading}
            onClick={() => void inspect()}
          >
            Read replacement status
          </button>
          <button type="button" onClick={onClose}>
            Close request view
          </button>
          {scope && (
            <LayoutActivation
              scope={scope}
              catalog={catalog}
              replacementState={progress?.work}
              onReplacementChanged={() => {
                controller.current?.abort();
                setObservation(undefined);
              }}
              target={{
                kind: "replacement",
                id: request.acknowledgement.requestId,
                generationId: request.acknowledgement.targetGenerationId,
              }}
            />
          )}
        </>
      ) : (
        <>
          <p role="status">
            {operation.busy
              ? "Checking the replacement request…"
              : operation.message ||
                "The original replacement request is unconfirmed."}
          </p>
          {operation.retryReady && (
            <button
              type="button"
              disabled={operation.busy}
              onClick={() => void operation.retry()}
            >
              Check original request
            </button>
          )}
          {operation.reviewedProgram && (
            <button
              type="button"
              disabled={operation.busy}
              onClick={() => void operation.copyOriginal()}
            >
              Copy original request for MCP
            </button>
          )}
          {operation.canCloseRecovery && (
            <button
              type="button"
              disabled={operation.busy}
              onClick={() => {
                if (operation.closeRecovery()) onClose();
              }}
            >
              Close unconfirmed request
            </button>
          )}
        </>
      )}
      {readError && <p role="alert">{readError}</p>}
    </section>
  );
}
