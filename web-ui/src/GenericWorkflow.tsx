import "./focused-workspaces.css";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  isApplicationAccessDenied,
  isDefiniteEffectRefusal,
  readProgram,
  prepareAdmittedProgramEffect,
  replayAdmittedEffect,
  type AdmittedEffectPacket,
} from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import { usePreservedDraft, type DraftRecoveryLease } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { focusWhenInteractive } from "./MetadataReceiptRecovery";
import {
  ActivityPagination,
  activityPageBounds,
  blockedWorkflowDetail,
  readCompleteWorkflowWorklist,
  type BlockedWorkflowWork,
} from "./MyWork";
import {
  RECEIPT_AUTHORIZATION_STALE,
  ReceiptInspector,
  copyOperationReceiptCheck,
  exactOperationReceipt,
  outcomeAuthorityKey,
  outcomeReadError,
} from "./ReceiptInspector";
import { authoringContextKey } from "./python-authoring";
import {
  LEGACY_SEQUENCE_UNSUPPORTED,
  RETIRED_FUNCTION,
} from "./sequence-availability";
import {
  WorkflowStarter,
  WORKFLOW_LIST,
  WORKFLOW_READ,
  WORKFLOW_START,
  type WorkflowStartReview,
} from "./WorkflowStarter";

type ReadyActivity = {
  occurrenceId: string;
  occurrenceStateToken: string;
  flowId: string;
  flowStateToken: string;
  definitionDigest: string;
  activityId: string;
  activityStateToken: string;
  name: string;
  kind: "Action" | "Review";
  destination: Record<string, unknown>;
  assignmentResolution: { assignmentId: string; kind: string };
};

type Occurrence = {
  occurrenceId: string;
  flowId: string;
  flowStateToken: string;
  definitionDigest: string;
  status: string;
  occurrenceStateToken: string;
  lastEventOrdinal: number;
  activities: Array<{
    activityId: string;
    kind: "Action" | "Review";
    status: string;
    activityStateToken: string;
    operationId?: string | null;
    completedAt?: string | null;
    returnedToActivityId?: string | null;
  }>;
  events: Array<{
    ordinal: number;
    eventType: string;
    activityId?: string | null;
    operationId?: string | null;
    evidence?: unknown;
    committedRevision: number;
    createdAt: string;
  }>;
  nextEventOrdinal?: number | null;
  currentReturns?: Occurrence["events"];
};

function reviewReturnEvidence(event: Occurrence["events"][number]) {
  if (event.eventType !== "ActivityReturned") return null;
  const value = event.evidence as
    | {
        kind?: unknown;
        reason?: unknown;
        targetActivityId?: unknown;
      }
    | null
    | undefined;
  return value?.kind === "ReviewReturn" &&
    typeof value.reason === "string" &&
    value.reason.trim() &&
    typeof value.targetActivityId === "string" &&
    value.targetActivityId.trim()
    ? { reason: value.reason, targetActivityId: value.targetActivityId }
    : null;
}

const evidenceAssessmentFunction =
  "application.workflow.activity.evidence.read";
const workflowReceiptFunction = "application.operation.receipt.read";
const workflowAuthorityStale = "APPLICATION_WORKFLOW_AUTHORIZATION_STALE";
const workflowAuthorityChangedMessage =
  "Your access changed during this workflow read. Refresh the workflow to check current assigned work.";
const initialActionAccessRefused =
  "The workflow action was refused after an access change. Refresh the workflow before reviewing it again.";
const originalOutcomeAccessChanged =
  "Access changed while reconciling. The original workflow outcome remains unconfirmed. Refresh the workflow before checking its receipt.";
const workflowReceiptContractUnsupported =
  "APPLICATION_WORKFLOW_RECEIPT_CONTRACT_UNSUPPORTED";
const workflowViewScopeMismatch =
  "APPLICATION_WORKFLOW_EVIDENCE_VIEW_SCOPE_MISMATCH";

function workflowReadError(reason: unknown) {
  if (reason instanceof ApiError && reason.code === workflowAuthorityStale)
    return workflowAuthorityChangedMessage;
  return reason instanceof Error ? reason.message : String(reason);
}

type EvidenceAssessment = {
  message: string;
  blocksReview?: true;
  requiredBasisCheck?: "current" | "unknown";
};

const reviewRefusalMessages: Readonly<Record<string, string>> = {
  APPLICATION_WORKFLOW_REVIEW_BASIS_STALE:
    "Required evidence has changed. Return the work to replace that evidence.",
  APPLICATION_WORKFLOW_REVIEW_BASIS_UNAVAILABLE:
    "Required evidence could not be verified. Check the evidence and refresh the workflow.",
};

// These codes are emitted by the fixed workflow, authorization, or admission
// checks. A bare HTTP failure cannot establish the outcome of a sent request.
const initialWorkflowRefusalCodes = new Set([
  workflowAuthorityStale,
  workflowReceiptContractUnsupported,
  workflowViewScopeMismatch,
  LEGACY_SEQUENCE_UNSUPPORTED,
  RETIRED_FUNCTION,
  "APPLICATION_WORKFLOW_EVIDENCE_VIEW_UNSUPPORTED",
  ...Object.keys(reviewRefusalMessages),
  "APPLICATION_WORKFLOW_STALE_CONTEXT",
  "APPLICATION_WORKFLOW_CURRENT_UNAVAILABLE",
  "APPLICATION_WORKFLOW_OCCURRENCE_UNAVAILABLE",
  "APPLICATION_WORKFLOW_OCCURRENCE_DEFINITION_STALE",
  "APPLICATION_WORKFLOW_OCCURRENCE_STALE",
  "APPLICATION_WORKFLOW_ACTIVITY_STALE",
  "APPLICATION_WORKFLOW_ACTIVITY_NOT_ASSIGNED",
  "APPLICATION_WORKFLOW_SELECTION_NOT_ASSIGNED",
  "APPLICATION_WORKFLOW_ASSIGNMENT_UNAVAILABLE",
  "APPLICATION_WORKFLOW_ASSIGNMENT_NOT_EFFECTIVE",
  "APPLICATION_WORKFLOW_RETURN_UNAVAILABLE",
  "APPLICATION_WORKFLOW_RETURN_TARGET_STALE",
  "APPLICATION_WORKFLOW_EVIDENCE_INVALID",
  "APPLICATION_WORKFLOW_EVIDENCE_UNAVAILABLE",
  "APPLICATION_WORKFLOW_EVIDENCE_NOT_CURRENT",
  "APPLICATION_WORKFLOW_EVIDENCE_EFFECT_MISMATCH",
  "APPLICATION_WORKFLOW_EVIDENCE_RECEIPT_MISMATCH",
  "APPLICATION_WORKFLOW_EVIDENCE_DESTINATION_MISMATCH",
  "APPLICATION_GRANT_REQUIRED",
  "APPLICATION_UNAVAILABLE",
  "APPLICATION_NOT_WRITABLE",
  "WORKSPACE_ADMIN_REQUIRED",
  "WORKSPACE_NOT_WRITABLE",
  "PROGRAM_VALIDATION_FAILED",
  "OPERATION_ADMISSION_EXPIRED",
]);

function reviewIdentity(
  identity: string,
  occurrenceId: unknown,
  activityId: unknown,
  activityStateToken: unknown,
) {
  return JSON.stringify([
    identity,
    occurrenceId,
    activityId,
    activityStateToken,
  ]);
}

function parseEvidenceAssessment(
  value: unknown,
  occurrenceId: string,
  activityId: string,
  activityStateToken: string,
): EvidenceAssessment {
  const unavailable = { message: "Current evidence could not be assessed." };
  if (!value || typeof value !== "object") return unavailable;
  const assessment = value as Record<string, unknown>;
  if (
    assessment.occurrenceId !== occurrenceId ||
    assessment.activityId !== activityId
  )
    return unavailable;
  if (
    assessment.state === "TemporarilyUnavailable" &&
    assessment.retryable === true
  )
    return {
      message:
        "Evidence changed during the check or could not be read. Check again.",
    };
  if (
    assessment.state === "NoCompletedBasis" &&
    assessment.basis === null &&
    assessment.suitability === "NotApplicable"
  )
    return {
      message:
        "This step no longer has a recorded completion. Refresh the workflow.",
    };
  if (
    assessment.state === "UnavailableToAssess" &&
    assessment.basis === null &&
    assessment.requireCurrent === null &&
    assessment.suitability === "Unknown" &&
    assessment.retryable === false &&
    !("activityStateToken" in assessment)
  )
    return { ...unavailable, requiredBasisCheck: "unknown" };
  if (assessment.activityStateToken !== activityStateToken) return unavailable;
  if (
    assessment.state === "NotApplicable" &&
    assessment.basis === "ManualAttestation"
  )
    return { message: "Recorded manual attestation." };
  if (
    assessment.basis !== "ExactNumericEffects" &&
    assessment.basis !== "RulePublication" &&
    assessment.basis !== "CalculationPublication"
  )
    return unavailable;
  const evidenceName =
    assessment.basis === "ExactNumericEffects"
      ? "evidence"
      : assessment.basis === "RulePublication"
        ? "rule publication"
        : "calculated result";
  const recordedName =
    assessment.basis === "ExactNumericEffects"
      ? "numeric evidence"
      : evidenceName;
  if (
    assessment.state === "Current" &&
    assessment.suitability === "SuitableUnderConfiguredEvidenceCondition"
  )
    return {
      message: `The recorded ${recordedName} is current at the time of this check.`,
      ...(assessment.requireCurrent === true
        ? { requiredBasisCheck: "current" }
        : {}),
    };
  if (assessment.state === "Stale") {
    if (
      assessment.requireCurrent === true &&
      assessment.suitability === "UnsuitableNow"
    )
      return {
        message: `This ${evidenceName} is stale. The activity requires current evidence.`,
        blocksReview: true,
      };
    if (
      assessment.requireCurrent === false &&
      assessment.suitability === "HistoricalPermitted"
    )
      return {
        message: `This ${evidenceName} is stale. The activity allows historical evidence.`,
      };
  }
  return unavailable;
}

async function readWorkflowOccurrencePage(
  scope: Scope,
  occurrenceId: string,
  afterEventOrdinal: number,
  includeCurrentReturns: boolean,
  signal: AbortSignal,
): Promise<Occurrence> {
  const page = await readProgram<Occurrence>(
    scope,
    "application.workflow.occurrence.read",
    {
      occurrenceId,
      eventLimit: 50,
      afterEventOrdinal,
      ...(includeCurrentReturns ? { includeCurrentReturns: true } : {}),
    },
    signal,
  );
  if (
    page.occurrenceId !== occurrenceId ||
    !/^[0-9a-f]{64}$/.test(page.occurrenceStateToken) ||
    !/^[0-9a-f]{64}$/.test(page.flowStateToken) ||
    !/^[0-9a-f]{64}$/.test(page.definitionDigest) ||
    !Array.isArray(page.activities) ||
    !Array.isArray(page.events) ||
    !Number.isSafeInteger(page.lastEventOrdinal) ||
    page.lastEventOrdinal < 0 ||
    (includeCurrentReturns && !Array.isArray(page.currentReturns))
  )
    throw new Error("INVALID_WORKFLOW_OCCURRENCE_PAGE");
  let previousEvent = afterEventOrdinal;
  for (const event of page.events) {
    if (
      !Number.isSafeInteger(event.ordinal) ||
      event.ordinal <= previousEvent ||
      event.ordinal > page.lastEventOrdinal
    )
      throw new Error("INVALID_WORKFLOW_EVENT_CONTINUATION");
    previousEvent = event.ordinal;
  }
  if (
    page.nextEventOrdinal != null &&
    (page.nextEventOrdinal !== previousEvent ||
      previousEvent <= afterEventOrdinal ||
      previousEvent >= page.lastEventOrdinal)
  )
    throw new Error("INVALID_WORKFLOW_EVENT_CONTINUATION");
  return page;
}

type WorkflowDefinition = {
  flowId: string;
  stateToken: string;
  definitionDigest: string;
  definition: {
    name?: string;
    activities: Array<{
      activityId: string;
      name?: string;
      kind: "Action" | "Review";
      dependsOn: string[];
      returnTo: string | null;
      evidenceContract:
        | { kind: "ManualAttestation"; statement: string }
        | {
            kind: "OperationReceipt";
            allowedFunctions: string[];
            requireCurrent: boolean;
          };
    }>;
  };
};

export function exactWorkflowDefinition(
  value: WorkflowDefinition,
  occurrence: Occurrence,
) {
  if (
    !value ||
    value.flowId !== occurrence.flowId ||
    value.stateToken !== occurrence.flowStateToken ||
    value.definitionDigest !== occurrence.definitionDigest ||
    !Array.isArray(value.definition?.activities)
  )
    throw new Error(
      "The current workflow definition no longer matches this occurrence. Refresh its context; no action was submitted.",
    );
  for (const activity of value.definition.activities) {
    const evidence = activity?.evidenceContract;
    if (
      !activity ||
      typeof activity.activityId !== "string" ||
      !["Action", "Review"].includes(activity.kind) ||
      !Array.isArray(activity.dependsOn) ||
      activity.dependsOn.some((id) => typeof id !== "string") ||
      !(activity.returnTo === null || typeof activity.returnTo === "string") ||
      !(
        (evidence?.kind === "ManualAttestation" &&
          typeof evidence.statement === "string") ||
        (evidence?.kind === "OperationReceipt" &&
          Array.isArray(evidence.allowedFunctions) &&
          evidence.allowedFunctions.length > 0 &&
          evidence.allowedFunctions.every((name) => typeof name === "string") &&
          typeof evidence.requireCurrent === "boolean")
      )
    )
      throw new Error(
        "Workflow activity requirements are unavailable. Refresh before reviewing this occurrence.",
      );
  }
  return value;
}

type EvidenceOption = {
  selectionKey: string;
  label: string;
  occurredAt: string;
  outcome: "Committed";
  current: boolean;
};

type EvidenceListRequest = {
  scope: Scope;
  occurrenceId: string;
  activityId: string;
};

type EvidencePage = {
  items: EvidenceOption[];
  nextBeforeCommittedRevision: number | null;
};

type EvidenceListResult = { request: EvidenceListRequest } & (
  | { state: "ready" | "paging"; page: EvidencePage }
  | { state: "unavailable" }
);

type WorkflowAttempt = {
  packet: AdmittedEffectPacket;
  kind: "start" | "complete" | "return" | "cancel";
  identity: string;
  expectedReturnTarget?: string;
  admissionExpired?: true;
};

function startReviewRefusal(kind: WorkflowAttempt["kind"], reason: unknown) {
  if (kind !== "start" || !(reason instanceof ApiError)) return;
  if (reason.code === "APPLICATION_WORKFLOW_STALE_CONTEXT")
    return {
      reloadNotice:
        "The workflow context changed. Open the first workflow page and review the current workflow before starting.",
    };
  if (reason.code === "APPLICATION_WORKFLOW_CURRENT_UNAVAILABLE")
    return {
      reloadNotice:
        "The selected workflow is unavailable for a new occurrence. Open the first workflow page to choose a current workflow.",
    };
  if (reason.code === workflowReceiptContractUnsupported)
    return {
      reloadNotice:
        "A workflow administrator must update the evidence condition before this workflow can start. Open the first workflow page to choose a current workflow.",
    };
  if (reason.code === workflowViewScopeMismatch)
    return {
      reloadNotice:
        "A workflow administrator must align the saved view and workflow selections before this workflow can start. Open the first workflow page to choose a current workflow.",
    };
  if (reason.code === LEGACY_SEQUENCE_UNSUPPORTED)
    return {
      reloadNotice:
        "A workflow administrator must replace the unavailable legacy sequence before this workflow can start. Open the first workflow page to choose a current workflow.",
    };
  if (reason.code === RETIRED_FUNCTION)
    return {
      reloadNotice:
        "A workflow administrator must replace the retired destination before this workflow can start. Open the first workflow page to choose a current workflow.",
    };
}

function confirmsWorkflowOutcome(
  attempt: WorkflowAttempt,
  outcome: Record<string, unknown>,
  receipt = false,
) {
  const { program } = attempt.packet.body;
  const args = program.arguments as Record<string, unknown>;
  if (outcome.function !== program.function) return false;
  if (attempt.kind === "start") {
    return (
      outcome.status === "Active" &&
      typeof outcome.occurrenceId === "string" &&
      /^[0-9a-f]{32}$/.test(outcome.occurrenceId) &&
      (receipt ||
        (outcome.flowId === args.flowId &&
          outcome.flowStateToken === args.expectedStateToken &&
          typeof outcome.occurrenceStateToken === "string" &&
          /^[0-9a-f]{64}$/.test(outcome.occurrenceStateToken)))
    );
  }
  if (outcome.occurrenceId !== args.occurrenceId) return false;
  if (attempt.kind === "cancel") return outcome.status === "Cancelled";
  if (outcome.activityId !== args.activityId) return false;
  if (attempt.kind === "return")
    return (
      outcome.status === "Active" &&
      Boolean(attempt.expectedReturnTarget) &&
      outcome.returnedToActivityId === attempt.expectedReturnTarget
    );
  return outcome.status === "Active" || outcome.status === "Completed";
}

type BasisCheck = {
  context: string;
  authority: string;
  occurrenceId: string;
  activityId: string;
  activityStateToken: string;
};

export function mergeWorkflowEvidence(
  current: EvidenceOption[],
  page: EvidencePage,
  before?: number,
) {
  const cursor = page.nextBeforeCommittedRevision;
  if (
    !Array.isArray(page.items) ||
    !(
      cursor === null ||
      (Number.isSafeInteger(cursor) &&
        cursor > 0 &&
        (before === undefined || cursor < before))
    )
  )
    throw new Error(
      "Workflow evidence continuation is invalid. Refresh the activity.",
    );
  const seen = new Set(current.map((item) => item.selectionKey));
  for (const item of page.items) {
    if (
      !item ||
      typeof item.selectionKey !== "string" ||
      !item.selectionKey ||
      typeof item.label !== "string" ||
      typeof item.current !== "boolean" ||
      item.outcome !== "Committed" ||
      !Number.isFinite(Date.parse(item.occurredAt)) ||
      seen.has(item.selectionKey)
    )
      throw new Error(
        "Workflow evidence response is invalid or repeated. Refresh the activity.",
      );
    seen.add(item.selectionKey);
  }
  return {
    items: [...current, ...page.items],
    nextBeforeCommittedRevision: cursor,
  };
}

export const genericWorkflowActionBody = (
  scope: Scope,
  program: Record<string, unknown>,
  idempotencyKey: string,
) => ({ ...scope, program, idempotencyKey, confirmed: true });

export function GenericWorkflow({
  app,
  catalog: confirmedCatalog,
  catalogueUnavailable: catalogueReadFailed = false,
  onRefreshCatalog,
  targetOccurrenceId,
  targetActivityId,
  openDestination,
  openMyWork,
  openOccurrence,
  onRequestTransition = (action) => action(),
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  catalogueUnavailable?: boolean;
  onRefreshCatalog?: () => Promise<unknown>;
  targetOccurrenceId?: string;
  targetActivityId?: string;
  onRequestTransition?: (action: () => void) => void;
  openMyWork?: () => void;
  openOccurrence?: (occurrenceId: string) => void;
  openDestination?: (
    destination: Record<string, unknown>,
    activityContext?: { occurrenceId: string; activityId: string },
  ) => string | null | undefined;
}) {
  const [query, setQuery] = useState("");
  const [workPage, setWorkPage] = useState(0);
  const [chosenActivity, setChosenActivity] = useState<{
    context: string;
    occurrenceId: string;
    activityId: string;
  } | null>(null);
  const [occurrenceResult, setOccurrenceResult] = useState<{
    request: { scope: Scope; occurrenceId: string };
    value: Occurrence | null;
    error?: string;
  } | null>(null);
  const [historyResult, setHistoryResult] = useState<{
    occurrence: Occurrence;
    events: Occurrence["events"];
    next: number | null;
    pending?: true;
    changed?: true;
    error?: string;
  } | null>(null);
  const historyRequest = useRef<AbortController | null>(null);
  const [definitionResult, setDefinitionResult] = useState<{
    request: { scope: Scope; occurrence: Occurrence };
    value: WorkflowDefinition | null;
    error?: string;
  } | null>(null);
  const [storedReceiptId, setReceiptId] = useState("");
  const [evidenceResult, setEvidenceResult] =
    useState<EvidenceListResult | null>(null);
  const evidenceController = useRef<AbortController | null>(null);
  const [storedReturnReason, setReturnReason] = useState("");
  const [reviewedContext, setReviewedContext] = useState<string | null>(null);
  const [admitting, setAdmitting] = useState(false);
  const [settling, setSettling] = useState<"send" | "receipt" | null>(null);
  const settlementRequest = useRef<AbortController | null>(null);
  const busy = admitting || settling !== null;
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const [startOutcome, setStartOutcome] = useState<{
    occurrenceId: string;
    operationId: string;
  } | null>(null);
  const startFocusOrigin = useRef<HTMLButtonElement | null>(null);
  const recoveryHeading = useRef<HTMLHeadingElement>(null);
  const resultStatus = useRef<HTMLParagraphElement>(null);
  const startedOccurrenceButton = useRef<HTMLButtonElement>(null);
  const [inspectReceiptId, setInspectReceiptId] = useState("");
  const [destinationError, setDestinationError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [withdrawnAccess, setWithdrawnAccess] = useState<{
    authority: string;
    message: string;
  } | null>(null);
  const [checkingAccess, setCheckingAccess] = useState(false);
  const workflowPage = useRef<HTMLDivElement>(null);
  const refreshButton = useRef<HTMLButtonElement>(null);
  const [basisTarget, setBasisTarget] = useState<BasisCheck | null>(null);
  const [basisResults, setBasisResults] = useState(
    () => new Map<string, EvidenceAssessment & { target: BasisCheck }>(),
  );
  const [reviewRefusal, setReviewRefusal] = useState<{
    identity: string;
    message: string;
    version: number;
  } | null>(null);
  const [attempt, setAttempt] = useState<WorkflowAttempt | null>(null);
  const [missingReceiptCheck, setMissingReceiptCheck] = useState<string | null>(
    null,
  );
  const [receiptHandoff, setReceiptHandoff] = useState<{
    key: string;
    message: string;
  } | null>(null);
  const workflowIntentKey = useStableMutationIntentKey("workflow-ui");
  const scope = app
    ? { workspaceId: app.workspaceId, applicationId: app.applicationId }
    : null;
  const confirmedAuthority =
    app && confirmedCatalog
      ? JSON.stringify([
          authoringContextKey(app, confirmedCatalog),
          confirmedCatalog.applicationAccess.role,
          confirmedCatalog.applicationAccess.workspaceAdministrator,
          confirmedCatalog.revisions.capability,
          refresh,
        ])
      : null;
  const currentAuthority = useRef(confirmedAuthority);
  currentAuthority.current = confirmedAuthority;
  const accessRefusal =
    withdrawnAccess?.authority === confirmedAuthority ? withdrawnAccess : null;
  const accessNeedsRefresh = accessRefusal !== null;
  const catalog = accessNeedsRefresh ? null : confirmedCatalog;
  const catalogueUnavailable =
    catalogueReadFailed || (accessNeedsRefresh && !checkingAccess);

  function withdrawWorkflowAccess(
    reason: unknown,
    message = workflowAuthorityChangedMessage,
  ) {
    if (
      !isApplicationAccessDenied(reason) &&
      !(
        reason instanceof ApiError &&
        [workflowAuthorityStale, RECEIPT_AUTHORIZATION_STALE].includes(
          reason.code,
        )
      )
    )
      return false;
    if (
      confirmedAuthority !== null &&
      currentAuthority.current === confirmedAuthority
    ) {
      const active = workflowPage.current?.ownerDocument.activeElement;
      if (active && workflowPage.current?.contains(active))
        refreshButton.current?.focus();
      setWithdrawnAccess({ authority: confirmedAuthority, message });
    }
    return true;
  }
  const canRead = Boolean(catalog?.functions["application.workflow.worklist"]);
  const canReadOccurrence = Boolean(
    catalog?.functions["application.workflow.occurrence.read"],
  );
  const canReadDefinition = Boolean(
    catalog?.functions["application.workflow.read"],
  );
  const authorityKey =
    app && catalog ? authoringContextKey(app, catalog) : "unavailable";
  const settlementAuthority =
    scope && catalog ? outcomeAuthorityKey(scope, catalog) : null;
  const canStart = Boolean(
    settlementAuthority &&
      catalog?.functions[WORKFLOW_LIST] &&
      catalog.functions[WORKFLOW_READ] &&
      catalog.functions[WORKFLOW_START],
  );
  const canReadOriginalReceipt = Boolean(
    catalog?.functions[workflowReceiptFunction],
  );
  useLayoutEffect(() => {
    startFocusOrigin.current = null;
    setSettling(null);
    setResult("");
    setStartOutcome(null);
    setMissingReceiptCheck(null);
    return () => {
      // The packet remains retained. Cancelling this wait does not cancel an
      // effect that the server may already have committed.
      settlementRequest.current?.abort();
      settlementRequest.current = null;
    };
  }, [settlementAuthority, canReadOriginalReceipt]);
  useEffect(() => {
    const releaseStartFocus = (event: FocusEvent) => {
      if (
        startFocusOrigin.current &&
        event.target !== startFocusOrigin.current &&
        event.target !== document.body
      )
        startFocusOrigin.current = null;
    };
    document.addEventListener("focusin", releaseStartFocus);
    return () => document.removeEventListener("focusin", releaseStartFocus);
  }, []);
  const identityKey = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    confirmedCatalog?.applicationAccess.issuer,
    confirmedCatalog?.applicationAccess.subjectId,
  ]);
  const choiceContext = JSON.stringify([
    identityKey,
    targetOccurrenceId,
    targetActivityId,
  ]);
  const choice =
    catalog && chosenActivity?.context === choiceContext
      ? chosenActivity
      : null;
  const requestedOccurrenceId = choice?.occurrenceId ?? targetOccurrenceId;
  const requestedActivityId = choice?.activityId ?? targetActivityId;
  useEffect(() => {
    if (catalog && chosenActivity && !choice) setChosenActivity(null);
  }, [catalog, chosenActivity, choice]);
  const worklistRequest = useMemo(
    () => ({ scope, occurrenceId: targetOccurrenceId }),
    [
      app?.workspaceId,
      app?.applicationId,
      catalog,
      refresh,
      targetOccurrenceId,
      targetActivityId,
    ],
  );
  const [worklistResult, setWorklistResult] = useState<
    | {
        request: typeof worklistRequest;
        state: "ready";
        items: ReadyActivity[];
        blockedItems: BlockedWorkflowWork[];
      }
    | { request: typeof worklistRequest; state: "error" }
    | null
  >(null);
  const currentWorklist =
    canRead && worklistResult?.request === worklistRequest
      ? worklistResult
      : null;
  const worklistRead = currentWorklist?.state === "ready";
  const worklistLoading = Boolean(scope && canRead && !currentWorklist);
  const checkingWorklist = Boolean(app && !catalog && !catalogueUnavailable);
  const ready = currentWorklist?.state === "ready" ? currentWorklist.items : [];
  const blocked =
    currentWorklist?.state === "ready" ? currentWorklist.blockedItems : [];
  const blockedTarget = requestedOccurrenceId
    ? blocked.find(
        (item) =>
          item.occurrenceId === requestedOccurrenceId &&
          (!requestedActivityId || item.activityId === requestedActivityId),
      )
    : undefined;
  const selected = requestedOccurrenceId
    ? ready.find(
        (item) =>
          item.occurrenceId === requestedOccurrenceId &&
          (!requestedActivityId || item.activityId === requestedActivityId),
      )
    : ready[0];
  const filteredReady = useMemo(
    () =>
      ready.filter((item) =>
        `${item.name} ${item.kind}`
          .toLocaleLowerCase()
          .includes(query.trim().toLocaleLowerCase()),
      ),
    [ready, query],
  );
  const workBounds = activityPageBounds(workPage, filteredReady.length);
  const visibleReady = filteredReady.slice(workBounds.start, workBounds.end);
  const currentIdentity = useRef(identityKey);
  currentIdentity.current = identityKey;
  const currentAttempt = attempt?.identity === identityKey ? attempt : null;
  const receiptCheckKey =
    currentAttempt && settlementAuthority
      ? JSON.stringify([
          settlementAuthority,
          currentAttempt.packet.body.idempotencyKey,
        ])
      : null;
  const canReplayOriginal = Boolean(
    currentAttempt &&
      settlementAuthority &&
      !currentAttempt.admissionExpired &&
      catalog?.functions[String(currentAttempt.packet.body.program.function)] &&
      (!canReadOriginalReceipt || missingReceiptCheck === receiptCheckKey),
  );
  useLayoutEffect(() => {
    const origin = startFocusOrigin.current;
    if (!origin || busy) return;
    startFocusOrigin.current = null;
    const document = origin.ownerDocument;
    if (
      document.activeElement !== origin &&
      document.activeElement !== document.body
    )
      return;
    if (startOutcome)
      return focusWhenInteractive(
        startedOccurrenceButton.current ?? resultStatus.current,
      );
    if (currentAttempt?.kind === "start")
      return focusWhenInteractive(recoveryHeading.current);
  }, [busy, currentAttempt, startOutcome]);
  const draftIdentity = useRef(identityKey);
  const ownDraft = draftIdentity.current === identityKey;
  const draftActivity = useRef<string | null>(null);
  const selectedActivity = selected
    ? reviewIdentity(
        identityKey,
        selected.occurrenceId,
        selected.activityId,
        selected.activityStateToken,
      )
    : null;
  const ownActivityDraft =
    ownDraft &&
    (selectedActivity === null || selectedActivity === draftActivity.current);
  // While recovering, the exact admitted proposal is the display owner too;
  // loading the current worklist must not blank its original reason/evidence.
  const pendingArguments = currentAttempt?.packet.body.program.arguments as
    | { reason?: unknown; evidence?: { operationId?: unknown } }
    | undefined;
  const receiptId =
    currentAttempt?.kind === "complete" &&
    typeof pendingArguments?.evidence?.operationId === "string"
      ? pendingArguments.evidence.operationId
      : ownActivityDraft
        ? storedReceiptId
        : "";
  const returnReason =
    currentAttempt?.kind === "return" &&
    typeof pendingArguments?.reason === "string"
      ? pendingArguments.reason
      : ownActivityDraft
        ? storedReturnReason
        : "";
  useEffect(() => {
    if (draftIdentity.current === identityKey) return;
    draftIdentity.current = identityKey;
    draftActivity.current = null;
    setAttempt(null);
    setReceiptId("");
    setReturnReason("");
    setInspectReceiptId("");
    setResult("");
  }, [identityKey]);
  const proposalLocked = busy || Boolean(currentAttempt);
  useEffect(
    () => setDestinationError(""),
    [selected?.occurrenceId, selected?.activityId],
  );
  useEffect(() => {
    setError("");
    if (!worklistRequest.scope || !canRead) return;
    const controller = new AbortController();
    void readCompleteWorkflowWorklist<ReadyActivity>(
      worklistRequest.scope,
      controller.signal,
      { occurrenceId: worklistRequest.occurrenceId },
    )
      .then(({ items, blockedItems }) => {
        if (controller.signal.aborted) return;
        setWorklistResult({
          request: worklistRequest,
          state: "ready",
          items,
          blockedItems,
        });
      })
      .catch((reason: Error) => {
        if (!controller.signal.aborted) {
          if (withdrawWorkflowAccess(reason)) return;
          setWorklistResult({ request: worklistRequest, state: "error" });
          setError(workflowReadError(reason));
        }
      });
    return () => controller.abort();
  }, [worklistRequest, canRead]);

  const occurrenceId = selected?.occurrenceId || requestedOccurrenceId;
  const occurrenceRequest = useMemo(
    () =>
      scope && occurrenceId && canReadOccurrence
        ? { scope, occurrenceId }
        : null,
    [
      app?.workspaceId,
      app?.applicationId,
      occurrenceId,
      refresh,
      authorityKey,
      canReadOccurrence,
      catalog?.applicationAccess.role,
      catalog?.applicationAccess.workspaceAdministrator,
      catalog?.revisions.commit,
      catalog?.revisions.capability,
    ],
  );
  const currentOccurrence =
    occurrenceResult?.request === occurrenceRequest ? occurrenceResult : null;
  const occurrence = currentOccurrence?.value ?? null;
  const history =
    historyResult?.occurrence === occurrence ? historyResult : null;
  const historyEvents = history?.events ?? occurrence?.events ?? [];
  const nextHistory = history
    ? history.next
    : (occurrence?.nextEventOrdinal ?? null);
  const historyChanged = Boolean(history?.changed);
  const canCancelOccurrence =
    occurrence?.status === "Active" &&
    !historyChanged &&
    Boolean(catalog?.functions["application.workflow.occurrence.cancel"]);
  const occurrenceLoading = Boolean(occurrenceRequest && !currentOccurrence);
  const definitionRequest = useMemo(
    () =>
      canReadDefinition && occurrenceRequest && occurrence
        ? { scope: occurrenceRequest.scope, occurrence }
        : null,
    [canReadDefinition, occurrenceRequest, occurrence],
  );
  const currentDefinition =
    definitionResult?.request === definitionRequest ? definitionResult : null;
  const definition = currentDefinition?.value ?? null;
  const definitionLoading = Boolean(definitionRequest && !currentDefinition);
  const canRefresh =
    accessNeedsRefresh || canRead || Boolean(occurrenceRequest);
  const refreshBlocked = accessNeedsRefresh
    ? checkingAccess || busy
    : worklistLoading ||
      occurrenceLoading ||
      definitionLoading ||
      proposalLocked;
  const currentError =
    accessRefusal?.message ||
    error ||
    currentOccurrence?.error ||
    currentDefinition?.error;
  useEffect(() => {
    if (!occurrenceRequest) return;
    const controller = new AbortController();
    readWorkflowOccurrencePage(
      occurrenceRequest.scope,
      occurrenceRequest.occurrenceId,
      0,
      true,
      controller.signal,
    )
      .then((value) => {
        if (!controller.signal.aborted)
          setOccurrenceResult({ request: occurrenceRequest, value });
      })
      .catch((reason: Error) => {
        if (controller.signal.aborted || withdrawWorkflowAccess(reason)) return;
        setOccurrenceResult({
          request: occurrenceRequest,
          value: null,
          error: workflowReadError(reason),
        });
      });
    return () => controller.abort();
  }, [occurrenceRequest]);

  useLayoutEffect(() => {
    setHistoryResult(null);
    return () => {
      historyRequest.current?.abort();
      historyRequest.current = null;
    };
  }, [occurrenceRequest]);

  async function loadActivityHistory() {
    if (
      !occurrence ||
      !occurrenceRequest ||
      nextHistory === null ||
      historyRequest.current
    )
      return;
    const controller = new AbortController();
    historyRequest.current = controller;
    const original = { occurrence, events: historyEvents, next: nextHistory };
    setHistoryResult({ ...original, pending: true });
    try {
      const page = await readWorkflowOccurrencePage(
        occurrenceRequest.scope,
        occurrence.occurrenceId,
        nextHistory,
        false,
        controller.signal,
      );
      if (controller.signal.aborted) return;
      if (
        page.occurrenceStateToken !== occurrence.occurrenceStateToken ||
        page.flowStateToken !== occurrence.flowStateToken ||
        page.flowId !== occurrence.flowId ||
        page.definitionDigest !== occurrence.definitionDigest ||
        page.lastEventOrdinal !== occurrence.lastEventOrdinal
      ) {
        setHistoryResult({
          ...original,
          next: null,
          changed: true,
          error:
            "The workflow occurrence changed. Refresh it before reviewing or loading more history.",
        });
        return;
      }
      setHistoryResult({
        ...original,
        events: [...historyEvents, ...page.events],
        next: page.nextEventOrdinal ?? null,
      });
    } catch (reason) {
      if (!controller.signal.aborted && !withdrawWorkflowAccess(reason))
        setHistoryResult({
          ...original,
          error: "This page of activity history could not be read. Try again.",
        });
    } finally {
      if (historyRequest.current === controller) historyRequest.current = null;
    }
  }

  useEffect(() => {
    if (!definitionRequest) return;
    const controller = new AbortController();
    const { scope, occurrence } = definitionRequest;
    readProgram<WorkflowDefinition>(
      scope,
      "application.workflow.read",
      { flowId: occurrence.flowId },
      controller.signal,
    )
      .then((value) => {
        if (!controller.signal.aborted)
          setDefinitionResult({
            request: definitionRequest,
            value: exactWorkflowDefinition(value, occurrence),
          });
      })
      .catch((reason: Error) => {
        if (!controller.signal.aborted && !withdrawWorkflowAccess(reason))
          setDefinitionResult({
            request: definitionRequest,
            value: null,
            error: reason.message,
          });
      });
    return () => controller.abort();
  }, [definitionRequest]);

  useEffect(() => {
    if (selectedActivity === null || selectedActivity === draftActivity.current)
      return;
    draftActivity.current = selectedActivity;
    setReceiptId("");
    setReturnReason("");
  }, [selectedActivity]);

  const focusedId = selected?.activityId || requestedActivityId;
  const focused = occurrence?.activities.find(
    (item) => item.activityId === focusedId,
  );
  const evidenceContract = useMemo(
    () =>
      definition?.definition.activities.find(
        (item) => item.activityId === focusedId,
      )?.evidenceContract || null,
    [definition, focusedId],
  );
  const activityDefinition = definition?.definition.activities.find(
    (item) => item.activityId === focusedId,
  );
  const currentReturn =
    !historyChanged &&
    occurrence?.status === "Active" &&
    focused?.status === "Ready"
      ? occurrence.currentReturns?.findLast((event) => {
          const evidence = reviewReturnEvidence(event);
          return (
            evidence?.targetActivityId === focused.activityId &&
            typeof event.operationId === "string" &&
            event.operationId.length > 0 &&
            occurrence.activities.some(
              (item) =>
                item.activityId === event.activityId &&
                item.kind === "Review" &&
                item.status === "Returned" &&
                item.operationId === event.operationId &&
                item.returnedToActivityId === focused.activityId,
            )
          );
        })
      : undefined;
  const returnEvidence = currentReturn && reviewReturnEvidence(currentReturn);
  const currentActivity = Boolean(
    selected &&
      occurrence &&
      definition &&
      focused &&
      !historyChanged &&
      occurrence.status === "Active" &&
      focused.status === "Ready" &&
      selected.occurrenceId === occurrence.occurrenceId &&
      selected.occurrenceStateToken === occurrence.occurrenceStateToken &&
      selected.flowId === occurrence.flowId &&
      selected.flowStateToken === occurrence.flowStateToken &&
      selected.definitionDigest === occurrence.definitionDigest &&
      selected.activityStateToken === focused.activityStateToken,
  );
  const canListEvidence = Boolean(
    catalog?.functions["application.workflow.activity.evidence.list"],
  );
  const evidenceRequest = useMemo<EvidenceListRequest | null>(() => {
    if (
      !occurrenceRequest ||
      !selected ||
      !currentActivity ||
      evidenceContract?.kind !== "OperationReceipt" ||
      !canListEvidence
    )
      return null;
    return {
      scope: occurrenceRequest.scope,
      occurrenceId: selected.occurrenceId,
      activityId: selected.activityId,
    };
  }, [
    occurrenceRequest,
    selected?.activityId,
    selected?.activityStateToken,
    currentActivity,
    evidenceContract?.kind,
    canListEvidence,
  ]);
  const activeEvidenceRequest = useRef(evidenceRequest);
  activeEvidenceRequest.current = evidenceRequest;
  const currentEvidence =
    evidenceResult?.request === evidenceRequest ? evidenceResult : null;
  const evidencePage =
    currentEvidence && currentEvidence.state !== "unavailable"
      ? currentEvidence.page
      : null;
  const evidenceLoading = Boolean(
    evidenceRequest && (!currentEvidence || currentEvidence.state === "paging"),
  );
  const evidenceChoice = evidencePage?.items.find(
    (item) => item.selectionKey === receiptId,
  );
  const evidenceReady = Boolean(
    currentActivity &&
      (evidenceContract?.kind === "ManualAttestation" ||
        (evidenceContract?.kind === "OperationReceipt" &&
          evidenceChoice &&
          (!evidenceContract.requireCurrent || evidenceChoice.current))),
  );
  const actionContextKey = JSON.stringify([
    authorityKey,
    catalog?.applicationAccess.role,
    catalog?.revisions.data,
    catalog?.revisions.commit,
    refresh,
    historyChanged,
    selected?.occurrenceId,
    selected?.activityId,
    selected?.activityStateToken,
    occurrence?.occurrenceStateToken,
    definition?.stateToken,
    receiptId,
    returnReason,
  ]);
  const startContextKey = JSON.stringify([
    authorityKey,
    settlementAuthority,
    catalog?.revisions.commit,
    refresh,
    canStart,
  ]);
  const cancelContextKey = JSON.stringify([
    settlementAuthority,
    canCancelOccurrence,
    occurrence?.occurrenceId,
    occurrence?.occurrenceStateToken,
  ]);
  const currentReviewed =
    currentActivity && reviewedContext === actionContextKey;
  // Retire an obsolete acknowledgement before committing the new controls.
  // A deferred reset can otherwise erase the first acknowledgement they receive.
  if (reviewedContext !== null && !currentReviewed) setReviewedContext(null);
  const reviewedActionContext = currentReviewed ? actionContextKey : null;
  const recovery = usePreservedDraft(
    app?.workspaceId || "",
    app?.applicationId || "",
    "workflow-action",
    currentAttempt
      ? "Workflow action with an unconfirmed outcome"
      : "Unsubmitted workflow action",
    ownDraft &&
      Boolean(
        currentAttempt ||
          currentReviewed ||
          receiptId.trim() ||
          returnReason.trim(),
      ),
    { identity: identityKey, attempt: currentAttempt, receiptId, returnReason },
    (saved) => {
      if (saved.identity !== identityKey) return;
      draftIdentity.current = identityKey;
      setAttempt(saved.attempt);
      setReceiptId(saved.receiptId);
      setReturnReason(saved.returnReason);
      setReviewedContext(null);
    },
  );
  const actionContexts = {
    start: startContextKey,
    cancel: cancelContextKey,
    complete: reviewedActionContext,
    return: reviewedActionContext,
  };
  const latestActionContexts = useRef(actionContexts);
  latestActionContexts.current = actionContexts;
  const activityDraft =
    currentReviewed || Boolean(receiptId.trim() || returnReason.trim());
  const admission = useRef<{
    kind: WorkflowAttempt["kind"];
    context: string;
    controller: AbortController;
  } | null>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      admission.current?.controller.abort();
      admission.current = null;
    };
  }, []);
  useLayoutEffect(() => {
    const pending = admission.current;
    if (
      pending &&
      pending.context !== latestActionContexts.current[pending.kind]
    ) {
      admission.current = null;
      pending.controller.abort();
      setAdmitting(false);
    }
  }, [reviewedActionContext, startContextKey, cancelContextKey]);
  const activityName = (activityId?: string | null) =>
    definition?.definition.activities.find(
      (item) => item.activityId === activityId,
    )?.name ||
    ready.find(
      (item) =>
        item.activityId === activityId &&
        item.occurrenceId ===
          (occurrence?.occurrenceId || selected?.occurrenceId),
    )?.name ||
    "Workflow activity";
  const completed =
    occurrence?.activities.filter((item) => item.status === "Completed")
      .length || 0;
  const total = occurrence?.activities.length || 0;
  const canAssessEvidence = Boolean(
    catalog?.functions[evidenceAssessmentFunction],
  );
  const activeReviewRefusal =
    currentActivity &&
    selected?.kind === "Review" &&
    reviewRefusal?.identity ===
      reviewIdentity(
        identityKey,
        selected.occurrenceId,
        selected.activityId,
        selected.activityStateToken,
      )
      ? reviewRefusal
      : null;
  const basisAuthority = JSON.stringify([
    authorityKey,
    catalog?.applicationAccess.role,
    catalog?.applicationAccess.workspaceAdministrator,
  ]);
  const basisContext = JSON.stringify([
    basisAuthority,
    catalog?.revisions.data,
    catalog?.revisions.commit,
    selected?.occurrenceId,
    selected?.activityId,
    requestedOccurrenceId,
    requestedActivityId,
    occurrence?.occurrenceStateToken,
    refresh,
    activeReviewRefusal?.version,
  ]);
  const visibleBasis =
    canAssessEvidence && basisTarget?.context === basisContext
      ? basisTarget
      : null;
  const pendingBasis =
    visibleBasis &&
    basisResults.get(visibleBasis.activityId)?.target !== visibleBasis
      ? visibleBasis
      : null;
  const reviewPrerequisites =
    currentActivity && selected?.kind === "Review" && activityDefinition
      ? new Set([...activityDefinition.dependsOn, activityDefinition.returnTo])
      : new Set<string | null>();
  const reviewBasis = canAssessEvidence
    ? (occurrence?.activities ?? []).filter(
        (item) =>
          item.status === "Completed" &&
          reviewPrerequisites.has(item.activityId),
      )
    : [];
  const checkingReviewBasis = reviewBasis.some(
    (item) => pendingBasis?.activityId === item.activityId,
  );
  function currentBasisAssessment(item: Occurrence["activities"][number]) {
    const result = basisResults.get(item.activityId);
    if (
      result?.target.authority !== basisAuthority ||
      result.target.occurrenceId !== occurrence?.occurrenceId ||
      result.target.activityStateToken !== item.activityStateToken
    )
      return undefined;
    if (result.target.context === basisContext) return result;
    if (!result.blocksReview) return undefined;
    return {
      ...result,
      message:
        "Last confirmed check found stale required evidence. Check current evidence before accepting.",
    };
  }
  const requiredBasisStale = reviewBasis.some(
    (item) => currentBasisAssessment(item)?.blocksReview,
  );
  const requiredBasisChecks = activeReviewRefusal
    ? (definition?.definition.activities ?? [])
        .filter(
          (item) =>
            reviewPrerequisites.has(item.activityId) &&
            item.evidenceContract.kind === "OperationReceipt" &&
            item.evidenceContract.requireCurrent,
        )
        .map(({ activityId }) => {
          const basis = reviewBasis.find(
            (item) => item.activityId === activityId,
          );
          return basis && currentBasisAssessment(basis)?.requiredBasisCheck;
        })
    : [];
  const awaitingRequiredBasis = Boolean(
    activeReviewRefusal &&
      (!canAssessEvidence ||
        requiredBasisChecks.length === 0 ||
        requiredBasisChecks.includes(undefined)),
  );
  const reviewBasisBlocked = requiredBasisStale || awaitingRequiredBasis;
  useEffect(() => {
    setBasisTarget(null);
    // A refresh expires positive assessments. Keep a confirmed block for the
    // same retained completion until a new check or a replacement settles it.
    const completed =
      occurrence &&
      new Map(
        occurrence.activities
          .filter((item) => item.status === "Completed")
          .map((item) => [item.activityId, item.activityStateToken]),
      );
    setBasisResults(
      (previous) =>
        new Map(
          [...previous].filter(
            ([activityId, result]) =>
              canAssessEvidence &&
              result.blocksReview &&
              result.target.authority === basisAuthority &&
              (!occurrenceId || result.target.occurrenceId === occurrenceId) &&
              (!completed ||
                completed.get(activityId) === result.target.activityStateToken),
          ),
        ),
    );
  }, [basisContext, canAssessEvidence]);
  useEffect(() => {
    if (!visibleBasis || !app) return;
    const controller = new AbortController();
    const { occurrenceId, activityId, activityStateToken } = visibleBasis;
    const settle = (assessment: EvidenceAssessment) => {
      if (controller.signal.aborted) return;
      setBasisResults((previous) => {
        const prior = previous.get(activityId);
        const stillBlocked =
          prior?.target.authority === visibleBasis.authority &&
          prior.target.occurrenceId === occurrenceId &&
          prior.target.activityStateToken === activityStateToken &&
          prior.blocksReview &&
          !assessment.blocksReview &&
          assessment.requiredBasisCheck !== "current";
        const current: EvidenceAssessment = stillBlocked
          ? {
              ...assessment,
              blocksReview: true,
              message: `${assessment.message} Accept is still blocked by the last confirmed evidence check.`,
            }
          : assessment;
        return new Map(previous).set(activityId, {
          target: visibleBasis,
          ...current,
        });
      });
    };
    void readProgram<unknown>(
      { workspaceId: app.workspaceId, applicationId: app.applicationId },
      evidenceAssessmentFunction,
      { occurrenceId, activityId },
      controller.signal,
    )
      .then((value) => {
        settle(
          parseEvidenceAssessment(
            value,
            occurrenceId,
            activityId,
            activityStateToken,
          ),
        );
      })
      .catch((reason: unknown) => {
        if (controller.signal.aborted || withdrawWorkflowAccess(reason)) return;
        settle({ message: "Current evidence could not be read. Check again." });
      });
    return () => controller.abort();
  }, [visibleBasis, app?.workspaceId, app?.applicationId]);

  function evidenceCheck(
    item: Occurrence["activities"][number],
    forReview = false,
  ) {
    if (!occurrence || !canAssessEvidence || item.status !== "Completed")
      return null;
    const message = currentBasisAssessment(item)?.message ?? "";
    const pending =
      pendingBasis?.activityId === item.activityId &&
      pendingBasis.activityStateToken === item.activityStateToken;
    return (
      <>
        <button
          type="button"
          aria-disabled={Boolean(pendingBasis) || undefined}
          aria-label={`Check current evidence for ${activityName(item.activityId)}`}
          onClick={() => {
            if (pendingBasis) return;
            if (forReview) setReviewedContext(null);
            setBasisResults((previous) => {
              const prior = previous.get(item.activityId);
              if (!prior || prior.blocksReview) return previous;
              const remaining = new Map(previous);
              remaining.delete(item.activityId);
              return remaining;
            });
            setBasisTarget({
              context: basisContext,
              authority: basisAuthority,
              occurrenceId: occurrence.occurrenceId,
              activityId: item.activityId,
              activityStateToken: item.activityStateToken,
            });
          }}
        >
          Check current evidence
        </button>
        {(pending || message) && (
          <small role="status">
            {pending ? "Checking current evidence…" : message}
          </small>
        )}
      </>
    );
  }

  useEffect(() => {
    setReceiptId("");
    if (!evidenceRequest) return;
    const controller = new AbortController();
    evidenceController.current = controller;
    const { scope, occurrenceId, activityId } = evidenceRequest;
    const isCurrent = () =>
      !controller.signal.aborted &&
      activeEvidenceRequest.current === evidenceRequest;
    void readProgram<EvidencePage>(
      scope,
      "application.workflow.activity.evidence.list",
      { occurrenceId, activityId, limit: 50 },
      controller.signal,
    )
      .then((value) => {
        if (!isCurrent()) return;
        setEvidenceResult({
          request: evidenceRequest,
          state: "ready",
          page: mergeWorkflowEvidence([], value),
        });
      })
      .catch((reason: unknown) => {
        if (!isCurrent() || withdrawWorkflowAccess(reason)) return;
        setEvidenceResult({ request: evidenceRequest, state: "unavailable" });
        setError(workflowReadError(reason));
      });
    return () => {
      controller.abort();
      evidenceController.current = null;
    };
  }, [evidenceRequest]);

  async function readOlderEvidence() {
    if (currentEvidence?.state !== "ready") return;
    const { request, page } = currentEvidence;
    const cursor = page.nextBeforeCommittedRevision;
    const controller = evidenceController.current;
    if (cursor === null || !controller) return;
    const { scope, occurrenceId, activityId } = request;
    const isCurrent = () =>
      !controller.signal.aborted && activeEvidenceRequest.current === request;
    setEvidenceResult({ request, page, state: "paging" });
    try {
      const value = await readProgram<EvidencePage>(
        scope,
        "application.workflow.activity.evidence.list",
        {
          occurrenceId,
          activityId,
          limit: 50,
          beforeCommittedRevision: cursor,
        },
        controller.signal,
      );
      if (!isCurrent()) return;
      setEvidenceResult({
        request,
        state: "ready",
        page: mergeWorkflowEvidence(page.items, value, cursor),
      });
    } catch (reason) {
      if (!isCurrent() || withdrawWorkflowAccess(reason)) return;
      setEvidenceResult(currentEvidence);
      setError(workflowReadError(reason));
    }
  }

  async function act(kind: "complete" | "return" | "cancel") {
    if (
      !scope ||
      !occurrence ||
      historyChanged ||
      proposalLocked ||
      occurrence.status !== "Active"
    )
      return;
    if (
      kind !== "cancel" &&
      (!currentActivity || checkingReviewBasis || !currentReviewed)
    )
      return;
    const functionName =
      kind === "cancel"
        ? "application.workflow.occurrence.cancel"
        : `application.workflow.activity.${kind}`;
    if (!catalog?.functions[functionName]) return;
    if (kind === "complete" && (!evidenceReady || reviewBasisBlocked)) return;
    if (
      kind === "return" &&
      (!currentActivity ||
        selected?.kind !== "Review" ||
        !activityDefinition?.returnTo)
    )
      return;
    let program: Record<string, unknown>;
    if (kind === "cancel") {
      program = {
        languageVersion: 2,
        function: "application.workflow.occurrence.cancel",
        arguments: {
          occurrenceId: occurrence.occurrenceId,
          expectedOccurrenceStateToken: occurrence.occurrenceStateToken,
        },
      };
    } else if (!selected) return;
    else if (kind === "return") {
      if (!returnReason.trim()) return;
      program = {
        languageVersion: 2,
        function: "application.workflow.activity.return",
        arguments: {
          occurrenceId: selected.occurrenceId,
          activityId: selected.activityId,
          expectedActivityStateToken: selected.activityStateToken,
          reason: returnReason.trim(),
        },
      };
    } else {
      const evidence =
        evidenceContract?.kind === "ManualAttestation"
          ? { kind: "ManualAttestation", confirmed: true }
          : evidenceContract?.kind === "OperationReceipt" && receiptId.trim()
            ? { kind: "OperationReceipt", operationId: receiptId.trim() }
            : null;
      if (!evidence) return;
      program = {
        languageVersion: 2,
        function: "application.workflow.activity.complete",
        arguments: {
          occurrenceId: selected.occurrenceId,
          activityId: selected.activityId,
          expectedActivityStateToken: selected.activityStateToken,
          evidence,
        },
      };
    }
    const confirmation =
      kind === "cancel"
        ? `Cancel occurrence ${occurrence.occurrenceId}? ${completed} of ${total} activities completed. Completed work remains recorded.`
        : `Apply reviewed workflow action: ${kind}?`;
    if (!window.confirm(confirmation)) return;
    await submitAction(
      kind,
      program,
      kind === "return"
        ? (activityDefinition?.returnTo ?? undefined)
        : undefined,
    );
  }

  function trackStartFocus(origin: HTMLButtonElement) {
    startFocusOrigin.current =
      origin.ownerDocument.activeElement === origin ? origin : null;
  }

  async function startWorkflow(
    review: WorkflowStartReview,
    origin: HTMLButtonElement,
  ) {
    if (!canStart || proposalLocked || activityDraft) return;
    if (
      !window.confirm(
        `Start an occurrence of ${review.name} (${review.flowId})?`,
      )
    )
      return;
    trackStartFocus(origin);
    return submitAction("start", {
      languageVersion: 2,
      function: WORKFLOW_START,
      arguments: {
        flowId: review.flowId,
        expectedStateToken: review.stateToken,
        expectedMetadataRevision: review.metadataRevision,
        expectedPolicyRevision: review.policyRevision,
        expectedSchemaEpoch: review.schemaEpoch,
      },
    });
  }

  async function submitAction(
    kind: WorkflowAttempt["kind"],
    program: Record<string, unknown>,
    expectedReturnTarget?: string,
  ) {
    const context = actionContexts[kind];
    if (
      context === null ||
      !scope ||
      !settlementAuthority ||
      proposalLocked ||
      admission.current
    )
      return;
    const pending = { kind, context, controller: new AbortController() };
    admission.current = pending;
    const stillCurrent = () =>
      mounted.current &&
      admission.current === pending &&
      latestActionContexts.current[kind] === pending.context;
    setAdmitting(true);
    setError("");
    setResult("");
    setStartOutcome(null);
    try {
      const packet = await prepareAdmittedProgramEffect(
        "/api/application-workflow-occurrence",
        { ...scope, program, confirmed: true },
        kind === "start"
          ? `workflow-start-${crypto.randomUUID()}`
          : workflowIntentKey({ scope, program }),
        pending.controller.signal,
      );
      if (!stillCurrent()) return;
      const captured = {
        packet,
        kind,
        identity: identityKey,
        expectedReturnTarget,
      };
      const lease = recovery.retain({
        identity: identityKey,
        attempt: captured,
        receiptId,
        returnReason,
      });
      setAttempt(captured);
      return sendOriginalAttempt(captured, lease, false);
    } catch (reason) {
      if (stillCurrent()) {
        if (withdrawWorkflowAccess(reason, initialActionAccessRefused)) return;
        const refusal = startReviewRefusal(kind, reason);
        if (refusal) return refusal;
        setError(workflowReadError(reason));
      }
    } finally {
      if (admission.current === pending) {
        admission.current = null;
        setAdmitting(false);
      }
    }
  }

  function startSettlement(kind: "send" | "receipt") {
    if (!settlementAuthority || settlementRequest.current) return null;
    const controller = new AbortController();
    settlementRequest.current = controller;
    setSettling(kind);
    setError("");
    setMissingReceiptCheck(null);
    return controller;
  }

  function finishSettlement(controller: AbortController) {
    if (settlementRequest.current !== controller) return;
    settlementRequest.current = null;
    setSettling(null);
  }

  function confirmOriginalAttempt(
    captured: WorkflowAttempt,
    outcome: Record<string, unknown>,
    lease: DraftRecoveryLease,
  ) {
    recovery.release(lease, {
      identity: identityKey,
      attempt: null,
      receiptId: "",
      returnReason: "",
    });
    setAttempt(null);
    setResult(
      captured.kind === "start"
        ? "Workflow start recorded."
        : `Original workflow ${captured.kind === "complete" ? "completion" : captured.kind} recorded. Status at commit: ${String(outcome.status)}.`,
    );
    if (captured.kind === "start")
      setStartOutcome({
        occurrenceId: String(outcome.occurrenceId),
        operationId: captured.packet.body.idempotencyKey,
      });
    else setInspectReceiptId(captured.packet.body.idempotencyKey);
    setReviewedContext(null);
    setReceiptId("");
    setReturnReason("");
    setRefresh((value) => value + 1);
  }

  async function sendOriginalAttempt(
    captured: WorkflowAttempt,
    lease: DraftRecoveryLease | null,
    wasUncertain = true,
  ) {
    if (
      captured.identity !== identityKey ||
      !mounted.current ||
      (wasUncertain && !canReplayOriginal)
    )
      return;
    const controller = startSettlement("send");
    if (!controller) return;
    const settlementIsCurrent = () =>
      !controller.signal.aborted &&
      mounted.current &&
      currentIdentity.current === captured.identity;
    try {
      if (!lease)
        throw new Error(
          "The original workflow recovery record is unavailable. No new request was sent.",
        );
      lease = recovery.retain(
        { identity: identityKey, attempt: captured, receiptId, returnReason },
        lease,
      );
      const response = await replayAdmittedEffect<{
        result: Record<string, unknown>;
      }>(captured.packet, controller.signal);
      if (!settlementIsCurrent()) return;
      const result = response.result;
      if (
        !result ||
        result.operationId !== captured.packet.body.idempotencyKey ||
        !confirmsWorkflowOutcome(captured, result)
      )
        throw new Error(
          "The workflow response did not confirm the original action. Its outcome remains unknown.",
        );
      confirmOriginalAttempt(captured, result, lease);
    } catch (reason) {
      if (!settlementIsCurrent()) return;
      if (
        !wasUncertain &&
        (isDefiniteEffectRefusal(reason, initialWorkflowRefusalCodes) ||
          (reason instanceof ApiError &&
            reason.retryable !== true &&
            isApplicationAccessDenied(reason)))
      ) {
        try {
          if (lease)
            recovery.release(
              lease,
              { identity: identityKey, attempt: null, receiptId, returnReason },
              Boolean(receiptId.trim() || returnReason.trim()),
            );
          setAttempt(null);
          setReviewedContext(null);
          if (withdrawWorkflowAccess(reason, initialActionAccessRefused))
            return;
          const startRefusal = startReviewRefusal(captured.kind, reason);
          if (startRefusal) return startRefusal;
          const refusal =
            captured.kind === "complete" &&
            Object.hasOwn(reviewRefusalMessages, reason.code) &&
            reviewRefusalMessages[reason.code];
          if (refusal) {
            const args = captured.packet.body.program.arguments as Record<
              string,
              unknown
            >;
            setReviewRefusal((previous) => ({
              identity: reviewIdentity(
                captured.identity,
                args.occurrenceId,
                args.activityId,
                args.expectedActivityStateToken,
              ),
              message: refusal,
              version: (previous?.version ?? 0) + 1,
            }));
            return;
          }
        } catch (changed) {
          setError(
            changed instanceof Error ? changed.message : String(changed),
          );
          return; // A newer recovery record retains its own outcome and intent.
        }
        setError(workflowReadError(reason));
        return;
      }
      if (
        wasUncertain &&
        lease &&
        reason instanceof ApiError &&
        reason.code === "OPERATION_ADMISSION_EXPIRED"
      ) {
        const expired: WorkflowAttempt = {
          ...captured,
          admissionExpired: true,
        };
        try {
          recovery.retain(
            {
              identity: identityKey,
              attempt: expired,
              receiptId,
              returnReason,
            },
            lease,
          );
          setAttempt(expired);
        } catch (changed) {
          setError(
            changed instanceof Error ? changed.message : String(changed),
          );
        }
        return;
      }
      // A denial after an earlier unconfirmed send is not evidence that no effect occurred.
      if (withdrawWorkflowAccess(reason, originalOutcomeAccessChanged)) return;
      setError(
        !wasUncertain && reason instanceof ApiError
          ? "The response did not confirm the original workflow action. Check its receipt before starting another action."
          : reason instanceof Error
            ? reason.message
            : String(reason),
      );
    } finally {
      finishSettlement(controller);
    }
  }

  async function inspectOriginalReceipt() {
    if (!currentAttempt || !scope || busy || !canReadOriginalReceipt) return;
    const captured = currentAttempt;
    const lease = recovery.lease;
    const controller = startSettlement("receipt");
    if (!controller) return;
    const settlementIsCurrent = () =>
      !controller.signal.aborted &&
      mounted.current &&
      currentIdentity.current === captured.identity;
    try {
      const value = await readProgram<unknown>(
        scope,
        workflowReceiptFunction,
        { operationId: captured.packet.body.idempotencyKey },
        controller.signal,
      );
      if (!settlementIsCurrent()) return;
      const receipt = exactOperationReceipt(
        value,
        captured.packet.body.idempotencyKey,
      );
      if (!confirmsWorkflowOutcome(captured, receipt.outcome, true))
        throw new Error(
          "The receipt does not confirm this original workflow action.",
        );
      if (!lease)
        throw new Error(
          "The original workflow recovery record is unavailable.",
        );
      confirmOriginalAttempt(captured, receipt.outcome, lease);
    } catch (reason) {
      if (settlementIsCurrent()) {
        if (withdrawWorkflowAccess(reason, originalOutcomeAccessChanged))
          return;
        if (
          reason instanceof ApiError &&
          reason.code === "OPERATION_RECEIPT_NOT_FOUND"
        ) {
          setMissingReceiptCheck(receiptCheckKey);
          setError(
            "No workflow receipt is visible yet. The original outcome remains unconfirmed.",
          );
        } else
          setError(
            reason instanceof ApiError
              ? outcomeReadError(reason)
              : reason instanceof Error
                ? reason.message
                : String(reason),
          );
      }
    } finally {
      finishSettlement(controller);
    }
  }

  async function copyOriginalReceiptCheck() {
    if (
      !currentAttempt ||
      !scope ||
      busy ||
      !canReadOriginalReceipt ||
      !receiptCheckKey
    )
      return;
    let message = "Receipt check copied for your MCP client.";
    try {
      await copyOperationReceiptCheck(
        scope,
        currentAttempt.packet.body.idempotencyKey,
      );
    } catch {
      message = "The workflow receipt check could not be copied.";
    }
    setReceiptHandoff({ key: receiptCheckKey, message });
  }

  async function refreshWorkflowAccess() {
    if (!onRefreshCatalog) {
      setRefresh((value) => value + 1);
      return;
    }
    setCheckingAccess(true);
    try {
      await onRefreshCatalog();
      if (mounted.current && currentAuthority.current === confirmedAuthority)
        setRefresh((value) => value + 1);
    } catch {
      // Keep the last workflow projection withdrawn while access is unconfirmed.
    } finally {
      if (mounted.current) setCheckingAccess(false);
    }
  }

  return (
    <div className="page guided-page" ref={workflowPage}>
      <div className="page-heading">
        <div>
          <small>{app?.name || "Application"}</small>
          <h1>Workflow</h1>
          <p>
            Find your assigned work, open the model task and review its evidence
            before completing the activity.
          </p>
          <p>
            Assignment identifies responsibility; it does not grant access to
            model data. Technical completion alone does not accept a business
            review.
          </p>
        </div>
        <button
          ref={refreshButton}
          type="button"
          disabled={!canRefresh}
          aria-disabled={canRefresh && refreshBlocked ? true : undefined}
          onClick={() => {
            if (!canRefresh || refreshBlocked) return;
            if (accessNeedsRefresh) {
              void refreshWorkflowAccess();
              return;
            }
            onRequestTransition(() => {
              if (!canAssessEvidence && activeReviewRefusal)
                setReviewRefusal(null);
              setRefresh((value) => value + 1);
            });
          }}
        >
          {checkingAccess ? "Checking workflow access…" : "Refresh workflow"}
        </button>
      </div>
      {currentError && (
        <div className="alert" role="alert">
          {currentError}
        </div>
      )}
      {currentAttempt && (
        <section className="panel" aria-label="Original workflow action">
          <h2 ref={recoveryHeading} tabIndex={-1}>
            {settling === "send"
              ? "Submitting original workflow action"
              : "Workflow outcome unknown"}
          </h2>
          {settling === "receipt" && (
            <p role="status">Reading original workflow receipt…</p>
          )}
          <p>
            The exact original {currentAttempt.kind} proposal and admitted
            identity are retained in this tab. Reconcile them before changing
            this proposal; a lost response does not mean that nothing happened.
          </p>
          <button
            disabled={busy || !canReadOriginalReceipt}
            onClick={(event) => {
              if (currentAttempt.kind === "start")
                trackStartFocus(event.currentTarget);
              void inspectOriginalReceipt();
            }}
          >
            Read original workflow receipt
          </button>
          {canReadOriginalReceipt && (
            <button
              type="button"
              disabled={busy}
              onClick={() => void copyOriginalReceiptCheck()}
            >
              Copy workflow receipt check for MCP
            </button>
          )}
          {receiptHandoff &&
            receiptHandoff.key === receiptCheckKey &&
            canReadOriginalReceipt && (
              <p role="status">{receiptHandoff.message}</p>
            )}
          <button
            disabled={busy || !canReplayOriginal || !recovery.lease}
            onClick={(event) => {
              if (currentAttempt.kind === "start")
                trackStartFocus(event.currentTarget);
              void sendOriginalAttempt(currentAttempt, recovery.lease);
            }}
          >
            Reconcile original workflow action
          </button>
          <p>
            {currentAttempt.admissionExpired
              ? "The original workflow admission expired. Check its receipt again."
              : canReadOriginalReceipt
                ? "Check the receipt first. If no receipt is visible, you can reconcile the original request when the action is available to you."
                : "Reconciliation submits the same original admitted request under your current access."}
          </p>
        </section>
      )}
      {result && (
        <p ref={resultStatus} role="status" tabIndex={-1}>
          {result}
        </p>
      )}
      {result && startOutcome && (
        <>
          {canReadOccurrence && openOccurrence && (
            <button
              ref={startedOccurrenceButton}
              type="button"
              onClick={() => openOccurrence(startOutcome.occurrenceId)}
            >
              Open started occurrence
            </button>
          )}
          {canReadOriginalReceipt && (
            <button
              type="button"
              onClick={() => setInspectReceiptId(startOutcome.operationId)}
            >
              View start receipt
            </button>
          )}
        </>
      )}
      {scope && canStart && (
        <WorkflowStarter
          key={startContextKey}
          scope={scope}
          blocked={proposalLocked}
          activityDraft={activityDraft}
          onStart={startWorkflow}
        />
      )}
      <section className="context-ribbon" aria-label="Workflow summary">
        <div>
          <small>READY NOW</small>
          <strong>{worklistRead ? ready.length : "—"}</strong>
        </div>
        <div>
          <small>COMPLETED STEPS</small>
          <strong>{occurrence ? completed : "—"}</strong>
        </div>
        <div>
          <small>TOTAL STEPS</small>
          <strong>{occurrence ? total : "—"}</strong>
        </div>
        <div>
          <small>STATUS</small>
          <strong>{occurrence?.status || "—"}</strong>
        </div>
      </section>
      <div className="guided-layout">
        <section className="panel journey-panel">
          <div className="section-title">
            <div>
              <h2>Ready activities</h2>
              <p>
                {targetOccurrenceId
                  ? "Work currently assigned to you in this occurrence."
                  : "Only work currently assigned to your verified identity appears here."}
              </p>
            </div>
            {targetOccurrenceId && openMyWork && (
              <button className="secondary-link" onClick={openMyWork}>
                Open My Work
              </button>
            )}
          </div>
          {blocked.length > 0 && (
            <p role="status">
              {blocked.length}{" "}
              {blocked.length === 1 ? "activity needs" : "activities need"}{" "}
              administrator review.
              {!targetOccurrenceId && openMyWork && (
                <button className="secondary-link" onClick={openMyWork}>
                  Open My Work
                </button>
              )}
            </p>
          )}
          <label className="workflow-activity-filter">
            Find an activity
            <input
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setWorkPage(0);
              }}
              placeholder="Name, workflow or assignment"
            />
          </label>
          <ActivityPagination
            bounds={workBounds}
            label="Ready"
            empty={
              worklistRead
                ? "0 activities"
                : checkingWorklist || worklistLoading
                  ? "Checking activity count…"
                  : "Activity count unavailable"
            }
            onPage={setWorkPage}
          />
          <div
            className="assignment-list"
            aria-busy={checkingWorklist || worklistLoading}
          >
            {visibleReady.map((item) => (
              <button
                disabled={proposalLocked}
                key={`${item.occurrenceId}/${item.activityId}`}
                aria-label={`Open activity ${item.name}`}
                className={
                  selected?.occurrenceId === item.occurrenceId &&
                  selected.activityId === item.activityId
                    ? "assignment-card active"
                    : "assignment-card"
                }
                aria-pressed={
                  selected?.occurrenceId === item.occurrenceId &&
                  selected.activityId === item.activityId
                }
                onClick={() => {
                  if (
                    selected?.occurrenceId === item.occurrenceId &&
                    selected.activityId === item.activityId
                  )
                    return;
                  onRequestTransition(() =>
                    setChosenActivity({
                      context: choiceContext,
                      occurrenceId: item.occurrenceId,
                      activityId: item.activityId,
                    }),
                  );
                }}
              >
                <span>Assigned to you</span>
                <strong>{item.name}</strong>
                <p>{item.kind} activity</p>
                <small>{item.kind} · current assigned state</small>
              </button>
            ))}
            {!visibleReady.length && (
              <div className="empty-state" role="status">
                {!app
                  ? "Choose an application to see assigned activities."
                  : !catalog
                    ? catalogueUnavailable
                      ? "Access to assigned activities could not be confirmed."
                      : "Checking access to assigned activities…"
                    : !canRead
                      ? canReadOccurrence
                        ? "Assigned activities are unavailable in this application context."
                        : "Generic application workflows are unavailable in the current application context."
                      : worklistLoading
                        ? "Loading assigned activities…"
                        : currentWorklist?.state === "error"
                          ? "Assigned activities could not be loaded. Refresh to retry."
                          : ready.length
                            ? "No activities match this search."
                            : targetOccurrenceId
                              ? "No workflow activity in this occurrence is ready for you now."
                              : "No generic workflow activity is ready for you now."}
              </div>
            )}
          </div>
        </section>
        <aside className="panel task-companion">
          <small>WORK COMPANION</small>
          <h2>
            {selected?.name ||
              blockedTarget?.name ||
              (focusedId
                ? activityName(focusedId)
                : canCancelOccurrence
                  ? "Workflow occurrence"
                  : "Choose an activity")}
          </h2>
          {blockedTarget && (
            <p role="status">{blockedWorkflowDetail(blockedTarget)}</p>
          )}
          {occurrence && focused ? (
            <>
              <p>
                {definition?.definition.name || "Assigned workflow"} ·{" "}
                {occurrence.status}
              </p>
              <div className="progress-label">
                <strong>
                  {completed} of {total} completed
                </strong>
                <span>{occurrence.status}</span>
              </div>
              <progress value={completed} max={Math.max(total, 1)} />
              {selected && currentActivity && (
                <section className="workflow-destination">
                  <h3>Configured destination</h3>
                  <p>
                    {selected.destination.kind === "CubeView"
                      ? `Pinned cube view ${String(selected.destination.viewId)}`
                      : selected.destination.kind === "Artifact"
                        ? `${String(selected.destination.artifactKind)} ${String(selected.destination.artifactId)}`
                        : selected.destination.kind === "Function"
                          ? `Function ${String(selected.destination.function)}`
                          : "This destination type is not supported by the browser."}
                  </p>
                  <button
                    type="button"
                    disabled={!openDestination || proposalLocked}
                    onClick={() => {
                      const failure = openDestination?.(selected.destination, {
                        occurrenceId: selected.occurrenceId,
                        activityId: selected.activityId,
                      });
                      setDestinationError(failure || "");
                    }}
                  >
                    Open governed destination
                  </button>
                  {destinationError && (
                    <p className="inline-error" role="alert">
                      {destinationError}
                    </p>
                  )}
                </section>
              )}
              <ol className="step-list">
                {occurrence.activities.map((item, position) => (
                  <li
                    key={item.activityId}
                    className={
                      item.activityId === focusedId
                        ? "current"
                        : item.status === "Completed"
                          ? "complete"
                          : ""
                    }
                  >
                    <b>{position + 1}</b>
                    <span>
                      <strong>{activityName(item.activityId)}</strong>
                      <small>
                        {item.kind} ·{" "}
                        {blockedTarget?.activityId === item.activityId
                          ? "Blocked for review"
                          : item.status}
                        {item.status === "Completed" && item.completedAt
                          ? ` · ${new Date(item.completedAt).toLocaleString()}`
                          : ""}
                      </small>
                      {!reviewBasis.includes(item) && evidenceCheck(item)}
                    </span>
                  </li>
                ))}
              </ol>
              {currentReturn && returnEvidence && (
                <section aria-label="Return instructions">
                  <h3>Return instructions</h3>
                  <p>
                    {activityName(currentReturn.activityId)} returned this
                    activity for correction.
                  </p>
                  <p className="workflow-return-reason">
                    {returnEvidence.reason}
                  </p>
                </section>
              )}
              {activityDefinition && (
                <section aria-label="Activity responsibility and evidence">
                  <h3>Activity requirements</h3>
                  {!blockedTarget && (
                    <p>
                      {selected
                        ? `Assigned to your verified identity for this ${selected.kind.toLowerCase()} activity.`
                        : worklistRead
                          ? "This activity is not currently ready and assigned to you."
                          : checkingWorklist || worklistLoading
                            ? "Checking whether this activity is currently assigned to you…"
                            : "The current assignment for this activity could not be confirmed."}
                    </p>
                  )}
                  <p>
                    Prerequisites:{" "}
                    {activityDefinition.dependsOn.length
                      ? activityDefinition.dependsOn
                          .map(
                            (id) =>
                              `${activityName(id)} (${occurrence.activities.find((item) => item.activityId === id)?.status || "Unavailable"})`,
                          )
                          .join(", ")
                      : "No preceding activities required."}
                  </p>
                  {activityDefinition.returnTo && (
                    <p>
                      Configured return target:{" "}
                      {activityName(activityDefinition.returnTo)}.
                    </p>
                  )}
                  {focused.returnedToActivityId && (
                    <p>
                      Returned work is with{" "}
                      {activityName(focused.returnedToActivityId)}. The same
                      occurrence retains the remaining obligation.
                    </p>
                  )}
                  {evidenceContract?.kind === "ManualAttestation" ? (
                    <p>Manual attestation: {evidenceContract.statement}</p>
                  ) : evidenceContract?.kind === "OperationReceipt" ? (
                    <>
                      <p>
                        Required evidence: a permitted committed operation
                        receipt for this exact activity.
                      </p>
                      <p>
                        Allowed actions:{" "}
                        {evidenceContract.allowedFunctions
                          .map((name) =>
                            name === "application.rule.run"
                              ? "Application rule run"
                              : name === "facts.numeric.batch"
                                ? "Numeric data update"
                                : name === "facts.expression.calculate"
                                  ? "Calculated result"
                                  : name,
                          )
                          .join(", ")}
                        .
                      </p>
                      <p>
                        {evidenceContract.requireCurrent
                          ? "This activity requires current evidence. Currentness is rechecked when completing it."
                          : "This activity's authored contract permits historical receipts. Currentness is not a condition of completion."}
                      </p>
                      {evidenceChoice && (
                        <p role="status">
                          Selected evidence: {evidenceChoice.label}.{" "}
                          {evidenceChoice.current
                            ? "Current at last check."
                            : "Historical at last check."}{" "}
                          Completion rechecks the configured requirement.
                        </p>
                      )}
                    </>
                  ) : (
                    <p>
                      Evidence requirement unavailable. Refresh before taking
                      action.
                    </p>
                  )}
                </section>
              )}
              {!canReadDefinition && (
                <p role="status">
                  Workflow definition reads are unavailable in this application
                  context.
                </p>
              )}
              {selected && canReadDefinition && !currentActivity && (
                <p role="status">
                  {definitionLoading
                    ? "Checking the current workflow definition…"
                    : definition
                      ? "The assigned activity no longer matches the current workflow. Refresh the workflow before taking action."
                      : "The current workflow definition could not be verified. Refresh the workflow to retry."}
                </p>
              )}
              {reviewBasis.length > 0 && (
                <section
                  aria-label="Evidence for this review"
                  className="workflow-review-evidence"
                >
                  <h3>Evidence for this review</h3>
                  <ul className="timeline-list">
                    {reviewBasis.map((item) => (
                      <li key={item.activityId}>
                        <span>{activityName(item.activityId)}</span>
                        {evidenceCheck(item, true)}
                      </li>
                    ))}
                  </ul>
                </section>
              )}
              {selected && (
                <div
                  className="workflow-actions"
                  aria-label="Reviewed generic workflow actions"
                >
                  <h3>Reviewed actions</h3>
                  {awaitingRequiredBasis && activeReviewRefusal && (
                    <div className="alert" role="alert">
                      <p>{activeReviewRefusal.message}</p>
                      <p>
                        {canAssessEvidence
                          ? "Check each required prerequisite before accepting this review again."
                          : "Refresh the workflow and review the activity again."}
                      </p>
                    </div>
                  )}
                  {!reviewBasisBlocked &&
                    requiredBasisChecks.includes("unknown") && (
                      <p role="status">
                        Some evidence could not be verified. Submitting the
                        review checks it again.
                      </p>
                    )}
                  {evidenceContract?.kind === "OperationReceipt" && (
                    <>
                      <label>
                        <span>Completion evidence</span>
                        <select
                          value={evidenceChoice?.selectionKey || ""}
                          disabled={
                            evidenceLoading || !evidencePage || proposalLocked
                          }
                          onChange={(event) => {
                            setReceiptId(event.target.value);
                          }}
                        >
                          <option value="">Choose completed activity</option>
                          {evidencePage?.items.map((option) => (
                            <option
                              key={option.selectionKey}
                              value={option.selectionKey}
                              disabled={
                                evidenceContract.requireCurrent &&
                                !option.current
                              }
                            >
                              {option.label} ·{" "}
                              {new Date(option.occurredAt).toLocaleString()} ·{" "}
                              {option.outcome} ·{" "}
                              {option.current
                                ? "Current at last check"
                                : "Historical at last check"}
                            </option>
                          ))}
                        </select>
                      </label>
                      {evidenceLoading && (
                        <p role="status">Loading completed activities…</p>
                      )}
                      {currentEvidence?.state === "ready" &&
                        !currentEvidence.page.items.length && (
                          <p role="status">
                            No eligible completed activity is available for this
                            workflow step.
                          </p>
                        )}
                      {currentEvidence?.state === "unavailable" && (
                        <p role="status">
                          Completion evidence is unavailable. Refresh the
                          workflow to retry the read.
                        </p>
                      )}
                      {currentActivity && !canListEvidence && (
                        <p role="status">
                          The current application catalogue does not include a
                          completion evidence list for this activity.
                        </p>
                      )}
                      {evidencePage?.nextBeforeCommittedRevision != null && (
                        <button
                          type="button"
                          disabled={evidenceLoading || proposalLocked}
                          onClick={() => void readOlderEvidence()}
                        >
                          Load older completed activity
                        </button>
                      )}
                      <button
                        type="button"
                        disabled={!evidenceChoice}
                        onClick={() => {
                          if (evidenceChoice)
                            setInspectReceiptId(evidenceChoice.selectionKey);
                        }}
                      >
                        Inspect receipt before completion
                      </button>
                    </>
                  )}
                  {selected.kind === "Review" && (
                    <label>
                      <span>Return reason</span>
                      <textarea
                        disabled={proposalLocked}
                        value={returnReason}
                        onChange={(event) => {
                          setReturnReason(event.target.value);
                        }}
                      />
                    </label>
                  )}
                  <label>
                    <input
                      type="checkbox"
                      disabled={
                        !currentActivity ||
                        proposalLocked ||
                        checkingReviewBasis
                      }
                      checked={currentReviewed}
                      onChange={(event) =>
                        setReviewedContext(
                          event.target.checked ? actionContextKey : null,
                        )
                      }
                    />
                    I reviewed this exact activity, evidence requirement and
                    current occurrence state.
                  </label>
                  <button
                    className="primary-action"
                    disabled={
                      proposalLocked ||
                      !currentReviewed ||
                      !evidenceReady ||
                      reviewBasisBlocked ||
                      !catalog?.functions[
                        "application.workflow.activity.complete"
                      ]
                    }
                    onClick={() => void act("complete")}
                  >
                    {selected.kind === "Review"
                      ? "Accept review"
                      : "Complete activity"}
                  </button>
                  {selected.kind === "Review" && (
                    <button
                      className="secondary-action"
                      disabled={
                        proposalLocked ||
                        !currentReviewed ||
                        !returnReason.trim() ||
                        !currentActivity ||
                        !activityDefinition?.returnTo ||
                        !catalog?.functions[
                          "application.workflow.activity.return"
                        ]
                      }
                      onClick={() => void act("return")}
                    >
                      Return to{" "}
                      {activityDefinition?.returnTo
                        ? activityName(activityDefinition.returnTo)
                        : "configured predecessor"}
                    </button>
                  )}
                </div>
              )}
            </>
          ) : !canCancelOccurrence ? (
            <p role="status">
              {app && occurrenceId && !catalog
                ? catalogueUnavailable
                  ? "Access to this workflow occurrence could not be confirmed."
                  : "Checking access to this workflow occurrence…"
                : occurrenceId && catalog && !canReadOccurrence
                  ? "Workflow occurrence reads are unavailable in this application context."
                  : occurrenceLoading
                    ? "Loading the requested workflow occurrence…"
                    : currentOccurrence?.error
                      ? "The requested workflow occurrence could not be read. Refresh to check its current status."
                      : requestedActivityId && occurrence
                        ? "The requested activity is unavailable in this occurrence."
                        : "Select assigned work to inspect its authoritative occurrence."}
            </p>
          ) : null}
          {occurrence && canCancelOccurrence && (
            <section
              aria-label="Occurrence administration"
              className="workflow-actions"
            >
              <h3>Occurrence administration</h3>
              <p>
                {definition?.definition.name || occurrence.flowId} ·{" "}
                {occurrence.status} · {completed} of {total} activities
                completed
              </p>
              <button
                className="danger-action"
                disabled={proposalLocked}
                onClick={() => void act("cancel")}
              >
                Cancel occurrence
              </button>
            </section>
          )}
        </aside>
      </div>
      {occurrence && (
        <section className="panel progress-panel" aria-label="Activity history">
          <div className="section-title">
            <div>
              <h2>Activity history</h2>
              <p>Recorded transitions for this workflow occurrence.</p>
            </div>
          </div>
          <ol className="timeline-list">
            {historyEvents.map((event) => {
              const returned = reviewReturnEvidence(event);
              return (
                <li key={event.ordinal}>
                  <b>{returned ? "Review returned" : event.eventType}</b>
                  <div>
                    <span>{activityName(event.activityId)}</span>
                    {returned && (
                      <>
                        <p>
                          Returned to {activityName(returned.targetActivityId)}
                        </p>
                        <p className="workflow-return-reason">
                          {returned.reason}
                        </p>
                      </>
                    )}
                  </div>
                  <small>{new Date(event.createdAt).toLocaleString()}</small>
                </li>
              );
            })}
          </ol>
          {history?.error && <p role="alert">{history.error}</p>}
          {occurrence.nextEventOrdinal != null && (
            <button
              type="button"
              aria-disabled={Boolean(history?.pending || nextHistory === null)}
              onClick={() => void loadActivityHistory()}
            >
              {history?.pending
                ? "Loading activity history…"
                : nextHistory !== null
                  ? "Load more activity history"
                  : historyChanged
                    ? "Refresh required to load more history"
                    : "All activity history loaded"}
            </button>
          )}
        </section>
      )}
      {scope && inspectReceiptId && (
        <ReceiptInspector
          scope={scope}
          catalog={catalog}
          operationId={inspectReceiptId}
          title={
            inspectReceiptId === startOutcome?.operationId
              ? "Workflow start receipt"
              : undefined
          }
          close={() => setInspectReceiptId("")}
        />
      )}
    </div>
  );
}
