import {
  act,
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import axe from "axe-core";
import { Profiler } from "react";
import { afterEach, expect, it, vi } from "vitest";
import {
  GenericWorkflow,
  genericWorkflowActionBody,
  mergeWorkflowEvidence,
} from "./GenericWorkflow";
import { operationAdmissionResponse } from "./test-setup";
import {
  discardUnsavedWork,
  usePreservedDraft,
  unsavedWorkSnapshot,
  setDraftIdentity,
} from "./unsaved-work";

afterEach(() => {
  vi.unstubAllGlobals();
  discardUnsavedWork();
});

const app = {
  workspaceId: "ws",
  applicationId: "cube",
  name: "Cube",
  status: "Active",
};
const occurrenceToken = "1".repeat(64);
const activityToken = "2".repeat(64);
const flowToken = "3".repeat(64);
const catalog = {
  applicationAccess: { role: "Reader", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "application.workflow.worklist": {},
    "application.workflow.read": {},
    "application.workflow.occurrence.read": {},
    "application.workflow.activity.evidence.list": {},
    "application.workflow.activity.complete": {},
    "application.workflow.activity.return": {},
  },
  revisions: { metadata: 1, data: 2, policy: 3, security: 4, commit: 5 },
};

function reviewFixture(
  options: {
    requireCurrent?: boolean;
    current?: boolean;
    changedDefinition?: boolean;
    definitionUnavailable?: boolean;
    blockedReview?: boolean;
    deferEffect?: boolean;
    deferReceipt?: boolean;
    firstReceiptMissing?: boolean;
    failEvidence?: boolean;
    deferEvidence?: boolean;
    loseResponse?: boolean;
    replayDenied?: boolean;
    refuseWorkflowAuthority?: boolean;
    assessment?: "current" | "stale" | "deferred";
    assessmentBasis?: "RulePublication" | "CalculationPublication";
    assessmentRequiresCurrent?: boolean;
    multipleBases?: boolean;
    refuseReviewBasis?: { suffix: "STALE" | "UNAVAILABLE"; message: string };
    assessmentAfterRefusal?: "stale" | "unavailable";
    returnHistory?: "active" | "resolved" | "different-operation";
    returnAcknowledgement?: Record<string, unknown>;
    returnReceiptTarget?: string;
    unassigned?: boolean;
    startable?: boolean;
    pagedWorkflows?: boolean;
    historyPages?: "stable" | "changed" | "authority";
    refuseStart?: {
      phase: "admission" | "effect";
      code:
        | "APPLICATION_WORKFLOW_STALE_CONTEXT"
        | "APPLICATION_WORKFLOW_CURRENT_UNAVAILABLE"
        | "APPLICATION_WORKFLOW_RECEIPT_CONTRACT_UNSUPPORTED"
        | "APPLICATION_WORKFLOW_EVIDENCE_VIEW_SCOPE_MISMATCH"
        | "APPLICATION_FUNCTION_RETIRED"
        | "ORDERED_RULE_CURRENT_OWNER_UNSUPPORTED";
    };
    deferAdmission?: boolean;
    deferDefinition?: boolean;
    extraReadyActivities?: number;
  } = {},
) {
  const occurrenceId = "1".repeat(32);
  const isRework =
    options.returnHistory === "active" ||
    options.returnHistory === "different-operation";
  const ready = [
    { activityId: "prepare", name: "Prepare capacity", kind: "Action" },
    { activityId: "review", name: "Review capacity", kind: "Review" },
  ].map((item) => ({
    ...item,
    occurrenceId,
    occurrenceStateToken: occurrenceToken,
    flowId: "capacity",
    flowStateToken: flowToken,
    definitionDigest: "a".repeat(64),
    activityStateToken: activityToken,
    destination: {
      kind: "Function",
      function: "application.rule.run",
      argumentsDigest: "d".repeat(64),
    },
    assignmentResolution: {
      assignmentId: "capacity-assignment",
      kind: item.kind,
    },
  }));
  ready.push(
    ...Array.from(
      { length: options.extraReadyActivities ?? 0 },
      (_, index) => ({
        ...ready[1],
        occurrenceId: (index + 2).toString(16).padStart(32, "0"),
        name: `Additional review ${index + 1}`,
      }),
    ),
  );
  const activities = [
    {
      activityId: "prior",
      name: "Prior preparation",
      kind: "Action",
      dependsOn: [],
      returnTo: null,
      evidenceContract: options.assessment
        ? {
            kind: "OperationReceipt",
            allowedFunctions: [
              options.assessmentBasis === "RulePublication"
                ? "application.rule.run"
                : options.assessmentBasis === "CalculationPublication"
                  ? "facts.expression.calculate"
                  : "facts.numeric.batch",
            ],
            requireCurrent: options.assessmentRequiresCurrent ?? true,
          }
        : {
            kind: "ManualAttestation",
            statement: "Prior preparation checked",
          },
    },
    {
      activityId: "prepare",
      name: "Prepare capacity",
      kind: "Action",
      dependsOn: [],
      returnTo: null,
      evidenceContract: {
        kind: "OperationReceipt",
        allowedFunctions: ["application.rule.run"],
        requireCurrent: options.requireCurrent ?? true,
      },
    },
    {
      activityId: "review",
      name: "Review capacity",
      kind: "Review",
      dependsOn: options.multipleBases ? ["prior", "validation"] : ["prior"],
      returnTo: "prior",
      evidenceContract: {
        kind: "ManualAttestation",
        statement: "I accept the submitted capacity evidence",
      },
    },
  ];
  if (options.multipleBases) {
    activities.push({
      activityId: "validation",
      name: "Validate capacity",
      kind: "Action",
      dependsOn: [],
      returnTo: null,
      evidenceContract: {
        kind: "OperationReceipt",
        allowedFunctions: ["facts.numeric.batch"],
        requireCurrent: false,
      },
    });
  }
  const calls: { url: string; body: any }[] = [];
  let finishEffect: ((response: Response) => void) | undefined;
  let finishAdmission: (() => void) | undefined;
  let finishDefinition: (() => void) | undefined;
  let finishReceipt: (() => void) | undefined;
  let nextAccessRefusal: { path: string; code: string; status: number } | null =
    null;
  let pendingReceiptSignal: AbortSignal | null | undefined;
  const pendingEvidence: {
    signal: AbortSignal | null | undefined;
    complete: (response: Response) => void;
  }[] = [];
  let finishAssessment: ((response: Response) => void) | undefined;
  let deferNextAssessment = false;
  let effectBody: any;
  let effectCount = 0;
  let returnReceiptTarget = options.returnReceiptTarget ?? "prior";
  let startRefused = false;
  function startRefusal(phase: "admission" | "effect", functionName: string) {
    if (
      !startRefused &&
      options.refuseStart?.phase === phase &&
      functionName === "application.workflow.occurrence.start"
    ) {
      startRefused = true;
      return new Response(JSON.stringify({ code: options.refuseStart.code }), {
        status:
          options.refuseStart.code ===
            "APPLICATION_WORKFLOW_RECEIPT_CONTRACT_UNSUPPORTED" ||
          options.refuseStart.code ===
            "APPLICATION_WORKFLOW_EVIDENCE_VIEW_SCOPE_MISMATCH"
            ? 422
            : 400,
      });
    }
  }
  let reviewRefused = false;
  let reviewReady = true;
  let readOccurrenceToken = occurrenceToken;
  let worklistOccurrenceToken = occurrenceToken;
  let worklistRelease: Promise<void> | undefined;
  const basis = {
    occurrenceId,
    activityId: "prior",
    activityStateToken: activityToken,
    basis: options.assessmentBasis ?? "ExactNumericEffects",
    requireCurrent: options.assessmentRequiresCurrent ?? true,
    retryable: false,
    state: options.assessment === "current" ? "Current" : "Stale",
    suitability:
      options.assessment === "current"
        ? "SuitableUnderConfiguredEvidenceCondition"
        : options.assessmentRequiresCurrent === false
          ? "HistoricalPermitted"
          : "UnsuitableNow",
  };
  const returnedEvents = [
    "Earlier reviewer notes.",
    "Replace the stale evidence.",
  ].map((reason, index) => ({
    ordinal: index + 1,
    eventType: "ActivityReturned",
    activityId: "review",
    operationId: `return-${index}`,
    evidence: { kind: "ReviewReturn", reason, targetActivityId: "prior" },
    committedRevision: index + 4,
    createdAt: "2026-11-17T10:00:00Z",
  }));
  const effectResult = (body: any) => ({
    operationId: body.idempotencyKey,
    function: body.program.function,
    occurrenceId: body.program.arguments.occurrenceId,
    activityId: body.program.arguments.activityId,
    status: body.program.function.endsWith("cancel") ? "Cancelled" : "Active",
    ...(body.program.function.endsWith(".return")
      ? { returnedToActivityId: "prior", ...options.returnAcknowledgement }
      : {}),
    ...(body.program.function.endsWith(".start")
      ? {
          occurrenceId: "8".repeat(32),
          flowId: "capacity",
          flowStateToken: flowToken,
          occurrenceStateToken: occurrenceToken,
        }
      : {}),
  });
  let receiptReads = 0;
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ url, body });
      if (nextAccessRefusal?.path === url) {
        const { code, status } = nextAccessRefusal;
        nextAccessRefusal = null;
        return Response.json({ code }, { status });
      }
      const response = (result: unknown) =>
        new Response(JSON.stringify({ result }));
      if (url === "/api/operation-admission") {
        const refused = startRefusal("admission", body.program.function);
        if (refused) return refused;
        if (options.deferAdmission)
          return new Promise<Response>((resolve) => {
            finishAdmission = () => resolve(operationAdmissionResponse("7"));
          });
        return operationAdmissionResponse(startRefused ? "8" : "7");
      }
      if (url === "/api/application-workflow-occurrence") {
        effectBody = body;
        if (options.loseResponse && effectCount++ === 0)
          throw new TypeError("Lost accepted response");
        const refused = startRefusal("effect", body.program.function);
        if (refused) return refused;
        if (options.refuseWorkflowAuthority)
          return Response.json(
            { code: "APPLICATION_WORKFLOW_AUTHORIZATION_STALE" },
            { status: 409 },
          );
        if (options.replayDenied)
          return new Response(
            JSON.stringify({ error: "OPERATION_ADMISSION_EXPIRED" }),
            { status: 403 },
          );
        if (
          options.refuseReviewBasis &&
          !reviewRefused &&
          body.program.function === "application.workflow.activity.complete" &&
          body.program.arguments.activityId === "review"
        ) {
          reviewRefused = true;
          return new Response(
            JSON.stringify({
              code: `APPLICATION_WORKFLOW_REVIEW_BASIS_${options.refuseReviewBasis.suffix}`,
              message: options.refuseReviewBasis.message,
            }),
            {
              status: options.refuseReviewBasis.suffix === "STALE" ? 409 : 400,
            },
          );
        }
        return options.deferEffect
          ? new Promise<Response>((resolve) => {
              finishEffect = resolve;
            })
          : response(effectResult(body));
      }
      switch (body.program.function) {
        case "application.operation.receipt.read": {
          if (options.firstReceiptMissing && receiptReads++ === 0)
            return Response.json(
              { code: "OPERATION_RECEIPT_NOT_FOUND" },
              { status: 404 },
            );
          const receipt = {
            operationId: effectBody.idempotencyKey,
            commandDigest: "d".repeat(64),
            actorId: "workflow-operator",
            committedRevision: 6,
            committedAt: "2026-11-17T10:00:00Z",
            outcome: {
              function: effectBody.program.function,
              occurrenceId: effectBody.program.function.endsWith(".start")
                ? "8".repeat(32)
                : occurrenceId,
              activityId: effectBody.program.arguments.activityId,
              status: effectBody.program.function.endsWith("cancel")
                ? "Cancelled"
                : "Active",
              ...(effectBody.program.function.endsWith(".return")
                ? { returnedToActivityId: returnReceiptTarget }
                : {}),
            },
          };
          if (options.deferReceipt && !finishReceipt)
            return new Promise<Response>((resolve) => {
              pendingReceiptSignal = init?.signal;
              finishReceipt = () => resolve(response(receipt));
            });
          return response(receipt);
        }
        case "application.workflow.worklist":
          await worklistRelease;
          return response({
            items: options.unassigned
              ? []
              : isRework
                ? [
                    {
                      ...ready[0],
                      activityId: "prior",
                      name: "Prior preparation",
                    },
                  ]
                : reviewReady && !options.blockedReview
                  ? ready.map((item) => ({
                      ...item,
                      occurrenceStateToken: worklistOccurrenceToken,
                    }))
                  : ready.slice(0, 1),
            blockedItems: options.blockedReview
              ? [
                  {
                    occurrenceId,
                    activityId: "review",
                    flowId: "capacity",
                    name: "Review capacity",
                    reason: "WorkflowDefinitionUnavailable",
                  },
                ]
              : undefined,
            nextCursor: null,
          });
        case "application.workflow.occurrence.read":
          const after = body.program.arguments.afterEventOrdinal;
          if (after && options.historyPages === "authority")
            return Response.json(
              { code: "APPLICATION_WORKFLOW_AUTHORIZATION_STALE" },
              { status: 409 },
            );
          const changed = after && options.historyPages === "changed";
          return response({
            occurrenceId,
            flowId: "capacity",
            flowStateToken: flowToken,
            definitionDigest: "a".repeat(64),
            status: "Active",
            occurrenceStateToken: changed
              ? "e".repeat(64)
              : readOccurrenceToken,
            lastEventOrdinal: options.returnHistory ? returnedEvents.length : 1,
            activities: activities.map((item) => ({
              activityId: item.activityId,
              kind: item.kind,
              status:
                isRework && item.activityId === "prior"
                  ? "Ready"
                  : isRework && item.activityId === "review"
                    ? "Returned"
                    : ["prior", "validation"].includes(item.activityId)
                      ? "Completed"
                      : "Ready",
              activityStateToken:
                item.activityId === "prior"
                  ? basis.activityStateToken
                  : item.activityId === "review"
                    ? ready[1].activityStateToken
                    : activityToken,
              ...(isRework && item.activityId === "review"
                ? {
                    operationId:
                      options.returnHistory === "active"
                        ? "return-1"
                        : "different-return",
                    returnedToActivityId: "prior",
                  }
                : {}),
            })),
            events: options.historyPages
              ? after
                ? [returnedEvents[1]]
                : [returnedEvents[0]]
              : options.returnHistory
                ? returnedEvents
                : [],
            currentReturns: isRework ? [returnedEvents[1]] : [],
            nextEventOrdinal: options.historyPages && !after ? 1 : null,
          });
        case "application.workflow.list": {
          const published = {
            flowId: "capacity",
            name: "Capacity review",
            status: "Active",
            stateToken: flowToken,
            definitionDigest: "a".repeat(64),
          };
          const earlier = {
            ...published,
            flowId: "allocation",
            name: "Allocation checks",
          };
          const firstPage =
            options.pagedWorkflows && !body.program.arguments.afterFlowId;
          const withdrawn =
            startRefused &&
            options.refuseStart?.code ===
              "APPLICATION_WORKFLOW_CURRENT_UNAVAILABLE";
          return response({
            workflows: withdrawn ? [] : firstPage ? [earlier] : [published],
            collectionToken: "c".repeat(64),
            nextAfterFlowId: firstPage ? earlier.flowId : null,
          });
        }
        case "application.workflow.read": {
          if (options.definitionUnavailable)
            return Response.json(
              { code: "APPLICATION_WORKFLOW_UNAVAILABLE" },
              { status: 400 },
            );
          const current = response({
            flowId: "capacity",
            stateToken: options.changedDefinition ? "f".repeat(64) : flowToken,
            definitionDigest: "a".repeat(64),
            definition: {
              name: "Capacity review",
              activities,
              workspaceId: app.workspaceId,
              applicationId: app.applicationId,
              flowId: "capacity",
            },
            ...(options.startable
              ? {
                  name: "Capacity review",
                  status: "Active",
                  metadataRevision: 2,
                  policyRevision: startRefused ? 4 : 3,
                  schemaEpoch: 4,
                }
              : {}),
          });
          if (options.deferDefinition)
            return new Promise<Response>((resolve) => {
              finishDefinition = () => resolve(current);
            });
          return current;
        }
        case "application.workflow.activity.evidence.list":
          if (options.deferEvidence)
            return new Promise<Response>((complete) => {
              pendingEvidence.push({ signal: init?.signal, complete });
            });
          if (options.failEvidence)
            return new Response(
              JSON.stringify({ error: "EVIDENCE_UNAVAILABLE" }),
              { status: 403 },
            );
          return response({
            items: [
              {
                selectionKey: "eligible-receipt",
                label: "Application rule run",
                occurredAt: "2026-11-17T10:00:00Z",
                outcome: "Committed",
                current: options.current ?? true,
              },
            ],
            nextBeforeCommittedRevision: null,
          });
        case "application.workflow.activity.evidence.read":
          if (body.program.arguments.activityId === "validation")
            return response({
              ...basis,
              activityId: "validation",
              requireCurrent: false,
              suitability: "HistoricalPermitted",
            });
          if (options.assessment === "deferred" || deferNextAssessment)
            return new Promise<Response>((resolve) => {
              deferNextAssessment = false;
              finishAssessment = resolve;
            });
          if (reviewRefused && options.assessmentAfterRefusal === "stale")
            return response({
              ...basis,
              state: "Stale",
              suitability: "UnsuitableNow",
            });
          if (reviewRefused && options.assessmentAfterRefusal === "unavailable")
            return response({
              occurrenceId,
              activityId: "prior",
              state: "UnavailableToAssess",
              basis: null,
              requireCurrent: null,
              suitability: "Unknown",
              retryable: false,
            });
          return response(basis);
        default:
          throw new Error(`Unexpected ${url} ${body.program.function}`);
      }
    }),
  );
  return {
    finishAdmission: () => finishAdmission?.(),
    finishDefinition: () => finishDefinition?.(),
    calls,
    pendingEvidence,
    refuseNextAccessAt: (path: string, code: string, status: number) => {
      nextAccessRefusal = { path, code, status };
    },
    removeReviewAssignment: () => {
      reviewReady = false;
    },
    holdWorklist: () => {
      let settle: () => void;
      worklistRelease = new Promise<void>((resolve) => {
        settle = resolve;
      });
      return () => settle();
    },
    advanceOccurrence: () => {
      readOccurrenceToken = "9".repeat(64);
    },
    advanceReviewActivity: () => {
      ready[1].activityStateToken = "9".repeat(64);
    },
    replacePrerequisite: () => {
      basis.activityStateToken = "8".repeat(64);
      basis.state = "Current";
      basis.suitability = "SuitableUnderConfiguredEvidenceCondition";
      readOccurrenceToken = worklistOccurrenceToken = "9".repeat(64);
    },
    completeAssessment: () =>
      finishAssessment?.(new Response(JSON.stringify({ result: basis }))),
    captureAssessment: () => {
      const finish = finishAssessment;
      const reply = Response.json({ result: { ...basis } });
      return () => finish?.(reply);
    },
    holdNextAssessment: () => {
      deferNextAssessment = true;
    },
    failAssessment: () =>
      finishAssessment?.(new Response(null, { status: 503 })),
    refuseAssessmentAccess: (code: string, status: number) =>
      finishAssessment?.(Response.json({ code }, { status })),
    confirmCurrentAssessment: () =>
      finishAssessment?.(
        new Response(
          JSON.stringify({
            result: {
              ...basis,
              state: "Current",
              suitability: "SuitableUnderConfiguredEvidenceCondition",
            },
          }),
        ),
      ),
    finish: (response?: Response) =>
      finishEffect?.(
        response ?? Response.json({ result: effectResult(effectBody) }),
      ),
    finishReceipt: () => finishReceipt?.(),
    confirmReturnReceipt: () => {
      returnReceiptTarget = "prior";
    },
    receiptSignal: () => pendingReceiptSignal,
  };
}

const assessmentCatalog = {
  ...catalog,
  functions: {
    ...catalog.functions,
    "application.workflow.activity.evidence.read": {},
  },
};

it("shows the blocked activity reason even when its original definition is no longer active", async () => {
  const { calls } = reviewFixture({
    blockedReview: true,
    changedDefinition: true,
  });
  render(
    <GenericWorkflow
      app={app}
      catalog={catalog}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  expect(
    await screen.findByText(
      /workflow definition is no longer active for this occurrence/,
    ),
  ).toBeVisible();
  expect(await screen.findByText("Review · Blocked for review")).toBeVisible();
  expect(
    screen.getByRole("button", { name: "Open activity Prepare capacity" }),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Open governed destination" }),
  ).not.toBeInTheDocument();
  expect(calls.some(({ url }) => url === "/api/operation-admission")).toBe(
    false,
  );
});

it("checks a completed prerequisite on demand and preserves its historical status", async () => {
  const { calls } = reviewFixture({ assessment: "stale" });
  render(<GenericWorkflow app={app} catalog={assessmentCatalog} />);
  const check = await screen.findByRole("button", {
    name: "Check current evidence for Prior preparation",
  });
  const assessments = () =>
    calls.filter(
      (entry) =>
        entry.body.program?.function ===
        "application.workflow.activity.evidence.read",
    );
  expect(assessments()).toHaveLength(0);
  fireEvent.click(check);
  expect(
    await screen.findByText(
      "This evidence is stale. The activity requires current evidence.",
    ),
  ).toBeVisible();
  expect(assessments()).toHaveLength(1);
  expect(assessments()[0].body).toMatchObject({
    workspaceId: "ws",
    applicationId: "cube",
    program: {
      arguments: { occurrenceId: "1".repeat(32), activityId: "prior" },
    },
  });
  expect(screen.getByText("Action · Completed")).toBeVisible();
  expect(calls.some(({ url }) => url === "/api/operation-admission")).toBe(
    false,
  );
});

it.each([
  [
    "RulePublication",
    "current",
    true,
    "The recorded rule publication is current",
    false,
  ],
  [
    "RulePublication",
    "stale",
    true,
    "This rule publication is stale. The activity requires current evidence.",
    true,
  ],
  [
    "RulePublication",
    "stale",
    false,
    "This rule publication is stale. The activity allows historical evidence.",
    false,
  ],
  [
    "CalculationPublication",
    "current",
    true,
    "The recorded calculated result is current",
    false,
  ],
  [
    "CalculationPublication",
    "stale",
    true,
    "This calculated result is stale. The activity requires current evidence.",
    true,
  ],
  [
    "CalculationPublication",
    "stale",
    false,
    "This calculated result is stale. The activity allows historical evidence.",
    false,
  ],
] as const)(
  "reflects %s assessment %s under the current-evidence condition %s",
  async (basis, assessment, requireCurrent, message, blocked) => {
    const { calls } = reviewFixture({
      assessment,
      assessmentBasis: basis,
      assessmentRequiresCurrent: requireCurrent,
    });
    render(
      <GenericWorkflow
        app={app}
        catalog={assessmentCatalog}
        targetOccurrenceId={"1".repeat(32)}
        targetActivityId="review"
      />,
    );
    const check = await screen.findByRole("button", {
      name: "Check current evidence for Prior preparation",
    });
    fireEvent.click(check);
    expect(await screen.findByText(message, { exact: false })).toBeVisible();
    fireEvent.change(screen.getByLabelText(/Return reason/), {
      target: {
        value: "Refresh the published rule and submit the new receipt.",
      },
    });
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I reviewed this exact activity/,
      }),
    );
    const accept = screen.getByRole("button", { name: "Accept review" });
    if (blocked) expect(accept).toBeDisabled();
    else expect(accept).toBeEnabled();
    expect(
      screen.getByRole("button", { name: "Return to Prior preparation" }),
    ).toBeEnabled();
    expect(calls.some(({ url }) => url === "/api/operation-admission")).toBe(
      false,
    );
  },
);

it("discards an assessment that finishes after application scope changes", async () => {
  const fixture = reviewFixture({ assessment: "deferred" });
  const view = render(
    <GenericWorkflow app={app} catalog={assessmentCatalog} />,
  );
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Check current evidence for Prior preparation",
    }),
  );
  expect(await screen.findByText("Checking current evidence…")).toBeVisible();
  view.rerender(
    <GenericWorkflow
      app={{ ...app, applicationId: "other" }}
      catalog={assessmentCatalog}
    />,
  );
  await act(async () => fixture.completeAssessment());
  expect(screen.queryByText(/This evidence is stale/)).toBeNull();
  expect(screen.queryByText("Checking current evidence…")).toBeNull();
});

it("retains each prerequisite assessment and blocks accepting stale required evidence after acknowledgement", async () => {
  const { calls } = reviewFixture({ assessment: "stale", multipleBases: true });
  render(
    <GenericWorkflow
      app={app}
      catalog={assessmentCatalog}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  const evidence = within(
    await screen.findByRole("region", { name: "Evidence for this review" }),
  );
  const review = screen.getByRole("checkbox", {
    name: /I reviewed this exact activity/,
  });
  await waitFor(() => expect(review).toBeEnabled());
  fireEvent.click(review);
  expect(review).toBeChecked();
  expect(screen.getByRole("button", { name: "Accept review" })).toBeEnabled();
  fireEvent.click(
    evidence.getByRole("button", {
      name: "Check current evidence for Prior preparation",
    }),
  );
  expect(
    await evidence.findByText(
      "This evidence is stale. The activity requires current evidence.",
    ),
  ).toBeVisible();
  expect(review).not.toBeChecked();
  expect(screen.getByRole("button", { name: "Accept review" })).toBeDisabled();
  fireEvent.click(
    evidence.getByRole("button", {
      name: "Check current evidence for Validate capacity",
    }),
  );
  expect(
    await evidence.findByText(
      "This evidence is stale. The activity allows historical evidence.",
    ),
  ).toBeVisible();
  expect(
    evidence.getByText(
      "This evidence is stale. The activity requires current evidence.",
    ),
  ).toBeVisible();
  expect(
    screen.getAllByRole("button", {
      name: "Check current evidence for Prior preparation",
    }),
  ).toHaveLength(1);
  expect(
    screen.getByRole("button", { name: "Return to Prior preparation" }),
  ).toBeDisabled();
  fireEvent.change(screen.getByRole("textbox", { name: "Return reason" }), {
    target: { value: "Replace the required numeric evidence." },
  });
  fireEvent.click(review);
  expect(review).toBeChecked();
  const accept = screen.getByRole("button", { name: "Accept review" });
  expect(accept).toBeDisabled();
  fireEvent.click(accept);
  expect(
    screen.getByRole("button", { name: "Return to Prior preparation" }),
  ).toBeEnabled();
  expect(
    calls.filter(({ url }) => url === "/api/operation-admission"),
  ).toHaveLength(0);
});

it.each(["Accept review", "Return to Prior preparation"])(
  "drops the pending admission for %s when the reviewer checks evidence again",
  async (action) => {
    const fixture = reviewFixture({
      assessment: "stale",
      deferAdmission: true,
    });
    render(
      <GenericWorkflow
        app={app}
        catalog={assessmentCatalog}
        targetOccurrenceId={"1".repeat(32)}
        targetActivityId="review"
      />,
    );
    const check = await screen.findByRole("button", {
      name: "Check current evidence for Prior preparation",
    });
    const acknowledge = screen.getByRole("checkbox", {
      name: /I reviewed this exact activity/,
    });
    if (action.startsWith("Return"))
      fireEvent.change(screen.getByRole("textbox", { name: "Return reason" }), {
        target: { value: "Replace the evidence for this period." },
      });
    fireEvent.click(acknowledge);
    const submit = screen.getByRole("button", { name: action });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);
    expect(
      fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
    ).toHaveLength(1);
    expect(submit).toBeDisabled();

    fireEvent.click(check);
    expect(
      await screen.findByText(
        "This evidence is stale. The activity requires current evidence.",
      ),
    ).toBeVisible();
    await act(async () => fixture.finishAdmission());

    expect(
      fixture.calls.filter(
        ({ url }) => url === "/api/application-workflow-occurrence",
      ),
    ).toHaveLength(0);
    expect(acknowledge).not.toBeChecked();
    expect(acknowledge).toBeEnabled();
    expect(submit).toBeDisabled();
    expect(screen.queryByText(/Original workflow .* recorded/)).toBeNull();
  },
);

it("finishes a required evidence check before allowing another prerequisite check", async () => {
  const fixture = reviewFixture({ assessment: "stale", multipleBases: true });
  fixture.holdNextAssessment();
  render(
    <GenericWorkflow
      app={app}
      catalog={assessmentCatalog}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  const evidence = within(
    await screen.findByRole("region", { name: "Evidence for this review" }),
  );
  const required = evidence.getByRole("button", {
    name: "Check current evidence for Prior preparation",
  });
  const historical = evidence.getByRole("button", {
    name: "Check current evidence for Validate capacity",
  });
  const acknowledgement = screen.getByRole("checkbox", {
    name: /I reviewed this exact activity/,
  });
  const assessments = () =>
    fixture.calls
      .filter(
        ({ body }) =>
          body.program?.function ===
          "application.workflow.activity.evidence.read",
      )
      .map(({ body }) => body.program.arguments.activityId);

  fireEvent.click(required);
  expect(evidence.getByText("Checking current evidence…")).toBeVisible();
  expect(acknowledgement).toBeDisabled();
  fireEvent.click(historical);
  expect(assessments()).toEqual(["prior"]);
  expect(historical).toHaveAttribute("aria-disabled", "true");
  expect(evidence.getByText("Checking current evidence…")).toBeVisible();
  expect(acknowledgement).toBeDisabled();

  await act(async () => fixture.completeAssessment());
  expect(
    evidence.getByText(/The activity requires current evidence/),
  ).toBeVisible();
  expect(historical).not.toHaveAttribute("aria-disabled");
  fireEvent.click(historical);
  expect(
    await evidence.findByText(/The activity allows historical evidence/),
  ).toBeVisible();
  expect(assessments()).toEqual(["prior", "validation"]);
  await waitFor(() => expect(acknowledgement).toBeEnabled());
  fireEvent.click(acknowledgement);
  expect(acknowledgement).toBeChecked();
  expect(screen.getByRole("button", { name: "Accept review" })).toBeDisabled();
});

it("keeps a confirmed stale prerequisite blocked after a failed recheck until it is confirmed current", async () => {
  const fixture = reviewFixture({ assessment: "stale" });
  render(
    <GenericWorkflow
      app={app}
      catalog={assessmentCatalog}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  const check = await screen.findByRole("button", {
    name: "Check current evidence for Prior preparation",
  });
  const accept = screen.getByRole("button", { name: "Accept review" });
  const acknowledge = screen.getByRole("checkbox", {
    name: /I reviewed this exact activity/,
  });
  fireEvent.click(check);
  await screen.findByText(
    "This evidence is stale. The activity requires current evidence.",
  );

  fixture.holdNextAssessment();
  fireEvent.click(check);
  expect(await screen.findByText("Checking current evidence…")).toBeVisible();
  expect(accept).toBeDisabled();
  await act(async () => fixture.failAssessment());
  expect(
    await screen.findByText(/Accept is still blocked by the last confirmed/),
  ).toBeVisible();
  fireEvent.change(screen.getByRole("textbox", { name: "Return reason" }), {
    target: { value: "Replace the required numeric evidence." },
  });
  fireEvent.click(acknowledge);
  expect(acknowledge).toBeChecked();
  expect(accept).toBeDisabled();
  fireEvent.click(accept);
  expect(
    screen.getByRole("button", { name: "Return to Prior preparation" }),
  ).toBeEnabled();
  expect(
    fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
  ).toHaveLength(0);

  fixture.holdNextAssessment();
  fireEvent.click(check);
  await act(async () => fixture.confirmCurrentAssessment());
  expect(await screen.findByText(/is current at the time/)).toBeVisible();
  expect(acknowledge).not.toBeChecked();
  fireEvent.click(acknowledge);
  expect(accept).toBeEnabled();
});

it.each(["replacement evidence", "new authority"])(
  "preserves confirmed stale evidence across refresh and forgets it for %s",
  async (change) => {
    const fixture = reviewFixture({ assessment: "stale" });
    const props = {
      app,
      targetOccurrenceId: "1".repeat(32),
      targetActivityId: "review",
    };
    let acknowledgeOnFirstReady = false;
    let acknowledgedOnFirstReady = false;
    const checkboxName = /I reviewed this exact activity/;
    const element = (catalogue: typeof assessmentCatalog) => (
      <Profiler
        id="first-ready-workflow-review"
        onRender={() => {
          if (!acknowledgeOnFirstReady) return;
          const checkbox = screen.queryByRole<HTMLInputElement>("checkbox", {
            name: checkboxName,
          });
          if (!checkbox || checkbox.disabled) return;
          acknowledgeOnFirstReady = false;
          acknowledgedOnFirstReady = true;
          checkbox.click();
        }}
      >
        <GenericWorkflow {...props} catalog={catalogue} />
      </Profiler>
    );
    const view = render(element(assessmentCatalog));
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Check current evidence for Prior preparation",
      }),
    );
    expect(
      await screen.findByText(
        "This evidence is stale. The activity requires current evidence.",
      ),
    ).toBeVisible();

    const refresh = () =>
      fireEvent.click(screen.getByRole("button", { name: "Refresh workflow" }));
    const acknowledge = async () => {
      const checkbox = await screen.findByRole("checkbox", {
        name: checkboxName,
      });
      await waitFor(() => expect(checkbox).toBeEnabled());
      expect(checkbox).not.toBeChecked();
      fireEvent.click(checkbox);
      expect(checkbox).toBeChecked();
    };
    const retained = /Last confirmed check found stale required evidence/;
    async function expectRetained() {
      const decision = await screen.findByRole("region", {
        name: "Evidence for this review",
      });
      expect(await within(decision).findByText(retained)).toBeVisible();
    }
    refresh();
    await expectRetained();
    await acknowledge();
    expect(
      screen.getByRole("button", { name: "Accept review" }),
    ).toBeDisabled();
    expect(
      fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
    ).toHaveLength(0);

    const updated = {
      ...assessmentCatalog,
      revisions: { ...assessmentCatalog.revisions, data: 3, commit: 6 },
    };
    view.rerender(element(updated));
    await expectRetained();
    await acknowledge();
    expect(
      screen.getByRole("button", { name: "Accept review" }),
    ).toBeDisabled();

    acknowledgeOnFirstReady = true;
    if (change === "replacement evidence") {
      fixture.replacePrerequisite();
      refresh();
    } else {
      view.rerender(
        element({
          ...updated,
          revisions: { ...updated.revisions, security: 5 },
        }),
      );
    }
    await waitFor(() => expect(acknowledgedOnFirstReady).toBe(true));
    expect(screen.getByRole("checkbox", { name: checkboxName })).toBeChecked();
    expect(screen.queryByText(retained)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Accept review" })).toBeEnabled();
    expect(
      fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
    ).toHaveLength(0);
  },
);

it.each(["replacement evidence", "new authority"])(
  "keeps the first current-evidence check after %s and ignores the previous reply",
  async (change) => {
    const fixture = reviewFixture({ assessment: "stale" });
    const occurrenceId = "1".repeat(32);
    const evidenceRegion = "Evidence for this review";
    const checkName = "Check current evidence for Prior preparation";
    let checkOnFirstReady = false;
    let checkedOnFirstReady = false;
    const element = (catalogue: typeof assessmentCatalog) => (
      <Profiler
        id="first-ready-workflow-evidence-check"
        onRender={() => {
          if (!checkOnFirstReady) return;
          const region = screen.queryByRole("region", { name: evidenceRegion });
          const check =
            region && within(region).queryByRole("button", { name: checkName });
          if (!check || check.getAttribute("aria-disabled") === "true") return;
          checkOnFirstReady = false;
          checkedOnFirstReady = true;
          check.click();
        }}
      >
        <GenericWorkflow
          app={app}
          catalog={catalogue}
          targetOccurrenceId={occurrenceId}
          targetActivityId="review"
        />
      </Profiler>
    );
    const assessmentRequests = () =>
      fixture.calls
        .filter(
          ({ body }) =>
            body.program?.function ===
            "application.workflow.activity.evidence.read",
        )
        .map(({ body }) => body.program.arguments);
    fixture.holdNextAssessment();
    const view = render(element(assessmentCatalog));
    const initial = within(
      await screen.findByRole("region", { name: evidenceRegion }),
    );
    fireEvent.click(initial.getByRole("button", { name: checkName }));
    expect(initial.getByText("Checking current evidence…")).toBeVisible();
    expect(assessmentRequests()).toEqual([
      { occurrenceId, activityId: "prior" },
    ]);
    const finishOldAssessment = fixture.captureAssessment();

    fixture.holdNextAssessment();
    checkOnFirstReady = true;
    if (change === "replacement evidence") {
      fixture.replacePrerequisite();
      fireEvent.click(screen.getByRole("button", { name: "Refresh workflow" }));
    } else {
      view.rerender(
        element({
          ...assessmentCatalog,
          revisions: { ...assessmentCatalog.revisions, security: 5 },
        }),
      );
    }
    await waitFor(() => expect(checkedOnFirstReady).toBe(true));
    const current = within(
      screen.getByRole("region", { name: evidenceRegion }),
    );
    expect(current.getByText("Checking current evidence…")).toBeVisible();
    expect(assessmentRequests()).toEqual([
      { occurrenceId, activityId: "prior" },
      { occurrenceId, activityId: "prior" },
    ]);
    expect(
      screen.getByRole("checkbox", { name: /I reviewed this exact activity/ }),
    ).toBeDisabled();

    await act(async () => finishOldAssessment());
    expect(current.getByText("Checking current evidence…")).toBeVisible();
    expect(
      current.queryByText(/evidence is stale|Last confirmed check/),
    ).not.toBeInTheDocument();
    await act(async () => fixture.confirmCurrentAssessment());
    expect(await current.findByText(/is current at the time/)).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Accept review" }),
    ).toBeDisabled();
    expect(
      fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
    ).toHaveLength(0);
  },
);

it.each([
  ["current", null],
  [
    "mismatched",
    "The assigned activity no longer matches the current workflow. Refresh the workflow before taking action.",
  ],
  [
    "unverifiable",
    "The current workflow definition could not be verified. Refresh the workflow to retry.",
  ],
] as const)(
  "shows an in-flight definition as pending before it settles %s",
  async (result, recovery) => {
    const fixture = reviewFixture({
      deferDefinition: true,
      changedDefinition: result === "unverifiable",
    });
    if (result === "mismatched") fixture.advanceOccurrence();
    render(
      <GenericWorkflow
        app={app}
        catalog={assessmentCatalog}
        targetOccurrenceId={"1".repeat(32)}
        targetActivityId="review"
      />,
    );
    await waitFor(() =>
      expect(
        fixture.calls.some(
          ({ body }) => body.program.function === "application.workflow.read",
        ),
      ).toBe(true),
    );
    const pending = "Checking the current workflow definition…";
    expect(await screen.findByText(pending)).toHaveAttribute("role", "status");
    const acknowledgement = () =>
      screen.getByRole("checkbox", { name: /I reviewed this exact activity/ });
    const refresh = screen.getByRole("button", { name: "Refresh workflow" });
    expect(refresh).toHaveAttribute("aria-disabled", "true");
    expect(acknowledgement()).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Accept review" }),
    ).toBeDisabled();
    expect(
      screen.queryByText(
        /Refresh the workflow (before taking action|to retry)/,
      ),
    ).not.toBeInTheDocument();

    await act(async () => fixture.finishDefinition());
    expect(screen.queryByText(pending)).not.toBeInTheDocument();
    expect(refresh).not.toHaveAttribute("aria-disabled");
    if (recovery) {
      expect(await screen.findByText(recovery)).toHaveAttribute(
        "role",
        "status",
      );
      expect(acknowledgement()).toBeDisabled();
    } else {
      expect(acknowledgement()).toBeEnabled();
    }
    expect(
      screen.getByRole("button", { name: "Accept review" }),
    ).toBeDisabled();
    expect(
      fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
    ).toHaveLength(0);
  },
);

it("opens the returned activity with current instructions before loading more history", async () => {
  const fixture = reviewFixture({
    returnHistory: "active",
    historyPages: "stable",
  });
  render(
    <GenericWorkflow
      app={app}
      catalog={catalog}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="prior"
    />,
  );
  const instructions = within(
    await screen.findByRole("region", { name: "Return instructions" }),
  );
  expect(
    await instructions.findByText(
      "Review capacity returned this activity for correction.",
    ),
  ).toBeVisible();
  expect(instructions.getByText("Replace the stale evidence.")).toBeVisible();
  expect(instructions.queryByText("Earlier reviewer notes.")).toBeNull();
  const history = within(
    screen.getByRole("region", { name: "Activity history" }),
  );
  expect(history.getByText("Earlier reviewer notes.")).toBeVisible();
  expect(history.queryByText("Replace the stale evidence.")).toBeNull();
  const acknowledge = screen.getByRole("checkbox", {
    name: /reviewed this exact activity/,
  });
  fireEvent.click(acknowledge);
  expect(
    screen.getByRole("button", { name: "Complete activity" }),
  ).toBeEnabled();
  const reads = () =>
    fixture.calls.filter(
      ({ body }) =>
        body.program?.function === "application.workflow.occurrence.read",
    );
  expect(reads()).toHaveLength(1);
  expect(reads()[0].body.program.arguments).toEqual({
    occurrenceId: "1".repeat(32),
    afterEventOrdinal: 0,
    eventLimit: 50,
    includeCurrentReturns: true,
  });
  fireEvent.click(
    history.getByRole("button", { name: "Load more activity history" }),
  );
  expect(await history.findByText("Replace the stale evidence.")).toBeVisible();
  expect(history.getAllByText("Returned to Prior preparation")).toHaveLength(2);
  expect(reads()).toHaveLength(2);
  expect(reads()[1].body.program.arguments).toEqual({
    occurrenceId: "1".repeat(32),
    afterEventOrdinal: 1,
    eventLimit: 50,
  });
  expect(
    history.getByRole("button", { name: "All activity history loaded" }),
  ).toHaveAttribute("aria-disabled", "true");
  expect(
    screen.getByRole("button", { name: "Complete activity" }),
  ).toBeEnabled();
});

it.each(["resolved", "different-operation"] as const)(
  "keeps historical return reasons out of current instructions for %s",
  async (returnHistory) => {
    reviewFixture({ returnHistory });
    render(
      <GenericWorkflow
        app={app}
        catalog={catalog}
        targetOccurrenceId={"1".repeat(32)}
        targetActivityId="prior"
      />,
    );
    const history = within(
      await screen.findByRole("region", { name: "Activity history" }),
    );
    expect(await history.findByText("Earlier reviewer notes.")).toBeVisible();
    expect(history.getByText("Replace the stale evidence.")).toBeVisible();
    expect(
      screen.queryByRole("region", { name: "Return instructions" }),
    ).toBeNull();
  },
);

it.each([
  {
    refusal: "STALE",
    recheck: "stale",
    message:
      "Required evidence has changed. Return the work to replace that evidence.",
    outcome: "This evidence is stale. The activity requires current evidence.",
  },
  {
    refusal: "UNAVAILABLE",
    recheck: undefined,
    message:
      "Required evidence could not be verified. Check the evidence and refresh the workflow.",
    outcome:
      "The recorded numeric evidence is current at the time of this check.",
  },
  {
    refusal: "UNAVAILABLE",
    recheck: "unavailable",
    message:
      "Required evidence could not be verified. Check the evidence and refresh the workflow.",
    outcome: "Current evidence could not be assessed.",
  },
] as const)(
  "requires a new prerequisite check after a $refusal review refusal with $recheck evidence",
  async ({ refusal, recheck, message, outcome }) => {
    const { calls } = reviewFixture({
      assessment: "current",
      refuseReviewBasis: { suffix: refusal, message },
      assessmentAfterRefusal: recheck,
    });
    render(
      <GenericWorkflow
        app={app}
        catalog={assessmentCatalog}
        targetOccurrenceId={"1".repeat(32)}
        targetActivityId="review"
      />,
    );
    const check = await screen.findByRole("button", {
      name: "Check current evidence for Prior preparation",
    });
    const accept = screen.getByRole("button", { name: "Accept review" });
    const acknowledgement = screen.getByRole("checkbox", {
      name: /I reviewed this exact activity/,
    });
    const currentMessage =
      "The recorded numeric evidence is current at the time of this check.";
    fireEvent.click(check);
    expect(await screen.findByText(currentMessage)).toBeVisible();
    fireEvent.click(acknowledgement);
    expect(accept).toBeEnabled();
    fireEvent.click(accept);
    expect(await screen.findByText(message)).toBeVisible();
    expect(screen.queryByText(currentMessage)).toBeNull();
    expect(acknowledgement).not.toBeChecked();
    await waitFor(() => expect(acknowledgement).toBeEnabled());
    fireEvent.click(acknowledgement);
    expect(acknowledgement).toBeChecked();
    expect(accept).toBeDisabled();
    fireEvent.click(accept);
    const admissions = () =>
      calls.filter(({ url }) => url === "/api/operation-admission");
    const effects = () =>
      calls.filter(({ url }) => url === "/api/application-workflow-occurrence");
    expect(admissions()).toHaveLength(1);
    expect(effects()).toHaveLength(1);

    fireEvent.click(check);
    expect(await screen.findByText(outcome)).toBeVisible();
    expect(acknowledgement).not.toBeChecked();
    if (recheck === "stale") {
      fireEvent.change(screen.getByRole("textbox", { name: "Return reason" }), {
        target: { value: "Replace the required numeric evidence." },
      });
      fireEvent.click(acknowledgement);
      expect(accept).toBeDisabled();
      const returnWork = screen.getByRole("button", {
        name: "Return to Prior preparation",
      });
      expect(returnWork).toBeEnabled();
      fireEvent.click(returnWork);
      await waitFor(() => expect(effects()).toHaveLength(2));
      expect(effects()[1].body.program).toMatchObject({
        function: "application.workflow.activity.return",
        arguments: { occurrenceId: "1".repeat(32), activityId: "review" },
      });
    } else {
      expect(screen.queryByText(message)).toBeNull();
      if (recheck === "unavailable")
        expect(
          screen.getByText(/Submitting the review checks it again/),
        ).toBeVisible();
      expect(accept).toBeDisabled();
      fireEvent.click(acknowledgement);
      expect(accept).toBeEnabled();
    }
  },
);

it("retains the chosen review and its acknowledgement while paging the ready activity list", async () => {
  const { calls } = reviewFixture({ extraReadyActivities: 49 });
  render(<GenericWorkflow app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Open activity Review capacity",
    }),
  );
  const acknowledgement = await screen.findByRole("checkbox", {
    name: /I reviewed this exact activity/,
  });
  fireEvent.click(acknowledgement);
  expect(acknowledgement).toBeChecked();
  const requests = calls.length;
  const next = screen.getByRole("button", { name: "Next ready activities" });
  const previous = screen.getByRole("button", {
    name: "Previous ready activities",
  });
  next.focus();
  fireEvent.click(next);
  expect(next).toHaveFocus();
  expect(next).toHaveAttribute("aria-disabled", "true");
  expect(screen.getByText("51–51 of 51 ready activities")).toHaveAttribute(
    "role",
    "status",
  );
  expect(
    screen.getByRole("button", { name: "Open activity Additional review 49" }),
  ).toBeVisible();
  expect(
    screen.getByRole("heading", { name: "Review capacity" }),
  ).toBeVisible();
  expect(acknowledgement).toBeChecked();
  previous.focus();
  fireEvent.click(previous);
  expect(previous).toHaveFocus();
  expect(previous).toHaveAttribute("aria-disabled", "true");
  expect(
    screen.getByRole("button", {
      name: "Open activity Review capacity",
      pressed: true,
    }),
  ).toBeVisible();
  expect(acknowledgement).toBeChecked();
  expect(calls).toHaveLength(requests);
});

it("returns to the exact chosen activity after refresh and clears its earlier acknowledgement", async () => {
  const { calls } = reviewFixture({ assessment: "current" });
  render(<GenericWorkflow app={app} catalog={assessmentCatalog} />);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Open activity Review capacity",
    }),
  );
  const evidence = await screen.findByRole("region", {
    name: "Evidence for this review",
  });
  fireEvent.click(
    within(evidence).getByRole("button", {
      name: "Check current evidence for Prior preparation",
    }),
  );
  expect(
    await within(evidence).findByText(/is current at the time/),
  ).toBeVisible();
  fireEvent.click(
    screen.getByRole("checkbox", { name: /I reviewed this exact activity/ }),
  );
  expect(screen.getByRole("button", { name: "Accept review" })).toBeEnabled();

  fireEvent.click(screen.getByRole("button", { name: "Refresh workflow" }));

  expect(
    await screen.findByRole("button", {
      name: "Open activity Review capacity",
      pressed: true,
    }),
  ).toBeVisible();
  expect(
    await screen.findByRole("region", { name: "Evidence for this review" }),
  ).toBeVisible();
  expect(
    screen.getByRole("checkbox", { name: /I reviewed this exact activity/ }),
  ).not.toBeChecked();
  expect(screen.queryByText(/is current at the time/)).toBeNull();
  expect(screen.getByRole("button", { name: "Accept review" })).toBeDisabled();
  expect(
    calls.filter(({ url }) => url === "/api/operation-admission"),
  ).toHaveLength(0);
});

it("does not substitute another ready activity when the chosen review leaves the worklist", async () => {
  const fixture = reviewFixture();
  render(<GenericWorkflow app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Open activity Review capacity",
    }),
  );
  expect(
    await screen.findByRole("heading", { name: "Review capacity" }),
  ).toBeVisible();

  fixture.removeReviewAssignment();
  const release = fixture.holdWorklist();
  const refresh = screen.getByRole("button", { name: "Refresh workflow" });
  refresh.focus();
  fireEvent.click(refresh);
  expect(
    await screen.findByText(
      "Checking whether this activity is currently assigned to you…",
    ),
  ).toBeVisible();
  expect(refresh).toHaveFocus();
  expect(refresh).toHaveAttribute("aria-disabled", "true");
  expect(
    screen.queryByText(
      "This activity is not currently ready and assigned to you.",
    ),
  ).toBeNull();
  await act(async () => release());

  expect(
    await screen.findByRole("button", {
      name: "Open activity Prepare capacity",
      pressed: false,
    }),
  ).toBeVisible();
  expect(
    await screen.findByText(
      "This activity is not currently ready and assigned to you.",
    ),
  ).toBeVisible();
  expect(
    screen.getByRole("heading", { name: "Review capacity" }),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Complete activity" }),
  ).toBeNull();
  expect(screen.queryByRole("button", { name: "Accept review" })).toBeNull();
});

it("withholds reviewed actions when the ready assignment and occurrence are from different revisions", async () => {
  const fixture = reviewFixture({ assessment: "current" });
  fixture.advanceOccurrence();
  render(
    <GenericWorkflow
      app={app}
      catalog={assessmentCatalog}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  expect(
    await screen.findByText(
      /The assigned activity no longer matches the current workflow/,
    ),
  ).toBeVisible();
  await screen.findByText(
    "Manual attestation: I accept the submitted capacity evidence",
  );
  expect(
    screen.getByRole("checkbox", { name: /I reviewed this exact activity/ }),
  ).toBeDisabled();
  expect(screen.getByRole("button", { name: "Accept review" })).toBeDisabled();
  expect(
    screen.queryByRole("button", { name: "Open governed destination" }),
  ).toBeNull();
  expect(
    fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
  ).toHaveLength(0);
});

it("does not describe an unavailable evidence read as a confirmed empty eligibility list", async () => {
  reviewFixture({ failEvidence: true });
  render(<GenericWorkflow app={app} catalog={catalog} />);
  expect(
    await screen.findByText(/Completion evidence is unavailable/),
  ).toBeVisible();
  expect(
    screen.queryByText(/No eligible completed activity is available/),
  ).toBeNull();
  expect(
    screen.getByRole("button", { name: "Complete activity" }),
  ).toBeDisabled();
});

it("shows a pending evidence list from its first render and an empty list only after success", async () => {
  const fixture = reviewFixture({ deferEvidence: true });
  const commitsWithFalseUnavailability: boolean[] = [];
  render(
    <Profiler
      id="workflow-evidence-loading"
      onRender={() => {
        if (screen.queryByLabelText("Completion evidence"))
          commitsWithFalseUnavailability.push(
            Boolean(screen.queryByText(/Completion evidence is unavailable/)),
          );
      }}
    >
      <GenericWorkflow app={app} catalog={catalog} />
    </Profiler>,
  );
  await waitFor(() => expect(fixture.pendingEvidence).toHaveLength(1));
  expect(screen.getByText("Loading completed activities…")).toHaveRole(
    "status",
  );
  expect(screen.getByLabelText("Completion evidence")).toBeDisabled();
  expect(
    screen.queryByText(/No eligible completed activity is available/),
  ).toBeNull();
  await act(async () =>
    fixture.pendingEvidence[0].complete(
      Response.json({
        result: { items: [], nextBeforeCommittedRevision: null },
      }),
    ),
  );
  expect(
    screen.getByText(/No eligible completed activity is available/),
  ).toBeVisible();
  expect(commitsWithFalseUnavailability).not.toHaveLength(0);
  expect(commitsWithFalseUnavailability).not.toContain(true);
  expect(
    fixture.calls.some(({ url }) => url === "/api/operation-admission"),
  ).toBe(false);
});

it("cancels an older evidence page when refreshing the activity and ignores its late refusal", async () => {
  const fixture = reviewFixture({ deferEvidence: true });
  const evidence = (label: string, cursor: number | null) =>
    Response.json({
      result: {
        items: [
          {
            selectionKey: label,
            label,
            occurredAt: "2026-11-17T10:00:00Z",
            outcome: "Committed",
            current: true,
          },
        ],
        nextBeforeCommittedRevision: cursor,
      },
    });
  render(<GenericWorkflow app={app} catalog={catalog} />);
  await waitFor(() => expect(fixture.pendingEvidence).toHaveLength(1));
  await act(async () =>
    fixture.pendingEvidence[0].complete(evidence("Previous evidence", 9)),
  );
  fireEvent.change(screen.getByLabelText("Completion evidence"), {
    target: { value: "Previous evidence" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Load older completed activity" }),
  );
  await waitFor(() => expect(fixture.pendingEvidence).toHaveLength(2));
  const older = fixture.pendingEvidence[1];
  expect(older.signal?.aborted).toBe(false);
  fireEvent.click(screen.getByRole("button", { name: "Refresh workflow" }));
  await waitFor(() => expect(fixture.pendingEvidence).toHaveLength(3));
  expect(older.signal?.aborted).toBe(true);
  expect(screen.getByLabelText("Completion evidence")).toBeDisabled();
  expect(screen.getByLabelText("Completion evidence")).toHaveValue("");
  expect(
    screen.queryByRole("option", { name: /Previous evidence/ }),
  ).toBeNull();
  await act(async () =>
    older.complete(
      Response.json(
        { code: "APPLICATION_WORKFLOW_AUTHORIZATION_STALE" },
        { status: 409 },
      ),
    ),
  );
  expect(screen.getByText("Loading completed activities…")).toBeVisible();
  expect(screen.queryByText(/Completion evidence is unavailable/)).toBeNull();
  await act(async () =>
    fixture.pendingEvidence[2].complete(evidence("Current evidence", null)),
  );
  expect(
    screen.getByRole("option", { name: /Current evidence/ }),
  ).toBeVisible();
  expect(screen.getByLabelText("Completion evidence")).toBeEnabled();
  expect(
    screen.getByRole("button", { name: "Complete activity" }),
  ).toBeDisabled();
});

it("preserves the original admitted return through unknown outcome, remount and elapsed admission time", async () => {
  const fixture = reviewFixture({ loseResponse: true });
  const rendered = render(
    <GenericWorkflow
      app={app}
      catalog={catalog}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  await screen.findByText(
    "Manual attestation: I accept the submitted capacity evidence",
  );
  fireEvent.change(screen.getByLabelText("Return reason"), {
    target: { value: "Correct the submitted evidence" },
  });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(
    screen.getByRole("button", { name: "Return to Prior preparation" }),
  );
  expect(
    await screen.findByRole("heading", { name: "Workflow outcome unknown" }),
  ).toBeVisible();
  expect(screen.getByLabelText("Return reason")).toBeDisabled();
  expect(screen.getByRole("button", { name: "Accept review" })).toBeDisabled();
  const original = fixture.calls.find(
    ({ url }) => url === "/api/application-workflow-occurrence",
  )!.body;
  rendered.unmount();
  act(discardUnsavedWork);
  expect(
    unsavedWorkSnapshot().some((item) => item.label.includes("unconfirmed")),
  ).toBe(true);
  render(
    <GenericWorkflow
      app={app}
      catalog={catalog}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  expect(
    await screen.findByRole("heading", { name: "Workflow outcome unknown" }),
  ).toBeVisible();
  const clock = vi
    .spyOn(Date, "now")
    .mockReturnValue(Date.now() + 60 * 60 * 1000);
  fireEvent.click(
    screen.getByRole("button", { name: "Reconcile original workflow action" }),
  );
  expect(
    await screen.findByText(
      "Original workflow return recorded. Status at commit: Active.",
    ),
  ).toBeVisible();
  clock.mockRestore();
  const effects = fixture.calls.filter(
    ({ url }) => url === "/api/application-workflow-occurrence",
  );
  expect(effects).toHaveLength(2);
  expect(effects[1].body).toEqual(original);
  expect(
    fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
  ).toHaveLength(1);
});

it.each([
  { returnedToActivityId: "prepare" },
  { returnedToActivityId: undefined },
  { status: "Cancelled" },
])(
  "holds a return with unconfirmed destination or state in %j until its exact receipt is read",
  async (returnAcknowledgement) => {
    const fixture = reviewFixture({
      returnAcknowledgement,
      returnReceiptTarget: "prepare",
    });
    const props = {
      app,
      catalog: {
        ...catalog,
        functions: {
          ...catalog.functions,
          "application.operation.receipt.read": {},
        },
      },
      targetOccurrenceId: "1".repeat(32),
      targetActivityId: "review",
    };
    const view = render(<GenericWorkflow {...props} />);
    await screen.findByText(
      "Manual attestation: I accept the submitted capacity evidence",
    );
    fireEvent.change(screen.getByLabelText("Return reason"), {
      target: { value: "Correct the submitted evidence" },
    });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(
      screen.getByRole("button", { name: "Return to Prior preparation" }),
    );
    await screen.findByText(/did not confirm the original action/);
    expect(
      screen.getByRole("heading", { name: "Workflow outcome unknown" }),
    ).toBeVisible();
    expect(screen.getByLabelText("Return reason")).toBeDisabled();

    view.unmount();
    render(<GenericWorkflow {...props} />);
    const read = await screen.findByRole("button", {
      name: "Read original workflow receipt",
    });
    fireEvent.click(read);
    await screen.findByText(
      /receipt does not confirm this original workflow action/,
    );
    expect(
      screen.getByRole("heading", { name: "Workflow outcome unknown" }),
    ).toBeVisible();

    fixture.confirmReturnReceipt();
    fireEvent.click(read);
    await screen.findByText(/Original workflow return recorded/);
    expect(
      screen.queryByRole("heading", { name: "Workflow outcome unknown" }),
    ).toBeNull();
    const admissions = fixture.calls.filter(
      ({ url }) => url === "/api/operation-admission",
    );
    const effects = fixture.calls.filter(
      ({ url }) => url === "/api/application-workflow-occurrence",
    );
    const receipts = fixture.calls.filter(
      ({ body }) =>
        body.program.function === "application.operation.receipt.read",
    );
    expect(admissions).toHaveLength(1);
    expect(effects).toHaveLength(1);
    expect(receipts).toHaveLength(3);
    for (const { body } of receipts) expect(body).toEqual(receipts[0].body);
    expect(receipts[0].body.program.arguments.operationId).toEqual(
      effects[0].body.idempotencyKey,
    );
  },
);

it.each([
  ["/api/operation-admission", "APPLICATION_GRANT_REQUIRED", 403, false],
  [
    "/api/application-workflow-occurrence",
    "APPLICATION_WORKFLOW_AUTHORIZATION_STALE",
    409,
    false,
  ],
  [
    "/api/application-workflow-occurrence",
    "APPLICATION_GRANT_REQUIRED",
    403,
    false,
  ],
  [
    "/api/application-workflow-occurrence",
    "APPLICATION_GRANT_REQUIRED",
    403,
    true,
  ],
] as const)(
  "withdraws the review when %s refuses initial access with %s (%s, changed activity %s)",
  async (path, code, status, changedActivity) => {
    const fixture = reviewFixture();
    fixture.refuseNextAccessAt(path, code, status);
    const recheck = vi.fn(async () => {
      if (changedActivity) fixture.advanceReviewActivity();
    });
    render(
      <GenericWorkflow
        app={app}
        catalog={catalog}
        onRefreshCatalog={recheck}
        targetOccurrenceId={"1".repeat(32)}
        targetActivityId="review"
      />,
    );
    await screen.findByText(
      "Manual attestation: I accept the submitted capacity evidence",
    );
    const reason = screen.getByLabelText("Return reason");
    fireEvent.change(reason, {
      target: { value: "Correct the submitted evidence" },
    });
    const acknowledgement = screen.getByRole("checkbox");
    fireEvent.click(acknowledgement);
    const send = screen.getByRole("button", {
      name: "Return to Prior preparation",
    });
    fireEvent.click(send);
    expect(
      await screen.findByText(
        /workflow action was refused after an access change/i,
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "Workflow outcome unknown" }),
    ).toBeNull();
    expect(screen.queryByLabelText("Return reason")).toBeNull();
    expect(
      screen.queryByRole("button", { name: "Return to Prior preparation" }),
    ).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Refresh workflow" }));
    expect(recheck).toHaveBeenCalledOnce();
    expect(
      await screen.findByRole("button", {
        name: "Return to Prior preparation",
      }),
    ).toBeDisabled();
    expect(screen.getByLabelText("Return reason")).toHaveValue(
      changedActivity ? "" : "Correct the submitted evidence",
    );
    expect(screen.getByRole("checkbox")).not.toBeChecked();
    expect(
      fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
    ).toHaveLength(1);
    expect(
      fixture.calls.filter(
        ({ url }) => url === "/api/application-workflow-occurrence",
      ),
    ).toHaveLength(path === "/api/operation-admission" ? 0 : 1);
  },
);

it.each([
  ["OPERATION_RECEIPT_AUTHORIZATION_STALE", 409],
  ["APPLICATION_GRANT_REQUIRED", 403],
] as const)(
  "preserves the unknown workflow outcome when its receipt read returns %s",
  async (code, status) => {
    const fixture = reviewFixture({ loseResponse: true });
    const recheck = vi.fn(async () => {});
    render(
      <GenericWorkflow
        app={app}
        catalog={{
          ...catalog,
          functions: {
            ...catalog.functions,
            "application.operation.receipt.read": {},
          },
        }}
        targetOccurrenceId={"1".repeat(32)}
        targetActivityId="review"
        onRefreshCatalog={recheck}
      />,
    );
    const accept = await screen.findByRole("button", { name: "Accept review" });
    await waitFor(() => expect(screen.getByRole("checkbox")).toBeEnabled());
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(accept);
    await screen.findByRole("heading", { name: "Workflow outcome unknown" });
    fixture.refuseNextAccessAt("/api/read", code, status);
    const receipt = () =>
      screen.getByRole("button", { name: "Read original workflow receipt" });
    fireEvent.click(receipt());
    expect(
      await screen.findByText(
        /Access changed while reconciling. The original workflow outcome remains unconfirmed/,
      ),
    ).toBeVisible();
    expect(receipt()).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Accept review" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Refresh workflow" }));
    await waitFor(() => expect(receipt()).toBeEnabled());
    fireEvent.click(receipt());
    expect(
      await screen.findByText(/Original workflow completion recorded/),
    ).toBeVisible();
    const sends = fixture.calls.filter(
      ({ url }) => url === "/api/application-workflow-occurrence",
    );
    expect(sends).toHaveLength(1);
    expect(
      fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
    ).toHaveLength(1);
    const receipts = fixture.calls.filter(
      ({ body }) =>
        body.program?.function === "application.operation.receipt.read",
    );
    expect(receipts.length).toBeGreaterThanOrEqual(2);
    for (const { body } of receipts)
      expect(body.program.arguments.operationId).toEqual(
        sends[0].body.idempotencyKey,
      );
  },
);

it.each([
  [
    "an opaque forbidden response",
    () => new Response("<h1>Forbidden</h1>", { status: 403 }),
  ],
  [
    "a conflict with no recognized outcome",
    () =>
      Response.json({ code: "UPSTREAM_RESPONSE_REPLACED" }, { status: 409 }),
  ],
] as const)(
  "keeps the first admitted return recoverable after %s",
  async (_label, failure) => {
    const fixture = reviewFixture({ deferEffect: true });
    render(
      <GenericWorkflow
        app={app}
        catalog={{
          ...catalog,
          functions: {
            ...catalog.functions,
            "application.operation.receipt.read": {},
          },
        }}
        targetOccurrenceId={"1".repeat(32)}
        targetActivityId="review"
      />,
    );
    const reason = await screen.findByLabelText("Return reason");
    fireEvent.change(reason, { target: { value: "Replace prior evidence" } });
    fireEvent.click(screen.getByRole("checkbox"));
    const send = await screen.findByRole("button", {
      name: "Return to Prior preparation",
    });
    fireEvent.click(send);
    await screen.findByRole("heading", {
      name: "Submitting original workflow action",
    });
    await act(async () => fixture.finish(failure()));
    expect(
      await screen.findByRole("heading", { name: "Workflow outcome unknown" }),
    ).toBeVisible();
    expect(reason).toHaveValue("Replace prior evidence");
    expect(reason).toBeDisabled();
    expect(send).toBeDisabled();
    expect(
      screen.getByRole("button", {
        name: "Reconcile original workflow action",
      }),
    ).toBeDisabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Read original workflow receipt" }),
    );
    expect(
      await screen.findByText(/Original workflow return recorded/),
    ).toBeVisible();
    expect(screen.queryByText("Workflow outcome unknown")).toBeNull();
    const sends = fixture.calls.filter(
      ({ url }) => url === "/api/application-workflow-occurrence",
    );
    const reads = fixture.calls.filter(
      ({ body }) =>
        body.program.function === "application.operation.receipt.read",
    );
    expect(sends).toHaveLength(1);
    // Recovery checks the receipt, then the inspector opens the same receipt.
    expect(reads).toHaveLength(2);
    for (const { body } of reads)
      expect(body.program.arguments).toEqual({
        operationId: sends[0].body.idempotencyKey,
      });
    expect(
      fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
    ).toHaveLength(1);
  },
);

it.each([
  "expired admission",
  "stale review basis",
  "changed workflow authority",
] as const)(
  "keeps an unknown outcome after %s on replay and resolves it from the original committed receipt",
  async (denial) => {
    const staleMessage =
      "Required evidence has changed. Return the work to replace that evidence.";
    const fixture = reviewFixture({
      loseResponse: true,
      firstReceiptMissing: true,
      replayDenied: denial === "expired admission",
      refuseWorkflowAuthority: denial === "changed workflow authority",
      refuseReviewBasis:
        denial === "stale review basis"
          ? { suffix: "STALE", message: staleMessage }
          : undefined,
    });
    const props = {
      app,
      catalog: {
        ...catalog,
        functions: {
          ...catalog.functions,
          "application.operation.receipt.read": {},
        },
      },
      targetOccurrenceId: "1".repeat(32),
      targetActivityId: "review",
    };
    const view = render(<GenericWorkflow {...props} />);
    await screen.findByText(
      "Manual attestation: I accept the submitted capacity evidence",
    );
    await waitFor(() => expect(screen.getByRole("checkbox")).toBeEnabled());
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Accept review" }));
    await screen.findByRole("heading", { name: "Workflow outcome unknown" });
    const replay = () =>
      screen.getByRole("button", {
        name: "Reconcile original workflow action",
      });
    const receipt = () =>
      screen.getByRole("button", {
        name: "Read original workflow receipt",
      });
    expect(replay()).toBeDisabled();
    fireEvent.click(receipt());
    expect(
      await screen.findByText(/No workflow receipt is visible yet/),
    ).toBeVisible();
    expect(replay()).toBeEnabled();
    fireEvent.click(replay());
    expect(
      await screen.findByText(
        denial === "expired admission"
          ? "The original workflow admission expired. Check its receipt again."
          : denial === "changed workflow authority"
            ? "Access changed while reconciling. The original workflow outcome remains unconfirmed. Refresh the workflow before checking its receipt."
            : staleMessage,
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("heading", { name: "Workflow outcome unknown" }),
    ).toBeVisible();
    if (denial === "changed workflow authority") {
      expect(
        screen.queryByRole("button", { name: "Accept review" }),
      ).toBeNull();
      expect(receipt()).toBeDisabled();
      fireEvent.click(screen.getByRole("button", { name: "Refresh workflow" }));
      await waitFor(() => expect(receipt()).toBeEnabled());
    } else {
      expect(
        screen.getByRole("button", { name: "Accept review" }),
      ).toBeDisabled();
    }
    expect(replay()).toBeDisabled();
    if (denial === "expired admission") {
      view.unmount();
      const { catalog: receiptCatalog, ...route } = props;
      const recovered = render(
        <GenericWorkflow {...route} catalog={catalog} />,
      );
      await screen.findByText(/The original workflow admission expired/);
      expect(replay()).toBeDisabled();
      expect(
        screen.queryByRole("button", {
          name: "Copy workflow receipt check for MCP",
        }),
      ).toBeNull();
      recovered.rerender(
        <GenericWorkflow {...route} catalog={receiptCatalog} />,
      );
      expect(replay()).toBeDisabled();
      const writeText = vi.fn().mockResolvedValue(undefined);
      vi.stubGlobal("navigator", { clipboard: { writeText } });
      fireEvent.click(
        screen.getByRole("button", {
          name: "Copy workflow receipt check for MCP",
        }),
      );
      await screen.findByText("Receipt check copied for your MCP client.");
      const original = fixture.calls.find(
        ({ url }) => url === "/api/application-workflow-occurrence",
      )!.body;
      expect(JSON.parse(writeText.mock.calls[0][0])).toEqual({
        workspace_id: original.workspaceId,
        application_id: original.applicationId,
        program: {
          languageVersion: 2,
          function: "application.operation.receipt.read",
          arguments: { operationId: original.idempotencyKey },
        },
      });
    }
    fireEvent.click(receipt());
    expect(
      await screen.findByText(
        "Original workflow completion recorded. Status at commit: Active.",
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "Workflow outcome unknown" }),
    ).toBeNull();
    expect(
      fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
    ).toHaveLength(1);
    const effects = fixture.calls.filter(
      ({ url }) => url === "/api/application-workflow-occurrence",
    );
    expect(effects).toHaveLength(2);
    expect(effects[1].body).toEqual(effects[0].body);
  },
);

it.each(["role", "capability"])(
  "holds an unconfirmed workflow action after an in-flight receipt loses its %s context",
  async (change) => {
    const fixture = reviewFixture({ loseResponse: true, deferReceipt: true });
    const withReceipt = {
      ...catalog,
      functions: {
        ...catalog.functions,
        "application.operation.receipt.read": {},
      },
    };
    const props = {
      app,
      targetOccurrenceId: "1".repeat(32),
      targetActivityId: "review",
    };
    const view = render(<GenericWorkflow {...props} catalog={withReceipt} />);
    await screen.findByText(
      "Manual attestation: I accept the submitted capacity evidence",
    );
    await waitFor(() => expect(screen.getByRole("checkbox")).toBeEnabled());
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Accept review" }));
    const unknown = () =>
      screen.getByRole("heading", { name: "Workflow outcome unknown" });
    const read = () =>
      screen.getByRole("button", { name: "Read original workflow receipt" });
    await screen.findByRole("heading", { name: "Workflow outcome unknown" });
    fireEvent.click(read());
    view.rerender(
      <GenericWorkflow
        {...props}
        catalog={
          change === "role"
            ? {
                ...withReceipt,
                applicationAccess: {
                  ...withReceipt.applicationAccess,
                  role: "Editor",
                },
              }
            : catalog
        }
      />,
    );
    await act(async () => fixture.finishReceipt());
    expect(
      screen.queryByText(/Original workflow completion recorded/),
    ).not.toBeInTheDocument();
    expect(unknown()).toBeVisible();
    expect(fixture.receiptSignal()?.aborted).toBe(true);
    expect(
      screen.getByRole("button", { name: "Accept review" }),
    ).toBeDisabled();
    if (change === "capability") expect(read()).toBeDisabled();
    view.rerender(<GenericWorkflow {...props} catalog={withReceipt} />);
    fireEvent.click(read());
    expect(
      await screen.findByText(
        "Original workflow completion recorded. Status at commit: Active.",
      ),
    ).toBeVisible();
    await screen.findByText("Activity outcome loaded.");
    const reads = fixture.calls.filter(
      ({ body }) =>
        body.program.function === "application.operation.receipt.read",
    );
    expect(reads).toHaveLength(3);
    expect(reads[0].body).toEqual(reads[1].body);
    expect(reads[1].body).toEqual(reads[2].body);
    expect(
      fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
    ).toHaveLength(1);
    expect(
      fixture.calls.filter(
        ({ url }) => url === "/api/application-workflow-occurrence",
      ),
    ).toHaveLength(1);
  },
);

it.each(["role", "application"])(
  "keeps the original workflow packet when an acknowledgement arrives after a %s change",
  async (change) => {
    const fixture = reviewFixture({ deferEffect: true });
    const withReceipt = {
      ...catalog,
      functions: {
        ...catalog.functions,
        "application.operation.receipt.read": {},
      },
    };
    const props = {
      app,
      targetOccurrenceId: "1".repeat(32),
      targetActivityId: "review",
    };
    const view = render(<GenericWorkflow {...props} catalog={withReceipt} />);
    await screen.findByText(
      "Manual attestation: I accept the submitted capacity evidence",
    );
    await waitFor(() => expect(screen.getByRole("checkbox")).toBeEnabled());
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Accept review" }));
    const captured = () =>
      fixture.calls.find(
        ({ url }) => url === "/api/application-workflow-occurrence",
      );
    await waitFor(() => expect(captured()).toBeDefined());
    const newRole = {
      ...withReceipt,
      applicationAccess: { ...withReceipt.applicationAccess, role: "Editor" },
    };
    view.rerender(
      <GenericWorkflow
        {...props}
        app={
          change === "application" ? { ...app, applicationId: "sibling" } : app
        }
        catalog={change === "role" ? newRole : withReceipt}
      />,
    );
    await act(async () => fixture.finish());
    expect(
      screen.queryByText(/Original workflow completion recorded/),
    ).not.toBeInTheDocument();
    if (change === "application") {
      expect(
        screen.queryByRole("button", {
          name: "Read original workflow receipt",
        }),
      ).not.toBeInTheDocument();
      view.rerender(<GenericWorkflow {...props} catalog={withReceipt} />);
    }
    expect(
      await screen.findByRole("heading", { name: "Workflow outcome unknown" }),
    ).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Read original workflow receipt" }),
    );
    expect(
      await screen.findByText(
        "Original workflow completion recorded. Status at commit: Active.",
      ),
    ).toBeVisible();
    expect(
      fixture.calls.filter(
        ({ body }) =>
          body.program.function === "application.operation.receipt.read",
      )[0].body.program.arguments.operationId,
    ).toEqual(captured()?.body.idempotencyKey);
    expect(
      fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
    ).toHaveLength(1);
  },
);

it("refuses a changed workflow definition before using its evidence contract", async () => {
  const { calls } = reviewFixture({ changedDefinition: true });
  render(<GenericWorkflow app={app} catalog={catalog} />);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "no longer matches this occurrence",
  );
  expect(
    screen.getByRole("button", { name: "Complete activity" }),
  ).toBeDisabled();
  expect(
    calls.some(
      ({ body }) =>
        body.program?.function ===
        "application.workflow.activity.evidence.list",
    ),
  ).toBe(false);
  expect(calls.some(({ url }) => url === "/api/operation-admission")).toBe(
    false,
  );
});

it.each([true, false])(
  "preserves the authored current-evidence rule requireCurrent=%s",
  async (requireCurrent) => {
    const { calls } = reviewFixture({ requireCurrent, current: false });
    render(<GenericWorkflow app={app} catalog={catalog} />);
    const receipt = await screen.findByLabelText("Completion evidence");
    const option = await screen.findByRole("option", {
      name: /Historical at last check/,
    });
    expect(option).toHaveProperty("disabled", requireCurrent);
    fireEvent.change(receipt, { target: { value: "eligible-receipt" } });
    expect(
      await screen.findByText(/Selected evidence:.*Historical at last check/),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("checkbox"));
    const complete = screen.getByRole("button", { name: "Complete activity" });
    expect(complete).toHaveProperty("disabled", requireCurrent);
    fireEvent.click(complete);
    if (requireCurrent)
      expect(
        calls.some(({ url }) => url === "/api/application-workflow-occurrence"),
      ).toBe(false);
    else {
      await waitFor(() =>
        expect(
          calls.some(
            ({ url }) => url === "/api/application-workflow-occurrence",
          ),
        ).toBe(true),
      );
      expect(
        calls.find(({ url }) => url === "/api/application-workflow-occurrence")
          ?.body.program.arguments.evidence,
      ).toEqual({ kind: "OperationReceipt", operationId: "eligible-receipt" });
    }
  },
);

it("shows review prerequisites and the exact configured correction target without treating a receipt as acceptance", async () => {
  const { calls } = reviewFixture();
  render(
    <GenericWorkflow
      app={app}
      catalog={catalog}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  await screen.findByText(
    "Manual attestation: I accept the submitted capacity evidence",
  );
  expect(
    screen.getByText("Prerequisites: Prior preparation (Completed)"),
  ).toBeVisible();
  expect(
    screen.getByText("Configured return target: Prior preparation."),
  ).toBeVisible();
  const accept = screen.getByRole("button", { name: "Accept review" });
  expect(accept).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Return reason"), {
    target: { value: "Capacity evidence is incomplete" },
  });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(
    screen.getByRole("button", { name: "Return to Prior preparation" }),
  );
  await waitFor(() =>
    expect(
      calls.some(({ url }) => url === "/api/application-workflow-occurrence"),
    ).toBe(true),
  );
  const body = calls.find(
    ({ url }) => url === "/api/application-workflow-occurrence",
  )!.body;
  expect(body.program).toEqual({
    languageVersion: 2,
    function: "application.workflow.activity.return",
    arguments: {
      occurrenceId: "1".repeat(32),
      activityId: "review",
      expectedActivityStateToken: activityToken,
      reason: "Capacity evidence is incomplete",
    },
  });
  expect(body.program.arguments).not.toHaveProperty("returnTo");
});

it("does not expose mutations omitted from the current function catalogue", async () => {
  const { calls } = reviewFixture();
  const functions = { ...catalog.functions };
  delete (functions as Record<string, unknown>)[
    "application.workflow.activity.complete"
  ];
  delete (functions as Record<string, unknown>)[
    "application.workflow.activity.return"
  ];
  delete (functions as Record<string, unknown>)[
    "application.workflow.occurrence.cancel"
  ];
  render(
    <GenericWorkflow
      app={app}
      catalog={{ ...catalog, functions }}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  await screen.findByText(
    "Manual attestation: I accept the submitted capacity evidence",
  );
  fireEvent.change(screen.getByLabelText("Return reason"), {
    target: { value: "Correction needed" },
  });
  fireEvent.click(screen.getByRole("checkbox"));
  for (const name of ["Accept review", "Return to Prior preparation"])
    expect(screen.getByRole("button", { name })).toBeDisabled();
  expect(
    screen.queryByRole("button", { name: "Cancel occurrence" }),
  ).toBeNull();
  expect(calls.some(({ url }) => url === "/api/operation-admission")).toBe(
    false,
  );
});

it("lets an administrator cancel the exact occurrence without assigned work", async () => {
  const fixture = reviewFixture({ unassigned: true });
  const occurrenceId = "1".repeat(32);
  const authorized = {
    ...catalog,
    applicationAccess: { role: "Administrator", workspaceAdministrator: false },
    functions: {
      ...catalog.functions,
      "application.workflow.occurrence.cancel": {},
    },
  };
  render(
    <GenericWorkflow
      app={app}
      catalog={authorized}
      targetOccurrenceId={occurrenceId}
    />,
  );
  const cancel = await screen.findByRole("button", {
    name: "Cancel occurrence",
  });
  expect(cancel).toBeEnabled();
  expect(
    screen.queryByRole("button", { name: "Complete activity" }),
  ).toBeNull();
  fireEvent.click(cancel);
  expect(window.confirm).toHaveBeenCalledWith(
    expect.stringContaining(occurrenceId),
  );
  expect(
    await screen.findByText(
      "Original workflow cancel recorded. Status at commit: Cancelled.",
    ),
  ).toBeVisible();
  const effects = fixture.calls.filter(
    ({ url }) => url === "/api/application-workflow-occurrence",
  );
  expect(effects).toHaveLength(1);
  expect(effects[0].body.program).toEqual({
    languageVersion: 2,
    function: "application.workflow.occurrence.cancel",
    arguments: { occurrenceId, expectedOccurrenceStateToken: occurrenceToken },
  });
});

const startCatalogue = {
  ...catalog,
  applicationAccess: { role: "Administrator", workspaceAdministrator: false },
  functions: {
    ...catalog.functions,
    "application.workflow.list": {},
    "application.workflow.occurrence.start": {},
  },
};

it("clears cached workflow choices when the exact definition is unavailable", async () => {
  const fixture = reviewFixture({
    startable: true,
    unassigned: true,
    definitionUnavailable: true,
  });
  render(<GenericWorkflow app={app} catalog={startCatalogue} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Show published workflows" }),
  );
  fireEvent.change(await screen.findByLabelText("Published workflow"), {
    target: { value: "capacity" },
  });
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Open the first page to refresh it",
  );
  expect(
    screen.queryByRole("option", { name: /Capacity review/ }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Start occurrence" }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByRole("heading", { name: "Published workflows" }),
  ).toHaveFocus();
  expect(
    fixture.calls.some(({ url }) => url === "/api/operation-admission"),
  ).toBe(false);
});

it("uses the exact current workflow pins and opens the occurrence returned by start", async () => {
  const fixture = reviewFixture({
    startable: true,
    pagedWorkflows: true,
    unassigned: true,
  });
  const openOccurrence = vi.fn();
  render(
    <GenericWorkflow
      app={app}
      catalog={startCatalogue}
      openOccurrence={openOccurrence}
    />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Show published workflows" }),
  );
  expect(
    await screen.findByRole("option", { name: /Allocation checks/ }),
  ).toBeVisible();
  const heading = screen.getByRole("heading", { name: "Published workflows" });
  const nextPage = screen.getByRole("button", { name: "Next workflow page" });
  nextPage.focus();
  fireEvent.click(nextPage);
  expect(heading).toHaveFocus();
  expect(screen.getByText("Reading workflows…")).toBeVisible();
  fireEvent.change(await screen.findByLabelText("Published workflow"), {
    target: { value: "capacity" },
  });
  expect(heading).toHaveFocus();
  const start = await screen.findByRole("button", { name: "Start occurrence" });
  start.focus();
  fireEvent.click(start);
  const open = await screen.findByRole("button", {
    name: "Open started occurrence",
  });
  expect(open).toHaveFocus();
  fireEvent.click(open);
  expect(openOccurrence).toHaveBeenCalledWith("8".repeat(32));
  expect(
    fixture.calls
      .filter(
        ({ body }) => body.program?.function === "application.workflow.list",
      )
      .at(-1)?.body.program.arguments,
  ).toEqual({
    limit: 50,
    status: "Active",
    afterFlowId: "allocation",
    collectionToken: "c".repeat(64),
  });
  expect(
    fixture.calls.find(
      ({ url }) => url === "/api/application-workflow-occurrence",
    )?.body.program,
  ).toEqual({
    languageVersion: 2,
    function: "application.workflow.occurrence.start",
    arguments: {
      flowId: "capacity",
      expectedStateToken: flowToken,
      expectedMetadataRevision: 2,
      expectedPolicyRevision: 3,
      expectedSchemaEpoch: 4,
    },
  });
});

it.each(["replay", "receipt"] as const)(
  "recovers a lost workflow start through the original %s and focuses the result",
  async (recovery) => {
    const fixture = reviewFixture({
      startable: true,
      unassigned: true,
      loseResponse: true,
    });
    const openOccurrence = vi.fn();
    render(
      <GenericWorkflow
        app={app}
        catalog={
          recovery === "receipt"
            ? {
                ...startCatalogue,
                functions: {
                  ...startCatalogue.functions,
                  "application.operation.receipt.read": {},
                },
              }
            : startCatalogue
        }
        openOccurrence={openOccurrence}
      />,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Show published workflows" }),
    );
    fireEvent.change(await screen.findByLabelText("Published workflow"), {
      target: { value: "capacity" },
    });
    const start = await screen.findByRole("button", {
      name: "Start occurrence",
    });
    start.focus();
    fireEvent.click(start);
    expect(
      await screen.findByRole("heading", { name: "Workflow outcome unknown" }),
    ).toHaveFocus();
    const settle = screen.getByRole("button", {
      name:
        recovery === "receipt"
          ? "Read original workflow receipt"
          : "Reconcile original workflow action",
    });
    await waitFor(() => expect(settle).toBeEnabled());
    expect(
      screen.queryByRole("button", { name: "Open started occurrence" }),
    ).toBeNull();
    settle.focus();
    fireEvent.click(settle);
    const open = await screen.findByRole("button", {
      name: "Open started occurrence",
    });
    expect(open).toHaveFocus();
    fireEvent.click(open);
    expect(openOccurrence).toHaveBeenCalledWith("8".repeat(32));
    expect(
      fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
    ).toHaveLength(1);
    const effects = fixture.calls.filter(
      ({ url }) => url === "/api/application-workflow-occurrence",
    );
    expect(effects).toHaveLength(recovery === "replay" ? 2 : 1);
    if (recovery === "replay") expect(effects[1].body).toEqual(effects[0].body);
    else {
      const read = fixture.calls.find(
        ({ body }) =>
          body.program.function === "application.operation.receipt.read",
      );
      expect(read?.body.program.arguments.operationId).toBe(
        effects[0].body.idempotencyKey,
      );
      expect(
        screen.queryByRole("heading", { name: "Workflow start receipt" }),
      ).toBeNull();
      const receipt = screen.getByRole("button", {
        name: "View start receipt",
      });
      receipt.focus();
      fireEvent.click(receipt);
      expect(
        await screen.findByRole("heading", { name: "Workflow start receipt" }),
      ).toHaveFocus();
      expect(await screen.findByText("Activity outcome loaded.")).toBeVisible();
      fireEvent.click(screen.getByRole("button", { name: "Close" }));
      expect(receipt).toHaveFocus();
    }
  },
);

it("leaves focus with the user when a workflow start finishes in the background", async () => {
  const fixture = reviewFixture({
    startable: true,
    unassigned: true,
    deferEffect: true,
  });
  render(
    <GenericWorkflow
      app={app}
      catalog={startCatalogue}
      openOccurrence={vi.fn()}
    />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Show published workflows" }),
  );
  fireEvent.change(await screen.findByLabelText("Published workflow"), {
    target: { value: "capacity" },
  });
  const start = await screen.findByRole("button", { name: "Start occurrence" });
  start.focus();
  fireEvent.click(start);
  await screen.findByRole("heading", {
    name: "Submitting original workflow action",
  });
  const filter = screen.getByRole("textbox", { name: "Find an activity" });
  filter.focus();
  await act(async () => fixture.finish());
  expect(
    await screen.findByRole("button", { name: "Open started occurrence" }),
  ).toBeVisible();
  expect(filter).toHaveFocus();
});

it.each([
  [
    "admission",
    "APPLICATION_WORKFLOW_STALE_CONTEXT",
    "The workflow context changed. Open the first workflow page",
  ],
  [
    "effect",
    "APPLICATION_WORKFLOW_STALE_CONTEXT",
    "The workflow context changed. Open the first workflow page",
  ],
  [
    "effect",
    "APPLICATION_WORKFLOW_RECEIPT_CONTRACT_UNSUPPORTED",
    "A workflow administrator must update the evidence condition before this workflow can start.",
  ],
  [
    "effect",
    "APPLICATION_WORKFLOW_EVIDENCE_VIEW_SCOPE_MISMATCH",
    "A workflow administrator must align the saved view and workflow selections before this workflow can start.",
  ],
  [
    "effect",
    "ORDERED_RULE_CURRENT_OWNER_UNSUPPORTED",
    "A workflow administrator must replace the unavailable legacy sequence before this workflow can start.",
  ],
  [
    "effect",
    "APPLICATION_FUNCTION_RETIRED",
    "A workflow administrator must replace the retired destination before this workflow can start.",
  ],
] as const)(
  "keeps the publisher open and requires fresh review after %s refuses with %s",
  async (phase, code, message) => {
    const { calls } = reviewFixture({
      startable: true,
      unassigned: true,
      refuseStart: { phase, code },
    });
    render(
      <GenericWorkflow
        app={app}
        catalog={startCatalogue}
        openOccurrence={vi.fn()}
      />,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Show published workflows" }),
    );
    const select = async () =>
      fireEvent.change(await screen.findByLabelText("Published workflow"), {
        target: { value: "capacity" },
      });
    await select();
    const start = await screen.findByRole("button", {
      name: "Start occurrence",
    });
    start.focus();
    fireEvent.click(start);
    const panel = within(
      screen.getByRole("region", { name: "Start a workflow" }),
    );
    expect(await panel.findByRole("alert")).toHaveTextContent(message);
    expect(
      panel.getByRole("heading", { name: "Published workflows" }),
    ).toHaveFocus();
    expect(
      panel.queryByRole("button", { name: "Start occurrence" }),
    ).toBeNull();
    expect(
      screen.queryByRole("region", { name: "Original workflow action" }),
    ).toBeNull();
    const admissions = () =>
      calls.filter(({ url }) => url === "/api/operation-admission");
    const effects = () =>
      calls.filter(({ url }) => url === "/api/application-workflow-occurrence");
    expect(admissions()).toHaveLength(1);
    expect(effects()).toHaveLength(phase === "effect" ? 1 : 0);

    fireEvent.click(panel.getByRole("button", { name: "First workflow page" }));
    const chooser = await panel.findByLabelText("Published workflow");
    expect(chooser).toHaveValue("");
    expect(admissions()).toHaveLength(1);
    await select();
    fireEvent.click(
      await panel.findByRole("button", { name: "Start occurrence" }),
    );
    expect(
      await screen.findByRole("button", { name: "Open started occurrence" }),
    ).toBeVisible();
    expect(
      admissions().map(
        ({ body }) => body.program.arguments.expectedPolicyRevision,
      ),
    ).toEqual([3, 4]);
    if (phase === "effect")
      expect(effects()[1].body.idempotencyKey).not.toBe(
        effects()[0].body.idempotencyKey,
      );
  },
);

it("refreshes the published list when the selected workflow has been withdrawn", async () => {
  const { calls } = reviewFixture({
    startable: true,
    unassigned: true,
    refuseStart: {
      phase: "effect",
      code: "APPLICATION_WORKFLOW_CURRENT_UNAVAILABLE",
    },
  });
  render(<GenericWorkflow app={app} catalog={startCatalogue} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Show published workflows" }),
  );
  fireEvent.change(await screen.findByLabelText("Published workflow"), {
    target: { value: "capacity" },
  });
  fireEvent.click(
    await screen.findByRole("button", { name: "Start occurrence" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "The selected workflow is unavailable for a new occurrence.",
  );
  fireEvent.click(screen.getByRole("button", { name: "First workflow page" }));
  expect(await screen.findByText("No active workflows.")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Start occurrence" })).toBeNull();
  expect(
    calls.filter(({ url }) => url === "/api/operation-admission"),
  ).toHaveLength(1);
});

it("keeps the original workflow start when a stale response follows an unconfirmed send", async () => {
  const { calls } = reviewFixture({
    startable: true,
    unassigned: true,
    loseResponse: true,
    refuseStart: {
      phase: "effect",
      code: "APPLICATION_WORKFLOW_STALE_CONTEXT",
    },
  });
  render(<GenericWorkflow app={app} catalog={startCatalogue} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Show published workflows" }),
  );
  fireEvent.change(await screen.findByLabelText("Published workflow"), {
    target: { value: "capacity" },
  });
  fireEvent.click(
    await screen.findByRole("button", { name: "Start occurrence" }),
  );
  await screen.findByText("Workflow outcome unknown");
  const reconcile = screen.getByRole("button", {
    name: "Reconcile original workflow action",
  });
  await waitFor(() => expect(reconcile).toBeEnabled());
  fireEvent.click(reconcile);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "APPLICATION_WORKFLOW_STALE_CONTEXT",
  );
  expect(await screen.findByText("Workflow outcome unknown")).toBeVisible();
  expect(
    screen.getByRole("button", { name: "Start occurrence" }),
  ).toBeDisabled();
  expect(
    screen.queryByRole("button", { name: "First workflow page" }),
  ).toBeNull();
  expect(
    calls.filter(({ url }) => url === "/api/operation-admission"),
  ).toHaveLength(1);
  const effects = calls.filter(
    ({ url }) => url === "/api/application-workflow-occurrence",
  );
  expect(effects).toHaveLength(2);
  expect(effects[1].body).toEqual(effects[0].body);
});

it("withdraws review when the selected definition no longer matches the published page", async () => {
  const fixture = reviewFixture({
    startable: true,
    changedDefinition: true,
    unassigned: true,
  });
  render(<GenericWorkflow app={app} catalog={startCatalogue} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Show published workflows" }),
  );
  fireEvent.change(await screen.findByLabelText("Published workflow"), {
    target: { value: "capacity" },
  });
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "The current workflow could not be confirmed",
  );
  expect(screen.queryByRole("button", { name: "Start occurrence" })).toBeNull();
  expect(
    fixture.calls.some(({ url }) => url === "/api/operation-admission"),
  ).toBe(false);
});

it("keeps an activity draft intact while another workflow is prepared", async () => {
  const fixture = reviewFixture({ startable: true });
  render(<GenericWorkflow app={app} catalog={startCatalogue} />);
  const evidence = await screen.findByLabelText("Completion evidence");
  await screen.findByRole("option", { name: /Application rule run/ });
  fireEvent.change(evidence, { target: { value: "eligible-receipt" } });
  fireEvent.click(
    screen.getByRole("button", { name: "Show published workflows" }),
  );
  fireEvent.change(await screen.findByLabelText("Published workflow"), {
    target: { value: "capacity" },
  });
  expect(
    await screen.findByRole("button", { name: "Start occurrence" }),
  ).toBeDisabled();
  expect(evidence).toHaveValue("eligible-receipt");
  expect(
    fixture.calls.some(({ url }) => url === "/api/operation-admission"),
  ).toBe(false);
});

it("keeps a reviewed occurrence cancellation valid when its definition finishes loading", async () => {
  const fixture = reviewFixture({
    unassigned: true,
    deferAdmission: true,
    deferDefinition: true,
  });
  const admin = {
    ...startCatalogue,
    functions: {
      ...startCatalogue.functions,
      "application.workflow.occurrence.cancel": {},
    },
  };
  render(
    <GenericWorkflow
      app={app}
      catalog={admin}
      targetOccurrenceId={"1".repeat(32)}
    />,
  );
  const cancel = await screen.findByRole("button", {
    name: "Cancel occurrence",
  });
  await waitFor(() =>
    expect(
      fixture.calls.some(
        ({ body }) => body.program?.function === "application.workflow.read",
      ),
    ).toBe(true),
  );
  fireEvent.click(cancel);
  await waitFor(() =>
    expect(
      fixture.calls.some(({ url }) => url === "/api/operation-admission"),
    ).toBe(true),
  );
  await act(async () => fixture.finishDefinition());
  await act(async () => fixture.finishAdmission());
  expect(
    await screen.findByText(
      "Original workflow cancel recorded. Status at commit: Cancelled.",
    ),
  ).toBeVisible();
});

it("drops a pending cancellation when the current catalogue withdraws cancellation authority", async () => {
  const fixture = reviewFixture({ unassigned: true, deferAdmission: true });
  const admin = {
    ...startCatalogue,
    functions: {
      ...startCatalogue.functions,
      "application.workflow.occurrence.cancel": {},
    },
  };
  const occurrenceId = "1".repeat(32);
  const { rerender } = render(
    <GenericWorkflow
      app={app}
      catalog={admin}
      targetOccurrenceId={occurrenceId}
    />,
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Cancel occurrence" }),
  );
  await waitFor(() =>
    expect(
      fixture.calls.some(({ url }) => url === "/api/operation-admission"),
    ).toBe(true),
  );
  rerender(
    <GenericWorkflow
      app={app}
      catalog={catalog}
      targetOccurrenceId={occurrenceId}
    />,
  );
  await act(async () => fixture.finishAdmission());
  expect(
    screen.queryByRole("button", { name: "Cancel occurrence" }),
  ).toBeNull();
  expect(
    fixture.calls.some(
      ({ url }) => url === "/api/application-workflow-occurrence",
    ),
  ).toBe(false);
});

it("freezes the reviewed proposal and activity selection while the original effect is pending", async () => {
  const fixture = reviewFixture({ deferEffect: true });
  render(<GenericWorkflow app={app} catalog={catalog} />);
  const evidence = await screen.findByLabelText("Completion evidence");
  await screen.findByRole("option", { name: /Application rule run/ });
  fireEvent.change(evidence, { target: { value: "eligible-receipt" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Complete activity" }));
  await waitFor(() =>
    expect(
      fixture.calls.some(
        ({ url }) => url === "/api/application-workflow-occurrence",
      ),
    ).toBe(true),
  );
  expect(
    screen.getByRole("button", { name: "Open activity Review capacity" }),
  ).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Open activity Review capacity" }),
  );
  expect(
    screen.getByRole("heading", { name: "Prepare capacity" }),
  ).toBeVisible();
  await act(async () => fixture.finish());
  expect(
    await screen.findByText(
      "Original workflow completion recorded. Status at commit: Active.",
    ),
  ).toBeVisible();
  expect(screen.getByRole("checkbox")).not.toBeChecked();
  expect(
    fixture.calls.filter(
      ({ url }) => url === "/api/application-workflow-occurrence",
    ),
  ).toHaveLength(1);
});

it.each([
  ["changed", "The workflow occurrence changed."],
  ["authority", "Your access changed during this workflow read."],
] as const)(
  "refuses a %s history page and invalidates the current review",
  async (historyPages, message) => {
    reviewFixture({ returnHistory: "active", historyPages });
    render(
      <GenericWorkflow
        app={app}
        catalog={catalog}
        targetOccurrenceId={"1".repeat(32)}
        targetActivityId="prior"
      />,
    );
    const history = within(
      await screen.findByRole("region", { name: "Activity history" }),
    );
    const acknowledgement = await screen.findByRole("checkbox", {
      name: /reviewed this exact activity/,
    });
    await waitFor(() => expect(acknowledgement).toBeEnabled());
    fireEvent.click(acknowledgement);
    const complete = screen.getByRole("button", { name: "Complete activity" });
    expect(complete).toBeEnabled();
    fireEvent.click(
      history.getByRole("button", { name: "Load more activity history" }),
    );
    if (historyPages === "authority") {
      expect(await screen.findByRole("alert")).toHaveTextContent(message);
      expect(
        screen.queryByRole("region", { name: "Activity history" }),
      ).toBeNull();
      expect(screen.queryByText("Earlier reviewer notes.")).toBeNull();
      expect(
        screen.queryByRole("button", { name: "Complete activity" }),
      ).toBeNull();
    } else {
      expect(await history.findByRole("alert")).toHaveTextContent(message);
      expect(history.queryByText("Replace the stale evidence.")).toBeNull();
      expect(history.getByText("Earlier reviewer notes.")).toBeVisible();
      expect(complete).toBeDisabled();
    }
  },
);

it.each([
  ["APPLICATION_WORKFLOW_AUTHORIZATION_STALE", 409],
  ["APPLICATION_GRANT_REQUIRED", 403],
] as const)(
  "withdraws the calculated review after %s and requires a fresh catalogue check",
  async (code, status) => {
    const fixture = reviewFixture({
      assessment: "current",
      assessmentBasis: "CalculationPublication",
      returnHistory: "resolved",
    });
    let confirmAccess: () => void;
    let failAccess: (error: Error) => void;
    const recheck = vi.fn(
      () =>
        new Promise<void>((resolve, reject) => {
          confirmAccess = resolve;
          failAccess = reject;
        }),
    );
    render(
      <GenericWorkflow
        app={app}
        catalog={assessmentCatalog}
        onRefreshCatalog={recheck}
        targetOccurrenceId={"1".repeat(32)}
        targetActivityId="review"
      />,
    );
    const check = await screen.findByRole("button", {
      name: "Check current evidence for Prior preparation",
    });
    fireEvent.click(check);
    expect(
      await screen.findByText(/recorded calculated result is current/),
    ).toBeVisible();
    expect(screen.getByText("Earlier reviewer notes.")).toBeVisible();
    fixture.holdNextAssessment();
    check.focus();
    fireEvent.click(check);
    await act(async () => fixture.refuseAssessmentAccess(code, status));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Your access changed during this workflow read.",
    );
    expect(
      screen.queryByRole("region", { name: "Activity history" }),
    ).toBeNull();
    expect(screen.queryByText("Earlier reviewer notes.")).toBeNull();
    expect(screen.queryByRole("button", { name: "Accept review" })).toBeNull();
    const reads = fixture.calls.length;
    const refresh = screen.getByRole("button", { name: "Refresh workflow" });
    expect(refresh).toHaveFocus();
    fireEvent.click(refresh);
    expect(recheck).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole("button", { name: "Checking workflow access…" }),
    ).toHaveAttribute("aria-disabled", "true");
    expect(fixture.calls).toHaveLength(reads);
    expect(screen.queryByText("Earlier reviewer notes.")).toBeNull();
    await act(async () => failAccess(new Error("Catalogue unavailable")));
    expect(screen.queryByText("Earlier reviewer notes.")).toBeNull();
    expect(fixture.calls).toHaveLength(reads);
    fireEvent.click(screen.getByRole("button", { name: "Refresh workflow" }));
    expect(recheck).toHaveBeenCalledTimes(2);
    await act(async () => confirmAccess());
    expect(
      await screen.findByRole("button", { name: "Accept review" }),
    ).toBeDisabled();
    expect(
      screen.queryByText(/recorded calculated result is current/),
    ).toBeNull();
    expect(
      fixture.calls.some(({ url }) => url === "/api/operation-admission"),
    ).toBe(false);
  },
);

it("rejects repeated or non-progressing evidence pages before presenting an eligibility choice", () => {
  const item = {
    selectionKey: "receipt",
    label: "Rule run",
    occurredAt: "2026-11-17T10:00:00Z",
    outcome: "Committed" as const,
    current: true,
  };
  expect(() =>
    mergeWorkflowEvidence(
      [item],
      { items: [item], nextBeforeCommittedRevision: null },
      20,
    ),
  ).toThrow("invalid or repeated");
  expect(() =>
    mergeWorkflowEvidence(
      [],
      { items: [], nextBeforeCommittedRevision: 20 },
      20,
    ),
  ).toThrow("continuation is invalid");
});

it("wraps exact generic workflow programs without evaluating them", () => {
  const program = {
    languageVersion: 2,
    function: "application.workflow.occurrence.cancel",
    arguments: {
      occurrenceId: "1".repeat(32),
      expectedOccurrenceStateToken: occurrenceToken,
    },
  };
  expect(
    genericWorkflowActionBody(
      { workspaceId: "ws", applicationId: "cube" },
      program,
      "workflow-action-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "cube",
    program,
    idempotencyKey: "workflow-action-1",
    confirmed: true,
  });
});

it("opens an exact occurrence without the wider worklist and submits server-owned evidence", async () => {
  const occurrence = "1".repeat(32);
  const openDestination = vi.fn(
    () =>
      "The configured function has no inspectable immutable artifact identity.",
  );
  vi.stubGlobal("crypto", { randomUUID: () => "workflow-complete-key" });
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  const calls: Array<{ url: string; body: any }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body));
      calls.push({ url, body });
      if (url === "/api/operation-admission")
        return operationAdmissionResponse("5");
      if (url === "/api/application-workflow-occurrence")
        return new Response(
          JSON.stringify({
            result: {
              operationId: body.idempotencyKey,
              function: body.program.function,
              occurrenceId: body.program.arguments.occurrenceId,
              activityId: body.program.arguments.activityId,
              status: "Completed",
            },
          }),
        );
      if (body.program.function === "application.workflow.worklist") {
        if (body.program.arguments.occurrenceId !== occurrence)
          return new Response("The wider worklist is unavailable", {
            status: 503,
          });
        return new Response(
          JSON.stringify({
            result: {
              items: [
                {
                  occurrenceId: occurrence,
                  occurrenceStateToken: occurrenceToken,
                  flowId: "generic-flow",
                  flowStateToken: flowToken,
                  definitionDigest: "a".repeat(64),
                  activityId: "prepare",
                  activityStateToken: activityToken,
                  name: "Prepare cube slice",
                  kind: "Action",
                  destination: {
                    kind: "Function",
                    function: "application.rule.run",
                    argumentsDigest: "d".repeat(64),
                  },
                  assignmentResolution: {
                    assignmentId: "owner",
                    kind: "Action",
                  },
                },
              ],
              nextCursor: null,
            },
          }),
        );
      }
      if (body.program.function === "application.workflow.occurrence.read")
        return new Response(
          JSON.stringify({
            result: {
              occurrenceId: occurrence,
              flowId: "generic-flow",
              flowStateToken: flowToken,
              definitionDigest: "a".repeat(64),
              status: "Active",
              occurrenceStateToken: occurrenceToken,
              lastEventOrdinal: 1,
              currentReturns: [],
              activities: [
                {
                  activityId: "prepare",
                  kind: "Action",
                  status: "Ready",
                  activityStateToken: activityToken,
                },
              ],
              events: [
                {
                  ordinal: 1,
                  eventType: "OccurrenceStarted",
                  committedRevision: 9,
                  createdAt: "2026-11-02T10:00:00Z",
                },
              ],
            },
          }),
        );
      if (body.program.function === "application.workflow.read")
        return new Response(
          JSON.stringify({
            result: {
              flowId: "generic-flow",
              stateToken: flowToken,
              definitionDigest: "a".repeat(64),
              definition: {
                name: "Monthly close",
                activities: [
                  {
                    activityId: "prepare",
                    name: "Prepare cube slice",
                    kind: "Action",
                    dependsOn: [],
                    returnTo: null,
                    evidenceContract: {
                      kind: "ManualAttestation",
                      statement: "Prepared",
                    },
                  },
                ],
              },
            },
          }),
        );
      throw new Error(`Unexpected ${body.program.function}`);
    }),
  );

  const rendered = render(
    <GenericWorkflow
      app={app}
      catalog={catalog}
      targetOccurrenceId={occurrence}
      openDestination={openDestination}
    />,
  );
  expect((await screen.findAllByText("Prepare cube slice")).length).toBe(3);
  expect(
    await screen.findByText("Manual attestation: Prepared"),
  ).toBeInTheDocument();
  expect(
    (
      await axe.run(rendered.container, {
        rules: { "color-contrast": { enabled: false } },
      })
    ).violations,
  ).toEqual([]);
  fireEvent.click(
    screen.getByRole("button", { name: "Open governed destination" }),
  );
  expect(openDestination).toHaveBeenCalledWith(
    {
      kind: "Function",
      function: "application.rule.run",
      argumentsDigest: "d".repeat(64),
    },
    { occurrenceId: occurrence, activityId: "prepare" },
  );
  expect(screen.getByRole("alert")).toHaveTextContent(
    "no inspectable immutable artifact identity",
  );
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact activity, evidence requirement and current occurrence state.",
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Complete activity" }));
  await screen.findByText(
    "Original workflow completion recorded. Status at commit: Completed.",
  );
  expect(screen.queryByText("complete-receipt")).not.toBeInTheDocument();
  expect(screen.queryByText("generic-flow · prepare")).not.toBeInTheDocument();
  expect(screen.queryByText("owner")).not.toBeInTheDocument();
  expect(screen.queryByText("Event 1")).not.toBeInTheDocument();
  const action = calls.find(
    (item) => item.url === "/api/application-workflow-occurrence",
  )!;
  expect(action.body).toEqual({
    workspaceId: "ws",
    applicationId: "cube",
    confirmed: true,
    idempotencyKey: expect.stringMatching(/^oa1_/),
    program: {
      languageVersion: 2,
      function: "application.workflow.activity.complete",
      arguments: {
        occurrenceId: occurrence,
        activityId: "prepare",
        expectedActivityStateToken: activityToken,
        evidence: { kind: "ManualAttestation", confirmed: true },
      },
    },
  });
  await waitFor(() =>
    expect(
      calls.filter(
        (item) =>
          item.body.program?.function === "application.workflow.worklist",
      ).length,
    ).toBeGreaterThan(1),
  );
  for (const { body } of calls.filter(
    (item) => item.body.program?.function === "application.workflow.worklist",
  )) {
    expect(body.program.arguments).toEqual({
      occurrenceId: occurrence,
      limit: 100,
      includeBlocked: true,
    });
  }
});

it("keeps an edited activity intact until local selection is accepted", async () => {
  const activities = ["prepare", "review"].map((activityId) => ({
    occurrenceId: "1".repeat(32),
    occurrenceStateToken: occurrenceToken,
    flowId: "cycle",
    flowStateToken: flowToken,
    definitionDigest: "a".repeat(64),
    activityId,
    activityStateToken: activityToken,
    name: activityId === "prepare" ? "Prepare plan" : "Review plan",
    kind: "Action",
    destination: {
      kind: "Function",
      function: "application.rule.run",
      argumentsDigest: "b".repeat(64),
    },
    assignmentResolution: { assignmentId: "owner", kind: "Action" },
  }));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const { program } = JSON.parse(String(init?.body));
      const result =
        program.function === "application.workflow.worklist"
          ? { items: activities, nextCursor: null }
          : program.function === "application.workflow.occurrence.read"
            ? {
                occurrenceId: "1".repeat(32),
                flowId: "cycle",
                flowStateToken: flowToken,
                definitionDigest: "a".repeat(64),
                status: "Active",
                occurrenceStateToken: occurrenceToken,
                lastEventOrdinal: 1,
                currentReturns: [],
                activities: activities.map((item) => ({
                  ...item,
                  status: "Ready",
                })),
                events: [],
              }
            : program.function === "application.workflow.activity.evidence.list"
              ? {
                  items: [
                    {
                      selectionKey: "keep-this-evidence",
                      label: "Application rule run",
                      occurredAt: "2026-11-02T10:00:00Z",
                      outcome: "Committed",
                      current: true,
                    },
                  ],
                  nextBeforeCommittedRevision: null,
                }
              : {
                  flowId: "cycle",
                  stateToken: flowToken,
                  definitionDigest: "a".repeat(64),
                  definition: {
                    name: "Planning review",
                    activities: activities.map((item) => ({
                      activityId: item.activityId,
                      name: item.name,
                      kind: "Action",
                      dependsOn: [],
                      returnTo: null,
                      evidenceContract: {
                        kind: "OperationReceipt",
                        allowedFunctions: ["application.rule.run"],
                        requireCurrent: true,
                      },
                    })),
                  },
                };
      return new Response(JSON.stringify({ result }));
    }),
  );
  let accept: (() => void) | undefined;
  const openDestination = vi.fn(() => null);
  render(
    <GenericWorkflow
      app={app}
      catalog={catalog}
      openDestination={openDestination}
      onRequestTransition={(action) => {
        accept = action;
      }}
    />,
  );
  const receipt = await screen.findByLabelText("Completion evidence");
  await screen.findByRole("option", { name: /Application rule run/ });
  fireEvent.change(receipt, { target: { value: "keep-this-evidence" } });
  fireEvent.click(
    screen.getByRole("button", { name: "Open activity Review plan" }),
  );
  expect(receipt).toHaveValue("keep-this-evidence");
  expect(
    screen.getByRole("heading", { name: "Prepare plan" }),
  ).toBeInTheDocument();
  act(() => accept?.());
  await waitFor(() =>
    expect(screen.getByLabelText("Completion evidence")).toHaveValue(""),
  );
  expect(
    screen.getByRole("heading", { name: "Review plan" }),
  ).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Open governed destination" }),
  );
  expect(openDestination).toHaveBeenCalledWith(activities[1].destination, {
    occurrenceId: activities[1].occurrenceId,
    activityId: "review",
  });
});

it("ignores late errors from a cancelled application worklist read", async () => {
  let rejectOld: ((error: Error) => void) | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (body.applicationId === "cube")
        return new Promise<Response>((_resolve, reject) => {
          rejectOld = reject;
        });
      return Promise.resolve(
        new Response(
          JSON.stringify({ result: { items: [], nextCursor: null } }),
        ),
      );
    }),
  );
  const view = render(<GenericWorkflow app={app} catalog={catalog} />);
  view.rerender(
    <GenericWorkflow
      app={{ ...app, applicationId: "other" }}
      catalog={catalog}
    />,
  );
  await screen.findByText("No generic workflow activity is ready for you now.");
  await act(async () => rejectOld?.(new Error("Old application failure")));
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it("refuses a workflow transition before dispatch when all recovery slots are pinned", async () => {
  const fixture = reviewFixture();
  for (let index = 0; index < 24; index += 1) {
    const pin = renderHook(() =>
      usePreservedDraft(
        "ws",
        "cube",
        `pending-${index}`,
        "Unconfirmed operation",
        false,
        { packet: "" },
        () => undefined,
      ),
    );
    act(() => {
      pin.result.current.retain({ packet: `original-${index}` });
    });
    pin.unmount();
  }
  render(
    <GenericWorkflow
      app={app}
      catalog={catalog}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  const confirmation = await screen.findByRole("checkbox", {
    name: /I reviewed this exact activity/,
  });
  await waitFor(() => expect(confirmation).toBeEnabled());
  fireEvent.click(confirmation);
  const accept = screen.getByRole("button", { name: "Accept review" });
  expect(accept).toBeEnabled();
  fireEvent.click(accept);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "cannot retain another recovery record",
  );
  expect(
    fixture.calls.filter(({ url }) => url === "/api/operation-admission"),
  ).toHaveLength(1);
  expect(
    fixture.calls.filter(
      ({ url }) => url === "/api/application-workflow-occurrence",
    ),
  ).toHaveLength(0);
  expect(
    unsavedWorkSnapshot().filter(
      (item) => item.label === "Unconfirmed operation",
    ),
  ).toHaveLength(24);
});

it("never copies an old actor's pending packet or return reason into an in-place replacement identity", async () => {
  reviewFixture({ loseResponse: true });
  const forActor = (subjectId: string) => ({
    ...catalog,
    applicationAccess: {
      ...catalog.applicationAccess,
      issuer: "issuer",
      subjectId,
    },
  });
  setDraftIdentity("actor-one");
  const view = render(
    <GenericWorkflow
      app={app}
      catalog={forActor("one")}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  await screen.findByText(
    "Manual attestation: I accept the submitted capacity evidence",
  );
  fireEvent.change(screen.getByLabelText("Return reason"), {
    target: { value: "private actor-one reason" },
  });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(
    screen.getByRole("button", { name: "Return to Prior preparation" }),
  );
  await screen.findByRole("heading", { name: "Workflow outcome unknown" });
  setDraftIdentity("actor-two");
  view.rerender(
    <GenericWorkflow
      app={app}
      catalog={forActor("two")}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  await screen.findByText(
    "Manual attestation: I accept the submitted capacity evidence",
  );
  expect(
    screen.queryByRole("heading", { name: "Workflow outcome unknown" }),
  ).not.toBeInTheDocument();
  expect(screen.getByLabelText("Return reason")).toHaveValue("");
  expect(
    unsavedWorkSnapshot().some((item) => item.id.startsWith("actor-two:")),
  ).toBe(false);
  view.unmount();
  const remount = render(
    <GenericWorkflow
      app={app}
      catalog={forActor("two")}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  await screen.findByText(
    "Manual attestation: I accept the submitted capacity evidence",
  );
  expect(screen.getByLabelText("Return reason")).toHaveValue("");
  expect(
    screen.queryByRole("heading", { name: "Workflow outcome unknown" }),
  ).not.toBeInTheDocument();
  remount.unmount();
  // No explicit abandonment in this isolated component test: the old actor's
  // record remains under its original key, never under the replacement key.
  setDraftIdentity("actor-one");
  render(
    <GenericWorkflow
      app={app}
      catalog={forActor("one")}
      targetOccurrenceId={"1".repeat(32)}
      targetActivityId="review"
    />,
  );
  await screen.findByRole("heading", { name: "Workflow outcome unknown" });
  expect(screen.getByLabelText("Return reason")).toHaveValue(
    "private actor-one reason",
  );
});

it("describes a missing workflow catalogue operation as unavailable, without inferring a role denial", () => {
  render(<GenericWorkflow app={app} catalog={{ ...catalog, functions: {} }} />);
  expect(
    screen.getByText(
      "Generic application workflows are unavailable in the current application context.",
    ),
  ).toBeVisible();
  expect(
    screen.queryByText(/current role cannot read/),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByText("No generic workflow activity is ready for you now."),
  ).not.toBeInTheDocument();
});

it("checks the catalogue before concluding that assigned activities are unavailable", () => {
  render(<GenericWorkflow app={app} catalog={null} />);
  expect(
    screen.getByText("Checking access to assigned activities…"),
  ).toBeVisible();
  expect(
    screen.queryByText("No generic workflow activity is ready for you now."),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByText(/generic application workflows are unavailable/i),
  ).not.toBeInTheDocument();
});

it("waits for the exact catalogue, reads only advertised workflow capabilities and restores the original link", async () => {
  const fixture = reviewFixture();
  const occurrenceId = "1".repeat(32);
  const route = {
    app,
    targetOccurrenceId: occurrenceId,
    targetActivityId: "review",
  };
  const occurrenceRead = "application.workflow.occurrence.read";
  const definitionRead = "application.workflow.read";
  const readsFor = (fn: string) =>
    fixture.calls.filter(({ body }) => body.program?.function === fn);
  const view = render(<GenericWorkflow {...route} catalog={null} />);
  expect(readsFor(occurrenceRead)).toHaveLength(0);
  expect(
    screen.getByText("Checking access to this workflow occurrence…"),
  ).toBeVisible();
  view.rerender(
    <GenericWorkflow {...route} catalog={null} catalogueUnavailable />,
  );
  expect(readsFor(occurrenceRead)).toHaveLength(0);
  expect(
    screen.getByText(
      "Access to this workflow occurrence could not be confirmed.",
    ),
  ).toBeVisible();

  const historyOnly = {
    ...catalog,
    functions: { [occurrenceRead]: {} },
  };
  view.rerender(<GenericWorkflow {...route} catalog={historyOnly} />);
  expect(
    await screen.findByRole("heading", { name: "Activity history" }),
  ).toBeVisible();
  expect(readsFor(occurrenceRead)).toHaveLength(1);
  expect(readsFor(definitionRead)).toHaveLength(0);
  expect(
    screen.getByText(
      "Workflow definition reads are unavailable in this application context.",
    ),
  ).toBeVisible();
  expect(
    screen.getByRole("button", { name: "Refresh workflow" }),
  ).toBeEnabled();

  const definitionOnly = {
    ...catalog,
    functions: { [definitionRead]: {} },
  };
  view.rerender(<GenericWorkflow {...route} catalog={definitionOnly} />);
  expect(
    screen.queryByRole("heading", { name: "Activity history" }),
  ).toBeNull();
  expect(
    screen.getByText(
      "Workflow occurrence reads are unavailable in this application context.",
    ),
  ).toBeVisible();
  expect(readsFor(occurrenceRead)).toHaveLength(1);
  expect(readsFor(definitionRead)).toHaveLength(0);

  view.rerender(<GenericWorkflow {...route} catalog={catalog} />);
  expect(
    await screen.findByText(
      "Manual attestation: I accept the submitted capacity evidence",
    ),
  ).toBeVisible();
  expect(readsFor(occurrenceRead)).toHaveLength(2);
  expect(
    readsFor(occurrenceRead).map(
      ({ body }) => body.program.arguments.occurrenceId,
    ),
  ).toEqual([occurrenceId, occurrenceId]);
  expect(readsFor(definitionRead)).toHaveLength(1);

  view.rerender(<GenericWorkflow {...route} catalog={historyOnly} />);
  expect(
    screen.queryByText(
      "Manual attestation: I accept the submitted capacity evidence",
    ),
  ).toBeNull();
  expect(
    screen.getByRole("heading", { name: "Activity history" }),
  ).toBeVisible();
  expect(readsFor(definitionRead)).toHaveLength(1);
  view.rerender(<GenericWorkflow {...route} catalog={catalog} />);
  expect(
    screen.queryByText(
      "Manual attestation: I accept the submitted capacity evidence",
    ),
  ).toBeNull();
  expect(
    await screen.findByText(
      "Manual attestation: I accept the submitted capacity evidence",
    ),
  ).toBeVisible();
  expect(readsFor(definitionRead)).toHaveLength(2);
  expect(fixture.calls.every(({ url }) => url === "/api/read")).toBe(true);
});
