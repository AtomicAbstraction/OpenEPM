import { useEffect, useMemo, useState } from "react";
import { readProgram, request } from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { readCompleteWorkflowWorklist } from "./MyWork";
import { ReceiptInspector } from "./ReceiptInspector";

type ReadyActivity = {
  occurrenceId: string;
  occurrenceVersion: number;
  flowId: string;
  version: number;
  definitionDigest: string;
  activityId: string;
  activityVersion: number;
  name: string;
  kind: "Action" | "Review";
  destination: Record<string, unknown>;
  assignmentResolution: { assignmentId: string; kind: string };
};

type Occurrence = {
  occurrenceId: string;
  flowId: string;
  version: number;
  status: string;
  occurrenceVersion: number;
  activities: Array<{
    activityId: string;
    kind: "Action" | "Review";
    status: string;
    activityVersion: number;
    returnedToActivityId?: string | null;
  }>;
  events: Array<{
    ordinal: number;
    eventType: string;
    activityId?: string | null;
    committedRevision: number;
    createdAt: string;
  }>;
  nextEventOrdinal?: number | null;
};

export async function readCompleteWorkflowOccurrence(
  scope: Scope,
  occurrenceId: string,
  signal?: AbortSignal,
): Promise<Occurrence> {
  let afterEventOrdinal = 0;
  let combined: Occurrence | null = null;
  const seen = new Set<number>();
  for (;;) {
    const page = await readProgram<Occurrence>(
      scope,
      "application.workflow.occurrence.read",
      { occurrenceId, eventLimit: 500, afterEventOrdinal },
      signal,
    );
    if (!Array.isArray(page.events))
      throw new Error("INVALID_WORKFLOW_OCCURRENCE_PAGE");
    for (const event of page.events) {
      if (!Number.isSafeInteger(event.ordinal) || seen.has(event.ordinal))
        throw new Error("INVALID_WORKFLOW_EVENT_CONTINUATION");
      seen.add(event.ordinal);
    }
    combined = combined
      ? { ...page, events: [...combined.events, ...page.events] }
      : page;
    if (page.nextEventOrdinal == null) return combined;
    if (
      !Number.isSafeInteger(page.nextEventOrdinal) ||
      page.nextEventOrdinal <= afterEventOrdinal ||
      !seen.has(page.nextEventOrdinal)
    )
      throw new Error("INVALID_WORKFLOW_EVENT_CONTINUATION");
    afterEventOrdinal = page.nextEventOrdinal;
  }
}

type WorkflowDefinition = {
  definition: {
    activities: Array<{
      activityId: string;
      evidenceContract: { kind: string; statement?: string };
    }>;
  };
};

export const genericWorkflowActionBody = (
  scope: Scope,
  program: Record<string, unknown>,
  idempotencyKey: string,
) => ({ ...scope, program, idempotencyKey, confirmed: true });

export function GenericWorkflow({
  app,
  catalog,
  targetOccurrenceId,
  targetActivityId,
  openDestination,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  targetOccurrenceId?: string;
  targetActivityId?: string;
  openDestination?: (
    destination: Record<string, unknown>,
  ) => string | null | undefined;
}) {
  const [ready, setReady] = useState<ReadyActivity[]>([]);
  const [selected, setSelected] = useState<ReadyActivity | null>(null);
  const [occurrence, setOccurrence] = useState<Occurrence | null>(null);
  const [definition, setDefinition] = useState<WorkflowDefinition | null>(null);
  const [receiptId, setReceiptId] = useState("");
  const [returnReason, setReturnReason] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const [inspectReceiptId, setInspectReceiptId] = useState("");
  const [destinationError, setDestinationError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const workflowIntentKey = useStableMutationIntentKey("workflow-ui");
  const scope = app
    ? { workspaceId: app.workspaceId, applicationId: app.applicationId }
    : null;
  const canRead = Boolean(catalog?.functions["application.workflow.worklist"]);
  useEffect(
    () => setDestinationError(""),
    [selected?.occurrenceId, selected?.activityId],
  );
  useUnsavedWork(
    "workflow-action",
    "Unsubmitted workflow action",
    Boolean(reviewed || receiptId.trim() || returnReason.trim()),
  );

  useEffect(() => {
    if (!scope || !canRead) return;
    const controller = new AbortController();
    readCompleteWorkflowWorklist<ReadyActivity>(scope, controller.signal)
      .then((items) => {
        setReady(items);
        const exact = items.find(
          (item) =>
            item.occurrenceId === targetOccurrenceId &&
            (!targetActivityId || item.activityId === targetActivityId),
        );
        setSelected(exact || (targetOccurrenceId ? null : items[0] || null));
      })
      .catch((reason: Error) => setError(reason.message));
    return () => controller.abort();
  }, [
    app?.workspaceId,
    app?.applicationId,
    canRead,
    refresh,
    targetOccurrenceId,
    targetActivityId,
  ]);

  const occurrenceId = selected?.occurrenceId || targetOccurrenceId;
  useEffect(() => {
    if (!scope || !occurrenceId) {
      setOccurrence(null);
      return;
    }
    const controller = new AbortController();
    readCompleteWorkflowOccurrence(scope, occurrenceId, controller.signal)
      .then(setOccurrence)
      .catch((reason: Error) => setError(reason.message));
    return () => controller.abort();
  }, [app?.workspaceId, app?.applicationId, occurrenceId, refresh]);

  useEffect(() => {
    if (!scope || !occurrence) {
      setDefinition(null);
      return;
    }
    const controller = new AbortController();
    readProgram<WorkflowDefinition>(
      scope,
      "application.workflow.read",
      { flowId: occurrence.flowId, version: occurrence.version },
      controller.signal,
    )
      .then(setDefinition)
      .catch((reason: Error) => setError(reason.message));
    return () => controller.abort();
  }, [
    app?.workspaceId,
    app?.applicationId,
    occurrence?.flowId,
    occurrence?.version,
  ]);

  useEffect(() => {
    setReviewed(false);
    setReceiptId("");
    setReturnReason("");
    setResult("");
  }, [selected?.occurrenceId, selected?.activityId, selected?.activityVersion]);

  const focusedId = selected?.activityId || targetActivityId;
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
  const completed =
    occurrence?.activities.filter((item) => item.status === "Completed")
      .length || 0;
  const total = occurrence?.activities.length || 0;

  async function act(kind: "complete" | "return" | "cancel") {
    if (!scope || !occurrence || busy || !reviewed) return;
    let program: Record<string, unknown>;
    if (kind === "cancel") {
      program = {
        languageVersion: 2,
        function: "application.workflow.occurrence.cancel",
        arguments: {
          occurrenceId: occurrence.occurrenceId,
          expectedOccurrenceVersion: occurrence.occurrenceVersion,
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
          expectedActivityVersion: selected.activityVersion,
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
          expectedActivityVersion: selected.activityVersion,
          evidence,
        },
      };
    }
    if (!window.confirm(`Apply reviewed workflow action: ${kind}?`)) return;
    setBusy(true);
    setError("");
    try {
      const response = await request<{
        result: { operationId: string; status: string };
      }>(
        "/api/application-workflow-occurrence",
        genericWorkflowActionBody(
          scope,
          program,
          workflowIntentKey({ scope, program }),
        ),
      );
      setResult(
        `Recorded by operation ${response.result.operationId} · ${response.result.status}.`,
      );
      setInspectReceiptId(response.result.operationId);
      setReviewed(false);
      setReceiptId("");
      setReturnReason("");
      setRefresh((value) => value + 1);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page guided-page">
      <div className="page-heading">
        <div>
          <small>{app?.name || "Application"}</small>
          <h1>Workflow</h1>
          <p>
            Generic assignments, evidence-backed activities and immutable
            progress.
          </p>
        </div>
      </div>
      {error && (
        <div className="alert" role="alert">
          {error}
        </div>
      )}
      {!canRead && (
        <div className="empty-state">
          Your current role cannot read generic application workflows.
        </div>
      )}
      <section className="context-ribbon" aria-label="Workflow summary">
        <div>
          <small>READY NOW</small>
          <strong>{ready.length}</strong>
        </div>
        <div>
          <small>COMPLETED STEPS</small>
          <strong>{completed}</strong>
        </div>
        <div>
          <small>TOTAL STEPS</small>
          <strong>{total}</strong>
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
                Only work currently assigned to your verified identity appears
                here.
              </p>
            </div>
          </div>
          <div className="assignment-list">
            {ready.map((item) => (
              <button
                key={`${item.occurrenceId}/${item.activityId}`}
                className={
                  selected?.occurrenceId === item.occurrenceId &&
                  selected.activityId === item.activityId
                    ? "assignment-card active"
                    : "assignment-card"
                }
                onClick={() => setSelected(item)}
              >
                <span>{item.assignmentResolution.assignmentId}</span>
                <strong>{item.name}</strong>
                <p>
                  {item.flowId} v{item.version} · {item.activityId}
                </p>
                <small>
                  {item.kind} · occurrence v{item.occurrenceVersion}
                </small>
              </button>
            ))}
            {!ready.length && (
              <div className="empty-state">
                No generic workflow activity is ready for you now.
              </div>
            )}
          </div>
        </section>
        <aside className="panel task-companion">
          <small>WORK COMPANION</small>
          <h2>
            {selected?.name || focused?.activityId || "Choose an activity"}
          </h2>
          {occurrence && focused ? (
            <>
              <p>
                {occurrence.flowId} v{occurrence.version} · {occurrence.status}
              </p>
              <div className="progress-label">
                <strong>
                  {completed} of {total} completed
                </strong>
                <span>Occurrence v{occurrence.occurrenceVersion}</span>
              </div>
              <progress value={completed} max={Math.max(total, 1)} />
              {selected && (
                <section className="workflow-destination">
                  <h3>Configured destination</h3>
                  <p>
                    {selected.destination.kind === "CubeView"
                      ? `Pinned cube view ${String(selected.destination.viewId)} v${String(selected.destination.version)}`
                      : selected.destination.kind === "Artifact"
                        ? `${String(selected.destination.artifactKind)} ${String(selected.destination.artifactId)} v${String(selected.destination.version)}`
                        : `Function ${String(selected.destination.function)}`}
                  </p>
                  <button
                    type="button"
                    disabled={!openDestination}
                    onClick={() => {
                      const failure = openDestination?.(selected.destination);
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
                      <strong>{item.activityId}</strong>
                      <small>
                        {item.kind} · {item.status}
                      </small>
                    </span>
                  </li>
                ))}
              </ol>
              {selected && (
                <div
                  className="workflow-actions"
                  aria-label="Reviewed generic workflow actions"
                >
                  <h3>Reviewed actions</h3>
                  {evidenceContract?.kind === "ManualAttestation" && (
                    <p>
                      {evidenceContract.statement ||
                        "Confirm the configured attestation."}
                    </p>
                  )}
                  {evidenceContract?.kind === "OperationReceipt" && (
                    <>
                      <label>
                        <span>Authoritative operation receipt</span>
                        <input
                          value={receiptId}
                          onChange={(event) => {
                            setReceiptId(event.target.value);
                            setReviewed(false);
                          }}
                        />
                      </label>
                      <button
                        type="button"
                        disabled={!receiptId.trim()}
                        onClick={() => setInspectReceiptId(receiptId.trim())}
                      >
                        Inspect receipt before completion
                      </button>
                    </>
                  )}
                  {selected.kind === "Review" && (
                    <label>
                      <span>Return reason</span>
                      <textarea
                        value={returnReason}
                        onChange={(event) => {
                          setReturnReason(event.target.value);
                          setReviewed(false);
                        }}
                      />
                    </label>
                  )}
                  <label>
                    <input
                      type="checkbox"
                      checked={reviewed}
                      onChange={(event) => setReviewed(event.target.checked)}
                    />
                    I reviewed this exact activity, evidence requirement and
                    current occurrence version.
                  </label>
                  <button
                    className="primary-action"
                    disabled={
                      busy ||
                      !reviewed ||
                      (evidenceContract?.kind === "OperationReceipt" &&
                        !receiptId.trim())
                    }
                    onClick={() => void act("complete")}
                  >
                    Complete activity
                  </button>
                  {selected.kind === "Review" && (
                    <button
                      className="secondary-action"
                      disabled={busy || !reviewed || !returnReason.trim()}
                      onClick={() => void act("return")}
                    >
                      Return to configured predecessor
                    </button>
                  )}
                  <button
                    className="danger-action"
                    disabled={
                      busy || !reviewed || occurrence.status !== "Active"
                    }
                    onClick={() => void act("cancel")}
                  >
                    Cancel occurrence
                  </button>
                  {result && <p role="status">{result}</p>}
                </div>
              )}
            </>
          ) : (
            <p>Select assigned work to inspect its authoritative occurrence.</p>
          )}
        </aside>
      </div>
      {occurrence && (
        <section className="panel progress-panel">
          <div className="section-title">
            <div>
              <h2>Immutable activity timeline</h2>
              <p>Every displayed transition comes from the fixed core.</p>
            </div>
          </div>
          <ol className="timeline-list">
            {occurrence.events.map((event) => (
              <li key={event.ordinal}>
                <b>{event.eventType}</b>
                <span>{event.activityId || occurrence.occurrenceId}</span>
                <small>
                  Revision {event.committedRevision} ·{" "}
                  {new Date(event.createdAt).toLocaleString()}
                </small>
              </li>
            ))}
          </ol>
        </section>
      )}
      {scope && inspectReceiptId && (
        <ReceiptInspector
          scope={scope}
          catalog={catalog}
          operationId={inspectReceiptId}
          close={() => setInspectReceiptId("")}
        />
      )}
    </div>
  );
}
