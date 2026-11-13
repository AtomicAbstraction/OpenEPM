import "./focused-workspaces.css";
import { useEffect, useMemo, useRef, useState } from "react";
import { readProgram, requestAdmittedEffect } from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { readCompleteWorkflowWorklist } from "./MyWork";
import { ReceiptInspector } from "./ReceiptInspector";

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
  status: string;
  occurrenceStateToken: string;
  lastEventOrdinal: number;
  activities: Array<{
    activityId: string;
    kind: "Action" | "Review";
    status: string;
    activityStateToken: string;
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
    name?: string;
    activities: Array<{
      activityId: string;
      name?: string;
      evidenceContract: { kind: string; statement?: string };
    }>;
  };
};

type EvidenceOption = {
  selectionKey: string;
  label: string;
  occurredAt: string;
  outcome: "Committed";
  current: boolean;
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
  onRequestTransition = (action) => action(),
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  targetOccurrenceId?: string;
  targetActivityId?: string;
  onRequestTransition?: (action: () => void) => void;
  openDestination?: (
    destination: Record<string, unknown>,
    activityContext?: { occurrenceId: string; activityId: string },
  ) => string | null | undefined;
}) {
  const [ready, setReady] = useState<ReadyActivity[]>([]);
  const [worklistLoading, setWorklistLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [workPage, setWorkPage] = useState(0);
  const filteredReady = useMemo(
    () =>
      ready.filter((item) =>
        `${item.name} ${item.kind}`
          .toLocaleLowerCase()
          .includes(query.trim().toLocaleLowerCase()),
      ),
    [ready, query],
  );
  const workStart = Math.min(
    workPage * 50,
    Math.max(0, Math.ceil(filteredReady.length / 50) - 1) * 50,
  );
  const visibleReady = filteredReady.slice(workStart, workStart + 50);
  useEffect(() => setWorkPage(0), [query]);
  const [selected, setSelected] = useState<ReadyActivity | null>(null);
  const [occurrence, setOccurrence] = useState<Occurrence | null>(null);
  const [definition, setDefinition] = useState<WorkflowDefinition | null>(null);
  const [receiptId, setReceiptId] = useState("");
  const [evidenceOptions, setEvidenceOptions] = useState<EvidenceOption[]>([]);
  const [evidenceCursor, setEvidenceCursor] = useState<number | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const evidenceGeneration = useRef(0);
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
    setReady([]);
    setSelected(null);
    setError("");
    if (!scope || !canRead) {
      setWorklistLoading(false);
      return;
    }
    const controller = new AbortController();
    setWorklistLoading(true);
    readCompleteWorkflowWorklist<ReadyActivity>(scope, controller.signal)
      .then((items) => {
        if (controller.signal.aborted) return;
        setReady(items);
        const exact = items.find(
          (item) =>
            item.occurrenceId === targetOccurrenceId &&
            (!targetActivityId || item.activityId === targetActivityId),
        );
        setSelected(exact || (targetOccurrenceId ? null : items[0] || null));
      })
      .catch((reason: Error) => {
        if (!controller.signal.aborted) setError(reason.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setWorklistLoading(false);
      });
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
    setOccurrence(null);
    setDefinition(null);
    readCompleteWorkflowOccurrence(scope, occurrenceId, controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setOccurrence(value);
      })
      .catch((reason: Error) => {
        if (!controller.signal.aborted) setError(reason.message);
      });
    return () => controller.abort();
  }, [app?.workspaceId, app?.applicationId, occurrenceId, refresh]);

  useEffect(() => {
    if (!scope || !occurrence) {
      setDefinition(null);
      return;
    }
    const controller = new AbortController();
    setDefinition(null);
    readProgram<WorkflowDefinition>(
      scope,
      "application.workflow.read",
      { flowId: occurrence.flowId },
      controller.signal,
    )
      .then((value) => {
        if (!controller.signal.aborted) setDefinition(value);
      })
      .catch((reason: Error) => {
        if (!controller.signal.aborted) setError(reason.message);
      });
    return () => controller.abort();
  }, [
    app?.workspaceId,
    app?.applicationId,
    occurrence?.flowId,
    occurrence?.flowStateToken,
  ]);

  useEffect(() => {
    setReviewed(false);
    setReceiptId("");
    setEvidenceOptions([]);
    setEvidenceCursor(null);
    setReturnReason("");
    setResult("");
  }, [
    selected?.occurrenceId,
    selected?.activityId,
    selected?.activityStateToken,
  ]);

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
  const activityName = (activityId?: string | null) =>
    definition?.definition.activities.find(
      (item) => item.activityId === activityId,
    )?.name ||
    ready.find((item) => item.activityId === activityId)?.name ||
    "Workflow activity";
  const completed =
    occurrence?.activities.filter((item) => item.status === "Completed")
      .length || 0;
  const total = occurrence?.activities.length || 0;

  useEffect(() => {
    const generation = ++evidenceGeneration.current;
    setEvidenceOptions([]);
    setEvidenceCursor(null);
    setReceiptId("");
    if (
      !scope ||
      !selected ||
      evidenceContract?.kind !== "OperationReceipt" ||
      !catalog?.functions["application.workflow.activity.evidence.list"]
    ) {
      setEvidenceLoading(false);
      return;
    }
    const controller = new AbortController();
    setEvidenceLoading(true);
    readProgram<{
      items: EvidenceOption[];
      nextBeforeCommittedRevision: number | null;
    }>(
      scope,
      "application.workflow.activity.evidence.list",
      {
        occurrenceId: selected.occurrenceId,
        activityId: selected.activityId,
        limit: 50,
      },
      controller.signal,
    )
      .then((value) => {
        if (
          controller.signal.aborted ||
          generation !== evidenceGeneration.current
        )
          return;
        setEvidenceOptions(value.items);
        setEvidenceCursor(value.nextBeforeCommittedRevision);
      })
      .catch((reason: Error) => {
        if (
          !controller.signal.aborted &&
          generation === evidenceGeneration.current
        )
          setError(reason.message);
      })
      .finally(() => {
        if (
          !controller.signal.aborted &&
          generation === evidenceGeneration.current
        )
          setEvidenceLoading(false);
      });
    return () => controller.abort();
  }, [
    app?.workspaceId,
    app?.applicationId,
    selected?.occurrenceId,
    selected?.activityId,
    selected?.activityStateToken,
    evidenceContract?.kind,
    Boolean(catalog?.functions["application.workflow.activity.evidence.list"]),
  ]);

  async function readOlderEvidence() {
    if (!scope || !selected || !evidenceCursor || evidenceLoading) return;
    const generation = evidenceGeneration.current;
    const selectedOccurrence = selected.occurrenceId;
    const selectedActivity = selected.activityId;
    setEvidenceLoading(true);
    try {
      const value = await readProgram<{
        items: EvidenceOption[];
        nextBeforeCommittedRevision: number | null;
      }>(scope, "application.workflow.activity.evidence.list", {
        occurrenceId: selectedOccurrence,
        activityId: selectedActivity,
        limit: 50,
        beforeCommittedRevision: evidenceCursor,
      });
      if (generation !== evidenceGeneration.current) return;
      setEvidenceOptions((current) => [...current, ...value.items]);
      setEvidenceCursor(value.nextBeforeCommittedRevision);
    } catch (reason) {
      if (generation === evidenceGeneration.current)
        setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      if (generation === evidenceGeneration.current) setEvidenceLoading(false);
    }
  }

  async function act(kind: "complete" | "return" | "cancel") {
    if (!scope || !occurrence || busy || !reviewed) return;
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
    if (!window.confirm(`Apply reviewed workflow action: ${kind}?`)) return;
    setBusy(true);
    setError("");
    try {
      const response = await requestAdmittedEffect<{
        result: { operationId: string; status: string };
      }>(
        "/api/application-workflow-occurrence",
        genericWorkflowActionBody(
          scope,
          program,
          workflowIntentKey({ scope, program }),
        ),
      );
      setResult(`Activity ${response.result.status.toLowerCase()}.`);
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
            Find your assigned work, open the model task and review its evidence
            before completing the activity.
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
          <label className="workflow-activity-filter">
            Find an activity
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Name, workflow or assignment"
            />
          </label>
          <div className="assignment-list" aria-busy={worklistLoading}>
            {visibleReady.map((item) => (
              <button
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
                  onRequestTransition(() => setSelected(item));
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
                {worklistLoading
                  ? "Loading assigned activities…"
                  : ready.length
                    ? "No activities match this search."
                    : "No generic workflow activity is ready for you now."}
              </div>
            )}
          </div>
          <div className="workspace-window-controls">
            <span>
              {filteredReady.length
                ? `${workStart + 1}–${workStart + visibleReady.length} of ${filteredReady.length} activities`
                : "0 activities"}
            </span>
            <button
              disabled={workStart === 0}
              onClick={() => setWorkPage(workStart / 50 - 1)}
            >
              Previous activities
            </button>
            <button
              disabled={workStart + 50 >= filteredReady.length}
              onClick={() => setWorkPage(workStart / 50 + 1)}
            >
              Next activities
            </button>
          </div>
        </section>
        <aside className="panel task-companion">
          <small>WORK COMPANION</small>
          <h2>
            {selected?.name || activityName(focusedId) || "Choose an activity"}
          </h2>
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
              {selected && (
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
                    disabled={!openDestination}
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
                        <span>Completion evidence</span>
                        <select
                          value={receiptId}
                          disabled={evidenceLoading}
                          onChange={(event) => {
                            setReceiptId(event.target.value);
                            setReviewed(false);
                          }}
                        >
                          <option value="">Choose completed activity</option>
                          {evidenceOptions.map((option) => (
                            <option
                              key={option.selectionKey}
                              value={option.selectionKey}
                            >
                              {option.label} ·{" "}
                              {new Date(option.occurredAt).toLocaleString()} ·{" "}
                              {option.outcome}
                            </option>
                          ))}
                        </select>
                      </label>
                      {evidenceLoading && <p>Loading completed activities…</p>}
                      {!evidenceLoading && !evidenceOptions.length && (
                        <p>
                          No eligible completed activity is available for this
                          workflow step.
                        </p>
                      )}
                      {evidenceCursor && (
                        <button
                          type="button"
                          disabled={evidenceLoading}
                          onClick={() => void readOlderEvidence()}
                        >
                          Load older completed activity
                        </button>
                      )}
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
                    current occurrence state.
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
              <h2>Activity history</h2>
              <p>Recorded transitions for this workflow occurrence.</p>
            </div>
          </div>
          <ol className="timeline-list">
            {occurrence.events.map((event) => (
              <li key={event.ordinal}>
                <b>{event.eventType}</b>
                <span>{activityName(event.activityId)}</span>
                <small>{new Date(event.createdAt).toLocaleString()}</small>
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
