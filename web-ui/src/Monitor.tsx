import { useEffect, useMemo, useState } from "react";
import { request, reviewAndSubmit } from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { ReceiptInspector } from "./ReceiptInspector";

type TaskSummary = {
  taskId: string;
  sourceFamily: string;
  function: string;
  status: string;
  interruptible: boolean;
  rerunSupported: boolean;
  createdAt?: string;
  updatedAt?: string;
  initiatorKind?: string;
  initiatedBy?: string;
};

type TaskEvent = {
  event?: number;
  status: string;
  occurredAt?: string;
  claimGeneration?: number;
  errorCode?: string;
};

type TaskDetail = TaskSummary & {
  events?: TaskEvent[];
  nextEvent?: number;
  hasMoreEvents?: boolean;
  result?: unknown;
};

type TaskSourceLog = {
  kind?: string;
  text?: string;
  totalCharacters?: number;
  nextAfterCharacter?: number | null;
  hasMore?: boolean;
};

type TaskLogPage = {
  taskId: string;
  lifecycle: { events: TaskEvent[]; nextEvent: number; hasMore: boolean };
  sourceLog: TaskSourceLog | null;
};

type TaskListPage = {
  tasks: TaskSummary[];
  nextSequence?: number | null;
  hasMore: boolean;
};

export function mergeTaskListPage(
  current: TaskSummary[],
  page: TaskListPage,
  previousCursor: number,
  append: boolean,
): { tasks: TaskSummary[]; nextSequence: number | null; hasMore: boolean } {
  if (!Array.isArray(page.tasks) || typeof page.hasMore !== "boolean")
    throw new Error("Task continuation response is invalid.");
  const next = page.nextSequence ?? null;
  if (
    typeof next !== "number" ||
    !Number.isSafeInteger(next) ||
    next < 0 ||
    (page.hasMore && next <= previousCursor)
  )
    throw new Error("Task continuation cursor is invalid.");
  const combined = append ? [...current, ...page.tasks] : [...page.tasks];
  const identifiers = new Set<string>();
  for (const task of combined) {
    if (!task || typeof task.taskId !== "string" || !task.taskId)
      throw new Error("Task continuation contains an invalid task.");
    if (identifiers.has(task.taskId))
      throw new Error("Task continuation repeated a task.");
    identifiers.add(task.taskId);
  }
  return { tasks: combined, nextSequence: next, hasMore: page.hasMore };
}

export function mergeTaskLogPage(
  current: TaskLogPage,
  next: TaskLogPage,
): TaskLogPage {
  if (
    !next ||
    typeof next.taskId !== "string" ||
    !next.taskId ||
    !next.lifecycle ||
    !Array.isArray(next.lifecycle.events) ||
    !Number.isSafeInteger(next.lifecycle.nextEvent) ||
    next.lifecycle.nextEvent < 0 ||
    typeof next.lifecycle.hasMore !== "boolean" ||
    (next.sourceLog !== null &&
      (!next.sourceLog ||
        typeof next.sourceLog.kind !== "string" ||
        typeof next.sourceLog.text !== "string" ||
        !Number.isSafeInteger(next.sourceLog.totalCharacters) ||
        (next.sourceLog.totalCharacters ?? -1) < 0 ||
        !Number.isSafeInteger(next.sourceLog.nextAfterCharacter) ||
        (next.sourceLog.nextAfterCharacter ?? -1) < 0 ||
        typeof next.sourceLog.hasMore !== "boolean"))
  )
    throw new Error("Task diagnostic response is invalid.");
  if (next.taskId !== current.taskId)
    throw new Error("Task diagnostic identity changed between pages.");
  const currentEvents = current.lifecycle.events;
  const nextEvents = next.lifecycle.events;
  if (!Array.isArray(currentEvents) || !Array.isArray(nextEvents))
    throw new Error("Task diagnostic lifecycle is invalid.");
  if (
    nextEvents.length > 0 &&
    (!Number.isSafeInteger(next.lifecycle.nextEvent) ||
      next.lifecycle.nextEvent <= current.lifecycle.nextEvent)
  )
    throw new Error("Task diagnostic event cursor did not advance.");
  const eventOrdinals = new Set(
    currentEvents
      .map((event) => event.event)
      .filter((event): event is number => typeof event === "number"),
  );
  for (const event of nextEvents) {
    if (
      !event ||
      !Number.isSafeInteger(event.event) ||
      (event.event ?? 0) <= 0 ||
      typeof event.status !== "string" ||
      !event.status
    )
      throw new Error("Task diagnostic lifecycle is invalid.");
    if (eventOrdinals.has(event.event as number))
      throw new Error("Task diagnostic lifecycle repeated an event.");
    eventOrdinals.add(event.event as number);
  }
  let sourceLog = current.sourceLog;
  if (next.sourceLog) {
    const prior = current.sourceLog;
    if (
      prior &&
      (next.sourceLog.kind !== prior.kind ||
        next.sourceLog.totalCharacters !== prior.totalCharacters)
    )
      throw new Error("Task diagnostic source identity changed between pages.");
    const nextText = next.sourceLog.text || "";
    const priorCursor = prior?.nextAfterCharacter ?? 0;
    if (
      nextText &&
      (typeof next.sourceLog.nextAfterCharacter !== "number" ||
        next.sourceLog.nextAfterCharacter <= priorCursor)
    )
      throw new Error("Task diagnostic character cursor did not advance.");
    sourceLog = {
      ...next.sourceLog,
      text: `${prior?.text || ""}${nextText}`,
    };
  }
  return {
    ...next,
    lifecycle: {
      ...next.lifecycle,
      events: [...currentEvents, ...nextEvents],
    },
    sourceLog,
  };
}

type ProgressState = "attention" | "running" | "succeeded" | "other";

export type TaskProgressRow = {
  sourceFamily: string;
  attention: number;
  running: number;
  succeeded: number;
  other: number;
  total: number;
};

export const taskListBody = (
  scope: Scope,
  afterSequence = 0,
  attentionOnly = false,
) => ({
  ...scope,
  afterSequence,
  limit: 100,
  attentionOnly,
});

export const taskInterruptBody = (scope: Scope, taskId: string) => ({
  ...scope,
  taskId,
  confirmed: true,
});

export const taskRerunBody = (
  scope: Scope,
  taskId: string,
  idempotencyKey: string,
) => ({ ...scope, taskId, idempotencyKey, confirmed: true });

export const jobSubmitBody = (
  scope: Scope,
  program: Record<string, unknown>,
  idempotencyKey: string,
) => ({
  ...scope,
  program,
  idempotencyKey,
  dependsOnJobIds: [] as string[],
  confirmed: true,
});

export const jobReadBody = (scope: Scope, jobId: string) => ({
  ...scope,
  jobId,
});

export const jobCancelBody = (scope: Scope, jobId: string) => ({
  ...scope,
  jobId,
  confirmed: true,
});

function initiator(task: TaskSummary) {
  const kind = (task.initiatorKind || "").toLowerCase();
  if (kind.includes("agent") || kind.includes("mcp")) return "MCP agent";
  if (kind.includes("schedule")) return "Schedule";
  if (kind.includes("recover")) return "Recovery";
  return task.initiatedBy
    ? `Human · ${task.initiatedBy}`
    : "Verified principal";
}

function stateClass(status: string) {
  if (
    ["Failed", "Interrupted", "Cancelled", "Rejected", "Stale"].includes(status)
  )
    return "attention";
  if (
    ["Accepted", "Queued", "Claimed", "Running", "Cancelling"].includes(status)
  )
    return "running";
  if (status === "Succeeded") return "succeeded";
  return "neutral";
}

export function taskProgressRows(tasks: TaskSummary[]): TaskProgressRow[] {
  const rows = new Map<string, TaskProgressRow>();
  tasks.forEach((task) => {
    const sourceFamily = task.sourceFamily || "Unclassified";
    const row = rows.get(sourceFamily) || {
      sourceFamily,
      attention: 0,
      running: 0,
      succeeded: 0,
      other: 0,
      total: 0,
    };
    const state = stateClass(task.status);
    const group: ProgressState =
      state === "attention" || state === "running" || state === "succeeded"
        ? state
        : "other";
    row[group] += 1;
    row.total += 1;
    rows.set(sourceFamily, row);
  });
  return [...rows.values()].sort(
    (left, right) =>
      right.attention + right.running - (left.attention + left.running) ||
      right.total - left.total ||
      left.sourceFamily.localeCompare(right.sourceFamily),
  );
}

function time(value?: string) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

export function Monitor({
  app,
  catalog,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
}) {
  const scope = app
    ? { workspaceId: app.workspaceId, applicationId: app.applicationId }
    : null;
  const [tasks, setTasks] = useState<TaskSummary[]>([]);
  const [nextSequence, setNextSequence] = useState<number | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [attentionOnly, setAttentionOnly] = useState(false);
  const [selected, setSelected] = useState<TaskDetail | null>(null);
  const [selectedFamily, setSelectedFamily] = useState("");
  const [selectedState, setSelectedState] = useState<ProgressState | "all">(
    "all",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function load(append = false) {
    if (!scope) return;
    setBusy(true);
    setError("");
    try {
      const page = await request<TaskListPage>(
        "/api/tasks",
        taskListBody(scope, append ? nextSequence || 0 : 0, attentionOnly),
      );
      const merged = mergeTaskListPage(
        tasks,
        page,
        append ? nextSequence || 0 : 0,
        append,
      );
      setTasks(merged.tasks);
      setNextSequence(merged.nextSequence);
      setHasMore(merged.hasMore);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read tasks",
      );
    } finally {
      setBusy(false);
    }
  }

  async function open(task: Pick<TaskSummary, "taskId">) {
    if (!scope) return;
    setBusy(true);
    setError("");
    try {
      const detail = await request<TaskDetail>("/api/task", {
        ...scope,
        taskId: task.taskId,
        afterEvent: 0,
        eventLimit: 100,
      });
      setSelected(detail);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read task",
      );
    } finally {
      setBusy(false);
    }
  }

  async function refreshSelected(taskId: string) {
    await load();
    await open({ taskId });
  }

  useEffect(() => {
    setTasks([]);
    setSelected(null);
    setSelectedFamily("");
    setSelectedState("all");
    void load();
  }, [app?.workspaceId, app?.applicationId, attentionOnly]);

  const counts = useMemo(
    () => ({
      visible: tasks.length,
      attention: tasks.filter((task) => stateClass(task.status) === "attention")
        .length,
      running: tasks.filter((task) => stateClass(task.status) === "running")
        .length,
      succeeded: tasks.filter((task) => task.status === "Succeeded").length,
    }),
    [tasks],
  );
  const progressRows = useMemo(() => taskProgressRows(tasks), [tasks]);
  const visibleTasks = useMemo(
    () =>
      tasks.filter(
        (task) =>
          (!selectedFamily || task.sourceFamily === selectedFamily) &&
          (selectedState === "all" ||
            (selectedState === "other"
              ? stateClass(task.status) === "neutral"
              : stateClass(task.status) === selectedState)),
      ),
    [tasks, selectedFamily, selectedState],
  );

  function selectProgress(sourceFamily: string, state: ProgressState) {
    if (selectedFamily === sourceFamily && selectedState === state) {
      setSelectedFamily("");
      setSelectedState("all");
      return;
    }
    setSelectedFamily(sourceFamily);
    setSelectedState(state);
  }

  return (
    <div className="page monitor-page">
      <div className="page-heading">
        <div>
          <span>{app?.name || "Application"}</span>
          <h1>Monitor</h1>
          <p>
            One durable history for human, MCP-agent, scheduled and recovery
            work.
          </p>
        </div>
        <div className="page-actions">
          <button
            className={attentionOnly ? "active" : ""}
            aria-pressed={attentionOnly}
            onClick={() => {
              setAttentionOnly((value) => !value);
              setNextSequence(null);
            }}
            disabled={busy}
          >
            {attentionOnly ? "Show all work" : "Needs attention"}
          </button>
          <button onClick={() => void load()} disabled={busy}>
            Refresh
          </button>
        </div>
      </div>
      {attentionOnly && (
        <p className="context-note" role="status">
          Showing the newest server-filtered tasks that need attention.
        </p>
      )}
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      <div className="monitor-summary" aria-label="Task status summary">
        <SummaryMetric label="Visible work" value={counts.visible} />
        <SummaryMetric
          label="Needs attention"
          value={counts.attention}
          tone="attention"
        />
        <SummaryMetric
          label="In progress"
          value={counts.running}
          tone="running"
        />
        <SummaryMetric
          label="Succeeded"
          value={counts.succeeded}
          tone="succeeded"
        />
      </div>
      <section
        className="panel workload-matrix"
        aria-labelledby="workload-title"
      >
        <div className="section-title">
          <div>
            <span>Authoritative durable tasks</span>
            <h2 id="workload-title">Workload and bottlenecks</h2>
            <p>
              Group the current task projection by work family and durable
              state. Select one cell to filter the detail table.
            </p>
          </div>
          {(selectedFamily || selectedState !== "all") && (
            <button
              type="button"
              onClick={() => {
                setSelectedFamily("");
                setSelectedState("all");
              }}
            >
              Clear matrix filter
            </button>
          )}
        </div>
        <div className="workload-matrix-scroll">
          <table>
            <caption>Task progress by work family</caption>
            <thead>
              <tr>
                <th scope="col">Work family</th>
                <th scope="col">Needs attention</th>
                <th scope="col">In progress</th>
                <th scope="col">Succeeded</th>
                <th scope="col">Other</th>
                <th scope="col">Total</th>
              </tr>
            </thead>
            <tbody>
              {progressRows.map((row) => (
                <tr key={row.sourceFamily}>
                  <th scope="row">{row.sourceFamily}</th>
                  {(
                    [
                      ["attention", row.attention],
                      ["running", row.running],
                      ["succeeded", row.succeeded],
                      ["other", row.other],
                    ] as Array<[ProgressState, number]>
                  ).map(([state, value]) => (
                    <td key={state}>
                      <button
                        type="button"
                        className={
                          selectedFamily === row.sourceFamily &&
                          selectedState === state
                            ? `matrix-count ${state} selected`
                            : `matrix-count ${state}`
                        }
                        aria-pressed={
                          selectedFamily === row.sourceFamily &&
                          selectedState === state
                        }
                        aria-label={`${row.sourceFamily}, ${state}, ${value}`}
                        disabled={!value}
                        onClick={() => selectProgress(row.sourceFamily, state)}
                      >
                        {value}
                      </button>
                    </td>
                  ))}
                  <td>{row.total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!progressRows.length && !busy && (
          <p className="empty-monitor">No task families are visible.</p>
        )}
      </section>
      {scope && <JobConsole scope={scope} catalog={catalog} />}
      <section className="monitor-table panel">
        <table>
          <caption>Durable application tasks</caption>
          <thead>
            <tr>
              <th scope="col">Task</th>
              <th scope="col">Initiator</th>
              <th scope="col">Work</th>
              <th scope="col">Status</th>
              <th scope="col">Controls</th>
            </tr>
          </thead>
          <tbody>
            {visibleTasks.map((task) => (
              <tr key={task.taskId}>
                <td>
                  <button className="task-link" onClick={() => void open(task)}>
                    {task.taskId}
                  </button>
                </td>
                <td>{initiator(task)}</td>
                <td>
                  <strong>{task.sourceFamily}</strong>
                  <small>{task.function}</small>
                </td>
                <td>
                  <span className={`task-state ${stateClass(task.status)}`}>
                    {task.status}
                  </span>
                </td>
                <td>
                  {task.interruptible
                    ? "Interrupt available"
                    : "No interruption"}{" "}
                  · {task.rerunSupported ? "Rerun available" : "No rerun"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!visibleTasks.length && !busy && (
          <p className="empty-monitor">
            {tasks.length
              ? "No durable tasks match the selected matrix cell."
              : "No visible durable tasks for this application."}
          </p>
        )}
        <footer>
          <span>
            {busy
              ? "Reading authoritative task state…"
              : `${visibleTasks.length} of ${tasks.length} visible tasks`}
          </span>
          <button disabled={busy || !hasMore} onClick={() => void load(true)}>
            Next tasks
          </button>
        </footer>
      </section>
      {selected && (
        <TaskPanel
          task={selected}
          scope={scope!}
          close={() => setSelected(null)}
          refresh={refreshSelected}
        />
      )}
    </div>
  );
}

type JobRecord = {
  job_id?: string;
  jobId?: string;
  status?: string;
  claim_generation?: number;
  attempts?: number;
  receipt_revision?: number | null;
  error_code?: string | null;
  result?: unknown;
};

type JobEvent = {
  sequence: number;
  job_id: string;
  status: string;
  occurred_at?: string;
  error_code?: string | null;
};

const JOB_ID = /^[0-9a-f]{32}$/;
const CANCELLABLE = new Set(["accepted", "ready", "running", "staged"]);
const DEFAULT_JOB_PROGRAM =
  '{"languageVersion":2,"function":"facts.expression.calculate","arguments":{}}';

function JobConsole({
  scope,
  catalog,
}: {
  scope: Scope;
  catalog: ApplicationCatalog | null;
}) {
  const [open, setOpen] = useState(false);
  const [programText, setProgramText] = useState(DEFAULT_JOB_PROGRAM);
  const [key, setKey] = useState("");
  const [submitReviewed, setSubmitReviewed] = useState(false);
  const [jobId, setJobId] = useState("");
  const [job, setJob] = useState<JobRecord | null>(null);
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [eventsAfter, setEventsAfter] = useState(0);
  const [eventsMore, setEventsMore] = useState(false);
  const [cancelReviewed, setCancelReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [inspectReceipt, setInspectReceipt] = useState("");

  const parsed = useMemo(() => {
    try {
      const value = JSON.parse(programText) as Record<string, unknown>;
      if (
        !value ||
        Array.isArray(value) ||
        value.languageVersion !== 2 ||
        typeof value.function !== "string" ||
        !catalog ||
        !Object.hasOwn(catalog.functions, value.function) ||
        !value.arguments ||
        Array.isArray(value.arguments) ||
        typeof value.arguments !== "object"
      )
        return null;
      return value;
    } catch {
      return null;
    }
  }, [programText, catalog]);
  const trimmedKey = key.trim();
  const submitReady = Boolean(parsed && trimmedKey && trimmedKey.length <= 200);
  const trimmedJobId = jobId.trim();
  const selectedId = job?.job_id || job?.jobId || "";
  const selectedStatus = String(job?.status || "").toLowerCase();
  const cancelReady = Boolean(
    JOB_ID.test(trimmedJobId) &&
      selectedId === trimmedJobId &&
      CANCELLABLE.has(selectedStatus),
  );
  useUnsavedWork(
    "monitor-job-submission",
    "Unsubmitted fixed-core job",
    Boolean(
      programText !== DEFAULT_JOB_PROGRAM || trimmedKey || submitReviewed,
    ),
  );
  useUnsavedWork(
    "monitor-job-cancellation",
    "Unsubmitted job cancellation review",
    cancelReviewed,
  );

  useEffect(() => {
    setJob(null);
    setEvents([]);
    setEventsAfter(0);
    setEventsMore(false);
    setCancelReviewed(false);
    setInspectReceipt("");
  }, [scope.workspaceId, scope.applicationId]);

  function invalidateSubmit() {
    setSubmitReviewed(false);
    setError("");
  }

  async function submit() {
    if (!parsed || !submitReady || !submitReviewed || busy) return;
    setBusy(true);
    setError("");
    try {
      const result = await reviewAndSubmit<JobRecord>(
        jobSubmitBody(scope, parsed, trimmedKey),
        "Review the fixed-core job preview.",
      );
      if (!result) return;
      const returnedId = result.jobId || result.job_id || "";
      setJob(result);
      setJobId(returnedId);
      setSubmitReviewed(false);
      setProgramText(DEFAULT_JOB_PROGRAM);
      setKey("");
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Job submission failed",
      );
    } finally {
      setBusy(false);
    }
  }

  async function read(id = trimmedJobId) {
    if (!JOB_ID.test(id) || busy) return;
    setBusy(true);
    setError("");
    setCancelReviewed(false);
    try {
      const result = await request<JobRecord>(
        "/api/job",
        jobReadBody(scope, id),
      );
      setJob(result);
      setJobId(id);
    } catch (reason) {
      setJob(null);
      setError(reason instanceof Error ? reason.message : "Unable to read job");
    } finally {
      setBusy(false);
    }
  }

  async function readEvents(append = false) {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const page = await request<{
        events: JobEvent[];
        nextSequence: number;
        hasMore: boolean;
      }>("/api/events", {
        ...scope,
        afterSequence: append ? eventsAfter : 0,
        limit: 100,
      });
      setEvents((current) =>
        append ? [...current, ...page.events] : page.events,
      );
      setEventsAfter(page.nextSequence);
      setEventsMore(page.hasMore);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read job events",
      );
    } finally {
      setBusy(false);
    }
  }

  async function cancel() {
    if (!cancelReady || !cancelReviewed || busy) return;
    if (
      !window.confirm("Request cancellation of this exact current job state?")
    )
      return;
    setBusy(true);
    setError("");
    try {
      const result = await request<JobRecord>(
        "/api/cancel",
        jobCancelBody(scope, trimmedJobId),
      );
      setJob(result);
      setCancelReviewed(false);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to cancel job",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel job-console" aria-labelledby="job-console-title">
      <div className="section-title">
        <div>
          <span>Fixed-core queue</span>
          <h2 id="job-console-title">Your typed jobs</h2>
          <p>
            Submit an authorized V2 program, inspect owner-visible events and
            request cancellation of the exact current job state.
          </p>
        </div>
        <button
          aria-expanded={open}
          aria-controls="job-console-body"
          onClick={() => setOpen((value) => !value)}
        >
          {open ? "Hide job controls" : "Open job controls"}
        </button>
      </div>
      {open && (
        <div id="job-console-body" className="job-console-body">
          <div className="job-submit-grid">
            <label>
              Typed V2 program
              <textarea
                value={programText}
                spellCheck={false}
                rows={6}
                onChange={(event) => {
                  setProgramText(event.target.value);
                  invalidateSubmit();
                }}
              />
            </label>
            <label>
              Idempotency key
              <input
                value={key}
                maxLength={200}
                onChange={(event) => {
                  setKey(event.target.value);
                  invalidateSubmit();
                }}
              />
            </label>
          </div>
          <p
            className={
              submitReady ? "drawer-readiness ready" : "drawer-readiness"
            }
          >
            {submitReady
              ? `Authorized function ${String(parsed?.function)} is ready for exact review.`
              : "Enter an authorized typed V2 program and a nonempty idempotency key."}
          </p>
          <label className="review-check">
            <input
              type="checkbox"
              checked={submitReviewed}
              disabled={!submitReady || busy}
              onChange={(event) => setSubmitReviewed(event.target.checked)}
            />
            I reviewed this exact typed job and idempotency key
          </label>
          <button
            disabled={!submitReady || !submitReviewed || busy}
            onClick={submit}
          >
            Preview and submit
          </button>

          <div className="job-read-controls">
            <button disabled={busy} onClick={() => void readEvents(false)}>
              Refresh job events
            </button>
            <label>
              Job ID
              <input
                value={jobId}
                maxLength={32}
                onChange={(event) => {
                  setJobId(event.target.value.trim().toLowerCase());
                  setJob(null);
                  setCancelReviewed(false);
                }}
              />
            </label>
            <button
              disabled={busy || !JOB_ID.test(trimmedJobId)}
              onClick={() => void read()}
            >
              Read authoritative status
            </button>
          </div>
          {events.length > 0 && (
            <div className="job-events" aria-label="Owner-visible job events">
              {events.map((event) => (
                <button
                  key={event.sequence}
                  onClick={() => {
                    setJobId(event.job_id);
                    setJob(null);
                    setCancelReviewed(false);
                    void read(event.job_id);
                  }}
                >
                  <strong>{event.status}</strong>
                  <span>{event.job_id}</span>
                  <small>{time(event.occurred_at)}</small>
                </button>
              ))}
              <button
                disabled={busy || !eventsMore}
                onClick={() => void readEvents(true)}
              >
                Next job events
              </button>
            </div>
          )}
          {job && (
            <div className="job-record">
              <div>
                <small>Current authoritative state</small>
                <strong>{job.status || "Unknown"}</strong>
              </div>
              <label className="review-check">
                <input
                  type="checkbox"
                  checked={cancelReviewed}
                  disabled={!cancelReady || busy}
                  onChange={(event) => setCancelReviewed(event.target.checked)}
                />
                I reviewed cancellation of this exact current job state
              </label>
              <button
                className="danger-action"
                disabled={!cancelReady || !cancelReviewed || busy}
                onClick={cancel}
              >
                Request cancellation
              </button>
              {job.receipt_revision != null && selectedId && (
                <button
                  type="button"
                  onClick={() => setInspectReceipt(selectedId)}
                >
                  Inspect publication receipt
                </button>
              )}
              <details>
                <summary>Technical job record</summary>
                <pre>{JSON.stringify(job, null, 2)}</pre>
              </details>
            </div>
          )}
          {error && (
            <p className="inline-error" role="alert">
              {error}
            </p>
          )}
          {inspectReceipt && (
            <ReceiptInspector
              scope={scope}
              catalog={catalog}
              operationId={inspectReceipt}
              close={() => setInspectReceipt("")}
            />
          )}
        </div>
      )}
    </section>
  );
}

function SummaryMetric({
  label,
  value,
  tone = "",
}: {
  label: string;
  value: number;
  tone?: string;
}) {
  return (
    <div className={tone}>
      <small>{label}</small>
      <strong>{value}</strong>
    </div>
  );
}

function TaskPanel({
  task,
  scope,
  close,
  refresh,
}: {
  task: TaskDetail;
  scope: Scope;
  close: () => void;
  refresh: (taskId: string) => Promise<void>;
}) {
  const latest = task.events?.at(-1);
  const [log, setLog] = useState<TaskLogPage | null>(null);
  const [logBusy, setLogBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const [interruptReviewed, setInterruptReviewed] = useState(false);
  const [rerunKey, setRerunKey] = useState("");
  const [rerunReviewed, setRerunReviewed] = useState(false);
  useUnsavedWork(
    `monitor-task-action-${task.taskId}`,
    "Unsubmitted durable task action",
    Boolean(interruptReviewed || rerunKey.trim() || rerunReviewed),
  );

  useEffect(() => {
    setLog(null);
    setActionError("");
    setInterruptReviewed(false);
    setRerunKey("");
    setRerunReviewed(false);
  }, [task.taskId, task.status, task.interruptible, task.rerunSupported]);

  useEffect(() => setRerunReviewed(false), [rerunKey]);

  async function readLogs(append = false) {
    setLogBusy(true);
    setActionError("");
    try {
      const next = await request<TaskLogPage>("/api/task-logs", {
        ...scope,
        taskId: task.taskId,
        afterEvent: append ? log?.lifecycle.nextEvent || 0 : 0,
        eventLimit: 100,
        afterCharacter: append ? log?.sourceLog?.nextAfterCharacter || 0 : 0,
        characterLimit: 16384,
      });
      const baseline: TaskLogPage = (append && log) || {
        taskId: task.taskId,
        lifecycle: { events: [], nextEvent: 0, hasMore: true },
        sourceLog: null,
      };
      setLog(mergeTaskLogPage(baseline, next));
    } catch (reason) {
      setActionError(
        reason instanceof Error ? reason.message : "Unable to read task logs",
      );
    } finally {
      setLogBusy(false);
    }
  }

  async function interrupt() {
    if (!task.interruptible || !interruptReviewed || actionBusy) return;
    if (!window.confirm("Request interruption of this exact durable task?"))
      return;
    setActionBusy(true);
    setActionError("");
    try {
      await request("/api/task-interrupt", {
        ...taskInterruptBody(scope, task.taskId),
      });
      setInterruptReviewed(false);
      await refresh(task.taskId);
    } catch (reason) {
      setActionError(
        reason instanceof Error ? reason.message : "Unable to interrupt task",
      );
    } finally {
      setActionBusy(false);
    }
  }

  async function rerun() {
    const key = rerunKey.trim();
    if (
      !task.rerunSupported ||
      !rerunReviewed ||
      !key ||
      key.length > 200 ||
      actionBusy
    )
      return;
    if (
      !window.confirm("Create distinct new work from this exact durable task?")
    )
      return;
    setActionBusy(true);
    setActionError("");
    try {
      const result = await request<{ taskId: string }>("/api/task-rerun", {
        ...taskRerunBody(scope, task.taskId, key),
      });
      setRerunKey("");
      setRerunReviewed(false);
      await refresh(result.taskId);
    } catch (reason) {
      setActionError(
        reason instanceof Error ? reason.message : "Unable to rerun task",
      );
    } finally {
      setActionBusy(false);
    }
  }
  return (
    <aside className="task-drawer" aria-label="Selected task detail">
      <div className="drawer-heading">
        <div>
          <span>Durable task</span>
          <h2>{task.function}</h2>
        </div>
        <button aria-label="Close task detail" onClick={close}>
          ×
        </button>
      </div>
      <div className="task-detail-cards">
        <DetailMetric label="Status" valueText={task.status} />
        <DetailMetric label="Work type" valueText={task.sourceFamily} />
        <DetailMetric label="Created" valueText={time(task.createdAt)} />
        <DetailMetric label="Last updated" valueText={time(task.updatedAt)} />
      </div>
      <p className={`task-outcome ${stateClass(task.status)}`}>
        {task.status === "Succeeded"
          ? "Completed successfully. The timeline is the durable execution evidence."
          : task.status === "Failed"
            ? `This task failed${latest?.errorCode ? `: ${latest.errorCode}` : ""}.`
            : `Current durable state: ${task.status}.`}
      </p>
      <h3>Timeline</h3>
      <ol className="task-timeline">
        {(task.events || []).map((event, index) => (
          <li
            className={
              index === (task.events?.length || 0) - 1 ? "current" : ""
            }
            key={`${event.status}-${event.occurredAt || index}`}
          >
            <span />
            <div>
              <strong>{event.status}</strong>
              <small>
                {time(event.occurredAt)} · attempt{" "}
                {event.claimGeneration ?? "—"}
                {event.errorCode ? ` · ${event.errorCode}` : ""}
              </small>
            </div>
          </li>
        ))}
      </ol>
      {actionError && (
        <p className="inline-error" role="alert">
          {actionError}
        </p>
      )}
      <section className="task-control-section">
        <div className="section-title">
          <div>
            <h3>Worker diagnostics</h3>
            <p>Read the bounded log stream attached to this durable task.</p>
          </div>
          <button disabled={logBusy} onClick={() => void readLogs(false)}>
            {logBusy ? "Reading…" : "Read logs"}
          </button>
        </div>
        {log && (
          <div className="task-log">
            <small>Lifecycle · {log.lifecycle.events.length} events</small>
            <ol className="task-timeline">
              {log.lifecycle.events.map((event, index) => (
                <li key={`${event.status}-${event.occurredAt || index}`}>
                  <span />
                  <div>
                    <strong>{event.status}</strong>
                    <small>{time(event.occurredAt)}</small>
                  </div>
                </li>
              ))}
            </ol>
            <small>
              {log.sourceLog?.kind || "Worker"} ·{" "}
              {(log.sourceLog?.text || "").length} of{" "}
              {log.sourceLog?.totalCharacters ??
                (log.sourceLog?.text || "").length}{" "}
              characters
            </small>
            <pre>
              {log.sourceLog?.text ||
                "No source diagnostic characters recorded."}
            </pre>
            <button
              disabled={
                logBusy || (!log.lifecycle.hasMore && !log.sourceLog?.hasMore)
              }
              onClick={() => void readLogs(true)}
            >
              Next diagnostics page
            </button>
          </div>
        )}
      </section>
      <section className="task-control-section">
        <h3>Governed controls</h3>
        <label className="review-check">
          <input
            type="checkbox"
            checked={interruptReviewed}
            disabled={!task.interruptible || actionBusy}
            onChange={(event) => setInterruptReviewed(event.target.checked)}
          />
          I reviewed interruption of this exact task state
        </label>
        <button
          disabled={!task.interruptible || !interruptReviewed || actionBusy}
          onClick={() => void interrupt()}
        >
          Request interruption
        </button>
        <label>
          Distinct rerun key
          <input
            value={rerunKey}
            maxLength={200}
            disabled={!task.rerunSupported || actionBusy}
            onChange={(event) => setRerunKey(event.target.value)}
          />
        </label>
        <label className="review-check">
          <input
            type="checkbox"
            checked={rerunReviewed}
            disabled={!task.rerunSupported || !rerunKey.trim() || actionBusy}
            onChange={(event) => setRerunReviewed(event.target.checked)}
          />
          I reviewed this exact distinct rerun
        </label>
        <button
          disabled={
            !task.rerunSupported ||
            !rerunReviewed ||
            !rerunKey.trim() ||
            actionBusy
          }
          onClick={() => void rerun()}
        >
          Create distinct rerun
        </button>
      </section>
      <details>
        <summary>Technical record</summary>
        <pre>{JSON.stringify(task, null, 2)}</pre>
      </details>
    </aside>
  );
}

function DetailMetric({
  label,
  valueText,
}: {
  label: string;
  valueText: string;
}) {
  return (
    <div>
      <small>{label}</small>
      <strong>{valueText}</strong>
    </div>
  );
}
