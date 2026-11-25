import {
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type Ref,
} from "react";
import { ApiError, isDefiniteEffectRefusal, request } from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { ReceiptInspector, outcomeAuthorityKey } from "./ReceiptInspector";
import { ApplicationQueue } from "./ApplicationQueue";
import { LayoutActivation } from "./LayoutActivation";
import { focusWhenInteractive } from "./MetadataReceiptRecovery";
import { workflowCountBasis } from "./workflow-outcome";
import {
  isTaskProgressState,
  mergeTaskListPage,
  taskListBody,
} from "./task-list";
import type { TaskListPage, TaskListRow } from "./task-list";

type TaskSummary = TaskListRow & {
  sourceFamily: string;
  sourceId?: string;
  interruptible: boolean;
  rerunSupported: boolean;
  createdAt?: string;
  updatedAt?: string;
  initiatorKind?: string;
  initiatedBy?: string;
  latestEvent: TaskEvent | null;
  recoveryState?:
    | "workflowCancellationPaused"
    | "scheduleCancellationUnresolved"
    | null;
};

type TaskEvent = {
  event?: number;
  status: string;
  occurredAt?: string;
  claimGeneration?: number | null;
  receiptRevision?: number | null;
  errorCode?: string | null;
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
  return task.initiatedBy ? `Human · ${task.initiatedBy}` : "Verified user";
}

async function readTaskDetail(
  scope: Scope,
  taskId: string,
  signal: AbortSignal,
) {
  const detail = await request<TaskDetail>(
    "/api/task",
    {
      ...scope,
      taskId,
      afterEvent: 0,
      eventLimit: 100,
    },
    signal,
  );
  if (detail.taskId !== taskId)
    throw new Error(
      "The task response does not match the requested reference.",
    );
  if (!isTaskProgressState(detail.progressState))
    throw new Error("Task progress is unavailable.");
  return detail;
}

function taskStateClass(task: TaskSummary) {
  if (task.progressState === "inProgress") return "running";
  if (task.progressState === "other") return "neutral";
  return task.progressState;
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
    const state = taskStateClass(task);
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

type MonitorProps = {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  onRefreshCatalog?: (signal?: AbortSignal) => Promise<ApplicationCatalog>;
  onRequestTransition?: (action: () => void, preserveDrafts?: boolean) => void;
  targetTaskId?: string;
  onTaskContextChange?: (taskId: string | null) => void;
  // Origin navigation owns its guard; local closes use onRequestTransition.
  onCloseTask?: () => void;
};

export function Monitor(props: MonitorProps) {
  const { app, catalog, onRefreshCatalog } = props;
  if (catalog?.applicationAccess.authorizationModel === "group_assignments") {
    if (!app || !catalog.ownedJobOperations?.includes("events")) return null;
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    return (
      <div className="monitor-page">
        <JobConsole
          key={outcomeAuthorityKey(scope, catalog)}
          scope={scope}
          catalog={catalog}
          onRefreshCatalog={onRefreshCatalog}
        />
      </div>
    );
  }
  return <TaskMonitor {...props} />;
}

function TaskMonitor({
  app,
  catalog,
  onRefreshCatalog,
  onRequestTransition = (action) => action(),
  targetTaskId,
  onTaskContextChange,
  onCloseTask,
}: MonitorProps) {
  const scope = app
    ? { workspaceId: app.workspaceId, applicationId: app.applicationId }
    : null;
  const taskResultsStatusId = useId();
  const [tasks, setTasks] = useState<TaskSummary[]>([]);
  const [taskListState, setTaskListState] = useState<
    "loading" | "ready" | "unavailable"
  >("loading");
  const [nextSequence, setNextSequence] = useState<number | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [attentionOnly, setAttentionOnly] = useState(false);
  const [selected, setSelected] = useState<TaskDetail | null>(null);
  const [selectedFamily, setSelectedFamily] = useState("");
  const [selectedState, setSelectedState] = useState<ProgressState | "all">(
    "all",
  );
  const [readingTaskId, setReadingTaskId] = useState<string | null>(null);
  const [listError, setListError] = useState("");
  const [detailError, setDetailError] = useState("");
  const busy = taskListState === "loading" || readingTaskId !== null;
  const error = detailError || listError;
  const [query, setQuery] = useState("");
  const taskListRead = useRef<AbortController | null>(null);
  const taskDetailRead = useRef<AbortController | null>(null);
  const taskOpener = useRef<{
    element: HTMLButtonElement;
    entering: boolean;
  } | null>(null);
  const closeTaskButton = useRef<HTMLButtonElement>(null);
  const taskSearch = useRef<HTMLInputElement>(null);
  const returnTaskFocus = useRef<HTMLElement | null>(null);

  useLayoutEffect(() => {
    if (selected) {
      const opener = taskOpener.current;
      if (!opener?.entering) return;
      opener.entering = false;
      // Keep the user's new position if they moved elsewhere while reading.
      if (opener.element.ownerDocument.activeElement === opener.element)
        return focusWhenInteractive(closeTaskButton.current);
    } else if (returnTaskFocus.current) {
      const opener = returnTaskFocus.current;
      returnTaskFocus.current = null;
      return focusWhenInteractive(
        opener.isConnected ? opener : taskSearch.current,
      );
    }
  }, [selected]);

  function changeTaskContext(action?: () => void) {
    onRequestTransition(() => {
      taskDetailRead.current?.abort();
      taskOpener.current = null;
      setReadingTaskId(null);
      setDetailError("");
      setSelected(null);
      onTaskContextChange?.(null);
      action?.();
    }, true);
  }

  function closeTaskDetail() {
    // Search stays mounted even when the refreshed list removes the prior row.
    const opener =
      taskListState === "loading" ? null : taskOpener.current?.element;
    changeTaskContext(() => {
      returnTaskFocus.current = opener ?? taskSearch.current;
    });
  }

  async function load(append = false) {
    if (!scope) return;
    taskListRead.current?.abort();
    const controller = new AbortController();
    taskListRead.current = controller;
    const { signal } = controller;
    setTaskListState("loading");
    setListError("");
    try {
      const cursor = append ? nextSequence || 0 : 0;
      const page = await request<TaskListPage<TaskSummary>>(
        "/api/tasks",
        taskListBody(scope, cursor, attentionOnly),
        signal,
      );
      if (signal.aborted) return;
      const list = mergeTaskListPage(tasks, page, cursor, append);
      setTasks(list.tasks);
      setNextSequence(list.nextSequence);
      setHasMore(list.hasMore);
      setTaskListState("ready");
    } catch (reason) {
      if (signal.aborted) return;
      setTasks([]);
      setNextSequence(null);
      setHasMore(false);
      setTaskListState("unavailable");
      setListError(
        reason instanceof Error ? reason.message : "Unable to read tasks",
      );
    }
  }

  async function open(
    task: Pick<TaskSummary, "taskId">,
    {
      opener,
      refresh = false,
    }: { opener?: HTMLButtonElement; refresh?: boolean } = {},
  ) {
    if (!scope) return;
    taskDetailRead.current?.abort();
    const controller = new AbortController();
    taskDetailRead.current = controller;
    const { signal } = controller;
    setReadingTaskId(task.taskId);
    setDetailError("");
    if (!refresh) {
      taskOpener.current = opener ? { element: opener, entering: true } : null;
      setSelected(null);
      onTaskContextChange?.(null);
    }
    try {
      const detail = await readTaskDetail(scope, task.taskId, signal);
      if (signal.aborted) return;
      setSelected(detail);
      if (!refresh) onTaskContextChange?.(detail.taskId);
    } catch (reason) {
      if (signal.aborted) return;
      if (refresh) {
        setSelected(null);
        onTaskContextChange?.(null);
      }
      setDetailError(
        reason instanceof Error ? reason.message : "Unable to read task",
      );
    } finally {
      if (!signal.aborted) setReadingTaskId(null);
    }
  }

  useEffect(() => {
    if (!scope) return;
    taskOpener.current = null;
    setTasks([]);
    setSelected(null);
    setReadingTaskId(null);
    setDetailError("");
    onTaskContextChange?.(null);
    setSelectedFamily("");
    setSelectedState("all");
    const loading = load();
    const signal = taskListRead.current?.signal;
    void loading.then(() => {
      if (signal && !signal.aborted && targetTaskId)
        void open({ taskId: targetTaskId });
    });
    return () => {
      taskListRead.current?.abort();
      taskDetailRead.current?.abort();
    };
  }, [app?.workspaceId, app?.applicationId, attentionOnly, targetTaskId]);

  const progressRows = useMemo(() => taskProgressRows(tasks), [tasks]);
  const counts = useMemo(
    () =>
      progressRows.reduce(
        (summary, row) => ({
          visible: summary.visible + row.total,
          attention: summary.attention + row.attention,
          running: summary.running + row.running,
          succeeded: summary.succeeded + row.succeeded,
        }),
        { visible: 0, attention: 0, running: 0, succeeded: 0 },
      ),
    [progressRows],
  );
  const visibleTasks = useMemo(
    () =>
      tasks.filter(
        (task) =>
          `${task.function} ${task.sourceFamily} ${task.status} ${initiator(task)}`
            .toLocaleLowerCase()
            .includes(query.trim().toLocaleLowerCase()) &&
          (!selectedFamily || task.sourceFamily === selectedFamily) &&
          (selectedState === "all" ||
            (selectedState === "other"
              ? taskStateClass(task) === "neutral"
              : taskStateClass(task) === selectedState)),
      ),
    [tasks, selectedFamily, selectedState, query],
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
          <p>One history for human, MCP-agent, scheduled and recovery work.</p>
        </div>
        <div className="page-actions">
          <button
            className={attentionOnly ? "active" : ""}
            aria-pressed={attentionOnly}
            onClick={() =>
              changeTaskContext(() => {
                setAttentionOnly((value) => !value);
                setNextSequence(null);
              })
            }
            disabled={busy}
          >
            {attentionOnly ? "Show all work" : "Needs attention"}
          </button>
          <button
            aria-disabled={busy || undefined}
            onClick={() => {
              if (busy) return;
              void load();
              if (selected) void open(selected, { refresh: true });
            }}
          >
            Refresh
          </button>
        </div>
      </div>
      {targetTaskId && readingTaskId === targetTaskId && !selected && (
        <p className="context-note" role="status">
          Checking current access to the referenced task…
        </p>
      )}
      {attentionOnly && taskListState === "ready" && (
        <p className="context-note" role="status">
          Showing the newest server-filtered tasks that need attention.
        </p>
      )}
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      <p id={taskResultsStatusId} role="status" aria-live="polite">
        <span>
          {taskListState === "loading"
            ? "Reading task results…"
            : taskListState === "unavailable"
              ? "Task results are unavailable. Refresh to retry."
              : busy
                ? "Reading task details…"
                : `${counts.visible} ${counts.visible === 1 ? "task" : "tasks"} loaded.${hasMore ? " More tasks are available." : ""}`}
        </span>
      </p>
      <div
        className="monitor-summary"
        role="group"
        aria-label="Loaded task counts"
      >
        <SummaryMetric
          label="Loaded work"
          value={taskListState === "ready" ? counts.visible : null}
        />
        <SummaryMetric
          label="Needs attention"
          value={taskListState === "ready" ? counts.attention : null}
          tone="attention"
        />
        <SummaryMetric
          label="In progress"
          value={taskListState === "ready" ? counts.running : null}
          tone="running"
        />
        <SummaryMetric
          label="Succeeded"
          value={taskListState === "ready" ? counts.succeeded : null}
          tone="succeeded"
        />
      </div>
      <div
        className={
          selected ? "monitor-workspace with-task" : "monitor-workspace"
        }
      >
        <div className="monitor-data">
          <section
            className="panel workload-matrix"
            aria-labelledby="workload-title"
          >
            <div className="section-title">
              <div>
                <span>Authoritative durable tasks</span>
                <h2 id="workload-title">Workload and bottlenecks</h2>
                <p>Select a count to filter the loaded task records.</p>
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
            <div
              className="workload-matrix-scroll"
              tabIndex={0}
              role="region"
              aria-label="Task progress matrix"
              aria-busy={taskListState === "loading"}
            >
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
                            aria-label={`${row.sourceFamily}, ${state === "running" ? "in progress" : state}, ${value}`}
                            disabled={!value}
                            onClick={() =>
                              selectProgress(row.sourceFamily, state)
                            }
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
            {!progressRows.length && !busy && taskListState === "ready" && (
              <p className="empty-monitor">No task families are visible.</p>
            )}
          </section>
          {scope && catalog?.applicationAccess.role === "Administrator" && (
            <ApplicationQueue
              key={outcomeAuthorityKey(scope, catalog)}
              scope={scope}
            />
          )}
          {scope && catalog && (
            <JobConsole
              key={`background-jobs:${outcomeAuthorityKey(scope, catalog)}`}
              scope={scope}
              catalog={catalog}
              onRefreshCatalog={onRefreshCatalog}
            />
          )}
          <section className="monitor-table panel">
            <div className="monitor-search">
              <label>
                Search loaded tasks
                <input
                  ref={taskSearch}
                  type="search"
                  value={query}
                  placeholder="Task, operation, status or initiator"
                  onChange={(event) => setQuery(event.target.value)}
                />
              </label>
              {taskListState === "ready" && (
                <span>
                  {visibleTasks.length} matching · {tasks.length} loaded
                  {hasMore ? " · more available" : ""}
                </span>
              )}
            </div>
            <div
              className="table-scroll"
              tabIndex={0}
              role="region"
              aria-label="Task records"
            >
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
                        <button
                          className="task-link"
                          aria-disabled={busy || undefined}
                          aria-pressed={selected?.taskId === task.taskId}
                          onClick={(event) => {
                            if (busy) return;
                            const opener = event.currentTarget;
                            changeTaskContext(
                              () => void open(task, { opener }),
                            );
                          }}
                        >
                          {task.function}
                        </button>
                      </td>
                      <td>{initiator(task)}</td>
                      <td>
                        <strong>{task.sourceFamily}</strong>
                      </td>
                      <td>
                        <span className={`task-state ${taskStateClass(task)}`}>
                          {task.status}
                        </span>
                      </td>
                      <td>Use the originating business workflow</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!visibleTasks.length && !busy && taskListState === "ready" && (
              <p className="empty-monitor">
                {tasks.length
                  ? "No loaded tasks match the current filters."
                  : attentionOnly
                    ? "No visible tasks need attention."
                    : "No visible durable tasks for this application."}
              </p>
            )}
            <footer>
              <button
                aria-disabled={busy || !hasMore || undefined}
                aria-describedby={taskResultsStatusId}
                tabIndex={hasMore ? 0 : -1}
                onClick={() => {
                  if (!busy && hasMore) void load(true);
                }}
              >
                Next tasks
              </button>
            </footer>
          </section>
        </div>
        {selected && (
          <TaskPanel
            key={JSON.stringify([
              scope!.workspaceId,
              scope!.applicationId,
              selected.taskId,
              selected.status,
            ])}
            task={selected}
            scope={scope!}
            catalog={catalog}
            closeButtonRef={closeTaskButton}
            close={
              selected.taskId === targetTaskId && onCloseTask
                ? onCloseTask
                : closeTaskDetail
            }
          />
        )}
      </div>
    </div>
  );
}

type JobRecord = {
  jobId: string;
  status: string;
  hasReceipt: boolean;
  retryAt: string | null;
  retryLimit: boolean;
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
const JOB_STATES = new Set([
  ...CANCELLABLE,
  "published",
  "failed",
  "cancel_requested",
  "cancelled",
  "needs_inspection",
]);
const CANCELLATION_REFUSALS = new Set([
  "APPLICATION_GRANT_REQUIRED",
  "APPLICATION_UNAVAILABLE",
  "WORKSPACE_UNAVAILABLE",
  "JOB_UNAVAILABLE",
]);
const JOB_ACCESS_CHANGES = new Set([
  "JOB_UNAVAILABLE",
  "JOB_READ_AUTHORIZATION_STALE",
  "APPLICATION_UNAVAILABLE",
  "WORKSPACE_UNAVAILABLE",
]);

function jobAccessChanged(reason: unknown) {
  return (
    reason instanceof ApiError &&
    (reason.kind === "authorization" ||
      isDefiniteEffectRefusal(reason, JOB_ACCESS_CHANGES))
  );
}

function exactJob(value: unknown, jobId: string): JobRecord {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("The job response could not be verified.");
  const result = value as Record<string, unknown>;
  if (
    (result.job_id ?? result.jobId) !== jobId ||
    (result.jobId !== undefined && result.jobId !== jobId)
  )
    throw new Error("The response does not match the requested job.");
  if (typeof result.status !== "string" || !JOB_STATES.has(result.status))
    throw new Error("The job response could not be verified.");
  return {
    jobId,
    status: result.status,
    hasReceipt:
      (result.status === "published" || result.status === "needs_inspection") &&
      typeof result.receipt_revision === "number" &&
      Number.isSafeInteger(result.receipt_revision) &&
      result.receipt_revision > 0,
    retryAt:
      result.status === "ready" &&
      typeof result.next_attempt_at === "string" &&
      /^\d{4}-\d{2}-\d{2}T/.test(result.next_attempt_at) &&
      Number.isFinite(Date.parse(result.next_attempt_at))
        ? result.next_attempt_at
        : null,
    retryLimit:
      result.status === "failed" && result.error_code === "RETRY_LIMIT",
  };
}

function JobConsole({
  scope,
  catalog,
  onRefreshCatalog,
}: {
  scope: Scope;
  catalog: ApplicationCatalog;
  onRefreshCatalog?: (signal?: AbortSignal) => Promise<ApplicationCatalog>;
}) {
  const [open, setOpen] = useState(false);
  const [jobId, setJobId] = useState("");
  const [job, setJob] = useState<JobRecord | null>(null);
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [eventsAfter, setEventsAfter] = useState(0);
  const [eventsMore, setEventsMore] = useState(false);
  const [eventsState, setEventsState] = useState<
    "idle" | "loading" | "ready" | "unavailable"
  >("idle");
  const [cancelReviewed, setCancelReviewed] = useState(false);
  const [accessNeedsRefresh, setAccessNeedsRefresh] = useState(false);
  const [cancellationNotice, setCancellationNotice] = useState<
    "unconfirmed" | "refused" | null
  >(null);
  const [operation, setOperation] = useState<
    "read" | "cancel" | "events" | null
  >(null);
  const busy = operation !== null;
  const [error, setError] = useState("");
  const [inspectReceipt, setInspectReceipt] = useState("");
  const activeRequest = useRef<AbortController | null>(null);
  const refreshJobs = useRef<HTMLButtonElement>(null);
  const jobEvents = useRef<HTMLDivElement>(null);
  const moreJobs = useRef<HTMLButtonElement>(null);
  const checkJob = useRef<HTMLButtonElement>(null);
  const cancelJob = useRef<HTMLButtonElement>(null);
  const restoreCancellationFocus = useRef(false);

  useEffect(() => {
    if (!cancellationNotice || busy || !restoreCancellationFocus.current)
      return;
    restoreCancellationFocus.current = false;
    const control = checkJob.current;
    if (
      control &&
      (control.closest("[inert]") || document.activeElement === document.body)
    )
      return focusWhenInteractive(control);
  }, [busy, cancellationNotice]);

  function startRequest() {
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    return controller.signal;
  }

  const selectedStatus = job?.status ?? "";
  const groupAssigned =
    catalog.applicationAccess.authorizationModel === "group_assignments";
  const cancelReady = Boolean(
    (groupAssigned
      ? catalog.ownedJobOperations?.includes("cancel")
      : ["Editor", "Administrator"].includes(catalog.applicationAccess.role)) &&
      !accessNeedsRefresh &&
      !cancellationNotice &&
      job?.jobId === jobId &&
      CANCELLABLE.has(selectedStatus),
  );
  const selectableJobs = useMemo(() => {
    const latest = new Map<string, JobEvent>();
    for (const event of events) {
      const current = latest.get(event.job_id);
      if (!current || event.sequence > current.sequence)
        latest.set(event.job_id, event);
    }
    return [...latest.values()].sort(
      (left, right) => right.sequence - left.sequence,
    );
  }, [events]);
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
    setEventsState("idle");
    setCancelReviewed(false);
    setAccessNeedsRefresh(false);
    setCancellationNotice(null);
    setInspectReceipt("");
    setOperation(null);
    return () => activeRequest.current?.abort();
  }, [scope.workspaceId, scope.applicationId]);

  function clearJobEvents() {
    setEvents([]);
    setEventsAfter(0);
    setEventsMore(false);
    setEventsState("unavailable");
  }

  function invalidateJobAccess() {
    setAccessNeedsRefresh(true);
    setJob(null);
    setCancelReviewed(false);
    setInspectReceipt("");
  }

  async function refreshJobAccess(signal: AbortSignal) {
    if (accessNeedsRefresh && onRefreshCatalog) {
      await onRefreshCatalog(signal);
      signal.throwIfAborted();
      setAccessNeedsRefresh(false);
    }
  }

  async function read(id = jobId) {
    if (!JOB_ID.test(id) || busy) return;
    const origin = document.activeElement;
    const originInEvents = jobEvents.current?.contains(origin);
    const signal = startRequest();
    setOperation("read");
    setError("");
    setCancelReviewed(false);
    setJob(null);
    setInspectReceipt("");
    if (id !== jobId) setCancellationNotice(null);
    setJobId(id);
    try {
      if (accessNeedsRefresh) await refreshJobAccess(signal);
      const result = await request<unknown>(
        "/api/job",
        jobReadBody(scope, id),
        signal,
      );
      if (signal.aborted) return;
      setJob(exactJob(result, id));
      setCancellationNotice(null);
    } catch (reason) {
      if (signal.aborted) return;
      setJob(null);
      if (jobAccessChanged(reason)) {
        if (
          originInEvents &&
          (document.activeElement === origin ||
            document.activeElement === document.body)
        )
          checkJob.current?.focus();
        clearJobEvents();
        invalidateJobAccess();
      }
      setError(reason instanceof Error ? reason.message : "Unable to read job");
    } finally {
      if (!signal.aborted) setOperation(null);
    }
  }

  async function readEvents(append = false) {
    if (busy) return;
    const signal = startRequest();
    setOperation("events");
    setEventsState("loading");
    setError("");
    try {
      if (accessNeedsRefresh) await refreshJobAccess(signal);
      const page = await request<{
        events: JobEvent[];
        nextSequence: number;
        hasMore: boolean;
      }>(
        "/api/events",
        {
          ...scope,
          afterSequence: append ? eventsAfter : 0,
          limit: 100,
        },
        signal,
      );
      if (signal.aborted) return;
      if (
        !Array.isArray(page.events) ||
        typeof page.hasMore !== "boolean" ||
        !Number.isSafeInteger(page.nextSequence) ||
        page.nextSequence < 0
      )
        throw new Error("Background job response is invalid.");
      setEvents((current) =>
        append ? [...current, ...page.events] : page.events,
      );
      setEventsAfter(page.nextSequence);
      setEventsMore(page.hasMore);
      setEventsState("ready");
    } catch (reason) {
      if (signal.aborted) return;
      if (document.activeElement === moreJobs.current)
        refreshJobs.current?.focus();
      clearJobEvents();
      if (jobAccessChanged(reason)) invalidateJobAccess();
      setError(
        reason instanceof Error ? reason.message : "Unable to read job events",
      );
    } finally {
      if (!signal.aborted) setOperation(null);
    }
  }

  async function cancel() {
    if (!cancelReady || !cancelReviewed || busy) return;
    if (!window.confirm("Request cancellation of this current job?")) return;
    restoreCancellationFocus.current =
      document.activeElement === cancelJob.current;
    if (restoreCancellationFocus.current) checkJob.current?.focus();
    const signal = startRequest();
    setOperation("cancel");
    setError("");
    setJob(null);
    setCancelReviewed(false);
    setInspectReceipt("");
    try {
      const result = await request<unknown>(
        "/api/cancel",
        jobCancelBody(scope, jobId),
        signal,
      );
      if (signal.aborted) return;
      const confirmed = exactJob(result, jobId);
      if (CANCELLABLE.has(confirmed.status))
        throw new Error("Cancellation response is inconclusive.");
      setJob(confirmed);
    } catch (reason) {
      if (signal.aborted) return;
      const refused = isDefiniteEffectRefusal(reason, CANCELLATION_REFUSALS);
      setCancellationNotice(refused ? "refused" : "unconfirmed");
      if (refused) setError(reason.message);
      if (jobAccessChanged(reason)) {
        clearJobEvents();
        invalidateJobAccess();
      }
    } finally {
      if (!signal.aborted) setOperation(null);
    }
  }

  return (
    <section className="panel job-console" aria-labelledby="job-console-title">
      <div className="section-title">
        <div>
          <span>BACKGROUND WORK</span>
          <h2 id="job-console-title">
            {groupAssigned ? "My numeric jobs" : "Background jobs"}
          </h2>
          <p>
            Review recent background work and request cancellation while it is
            still running.
          </p>
        </div>
        <button
          aria-expanded={open}
          aria-controls="job-console-body"
          onClick={() => {
            const next = !open;
            setOpen(next);
            if (next && eventsState !== "ready") void readEvents(false);
          }}
        >
          {open ? "Hide jobs" : "Show jobs"}
        </button>
      </div>
      {open && (
        <div id="job-console-body" className="job-console-body">
          <div className="job-read-controls">
            <button
              ref={refreshJobs}
              aria-disabled={busy || undefined}
              onClick={() => void readEvents(false)}
            >
              Refresh jobs
            </button>
          </div>
          {selectableJobs.length > 0 && (
            <div
              ref={jobEvents}
              className="job-events"
              aria-label="Recent background jobs"
            >
              {selectableJobs.map((event) => (
                <button
                  key={event.job_id}
                  disabled={busy}
                  aria-pressed={jobId === event.job_id}
                  onClick={() => void read(event.job_id)}
                >
                  <strong>{event.status}</strong>
                  <small>{time(event.occurred_at)}</small>
                </button>
              ))}
              <button
                ref={moreJobs}
                aria-disabled={busy || !eventsMore || undefined}
                onClick={() => {
                  if (eventsMore) void readEvents(true);
                }}
              >
                More jobs
              </button>
            </div>
          )}
          {eventsState !== "idle" && (
            <p className="empty-monitor" role="status">
              {eventsState === "loading"
                ? "Reading recent background jobs…"
                : eventsState === "unavailable"
                  ? "Background job results are unavailable. Refresh jobs to retry."
                  : selectableJobs.length === 0
                    ? "No recent jobs are visible."
                    : null}
            </p>
          )}
          {jobId && (
            <div className="job-record">
              {(operation === "read" || operation === "cancel") && (
                <p role="status">
                  {operation === "read"
                    ? "Reading current job…"
                    : "Requesting cancellation…"}
                </p>
              )}
              {job && (
                <div>
                  <small>Last confirmed job state</small>
                  <strong>{job.status}</strong>
                </div>
              )}
              {job?.retryAt && (
                <p role="status">
                  The same job is eligible for another worker attempt from{" "}
                  <time dateTime={job.retryAt}>
                    {new Date(job.retryAt).toLocaleString()}
                  </time>
                  . Check this job again for its current state.
                </p>
              )}
              {job?.retryLimit && (
                <p role="status">
                  This job reached its worker retry limit. Check its recorded
                  outcome before starting new work.
                </p>
              )}
              {selectedStatus === "needs_inspection" && (
                <p role="status">
                  This job needs inspection. Review its recorded outcome before
                  starting new work.
                </p>
              )}
              {cancellationNotice && (
                <p role="status">
                  {cancellationNotice === "unconfirmed"
                    ? "Cancellation outcome unconfirmed. Check the current job before requesting cancellation again."
                    : "Cancellation was refused. Check the current job before requesting cancellation again."}
                </p>
              )}
              {selectedStatus === "cancel_requested" && (
                <p role="status">
                  Cancellation requested. Check the job again to confirm its
                  final state.
                </p>
              )}
              <button
                type="button"
                ref={checkJob}
                aria-disabled={busy || undefined}
                onClick={() => void read()}
              >
                Check current job
              </button>
              <label className="review-check">
                <input
                  type="checkbox"
                  checked={cancelReviewed}
                  disabled={!cancelReady || busy}
                  onChange={(event) => setCancelReviewed(event.target.checked)}
                />
                I reviewed cancellation of this current job.
              </label>
              <button
                className="danger-action"
                ref={cancelJob}
                disabled={!cancelReady || !cancelReviewed || busy}
                onClick={cancel}
              >
                Request cancellation
              </button>
              {job?.hasReceipt && !groupAssigned && (
                <button
                  type="button"
                  onClick={() => setInspectReceipt(job.jobId)}
                >
                  {selectedStatus === "published"
                    ? "View publication outcome"
                    : "Inspect recorded receipt"}
                </button>
              )}
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
  value: number | null;
  tone?: string;
}) {
  return (
    <div className={tone}>
      <small>{label}</small>
      <strong>{value ?? "—"}</strong>
    </div>
  );
}

function TaskPanel({
  task,
  scope,
  catalog,
  close,
  closeButtonRef,
}: {
  task: TaskDetail;
  scope: Scope;
  catalog: ApplicationCatalog | null;
  close: () => void;
  closeButtonRef: Ref<HTMLButtonElement>;
}) {
  const latest = task.latestEvent;
  const layoutTarget =
    task.sourceId && task.sourceFamily === "LayoutReplacementBuild"
      ? { kind: "replacement" as const, id: task.sourceId }
      : task.sourceId && task.sourceFamily === "LayoutActivation"
        ? { kind: "activation" as const, id: task.sourceId }
        : null;
  const [log, setLog] = useState<TaskLogPage | null>(null);
  const [logBusy, setLogBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const logRequest = useRef<AbortController | null>(null);

  // TaskPanel is keyed by the full action context above. Fresh context starts
  // with fresh state before controls become interactive; a passive reset could
  // otherwise erase an edit made immediately after the task read completes.
  useEffect(() => () => logRequest.current?.abort(), []);

  async function readLogs(append = false) {
    logRequest.current?.abort();
    const controller = new AbortController();
    logRequest.current = controller;
    setLogBusy(true);
    setActionError("");
    try {
      const next = await request<TaskLogPage>(
        "/api/task-logs",
        {
          ...scope,
          taskId: task.taskId,
          afterEvent: append ? log?.lifecycle.nextEvent || 0 : 0,
          eventLimit: 100,
          afterCharacter: append ? log?.sourceLog?.nextAfterCharacter || 0 : 0,
          characterLimit: 16384,
        },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      const baseline: TaskLogPage = (append && log) || {
        taskId: task.taskId,
        lifecycle: { events: [], nextEvent: 0, hasMore: true },
        sourceLog: null,
      };
      setLog(mergeTaskLogPage(baseline, next));
    } catch (reason) {
      if (controller.signal.aborted) return;
      setActionError(
        reason instanceof Error ? reason.message : "Unable to read task logs",
      );
    } finally {
      if (!controller.signal.aborted) setLogBusy(false);
    }
  }

  return (
    <aside
      className="task-drawer"
      aria-label="Selected task detail"
      onKeyDown={(event) => {
        if (event.key !== "Escape" || event.defaultPrevented) return;
        event.preventDefault();
        event.stopPropagation();
        close();
      }}
    >
      <div className="drawer-heading">
        <div>
          <span>Durable task</span>
          <h2>{task.function}</h2>
        </div>
        <button
          ref={closeButtonRef}
          aria-label="Close task detail"
          onClick={close}
        >
          ×
        </button>
      </div>
      <div className="task-detail-cards">
        <DetailMetric label="Status" valueText={task.status} />
        <DetailMetric label="Work type" valueText={task.sourceFamily} />
        <DetailMetric label="Created" valueText={time(task.createdAt)} />
        <DetailMetric label="Last updated" valueText={time(task.updatedAt)} />
      </div>
      <p className={`task-outcome ${taskStateClass(task)}`}>
        {task.progressState === "succeeded"
          ? task.sourceFamily === "LayoutReplacementBuild"
            ? "Private layout validation completed. Publication requires a separate activation."
            : "Completed successfully. The timeline is the durable execution evidence."
          : task.status === "Failed"
            ? `This task failed${latest?.errorCode ? `: ${latest.errorCode}` : ""}.`
            : `Current durable state: ${task.status}.`}
      </p>
      {layoutTarget && (
        <LayoutActivation
          scope={scope}
          catalog={catalog}
          target={layoutTarget}
        />
      )}
      {task.status === "NeedsInspection" && (
        <p className="context-note" role="status">
          Review the diagnostic timeline. Reconcile the original task and
          receipt before submitting new work. Recovery could not establish a
          final outcome.
        </p>
      )}
      {task.recoveryState === "workflowCancellationPaused" && (
        <p className="context-note" role="status">
          Cancellation recovery is paused. Review the diagnostic timeline,
          restore required access or resolve the child task, then request
          interruption again for this same task with an authorized client.{" "}
          {workflowCountBasis} Committed work is retained. Repeating
          interruption continues cancellation reconciliation only; it does not
          restart the workflow.
        </p>
      )}
      {task.recoveryState === "scheduleCancellationUnresolved" && (
        <p className="context-note" role="status">
          Scheduled cancellation remains unresolved. A current application
          administrator can inspect this occurrence and its linked build or
          workflow tasks, then request cancellation again for this same
          scheduled occurrence with an authorized client to resume cancellation
          checks. Restoring access alone does not resume parked recovery. A
          missing historical link cannot prove that no work was accepted;
          unknown work stays unresolved and is never attached by guessing.
          Repeating cancellation cannot build, rerun or admit new work. Existing
          receipts and confirmed work are retained.
        </p>
      )}
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
                {time(event.occurredAt)}
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
