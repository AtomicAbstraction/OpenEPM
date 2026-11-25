import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError, readProgram, request } from "./api";
import { parameterObject } from "./ParameterFields";
import type { ApplicationCatalog, ApplicationSummary } from "./types";

export type WorkFocus = {
  workspaceId?: string;
  applicationId?: string;
  assignmentId?: string;
  occurrenceId?: string;
  activityId?: string;
};

type WorkPage = "flows";
type Item = {
  key: string;
  title: string;
  detail: string;
  source: string;
  page: WorkPage;
  focus: WorkFocus;
  state: "ready" | "waiting" | "blocked";
};

export type WorkflowWorkItem = {
  occurrenceId: string;
  activityId: string;
  name: string;
  flowId: string;
};

const blockedWorkDetails = {
  SelectionMetadataChanged:
    "The model changed after this workflow was published. Ask an application administrator to review it.",
  WorkflowDefinitionUnavailable:
    "The workflow definition is no longer active for this occurrence. Ask an application administrator to review it.",
  WorkflowDependencyUnavailable:
    "A required workflow dependency is unavailable. Ask an application administrator to review it.",
};

export type BlockedWorkflowWork = WorkflowWorkItem & {
  reason: keyof typeof blockedWorkDetails;
};

const waitingWorkDetails = {
  DependencyPending: "Waiting on an earlier workflow dependency",
  ReturnedForRework: "Waiting for the returned work to be completed",
};

type WaitingWorkflowWork = WorkflowWorkItem & {
  reason: keyof typeof waitingWorkDetails;
};

export function blockedWorkflowDetail(item: BlockedWorkflowWork) {
  return blockedWorkDetails[item.reason];
}

type WorkflowWorkPage<T extends WorkflowWorkItem> = {
  items: T[];
  blockedItems?: BlockedWorkflowWork[];
  waitingItems?: WaitingWorkflowWork[];
  nextCursor?: {
    afterOccurrenceId: string;
    afterActivityId: string;
  } | null;
};

type WaitingTaskPage = {
  tasks: Array<{
    taskId: string;
    sourceFamily: string;
    sourceId: string;
    status: string;
  }>;
  nextSequence?: number | null;
  hasMore?: boolean;
};

export async function readCompleteWorkflowWorklist<
  T extends WorkflowWorkItem = WorkflowWorkItem,
>(
  scope: { workspaceId: string; applicationId: string },
  signal?: AbortSignal,
  {
    occurrenceId,
    includeWaiting = false,
  }: {
    occurrenceId?: string;
    includeWaiting?: boolean;
  } = {},
): Promise<{
  items: T[];
  blockedItems: BlockedWorkflowWork[];
  waitingItems: WaitingWorkflowWork[];
}> {
  const items: T[] = [];
  const blockedItems: BlockedWorkflowWork[] = [];
  const waitingItems: WaitingWorkflowWork[] = [];
  let cursor: WorkflowWorkPage<T>["nextCursor"] = null;
  const seen = new Set<string>();
  const seenItems = new Set<string>();
  do {
    const page: WorkflowWorkPage<T> = await readProgram<WorkflowWorkPage<T>>(
      scope,
      "application.workflow.worklist",
      {
        limit: 100,
        includeBlocked: true,
        ...(includeWaiting ? { includeWaiting: true } : {}),
        ...(occurrenceId ? { occurrenceId } : {}),
        ...(cursor || {}),
      },
      signal,
    );
    const blocked =
      !includeWaiting && page.blockedItems === undefined
        ? []
        : page.blockedItems;
    const waiting = includeWaiting ? page.waitingItems : [];
    if (
      !Array.isArray(page.items) ||
      !Array.isArray(blocked) ||
      !Array.isArray(waiting)
    )
      throw new Error("Workflow worklist rows are invalid.");
    for (const item of [...page.items, ...blocked, ...waiting]) {
      if (
        !item ||
        typeof item.occurrenceId !== "string" ||
        !item.occurrenceId ||
        (occurrenceId && item.occurrenceId !== occurrenceId) ||
        typeof item.activityId !== "string" ||
        !item.activityId
      )
        throw new Error("Workflow worklist returned an invalid row.");
      const identity = `${item.occurrenceId}\u0000${item.activityId}`;
      if (seenItems.has(identity))
        throw new Error("Workflow worklist continuation repeated a row.");
      seenItems.add(identity);
    }
    for (const item of blocked) {
      if (
        !Object.prototype.hasOwnProperty.call(blockedWorkDetails, item.reason)
      )
        throw new Error(
          "Workflow worklist returned an invalid blocked reason.",
        );
    }
    for (const item of waiting) {
      if (
        typeof item.name !== "string" ||
        !Object.prototype.hasOwnProperty.call(waitingWorkDetails, item.reason)
      )
        throw new Error("Workflow worklist returned an invalid Waiting row.");
    }
    items.push(...page.items);
    blockedItems.push(...blocked);
    waitingItems.push(...waiting);
    cursor = page.nextCursor || null;
    if (cursor) {
      if (
        typeof cursor.afterOccurrenceId !== "string" ||
        !cursor.afterOccurrenceId ||
        (occurrenceId && cursor.afterOccurrenceId !== occurrenceId) ||
        typeof cursor.afterActivityId !== "string" ||
        !cursor.afterActivityId
      )
        throw new Error("Workflow worklist cursor is invalid.");
      const key = `${cursor.afterOccurrenceId}\u0000${cursor.afterActivityId}`;
      if (seen.has(key)) throw new Error("Workflow worklist cursor repeated.");
      seen.add(key);
    }
  } while (cursor);
  return { items, blockedItems, waitingItems };
}

export async function readCompleteWaitingTasks(
  scope: { workspaceId: string; applicationId: string },
  signal?: AbortSignal,
) {
  const tasks: WaitingTaskPage["tasks"] = [];
  let afterSequence = 0;
  const seen = new Set<string>();
  while (true) {
    const page = await request<WaitingTaskPage>(
      "/api/tasks",
      { ...scope, afterSequence, limit: 100 },
      signal,
    );
    if (!Array.isArray(page.tasks) || typeof page.hasMore !== "boolean")
      throw new Error("Task worklist response is invalid.");
    for (const task of page.tasks) {
      if (
        !task ||
        typeof task.taskId !== "string" ||
        !task.taskId ||
        typeof task.sourceFamily !== "string" ||
        typeof task.sourceId !== "string" ||
        typeof task.status !== "string" ||
        seen.has(task.taskId)
      )
        throw new Error("Task worklist contains an invalid or repeated task.");
      seen.add(task.taskId);
      tasks.push(task);
    }
    if (!page.hasMore) return tasks;
    const next = page.nextSequence;
    if (
      typeof next !== "number" ||
      !Number.isSafeInteger(next) ||
      next <= 0 ||
      (afterSequence !== 0 && next >= afterSequence)
    )
      throw new Error("Task worklist continuation is invalid.");
    afterSequence = next;
  }
}

type WorklistContext = {
  workspaceId: string;
  applicationId: string;
  catalog: ApplicationCatalog;
  refresh: number;
  nativeWaiting: boolean;
};
type WorkRead<Context, Rows> =
  | {
      context: Context;
      rows: Rows;
      error?: undefined;
      accessDenied?: undefined;
    }
  | {
      context: Context;
      rows?: undefined;
      error: string;
      accessDenied?: boolean;
    };

export function MyWork({
  app,
  catalog,
  catalogueUnavailable = false,
  open,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  catalogueUnavailable?: boolean;
  open: (page: WorkPage, focus?: WorkFocus) => void;
}) {
  const [read, setRead] = useState<WorkRead<WorklistContext, Item[]> | null>(
    null,
  );
  const [refresh, setRefresh] = useState(0);
  const [waitingRetry, setWaitingRetry] = useState(0);
  const [query, setQuery] = useState("");
  const [workState, setWorkState] = useState<"all" | Item["state"]>("all");
  const workHeading = useRef<HTMLHeadingElement>(null);
  const workspaceId = app?.workspaceId;
  const applicationId = app?.applicationId;
  const worklistSpec = parameterObject(
    catalog?.functions["application.workflow.worklist"],
  );
  const schema = parameterObject(worklistSpec?.programSchema);
  const args = parameterObject(parameterObject(schema?.properties)?.arguments);
  const waitingSchema = parameterObject(
    parameterObject(args?.properties)?.includeWaiting,
  );
  const nativeWaiting = waitingSchema?.type === "boolean";
  const context = useMemo(
    () =>
      workspaceId && applicationId && catalog
        ? { workspaceId, applicationId, catalog, refresh, nativeWaiting }
        : null,
    [workspaceId, applicationId, catalog, refresh, nativeWaiting],
  );
  const waitingContext = useMemo(
    () =>
      context && !context.nativeWaiting
        ? { worklist: context, retry: waitingRetry }
        : null,
    [context, waitingRetry],
  );
  const [waitingRead, setWaitingRead] = useState<WorkRead<
    NonNullable<typeof waitingContext>,
    WaitingTaskPage["tasks"]
  > | null>(null);
  const canRead = Boolean(catalog?.functions["application.workflow.worklist"]);
  const current = canRead && read?.context === context ? read : null;
  const currentWaiting =
    canRead && waitingRead?.context === waitingContext ? waitingRead : null;
  const accessFailure = currentWaiting?.accessDenied
    ? currentWaiting.error
    : undefined;
  const loadError = accessFailure ?? current?.error;
  const loading = Boolean(context && canRead && !current && !accessFailure);
  const assignmentRead = Boolean(current?.rows && accessFailure === undefined);
  const waitingConfirmed = nativeWaiting
    ? assignmentRead
    : Boolean(currentWaiting?.rows);

  useEffect(() => {
    if (!context || !canRead) return;
    const controller = new AbortController();
    const { signal } = controller;
    const scope = {
      workspaceId: context.workspaceId,
      applicationId: context.applicationId,
    };
    void readCompleteWorkflowWorklist(scope, signal, {
      includeWaiting: context.nativeWaiting,
    })
      .then((worklist) => {
        if (signal.aborted) return;
        const assignment = (
          item: WorkflowWorkItem,
          detail: string,
          state: Item["state"],
        ): Item => ({
          key: `flow-${item.occurrenceId}-${item.activityId}`,
          title: item.name,
          detail,
          source: "Workflow",
          page: "flows",
          focus: {
            ...scope,
            occurrenceId: item.occurrenceId,
            activityId: item.activityId,
          },
          state,
        });
        const ready = worklist.items.map((item) =>
          assignment(item, "Ready for your action", "ready"),
        );
        const blocked = worklist.blockedItems.map((item) =>
          assignment(item, blockedWorkflowDetail(item), "blocked"),
        );
        const waiting = worklist.waitingItems.map((item) =>
          assignment(item, waitingWorkDetails[item.reason], "waiting"),
        );
        setRead({ context, rows: [...ready, ...blocked, ...waiting] });
      })
      .catch((reason: Error) => {
        if (!signal.aborted) setRead({ context, error: reason.message });
      });
    return () => controller.abort();
  }, [context, canRead]);

  useEffect(() => {
    if (!waitingContext || !canRead) return;
    const controller = new AbortController();
    const { signal } = controller;
    const { workspaceId, applicationId } = waitingContext.worklist;
    void readCompleteWaitingTasks({ workspaceId, applicationId }, signal)
      .then((rows) => {
        if (!signal.aborted) setWaitingRead({ context: waitingContext, rows });
      })
      .catch((reason: Error) => {
        if (!signal.aborted)
          setWaitingRead({
            context: waitingContext,
            error: reason.message,
            accessDenied:
              reason instanceof ApiError && [401, 403].includes(reason.status),
          });
      });
    return () => controller.abort();
  }, [waitingContext, canRead]);

  const rows = useMemo(() => {
    const assigned = current?.rows;
    if (!assigned || !context) return [];
    const tasks = currentWaiting?.rows;
    if (!tasks) return assigned;
    const assignedKeys = new Set(
      assigned.map(({ focus }) => `${focus.occurrenceId}/${focus.activityId}`),
    );
    const waiting = tasks.flatMap((task): Item[] => {
      if (
        task.sourceFamily !== "ApplicationWorkflowActivity" ||
        task.status !== "Waiting" ||
        assignedKeys.has(task.sourceId)
      )
        return [];
      const separator = task.sourceId.indexOf("/");
      if (separator <= 0 || separator === task.sourceId.length - 1) return [];
      return [
        {
          key: `waiting-${task.taskId}`,
          title: "Workflow activity",
          detail: "Waiting on an earlier workflow dependency",
          source: "Workflow",
          page: "flows",
          focus: {
            workspaceId: context.workspaceId,
            applicationId: context.applicationId,
            occurrenceId: task.sourceId.slice(0, separator),
            activityId: task.sourceId.slice(separator + 1),
          },
          state: "waiting",
        },
      ];
    });
    return [...assigned, ...waiting];
  }, [context, current, currentWaiting]);

  const matching = rows.filter((item) =>
    `${item.title} ${item.detail}`
      .toLocaleLowerCase()
      .includes(query.trim().toLocaleLowerCase()),
  );
  const ready = matching.filter((item) => item.state === "ready");
  const waiting = matching.filter((item) => item.state === "waiting");
  const blocked = matching.filter((item) => item.state === "blocked");
  const showBlocked =
    rows.some((item) => item.state === "blocked") || workState === "blocked";
  const columns = [
    {
      key: "ready",
      label: "Ready",
      dot: "blue-dot",
      items: ready,
      empty: "No work is currently ready",
    },
    {
      key: "waiting",
      label: "Waiting",
      dot: "muted-dot",
      items: waitingConfirmed ? waiting : undefined,
      empty: "No work waiting on dependencies",
    },
    ...(showBlocked
      ? [
          {
            key: "blocked",
            label: "Blocked",
            dot: "muted-dot",
            items: blocked,
            empty: "No blocked activities",
          },
        ]
      : []),
  ];
  const visibleColumns =
    workState === "all"
      ? columns
      : columns.filter((item) => item.key === workState);
  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <small>{app?.name || "Workspace"}</small>
          <h1 ref={workHeading} tabIndex={-1}>
            My Work
          </h1>
          <p>
            Your assigned activities in{" "}
            {app?.name || "the selected application"}. Open an activity to see
            its context and next step.
          </p>
        </div>
      </div>
      <div
        className="filter-row"
        role="group"
        aria-label="Filter work by state"
      >
        {[
          ["all", "All", waitingConfirmed ? matching.length : "—"],
          ["ready", "Ready", ready.length],
          ["waiting", "Waiting", waitingConfirmed ? waiting.length : "—"],
          ...(showBlocked ? [["blocked", "Blocked", blocked.length]] : []),
        ].map(([value, label, count]) => (
          <button
            key={String(value)}
            className={workState === value ? "selected" : ""}
            aria-pressed={workState === value}
            disabled={!assignmentRead}
            onClick={() => setWorkState(value as typeof workState)}
          >
            {label} <span>{assignmentRead ? count : "—"}</span>
          </button>
        ))}
      </div>
      {loadError !== undefined && (
        <div className="alert" role="alert">
          {loadError}
          <p>
            Your work could not be loaded. Empty columns are not a confirmed
            result.
          </p>
          <button
            type="button"
            onClick={() => {
              workHeading.current?.focus();
              setRefresh((value) => value + 1);
            }}
          >
            Retry worklist
          </button>
        </div>
      )}
      <label className="work-search">
        Find an activity
        <input
          type="search"
          value={query}
          placeholder="Activity or workflow"
          onChange={(event) => setQuery(event.target.value)}
        />
      </label>
      {loading && <p role="status">Loading your work…</p>}
      {assignmentRead && (
        <section className="work-board" aria-label="Authoritative work board">
          {visibleColumns.map((column) => (
            <WorkColumn
              key={`${column.key}:${query}`}
              label={column.label}
              dot={column.dot}
              items={column.items}
              empty={column.empty}
              error={
                column.key === "waiting" ? currentWaiting?.error : undefined
              }
              retry={
                column.key === "waiting"
                  ? () => setWaitingRetry((value) => value + 1)
                  : undefined
              }
              open={open}
            />
          ))}
        </section>
      )}
      {!app && (
        <p className="context-note">Choose an application to see your work.</p>
      )}
      {app && !catalog && (
        <p role="status">
          {catalogueUnavailable
            ? "Access to assigned work could not be confirmed."
            : "Checking access to assigned work…"}
        </p>
      )}
      {app && catalog && !canRead && (
        <p role="status">
          The current application catalogue does not include assigned work.
        </p>
      )}
    </div>
  );
}

function EmptyWork({ text }: { text: string }) {
  return (
    <div className="empty-work">
      <span>✓</span>
      <p>{text}</p>
    </div>
  );
}

const activityPageSize = 50;

export function activityPageBounds(page: number, count: number) {
  const start = Math.min(
    page * activityPageSize,
    Math.max(0, Math.ceil(count / activityPageSize) - 1) * activityPageSize,
  );
  return { start, end: Math.min(start + activityPageSize, count), count };
}

export function ActivityPagination({
  label,
  bounds: { start, end, count },
  empty,
  onPage,
}: {
  label: string;
  bounds: ReturnType<typeof activityPageBounds>;
  empty?: string;
  onPage: (page: number) => void;
}) {
  const canGoBack = start > 0;
  const canGoForward = end < count;
  const activities = `${label.toLowerCase()} activities`;
  return (
    <div className="directory-pagination work-pagination">
      <span role="status">
        {count ? `${start + 1}–${end} of ${count} ${activities}` : empty}
      </span>
      <div>
        <button
          type="button"
          aria-label={`Previous ${activities}`}
          aria-disabled={!canGoBack || undefined}
          tabIndex={canGoBack ? undefined : -1}
          onClick={() => {
            if (canGoBack) onPage(start / activityPageSize - 1);
          }}
        >
          Previous
        </button>
        <button
          type="button"
          aria-label={`Next ${activities}`}
          aria-disabled={!canGoForward || undefined}
          tabIndex={canGoForward ? undefined : -1}
          onClick={() => {
            if (canGoForward) onPage(start / activityPageSize + 1);
          }}
        >
          Next
        </button>
      </div>
    </div>
  );
}

function WorkColumn({
  label,
  dot,
  items,
  empty,
  error,
  retry,
  open,
}: {
  label: string;
  dot: string;
  items?: Item[];
  empty: string;
  error?: string;
  retry?: () => void;
  open: (page: WorkPage, focus?: WorkFocus) => void;
}) {
  const [page, setPage] = useState(0);
  const header = useRef<HTMLElement>(null);
  const count = items?.length ?? 0;
  const bounds = activityPageBounds(page, count);
  return (
    <div className="work-column">
      <header ref={header} tabIndex={-1}>
        <span className={dot} />
        {label} <b>{items ? count : "—"}</b>
      </header>
      {!items ? (
        error !== undefined ? (
          <div className="alert">
            <p role="alert">Waiting work could not be loaded. {error}</p>
            <button
              type="button"
              onClick={() => {
                header.current?.focus();
                retry?.();
              }}
            >
              Retry Waiting
            </button>
          </div>
        ) : (
          <p role="status">Loading waiting work…</p>
        )
      ) : items.length ? (
        <>
          {count > activityPageSize && (
            <ActivityPagination
              label={label}
              bounds={bounds}
              onPage={setPage}
            />
          )}
          <div className="work-items">
            {items.slice(bounds.start, bounds.end).map((item) => (
              <article key={item.key}>
                <span>{item.source}</span>
                <strong>{item.title}</strong>
                <p>{item.detail}</p>
                <button
                  type="button"
                  className="secondary-link"
                  aria-label={`Open activity ${item.title}`}
                  onClick={() => open(item.page, item.focus)}
                >
                  Open activity →
                </button>
              </article>
            ))}
          </div>
        </>
      ) : (
        <EmptyWork text={empty} />
      )}
    </div>
  );
}
