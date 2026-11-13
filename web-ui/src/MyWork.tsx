import { useEffect, useState } from "react";
import { readProgram, request } from "./api";
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
  waiting?: boolean;
};

export type WorkflowWorkItem = {
  occurrenceId: string;
  activityId: string;
  name: string;
  flowId: string;
};

type WorkflowWorkPage<T extends WorkflowWorkItem> = {
  items: T[];
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
): Promise<T[]> {
  const items: T[] = [];
  let cursor: WorkflowWorkPage<T>["nextCursor"] = null;
  const seen = new Set<string>();
  const seenItems = new Set<string>();
  do {
    const page: WorkflowWorkPage<T> = await readProgram<WorkflowWorkPage<T>>(
      scope,
      "application.workflow.worklist",
      { limit: 100, ...(cursor || {}) },
      signal,
    );
    if (!Array.isArray(page.items))
      throw new Error("Workflow worklist rows are invalid.");
    for (const item of page.items) {
      if (
        !item ||
        typeof item.occurrenceId !== "string" ||
        !item.occurrenceId ||
        typeof item.activityId !== "string" ||
        !item.activityId
      )
        throw new Error("Workflow worklist returned an invalid row.");
      const identity = `${item.occurrenceId}\u0000${item.activityId}`;
      if (seenItems.has(identity))
        throw new Error("Workflow worklist continuation repeated a row.");
      seenItems.add(identity);
      items.push(item);
    }
    cursor = page.nextCursor || null;
    if (cursor) {
      if (
        typeof cursor.afterOccurrenceId !== "string" ||
        !cursor.afterOccurrenceId ||
        typeof cursor.afterActivityId !== "string" ||
        !cursor.afterActivityId
      )
        throw new Error("Workflow worklist cursor is invalid.");
      const key = `${cursor.afterOccurrenceId}\u0000${cursor.afterActivityId}`;
      if (seen.has(key)) throw new Error("Workflow worklist cursor repeated.");
      seen.add(key);
    }
  } while (cursor);
  return items;
}

export async function readCompleteWaitingTasks(
  scope: { workspaceId: string; applicationId: string },
  signal?: AbortSignal,
) {
  const tasks: WaitingTaskPage["tasks"] = [];
  let afterSequence = 0;
  const seen = new Set<number>();
  while (true) {
    const page = await request<WaitingTaskPage>(
      "/api/tasks",
      { ...scope, afterSequence, limit: 100 },
      signal,
    );
    tasks.push(...page.tasks);
    if (!page.hasMore) return tasks;
    const next = page.nextSequence;
    if (typeof next !== "number" || next <= 0 || seen.has(next))
      throw new Error("Task worklist continuation is invalid.");
    seen.add(next);
    afterSequence = next;
  }
}

export function MyWork({
  app,
  catalog,
  open,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  open: (page: WorkPage, focus?: WorkFocus) => void;
}) {
  const [items, setItems] = useState<Item[]>([]);
  const [workError, setWorkError] = useState("");
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [workState, setWorkState] = useState<"all" | "ready" | "waiting">(
    "all",
  );
  useEffect(() => {
    setItems([]);
    setWorkError("");
    setLoading(false);
    if (!app || !catalog) return;
    setLoading(true);
    const controller = new AbortController();
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    const reads: Promise<Item[]>[] = [];
    const workflowFunction = "application.workflow.worklist";
    if (Object.hasOwn(catalog.functions, workflowFunction))
      reads.push(
        readCompleteWorkflowWorklist(scope, controller.signal).then((items) =>
          items.map((item) => ({
            key: `flow-${item.occurrenceId}-${item.activityId}`,
            title: item.name,
            detail: "Ready for your action",
            source: "Workflow",
            page: "flows",
            focus: {
              workspaceId: app.workspaceId,
              applicationId: app.applicationId,
              occurrenceId: item.occurrenceId,
              activityId: item.activityId,
            },
          })),
        ),
      );
    if (Object.hasOwn(catalog.functions, workflowFunction))
      reads.push(
        readCompleteWaitingTasks(scope, controller.signal).then((tasks) =>
          tasks.flatMap((task) => {
            if (
              task.sourceFamily !== "ApplicationWorkflowActivity" ||
              task.status !== "Waiting"
            )
              return [];
            const separator = task.sourceId.indexOf("/");
            if (separator <= 0 || separator === task.sourceId.length - 1)
              return [];
            const occurrenceId = task.sourceId.slice(0, separator);
            const activityId = task.sourceId.slice(separator + 1);
            return [
              {
                key: `waiting-${task.taskId}`,
                title: "Workflow activity",
                detail: "Waiting on an earlier workflow dependency",
                source: "Workflow",
                page: "flows" as const,
                focus: {
                  workspaceId: app.workspaceId,
                  applicationId: app.applicationId,
                  occurrenceId,
                  activityId,
                },
                waiting: true,
              },
            ];
          }),
        ),
      );
    Promise.all(reads)
      .then((groups) => {
        if (controller.signal.aborted) return;
        const discovered = groups.flat();
        const readyWorkflow = new Set(
          discovered
            .filter((item) => item.page === "flows" && !item.waiting)
            .map(
              (item) =>
                `${item.focus.occurrenceId || ""}/${item.focus.activityId || ""}`,
            ),
        );
        setItems(
          discovered.filter(
            (item) =>
              !item.waiting ||
              !readyWorkflow.has(
                `${item.focus.occurrenceId || ""}/${item.focus.activityId || ""}`,
              ),
          ),
        );
      })
      .catch((reason: Error) => {
        if (!controller.signal.aborted) setWorkError(reason.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [app?.workspaceId, app?.applicationId, catalog]);

  const matching = items.filter((item) =>
    `${item.title} ${item.detail}`
      .toLocaleLowerCase()
      .includes(query.trim().toLocaleLowerCase()),
  );
  const ready = matching.filter((item) => !item.waiting);
  const waiting = matching.filter((item) => item.waiting);
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
      items: waiting,
      empty: "No work waiting on dependencies",
    },
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
          <h1>My Work</h1>
          <p>
            Your ready and waiting activities in{" "}
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
          ["all", "All", matching.length],
          ["ready", "Ready", ready.length],
          ["waiting", "Waiting", waiting.length],
        ].map(([value, label, count]) => (
          <button
            key={String(value)}
            className={workState === value ? "selected" : ""}
            aria-pressed={workState === value}
            onClick={() => setWorkState(value as typeof workState)}
          >
            {label} <span>{count}</span>
          </button>
        ))}
      </div>
      {workError && (
        <div className="alert" role="alert">
          {workError}
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
      {!loading && (
        <section className="work-board" aria-label="Authoritative work board">
          {visibleColumns.map((column) => (
            <WorkColumn
              key={`${column.key}:${query}`}
              label={column.label}
              dot={column.dot}
              items={column.items}
              empty={column.empty}
              open={open}
            />
          ))}
        </section>
      )}
      {!app && (
        <p className="context-note">Choose an application to see your work.</p>
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

function WorkColumn({
  label,
  dot,
  items,
  empty,
  open,
}: {
  label: string;
  dot: string;
  items: Item[];
  empty: string;
  open: (page: WorkPage, focus?: WorkFocus) => void;
}) {
  const [page, setPage] = useState(0);
  const start = Math.min(
    page * 50,
    Math.max(0, Math.ceil(items.length / 50) - 1) * 50,
  );
  return (
    <div className="work-column">
      <header>
        <span className={dot} />
        {label} <b>{items.length}</b>
      </header>
      {items.length ? (
        <div className="work-items">
          {items.slice(start, start + 50).map((item) => (
            <article key={item.key}>
              <span>{item.source}</span>
              <strong>{item.title}</strong>
              <p>{item.detail}</p>
              <button
                className="secondary-link"
                onClick={() => open(item.page, item.focus)}
              >
                Open activity →
              </button>
            </article>
          ))}
          {items.length > 50 && (
            <div className="directory-pagination">
              <span>
                {start + 1}–{Math.min(start + 50, items.length)} of{" "}
                {items.length}
              </span>
              <button disabled={start === 0} onClick={() => setPage(page - 1)}>
                Previous activities
              </button>
              <button
                disabled={start + 50 >= items.length}
                onClick={() => setPage(page + 1)}
              >
                Next activities
              </button>
            </div>
          )}
        </div>
      ) : (
        <EmptyWork text={empty} />
      )}
    </div>
  );
}
