import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import {
  Monitor,
  jobCancelBody,
  jobReadBody,
  mergeTaskLogPage,
  taskProgressRows,
} from "./Monitor";
import { mergeTaskListPage, taskListBody } from "./task-list";
import serverContracts from "./server-contract-fixtures.json";

afterEach(() => vi.unstubAllGlobals());

const catalog = {
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: { "facts.expression.calculate": {} },
  revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
};

const monitorApplication = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "active",
};

const selectionTasks = ["task-one", "task-two"].map((taskId, index) => ({
  taskId,
  sequence: 2 - index,
  sourceFamily: "Job",
  function: `${taskId}.calculate`,
  status: "Running",
  progressState: "inProgress" as const,
  interruptible: true,
  rerunSupported: true,
  latestEvent: null,
  events: [],
}));

it("shows an incomplete attention search as unavailable instead of an empty task list", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      if (url !== "/api/tasks") throw new Error("Unexpected request");
      const body = JSON.parse(init.body);
      return body.attentionOnly
        ? new Response(
            JSON.stringify({ code: "TASK_VISIBILITY_SEARCH_INCOMPLETE" }),
            { status: 400 },
          )
        : taskListResponse();
    }),
  );
  render(<Monitor app={monitorApplication} catalog={catalog} />);
  await screen.findByRole("button", { name: "task-one.calculate" });
  fireEvent.click(screen.getByRole("button", { name: "Needs attention" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "TASK_VISIBILITY_SEARCH_INCOMPLETE",
  );
  expect(
    screen.getByText("Task results are unavailable. Refresh to retry."),
  ).toBeVisible();
  expect(
    screen.queryByText("No visible durable tasks for this application."),
  ).toBeNull();
  expect(screen.queryByText("No task families are visible.")).toBeNull();
  expect(screen.queryByText(/0 matching/)).toBeNull();
});

it("reports a failed background job search as unavailable and allows a fresh read", async () => {
  let available = false;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url) => {
      if (url === "/api/tasks") return taskListResponse();
      if (url !== "/api/events") throw new Error("Unexpected request");
      return available
        ? new Response(
            JSON.stringify({ events: [], nextSequence: 0, hasMore: false }),
          )
        : new Response(JSON.stringify({ code: "READ_UNAVAILABLE" }), {
            status: 503,
          });
    }),
  );
  render(<Monitor app={monitorApplication} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Show jobs" }));
  expect(
    await screen.findByText(
      "Background job results are unavailable. Refresh jobs to retry.",
    ),
  ).toBeVisible();
  expect(screen.queryByText("No recent jobs are visible.")).toBeNull();
  available = true;
  fireEvent.click(screen.getByRole("button", { name: "Refresh jobs" }));
  expect(await screen.findByText("No recent jobs are visible.")).toBeVisible();
});

it.each([
  ["/api/events", 409, "JOB_READ_AUTHORIZATION_STALE"],
  ["/api/job", 403, "APPLICATION_GRANT_REQUIRED"],
])(
  "clears cached job evidence after %s returns %s and rechecks access before recovery",
  async (failedRoute, status, code) => {
    const jobId = "a".repeat(32);
    const requests: [string, Record<string, unknown>][] = [];
    let refuse = false;
    const refresh = vi.fn(async () => {
      requests.push(["catalogue", {}]);
      return catalog;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url, init) => {
        const body = JSON.parse(String(init?.body));
        requests.push([url, body]);
        if (url === "/api/tasks") return taskListResponse();
        if (url === failedRoute && refuse)
          return Response.json({ code }, { status });
        if (url === "/api/events")
          return Response.json({
            events: [{ sequence: 4, job_id: jobId, status: "published" }],
            nextSequence: 4,
            hasMore: true,
          });
        if (url === "/api/job")
          return Response.json({
            job_id: jobId,
            status: "published",
            receipt_revision: 8,
          });
        if (url === "/api/read")
          return Response.json({
            result: {
              operationId: jobId,
              commandDigest: "b".repeat(64),
              actorId: "planner",
              committedRevision: 8,
              committedAt: "2026-11-21T07:00:00Z",
              outcome: { setCount: 19 },
            },
          });
        throw new Error("Unexpected request");
      }),
    );
    render(
      <Monitor
        app={monitorApplication}
        catalog={{
          ...catalog,
          functions: {
            ...catalog.functions,
            "application.operation.receipt.read": {},
          },
        }}
        onRefreshCatalog={refresh}
      />,
    );
    const jobs = within(
      screen.getByRole("region", { name: "Background jobs" }),
    );
    fireEvent.click(jobs.getByRole("button", { name: "Show jobs" }));
    fireEvent.click(await jobs.findByRole("button", { name: /^published/ }));
    fireEvent.click(
      await jobs.findByRole("button", { name: "View publication outcome" }),
    );
    expect(await jobs.findByText("Activity outcome loaded.")).toBeVisible();
    refuse = true;
    const trigger = jobs.getByRole("button", {
      name: failedRoute === "/api/events" ? "More jobs" : "Check current job",
    });
    trigger.focus();
    fireEvent.click(trigger);
    expect(await jobs.findByRole("alert")).toHaveTextContent(code);
    expect(jobs.queryByText("No recent jobs are visible.")).toBeNull();
    expect(jobs.queryByText("Last confirmed job state")).toBeNull();
    expect(jobs.queryByText("Activity outcome loaded.")).toBeNull();
    expect(jobs.queryByRole("button", { name: /^published/ })).toBeNull();
    expect(
      jobs.getByRole("button", { name: "Request cancellation" }),
    ).toBeDisabled();
    if (failedRoute === "/api/events")
      expect(jobs.getByRole("button", { name: "Refresh jobs" })).toHaveFocus();
    expect(refresh).not.toHaveBeenCalled();
    refuse = false;
    fireEvent.click(jobs.getByRole("button", { name: "Check current job" }));
    expect(await jobs.findByText("Last confirmed job state")).toBeVisible();
    expect(requests.slice(-2)).toEqual([
      ["catalogue", {}],
      ["/api/job", { workspaceId: "ws", applicationId: "app", jobId }],
    ]);
    fireEvent.click(jobs.getByRole("button", { name: "Refresh jobs" }));
    await jobs.findByRole("button", { name: /^published/ });
    expect(requests.at(-1)).toEqual([
      "/api/events",
      { workspaceId: "ws", applicationId: "app", afterSequence: 0, limit: 100 },
    ]);
  },
);

it("loads older task pages with the visible cursor and preserves the loaded counts", async () => {
  const cursors: number[] = [];
  const newest = { ...selectionTasks[0], sequence: 9 };
  const older = {
    ...selectionTasks[1],
    sequence: 4,
    status: "NeedsInspection",
    progressState: "attention",
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      if (url !== "/api/tasks") throw new Error("Unexpected request");
      const { afterSequence } = JSON.parse(init.body);
      cursors.push(afterSequence);
      return new Response(
        JSON.stringify(
          afterSequence === 0
            ? { tasks: [newest], nextSequence: 9, hasMore: true }
            : afterSequence === 9
              ? { tasks: [older], nextSequence: 4, hasMore: true }
              : { tasks: [], nextSequence: 4, hasMore: false },
        ),
      );
    }),
  );
  render(<Monitor app={monitorApplication} catalog={catalog} />);
  await screen.findByRole("button", { name: newest.function });
  expect(screen.getByRole("status")).toHaveTextContent(
    "1 task loaded. More tasks are available.",
  );
  expect(
    screen.getByRole("region", { name: "Task progress matrix" }),
  ).toHaveAttribute("tabindex", "0");
  fireEvent.click(screen.getByRole("button", { name: "Next tasks" }));
  await screen.findByRole("button", { name: older.function });
  expect(
    screen.getByText(/2 matching · 2 loaded · more available/),
  ).toBeVisible();
  const next = screen.getByRole("button", { name: "Next tasks" });
  next.focus();
  fireEvent.click(next);
  await waitFor(() => {
    expect(screen.getByText("2 matching · 2 loaded")).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent(/^2 tasks loaded\.$/);
    expect(next).toHaveAttribute("aria-disabled", "true");
  });
  expect(next).toHaveFocus();
  expect(next).toHaveAccessibleDescription("2 tasks loaded.");
  expect(cursors).toEqual([0, 9, 4]);
});

it("settles the task list after Escape closes a detail during Refresh", async () => {
  let finishList: (response: Response) => void = () => {};
  let finishDetail: (response: Response) => void = () => {};
  const refreshedList = new Promise<Response>((resolve) => {
    finishList = resolve;
  });
  const refreshedDetail = new Promise<Response>((resolve) => {
    finishDetail = resolve;
  });
  let listSignal: AbortSignal | null | undefined;
  let detailSignal: AbortSignal | null | undefined;
  const [original, replacement] = selectionTasks;
  let refreshing = false;
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/api/tasks") {
        if (!refreshing)
          return Promise.resolve(
            Response.json({
              tasks: [original],
              nextSequence: original.sequence,
              hasMore: false,
            }),
          );
        listSignal = init?.signal;
        return refreshedList;
      }
      if (String(input) === "/api/task") {
        if (!refreshing) return Promise.resolve(Response.json(original));
        detailSignal = init?.signal;
        return refreshedDetail;
      }
      throw new Error("Unexpected route");
    }),
  );

  render(<Monitor app={monitorApplication} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", { name: original.function }),
  );
  const close = await screen.findByRole("button", {
    name: "Close task detail",
  });
  refreshing = true;
  fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  fireEvent.keyDown(close, { key: "Escape" });

  expect(detailSignal?.aborted).toBe(true);
  expect(listSignal?.aborted).toBe(false);
  expect(
    screen.getByRole("searchbox", { name: "Search loaded tasks" }),
  ).toHaveFocus();

  await act(async () =>
    finishList(
      Response.json({
        tasks: [replacement],
        nextSequence: replacement.sequence,
        hasMore: false,
      }),
    ),
  );
  expect(
    screen.getByRole("button", { name: replacement.function }),
  ).toBeVisible();
  expect(screen.getByRole("status")).toHaveTextContent(/^1 task loaded\.$/);

  await act(async () => finishDetail(Response.json(original)));
  expect(
    screen.queryByRole("complementary", { name: "Selected task detail" }),
  ).toBeNull();
});

it("announces a direct task reference only while its detail read is pending", async () => {
  const [task] = selectionTasks;
  let finishDetail: (response: Response) => void = () => {};
  const detail = new Promise<Response>((resolve) => {
    finishDetail = resolve;
  });
  const fetch = vi.fn(async (url) => {
    if (url === "/api/tasks") return taskListResponse();
    if (url === "/api/task") return detail;
    throw new Error("Unexpected route");
  });
  vi.stubGlobal("fetch", fetch);
  render(
    <Monitor
      app={monitorApplication}
      catalog={catalog}
      targetTaskId={task.taskId}
    />,
  );
  const pending = "Checking current access to the referenced task…";
  expect(await screen.findByText(pending)).toBeVisible();
  await act(async () => finishDetail(Response.json(task)));
  fireEvent.click(
    await screen.findByRole("button", { name: "Close task detail" }),
  );
  expect(screen.queryByText(pending)).not.toBeInTheDocument();
  expect(fetch.mock.calls.filter(([url]) => url === "/api/task")).toHaveLength(
    1,
  );
});

it("refreshes the exact open task from waiting through success and clears it on refusal", async () => {
  const calls: string[] = [];
  let state = "Waiting";
  const task = { ...selectionTasks[0], sourceFamily: "Job" };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      const body = JSON.parse(init.body);
      calls.push(url);
      if (url === "/api/tasks")
        return new Response(
          JSON.stringify({
            tasks:
              state === "Denied"
                ? []
                : [
                    {
                      ...task,
                      status: state,
                      progressState:
                        state === "Succeeded" ? "succeeded" : "inProgress",
                    },
                  ],
            nextSequence: state === "Denied" ? 0 : task.sequence,
            hasMore: false,
          }),
        );
      if (url !== "/api/task" || body.taskId !== task.taskId)
        throw new Error("Unexpected request");
      return state === "Denied"
        ? new Response(JSON.stringify({ error: "TASK_UNAVAILABLE" }), {
            status: 403,
          })
        : new Response(
            JSON.stringify({
              ...task,
              status: state,
              progressState: state === "Succeeded" ? "succeeded" : "inProgress",
            }),
          );
    }),
  );
  render(
    <Monitor
      app={monitorApplication}
      catalog={catalog}
      targetTaskId={task.taskId}
    />,
  );
  expect(
    await screen.findByText(/Current durable state: Waiting/),
  ).toBeVisible();
  const refresh = screen.getByRole("button", { name: "Refresh" });
  refresh.focus();
  state = "Succeeded";
  fireEvent.click(refresh);
  expect(await screen.findByText(/Completed successfully/)).toBeVisible();
  expect(refresh).toHaveFocus();
  state = "Denied";
  fireEvent.click(refresh);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "TASK_UNAVAILABLE",
  );
  expect(
    screen.queryByRole("complementary", { name: "Selected task detail" }),
  ).toBeNull();
  expect(calls).toEqual([
    "/api/tasks",
    "/api/task",
    "/api/tasks",
    "/api/task",
    "/api/tasks",
    "/api/task",
  ]);
});

it("puts a recovered task that needs inspection in the attention count and explains receipt recovery", async () => {
  const task = {
    ...selectionTasks[0],
    status: "NeedsInspection",
    progressState: "attention",
    interruptible: false,
    rerunSupported: false,
    latestEvent: {
      status: "NeedsInspection",
      errorCode: "RECEIPT_REQUIRES_PUBLICATION_REVIEW",
    },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (url) =>
        new Response(
          JSON.stringify(
            url === "/api/tasks"
              ? { tasks: [task], nextSequence: task.sequence, hasMore: false }
              : task,
          ),
        ),
    ),
  );
  render(
    <Monitor
      app={monitorApplication}
      catalog={catalog}
      targetTaskId={task.taskId}
    />,
  );
  expect(
    await screen.findByRole("button", { name: "Job, attention, 1" }),
  ).toBeEnabled();
  expect(
    await screen.findByText(
      /Reconcile the original task and receipt before submitting new work/,
    ),
  ).toBeVisible();
});

it.each([false, true])(
  "keeps keyboard context through a delayed task read and Escape when focus moved elsewhere (%s)",
  async (movedFocus) => {
    let deliver!: (value: Response) => void;
    const detail = new Promise<Response>((resolve) => {
      deliver = resolve;
    });
    const fetch = vi.fn(async (url) =>
      url === "/api/tasks" ? taskListResponse() : detail,
    );
    vi.stubGlobal("fetch", fetch);
    render(<Monitor app={monitorApplication} catalog={catalog} />);
    const opener = await screen.findByRole("button", {
      name: "task-one.calculate",
    });
    const search = screen.getByRole("searchbox", {
      name: "Search loaded tasks",
    });
    opener.focus();
    fireEvent.click(opener);
    expect(opener).toHaveFocus();
    if (movedFocus) search.focus();
    await act(async () => deliver(Response.json(selectionTasks[0])));
    const close = await screen.findByRole("button", {
      name: "Close task detail",
    });
    expect(movedFocus ? search : close).toHaveFocus();

    close.focus();
    fireEvent.keyDown(close, { key: "Escape" });
    expect(
      screen.queryByRole("complementary", { name: "Selected task detail" }),
    ).toBeNull();
    expect(opener).toHaveFocus();
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      "/api/tasks",
      "/api/task",
    ]);
  },
);

it("opens an exact referenced task outside the loaded list using only its native read", async () => {
  const context = vi.fn();
  const calls: { url: string; body: Record<string, unknown> }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      const body = JSON.parse(init.body);
      calls.push({ url, body });
      return url === "/api/tasks"
        ? taskListResponse()
        : new Response(
            JSON.stringify({
              ...selectionTasks[0],
              taskId: "exact-origin",
              function: "origin.inspect",
            }),
          );
    }),
  );
  render(
    <Monitor
      app={monitorApplication}
      catalog={catalog}
      targetTaskId="exact-origin"
      onTaskContextChange={context}
    />,
  );
  expect(
    await screen.findByRole("heading", { name: "origin.inspect" }),
  ).toBeVisible();
  expect(calls).toContainEqual({
    url: "/api/task",
    body: {
      workspaceId: "ws",
      applicationId: "app",
      taskId: "exact-origin",
      afterEvent: 0,
      eventLimit: 100,
    },
  });
  expect(calls.map((call) => call.url)).toEqual(["/api/tasks", "/api/task"]);
  expect(context).toHaveBeenLastCalledWith("exact-origin");
  const close = screen.getByRole("button", { name: "Close task detail" });
  close.focus();
  fireEvent.click(close);
  expect(context).toHaveBeenLastCalledWith(null);
  expect(
    screen.getByRole("searchbox", { name: "Search loaded tasks" }),
  ).toHaveFocus();
});

it.each([403, 404])(
  "does not replace an unavailable origin with a visible task (%i)",
  async (status) => {
    const context = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) =>
        url === "/api/tasks"
          ? taskListResponse()
          : new Response(JSON.stringify({ error: "TASK_UNAVAILABLE" }), {
              status,
            }),
      ),
    );
    render(
      <Monitor
        app={monitorApplication}
        catalog={catalog}
        targetTaskId="revoked-origin"
        onTaskContextChange={context}
      />,
    );
    expect(await screen.findByRole("alert")).toBeVisible();
    expect(
      screen.queryByRole("complementary", { name: "Selected task detail" }),
    ).toBeNull();
    expect(context.mock.calls.every(([task]) => task === null)).toBe(true);
  },
);

it("rejects a task response whose identity differs from the requested target", async () => {
  const context = vi.fn();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url) =>
      url === "/api/tasks"
        ? taskListResponse()
        : new Response(JSON.stringify(selectionTasks[0])),
    ),
  );
  render(
    <Monitor
      app={monitorApplication}
      catalog={catalog}
      targetTaskId="exact-origin"
      onTaskContextChange={context}
    />,
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "does not match the requested reference",
  );
  expect(context.mock.calls.every(([task]) => task === null)).toBe(true);
});

it("ignores a delayed origin response after the application changes", async () => {
  let finishOld!: (response: Response) => void;
  const context = vi.fn();
  const calls: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      const body = JSON.parse(init.body);
      calls.push(body);
      if (url === "/api/tasks") return taskListResponse();
      if (body.applicationId === "app")
        return new Promise<Response>((resolve) => {
          finishOld = resolve;
        });
      return new Response(
        JSON.stringify({
          ...selectionTasks[0],
          taskId: "current-origin",
          function: "current.inspect",
        }),
      );
    }),
  );
  const rendered = render(
    <Monitor
      app={monitorApplication}
      catalog={catalog}
      targetTaskId="old-origin"
      onTaskContextChange={context}
    />,
  );
  await waitFor(() => expect(finishOld).toBeDefined());
  rendered.rerender(
    <Monitor
      app={{ ...monitorApplication, applicationId: "other" }}
      catalog={catalog}
      targetTaskId="current-origin"
      onTaskContextChange={context}
    />,
  );
  await screen.findByRole("heading", { name: "current.inspect" });
  await act(async () =>
    finishOld(
      new Response(
        JSON.stringify({
          ...selectionTasks[0],
          taskId: "old-origin",
          function: "old.inspect",
        }),
      ),
    ),
  );
  expect(screen.queryByRole("heading", { name: "old.inspect" })).toBeNull();
  expect(context).toHaveBeenLastCalledWith("current-origin");
  expect(context).not.toHaveBeenCalledWith("old-origin");
  expect(calls.filter((body) => body.taskId === "current-origin")).toEqual([
    {
      workspaceId: "ws",
      applicationId: "other",
      taskId: "current-origin",
      afterEvent: 0,
      eventLimit: 100,
    },
  ]);
});

function taskListResponse() {
  return new Response(
    JSON.stringify({ tasks: selectionTasks, nextSequence: 1, hasMore: false }),
  );
}

function diagnosticResponse(taskId: string, text: string) {
  return new Response(
    JSON.stringify({
      taskId,
      lifecycle: { events: [], nextEvent: 0, hasMore: false },
      sourceLog: {
        kind: "Worker",
        text,
        totalCharacters: text.length,
        nextAfterCharacter: text.length,
        hasMore: false,
      },
    }),
  );
}

it("preserves the bounded application task-list contract", () => {
  expect(taskListBody({ workspaceId: "ws", applicationId: "app" }, 44)).toEqual(
    {
      workspaceId: "ws",
      applicationId: "app",
      afterSequence: 44,
      limit: 100,
      attentionOnly: false,
    },
  );
});

it("accepts descending visible task cursors and rejects repeated, reversed or unbound continuations", () => {
  const task = {
    taskId: "task-1",
    sequence: 8,
    sourceFamily: "Import",
    function: "facts.source.import",
    status: "Running",
    progressState: "inProgress" as const,
    interruptible: true,
    rerunSupported: false,
    latestEvent: null,
  };
  expect(
    mergeTaskListPage(
      [],
      { tasks: [task], nextSequence: 8, hasMore: true },
      0,
      false,
    ),
  ).toEqual({ tasks: [task], nextSequence: 8, hasMore: true });
  const older = { ...task, taskId: "older", sequence: 3 };
  expect(
    mergeTaskListPage(
      [task],
      { tasks: [older], nextSequence: 3, hasMore: true },
      8,
      true,
    ),
  ).toEqual({ tasks: [task, older], nextSequence: 3, hasMore: true });
  expect(
    mergeTaskListPage(
      [task],
      { tasks: [], nextSequence: 8, hasMore: false },
      8,
      true,
    ),
  ).toEqual({ tasks: [task], nextSequence: 8, hasMore: false });
  expect(() =>
    mergeTaskListPage(
      [task],
      { tasks: [task], nextSequence: 9, hasMore: true },
      8,
      true,
    ),
  ).toThrow("Task continuation repeated a task.");
  expect(() =>
    mergeTaskListPage(
      [task],
      {
        tasks: [{ ...older, sequence: 9 }],
        nextSequence: 9,
        hasMore: false,
      },
      8,
      true,
    ),
  ).toThrow("Task continuation is out of order.");
  expect(() =>
    mergeTaskListPage(
      [task],
      {
        tasks: [older],
        nextSequence: 2,
        hasMore: false,
      },
      8,
      true,
    ),
  ).toThrow("Task continuation cursor is invalid.");
  expect(() =>
    mergeTaskListPage(
      [],
      { tasks: [], nextSequence: 8, hasMore: true },
      8,
      true,
    ),
  ).toThrow("Task continuation cursor is invalid.");
  expect(() =>
    mergeTaskListPage(
      [],
      { tasks: [], nextSequence: 0, hasMore: false },
      8,
      true,
    ),
  ).toThrow("Task continuation cursor is invalid.");
});

it("merges diagnostic continuations only when exact cursors advance", () => {
  const first = {
    taskId: "task-1",
    lifecycle: {
      events: [{ event: 1, status: "Running" }],
      nextEvent: 1,
      hasMore: true,
    },
    sourceLog: {
      kind: "Worker",
      text: "first",
      totalCharacters: 11,
      nextAfterCharacter: 5,
      hasMore: true,
    },
  };
  const second = {
    taskId: "task-1",
    lifecycle: {
      events: [{ event: 2, status: "Succeeded" }],
      nextEvent: 2,
      hasMore: false,
    },
    sourceLog: {
      kind: "Worker",
      text: "second",
      totalCharacters: 11,
      nextAfterCharacter: 11,
      hasMore: false,
    },
  };
  expect(mergeTaskLogPage(first, second)).toMatchObject({
    taskId: "task-1",
    lifecycle: { nextEvent: 2, events: [{ event: 1 }, { event: 2 }] },
    sourceLog: { text: "firstsecond", nextAfterCharacter: 11 },
  });
  expect(() =>
    mergeTaskLogPage(first, { ...second, taskId: "task-2" }),
  ).toThrow("Task diagnostic identity changed between pages.");
  expect(() =>
    mergeTaskLogPage(first, {
      ...second,
      lifecycle: { ...second.lifecycle, nextEvent: 1 },
    }),
  ).toThrow("Task diagnostic event cursor did not advance.");
  expect(() =>
    mergeTaskLogPage(first, {
      ...second,
      sourceLog: { ...second.sourceLog, nextAfterCharacter: 5 },
    }),
  ).toThrow("Task diagnostic character cursor did not advance.");
  expect(() =>
    mergeTaskLogPage(
      {
        taskId: "task-1",
        lifecycle: { events: [], nextEvent: 0, hasMore: true },
        sourceLog: null,
      },
      {
        ...second,
        lifecycle: {
          events: [{ status: "Succeeded" }],
          nextEvent: 2,
          hasMore: false,
        },
      },
    ),
  ).toThrow("Task diagnostic lifecycle is invalid.");
});

it("derives a deterministic task-family progress matrix", () => {
  expect(
    taskProgressRows([
      {
        taskId: "1",
        sequence: 4,
        sourceFamily: "Planning",
        function: "plan",
        status: "Running",
        progressState: "inProgress",
        interruptible: true,
        rerunSupported: false,
        latestEvent: null,
      },
      {
        taskId: "2",
        sequence: 3,
        sourceFamily: "Planning",
        function: "plan",
        status: "Failed",
        progressState: "attention",
        interruptible: false,
        rerunSupported: true,
        latestEvent: null,
      },
      {
        taskId: "3",
        sequence: 2,
        sourceFamily: "Import",
        function: "load",
        status: "Succeeded",
        progressState: "succeeded",
        interruptible: false,
        rerunSupported: true,
        latestEvent: null,
      },
      {
        taskId: "4",
        sequence: 1,
        sourceFamily: "Import",
        function: "load",
        status: "Waiting",
        progressState: "inProgress",
        interruptible: false,
        rerunSupported: false,
        latestEvent: null,
      },
    ]),
  ).toEqual([
    {
      sourceFamily: "Planning",
      attention: 1,
      running: 1,
      succeeded: 0,
      other: 0,
      total: 2,
    },
    {
      sourceFamily: "Import",
      attention: 0,
      running: 1,
      succeeded: 1,
      other: 0,
      total: 2,
    },
  ]);
});

it("preserves exact job read and confirmed cancellation contracts", () => {
  const scope = { workspaceId: "ws", applicationId: "app" };
  expect(jobReadBody(scope, "a".repeat(32))).toEqual({
    ...scope,
    jobId: "a".repeat(32),
  });
  expect(jobCancelBody(scope, "a".repeat(32))).toEqual({
    ...scope,
    jobId: "a".repeat(32),
    confirmed: true,
  });
});

it("renders authoritative task state and its durable timeline", async () => {
  const bodies: unknown[] = [];
  const taskId = serverContracts.taskRead.taskId;
  const taskName = serverContracts.taskRead.function;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body));
      bodies.push(body);
      if (url === "/api/task-logs")
        return new Response(JSON.stringify(serverContracts.taskLogs));
      if ("limit" in body)
        return new Response(JSON.stringify(serverContracts.taskList));
      return new Response(JSON.stringify(serverContracts.taskRead));
    }),
  );
  const rendered = render(
    <Monitor
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "active",
      }}
      catalog={catalog}
    />,
  );
  await waitFor(() =>
    expect(screen.getByRole("button", { name: taskName })).toBeEnabled(),
  );
  expect(
    screen.getByRole("table", { name: "Durable application tasks" }),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("table", { name: "Task progress by work family" }),
  ).toBeInTheDocument();
  expect(
    (
      await axe.run(rendered.container, {
        rules: { "color-contrast": { enabled: false } },
      })
    ).violations,
  ).toEqual([]);
  expect(
    screen.getByRole("button", { name: "Job, succeeded, 1" }),
  ).toBeEnabled();
  fireEvent.click(screen.getByRole("button", { name: "Job, succeeded, 1" }));
  expect(
    screen.getByRole("button", { name: "Clear matrix filter" }),
  ).toBeEnabled();
  expect(screen.queryByText(taskId)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: taskName }));
  await waitFor(() =>
    expect(screen.getAllByText("Succeeded").length).toBeGreaterThan(0),
  );
  expect(screen.getAllByText("Succeeded").length).toBeGreaterThan(0);
  expect(bodies[1]).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    taskId,
    afterEvent: 0,
    eventLimit: 100,
  });
  fireEvent.click(screen.getByRole("button", { name: "Read logs" }));
  await waitFor(() =>
    expect(
      screen.getByText("No source diagnostic characters recorded."),
    ).toBeInTheDocument(),
  );
  expect(bodies[2]).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    taskId,
    afterEvent: 0,
    eventLimit: 100,
    afterCharacter: 0,
    characterLimit: 16384,
  });

  expect(
    screen.queryByRole("heading", { name: "Governed controls" }),
  ).not.toBeInTheDocument();
});

it.each(["legacy", "group_assignments"] as const)(
  "reads and cancels only an exactly selected authorized job in %s",
  async (model) => {
    const bodies: Array<{ url: string; body: Record<string, unknown> }> = [];
    const id = "a".repeat(32);
    vi.spyOn(window, "confirm").mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const body = JSON.parse(String(init?.body));
        bodies.push({ url, body });
        if (url === "/api/tasks")
          return new Response(
            JSON.stringify({ tasks: [], nextSequence: 0, hasMore: false }),
          );
        if (url === "/api/events")
          return new Response(
            JSON.stringify({
              events: [
                {
                  sequence: 1,
                  job_id: id,
                  status: "accepted",
                  occurred_at: "2026-11-13T11:59:00Z",
                },
                {
                  sequence: 2,
                  job_id: id,
                  status: "running",
                  occurred_at: "2026-11-13T12:00:00Z",
                },
              ],
              nextSequence: 2,
              hasMore: false,
            }),
          );
        if (url === "/api/job")
          return new Response(
            JSON.stringify({ job_id: id, status: "running" }),
          );
        if (url === "/api/cancel")
          return new Response(
            JSON.stringify({ job_id: id, status: "cancel_requested" }),
          );
        return new Response("{}", { status: 404 });
      }),
    );
    render(
      <Monitor
        app={{
          workspaceId: "ws",
          applicationId: "app",
          name: "Plan",
          status: "active",
        }}
        catalog={
          model === "legacy"
            ? catalog
            : {
                ...catalog,
                applicationAccess: {
                  role: "Assigned",
                  workspaceAdministrator: false,
                  authorizationModel: model,
                },
                ownedJobOperations: ["read", "events", "cancel"],
              }
        }
      />,
    );
    if (model === "legacy") {
      await screen.findByText("No visible durable tasks for this application.");
    } else {
      expect(
        screen.getByRole("heading", { name: "My numeric jobs" }),
      ).toBeVisible();
    }
    fireEvent.click(screen.getByRole("button", { name: "Show jobs" }));
    expect(screen.queryByLabelText("Typed V2 program")).not.toBeInTheDocument();
    const jobChoice = await screen.findByRole("button", { name: /running/i });
    expect(
      screen.queryByRole("button", { name: /accepted/i }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(id)).not.toBeInTheDocument();
    fireEvent.click(jobChoice);
    await waitFor(() =>
      expect(screen.getByText("running")).toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByLabelText("I reviewed cancellation of this current job."),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Request cancellation" }),
    );
    await waitFor(() =>
      expect(screen.getByText("cancel_requested")).toBeInTheDocument(),
    );
    expect(bodies).toContainEqual({
      url: "/api/cancel",
      body: jobCancelBody({ workspaceId: "ws", applicationId: "app" }, id),
    });
    if (model === "group_assignments") {
      expect(bodies.map(({ url }) => url)).toEqual([
        "/api/events",
        "/api/job",
        "/api/cancel",
      ]);
    }
  },
);

it.each([
  ["cancel_requested", 503, false],
  ["published", 200, false],
  ["running", 403, true],
  ["running", 429, false],
  ["running", 403, false],
] as const)(
  "requires a fresh exact read before showing %s after cancellation returned %i (retryable %s)",
  async (reading, status, retryable) => {
    const id = "a".repeat(32);
    const other = "b".repeat(32);
    const traffic: Array<{ url: unknown; body: unknown }> = [];
    let reads = 0;
    const fetch = vi.fn(async (url, init) => {
      traffic.push({ url, body: JSON.parse(String(init.body)) });
      if (url === "/api/tasks")
        return Response.json({ tasks: [], nextSequence: 0, hasMore: false });
      if (url === "/api/events")
        return Response.json({
          events: [{ sequence: 1, job_id: id, status: "running" }],
          nextSequence: 1,
          hasMore: false,
        });
      if (url === "/api/cancel")
        return status === 200
          ? Response.json({ jobId: other, status: "cancelled" })
          : Response.json({ code: "JOB_UNAVAILABLE", retryable }, { status });
      if (url === "/api/job") {
        reads += 1;
        if (reads === 1)
          return Response.json({ job_id: id, status: "running" });
        if (reads === 2)
          return Response.json({
            job_id: other,
            status: "published",
            receipt_revision: 9,
          });
        return Response.json({
          job_id: id,
          status: reading,
          ...(reading === "published" ? { receipt_revision: 9 } : {}),
        });
      }
      throw new Error("Unexpected route");
    });
    vi.stubGlobal("fetch", fetch);
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const refreshAccess = vi.fn(async () => catalog);
    render(
      <Monitor
        app={monitorApplication}
        catalog={catalog}
        onRefreshCatalog={refreshAccess}
      />,
    );
    const console = within(
      screen.getByRole("region", { name: "Background jobs" }),
    );
    fireEvent.click(console.getByRole("button", { name: "Show jobs" }));
    fireEvent.click(await console.findByRole("button", { name: /running/i }));
    const review = () =>
      console.getByRole("checkbox", {
        name: "I reviewed cancellation of this current job.",
      });
    const request = () =>
      console.getByRole("button", { name: "Request cancellation" });
    await waitFor(() => expect(review()).toBeEnabled());
    fireEvent.click(review());
    request().focus();
    fireEvent.click(request());
    const refused = status === 403 && !retryable;
    expect(
      await console.findByText(
        refused
          ? "Cancellation was refused. Check the current job before requesting cancellation again."
          : "Cancellation outcome unconfirmed. Check the current job before requesting cancellation again.",
      ),
    ).toBeVisible();
    const check = console.getByRole("button", { name: "Check current job" });
    expect(check).toHaveFocus();
    expect(review()).not.toBeChecked();
    expect(request()).toBeDisabled();
    fireEvent.click(request());
    expect(traffic.filter(({ url }) => url === "/api/cancel")).toHaveLength(1);
    fireEvent.click(check);
    expect(await console.findByRole("alert")).toHaveTextContent(
      "The response does not match the requested job.",
    );
    expect(
      console.queryByRole("button", { name: "View publication outcome" }),
    ).not.toBeInTheDocument();
    expect(request()).toBeDisabled();
    fireEvent.click(check);
    const state = await console.findByText("Last confirmed job state");
    expect(state.parentElement).toHaveTextContent(reading);
    expect(review()).not.toBeChecked();
    expect(request()).toBeDisabled();
    if (reading === "running") {
      fireEvent.click(review());
      expect(request()).toBeEnabled();
    } else if (reading === "published") {
      expect(
        console.getByRole("button", { name: "View publication outcome" }),
      ).toBeEnabled();
    } else {
      expect(
        console.getByText(
          "Cancellation requested. Check the job again to confirm its final state.",
        ),
      ).toBeVisible();
      expect(review()).toBeDisabled();
    }
    expect(
      traffic.filter(({ url }) => url === "/api/job").map(({ body }) => body),
    ).toEqual(
      Array(3).fill(
        jobReadBody({ workspaceId: "ws", applicationId: "app" }, id),
      ),
    );
    expect(confirm).toHaveBeenCalledOnce();
    expect(refreshAccess).toHaveBeenCalledTimes(status === 403 ? 1 : 0);
    confirm.mockRestore();
  },
);

it("uses only the current job's durable worker retry schedule and attempt limit", async () => {
  const id = "c".repeat(32);
  const retryAt = "2026-11-23T04:00:05.20+00:00";
  let reads = 0;
  const fetch = vi.fn(async (url) => {
    if (url === "/api/tasks")
      return Response.json({ tasks: [], nextSequence: 0, hasMore: false });
    if (url === "/api/events")
      return Response.json({
        events: [{ sequence: 1, job_id: id, status: "running" }],
        nextSequence: 1,
        hasMore: false,
      });
    if (url === "/api/job")
      return Response.json(
        ++reads === 1
          ? { job_id: id, status: "ready", next_attempt_at: retryAt }
          : {
              job_id: id,
              status: "failed",
              error_code: "RETRY_LIMIT",
              receipt_revision: 9,
            },
      );
    throw new Error("Unexpected route");
  });
  vi.stubGlobal("fetch", fetch);
  render(<Monitor app={monitorApplication} catalog={catalog} />);
  const jobs = within(screen.getByRole("region", { name: "Background jobs" }));
  fireEvent.click(jobs.getByRole("button", { name: "Show jobs" }));
  fireEvent.click(await jobs.findByRole("button", { name: /running/i }));
  expect(
    (
      await jobs.findByText(/same job is eligible for another worker attempt/)
    ).querySelector("time"),
  ).toHaveAttribute("datetime", retryAt);
  fireEvent.click(jobs.getByRole("button", { name: "Check current job" }));
  expect(await jobs.findByText(/reached its worker retry limit/)).toBeVisible();
  expect(
    jobs.queryByText(/eligible for another worker attempt/),
  ).not.toBeInTheDocument();
  expect(
    jobs.queryByRole("button", { name: "View publication outcome" }),
  ).not.toBeInTheDocument();
  expect(
    jobs.getByRole("button", { name: "Request cancellation" }),
  ).toBeDisabled();
  expect(fetch.mock.calls.filter(([url]) => url === "/api/job")).toHaveLength(
    2,
  );
});

it("keeps diagnostics with their selected task when an older read finishes late", async () => {
  let finishOldLog: (value: Response) => void = () => {};
  const oldLog = new Promise<Response>((resolve) => {
    finishOldLog = resolve;
  });
  let oldSignal: AbortSignal | null | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/api/tasks") return taskListResponse();
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/task-logs") {
        if (body.taskId === "task-one") {
          oldSignal = init?.signal;
          return oldLog;
        }
        return diagnosticResponse("task-two", "Current task diagnostics");
      }
      return new Response(
        JSON.stringify(
          selectionTasks.find((task) => task.taskId === body.taskId),
        ),
      );
    }),
  );
  render(<Monitor app={monitorApplication} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "task-one.calculate" }),
  );
  fireEvent.click(await screen.findByRole("button", { name: "Read logs" }));
  fireEvent.click(screen.getByRole("button", { name: "task-two.calculate" }));
  await screen.findByRole("heading", { name: "task-two.calculate" });
  expect(oldSignal?.aborted).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: "Read logs" }));
  await screen.findByText("Current task diagnostics");
  await act(async () =>
    finishOldLog(diagnosticResponse("task-one", "Obsolete diagnostics")),
  );
  expect(screen.getByText("Current task diagnostics")).toBeInTheDocument();
  expect(screen.queryByText("Obsolete diagnostics")).not.toBeInTheDocument();
});

it("delegates explicit-origin Close without a second guard or clearing selected context", async () => {
  const context = vi.fn();
  const close = vi.fn();
  const transition = vi.fn((action: () => void) => action());
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url) =>
      url === "/api/tasks"
        ? taskListResponse()
        : new Response(
            JSON.stringify({
              ...selectionTasks[0],
              taskId: "exact-origin",
              function: "origin.inspect",
            }),
          ),
    ),
  );
  render(
    <Monitor
      app={monitorApplication}
      catalog={catalog}
      targetTaskId="exact-origin"
      onTaskContextChange={context}
      onRequestTransition={transition}
      onCloseTask={close}
    />,
  );
  await screen.findByRole("heading", { name: "origin.inspect" });
  fireEvent.click(screen.getByRole("button", { name: "Close task detail" }));
  expect(close).toHaveBeenCalledOnce();
  expect(transition).not.toHaveBeenCalled();
  expect(context).toHaveBeenLastCalledWith("exact-origin");
  expect(
    screen.getByRole("complementary", { name: "Selected task detail" }),
  ).toBeVisible();
});

it.each(["PythonWorkflow", "ApplicationRuleWorkflow"])(
  "explains the existing safe cancellation retry for a parked %s task",
  async (sourceFamily) => {
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) => {
        calls.push(String(url));
        return url === "/api/tasks"
          ? taskListResponse()
          : new Response(
              JSON.stringify({
                ...selectionTasks[0],
                sourceFamily,
                status: "InterruptRequested",
                progressState: "attention",
                recoveryState: "workflowCancellationPaused",
                events: Array.from({ length: 100 }, (_, index) => ({
                  event: index + 1,
                  status: "Running",
                  errorCode: null,
                })),
                nextEvent: 100,
                hasMoreEvents: true,
                latestEvent: {
                  event: 140,
                  status: "InterruptRequested",
                  errorCode: null,
                },
              }),
            );
      }),
    );
    render(
      <Monitor
        app={monitorApplication}
        catalog={catalog}
        targetTaskId="task-one"
      />,
    );
    expect(
      await screen.findByText(/Cancellation recovery is paused/),
    ).toHaveTextContent(
      "request interruption again for this same task with an authorized client",
    );
    expect(
      screen.getByText(/Cancellation recovery is paused/),
    ).toHaveTextContent(
      "remaining units include unstarted, cancelled or unresolved work",
    );
    expect(
      screen.getByText(/Cancellation recovery is paused/),
    ).toHaveTextContent(
      "Repeating interruption continues cancellation reconciliation only; it does not restart the workflow",
    );
    expect(calls).toEqual(["/api/tasks", "/api/task"]);
    expect(
      screen.queryByRole("button", { name: /restart|retry|interrupt/i }),
    ).not.toBeInTheDocument();
  },
);

it.each([
  [
    "PythonWorkflow",
    "InterruptRequested",
    "WORKFLOW_CANCELLATION_RECOVERY_PARKED",
  ],
  [
    "PythonWorkflow",
    "InterruptRequested",
    "PYTHON_WORKFLOW_AUTHORIZATION_REVOKED",
  ],
  ["Job", "InterruptRequested", "WORKFLOW_CANCELLATION_RECOVERY_PARKED"],
  [
    "ApplicationRuleWorkflow",
    "Running",
    "WORKFLOW_CANCELLATION_RECOVERY_PARKED",
  ],
])(
  "does not invent parked cancellation guidance for %s / %s / %s",
  async (sourceFamily, status, errorCode) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) =>
        url === "/api/tasks"
          ? taskListResponse()
          : new Response(
              JSON.stringify({
                ...selectionTasks[0],
                sourceFamily,
                status,
                recoveryState: null,
                events: [{ status, errorCode }],
                latestEvent: { event: 140, status, errorCode },
              }),
            ),
      ),
    );
    render(
      <Monitor
        app={monitorApplication}
        catalog={catalog}
        targetTaskId="task-one"
      />,
    );
    expect(
      await screen.findByRole("heading", { name: "task-one.calculate" }),
    ).toBeVisible();
    expect(
      screen.queryByText(/Cancellation recovery is paused/),
    ).not.toBeInTheDocument();
  },
);

it.each([null, { event: 141, status: "InterruptRequested", errorCode: null }])(
  "does not reuse old parked events when latest observation is %j",
  async (latestEvent) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) =>
        url === "/api/tasks"
          ? taskListResponse()
          : new Response(
              JSON.stringify({
                ...selectionTasks[0],
                sourceFamily: "PythonWorkflow",
                status: "InterruptRequested",
                events: [
                  {
                    event: 100,
                    status: "InterruptRequested",
                    errorCode: "WORKFLOW_CANCELLATION_RECOVERY_PARKED",
                  },
                ],
                nextEvent: 100,
                hasMoreEvents: true,
                latestEvent,
              }),
            ),
      ),
    );
    render(
      <Monitor
        app={monitorApplication}
        catalog={catalog}
        targetTaskId="task-one"
      />,
    );
    expect(
      await screen.findByRole("heading", { name: "task-one.calculate" }),
    ).toBeVisible();
    expect(
      screen.queryByText(/Cancellation recovery is paused/),
    ).not.toBeInTheDocument();
  },
);

it("uses the server's progress state for parked and rearmed workflow counts", () => {
  const base = {
    ...selectionTasks[0],
    sourceFamily: "PythonWorkflow",
    status: "InterruptRequested",
  };
  expect(
    taskProgressRows([
      {
        ...base,
        progressState: "attention",
        latestEvent: {
          event: 140,
          status: "InterruptRequested",
          errorCode: "WORKFLOW_CANCELLATION_RECOVERY_PARKED",
        },
      },
      {
        ...base,
        latestEvent: {
          event: 141,
          status: "InterruptRequested",
          errorCode: null,
        },
      },
      { ...base, latestEvent: null },
    ]),
  ).toEqual([
    {
      sourceFamily: "PythonWorkflow",
      attention: 1,
      running: 2,
      succeeded: 0,
      other: 0,
      total: 3,
    },
  ]);
});

it("uses the same server progress state for the headline, matrix and task detail", async () => {
  const task = {
    ...selectionTasks[0],
    status: "Published",
    progressState: "succeeded",
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url) =>
      url === "/api/tasks"
        ? Response.json({ tasks: [task], nextSequence: 2, hasMore: false })
        : Response.json(task),
    ),
  );
  render(<Monitor app={monitorApplication} catalog={catalog} />);
  await screen.findByRole("button", { name: "Job, succeeded, 1" });
  const counts = screen.getByRole("group", { name: "Loaded task counts" });
  expect(within(counts).getByText("Succeeded").parentElement).toHaveTextContent(
    "Succeeded1",
  );
  fireEvent.click(screen.getByRole("button", { name: task.function }));
  expect(await screen.findByText(/Completed successfully/)).toBeVisible();
});

it.each([
  "PYTHON_SCHEDULE_CANCELLATION_RECOVERY_PARKED",
  "PYTHON_SCHEDULE_ADMISSION_UNRESOLVED",
  "PYTHON_SCHEDULE_CONTROL_AUTHORITY_REQUIRED",
])(
  "explains unresolved scheduled cancellation when the core reports it with %s",
  async (errorCode) => {
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) => {
        calls.push(String(url));
        return url === "/api/tasks"
          ? taskListResponse()
          : new Response(
              JSON.stringify({
                ...selectionTasks[0],
                sourceFamily: "PythonScheduleOccurrence",
                status: "InterruptRequested",
                progressState: "attention",
                recoveryState: "scheduleCancellationUnresolved",
                events: [{ event: 1, status: "Running", errorCode: null }],
                hasMoreEvents: true,
                latestEvent: {
                  event: 150,
                  status: "InterruptRequested",
                  errorCode,
                },
              }),
            );
      }),
    );
    render(
      <Monitor
        app={monitorApplication}
        catalog={catalog}
        targetTaskId="task-one"
      />,
    );
    const guidance = await screen.findByText(
      /Scheduled cancellation remains unresolved/,
    );
    expect(guidance).toHaveTextContent("current application administrator");
    expect(guidance).toHaveTextContent(
      "unknown work stays unresolved and is never attached by guessing",
    );
    expect(guidance).toHaveTextContent(
      "Repeating cancellation cannot build, rerun or admit new work",
    );
    expect(guidance).toHaveTextContent(
      "Restoring access alone does not resume parked recovery",
    );
    expect(calls).toEqual(["/api/tasks", "/api/task"]);
  },
);

it.each([
  ["PythonScheduleOccurrence", "InterruptRequested", null],
  [
    "PythonScheduleOccurrence",
    "InterruptRequested",
    "PYTHON_SCHEDULE_ADMISSION_UNRESOLVED",
  ],
  [
    "PythonScheduleOccurrence",
    "Running",
    "PYTHON_SCHEDULE_ADMISSION_UNRESOLVED",
  ],
  ["Job", "InterruptRequested", "PYTHON_SCHEDULE_ADMISSION_UNRESOLVED"],
])(
  "does not infer scheduled parking from diagnostics for %s/%s/%s",
  async (sourceFamily, status, errorCode) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) =>
        url === "/api/tasks"
          ? taskListResponse()
          : new Response(
              JSON.stringify({
                ...selectionTasks[0],
                sourceFamily,
                status,
                recoveryState: null,
                events: [
                  {
                    event: 149,
                    status: "InterruptRequested",
                    errorCode: "PYTHON_SCHEDULE_ADMISSION_UNRESOLVED",
                  },
                ],
                latestEvent: { event: 150, status, errorCode },
              }),
            ),
      ),
    );
    render(
      <Monitor
        app={monitorApplication}
        catalog={catalog}
        targetTaskId="task-one"
      />,
    );
    await screen.findByRole("complementary", { name: "Selected task detail" });
    expect(
      screen.queryByText(/Scheduled cancellation remains unresolved/),
    ).not.toBeInTheDocument();
  },
);
