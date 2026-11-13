import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import {
  Monitor,
  jobCancelBody,
  jobReadBody,
  mergeTaskListPage,
  mergeTaskLogPage,
  taskProgressRows,
  taskListBody,
} from "./Monitor";
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

const selectionTasks = ["task-one", "task-two"].map((taskId) => ({
  taskId,
  sourceFamily: "Job",
  function: `${taskId}.calculate`,
  status: "Running",
  interruptible: true,
  rerunSupported: true,
  events: [],
}));

function taskListResponse() {
  return new Response(
    JSON.stringify({ tasks: selectionTasks, nextSequence: 2, hasMore: false }),
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

it("fails closed on repeated task pages and non-advancing cursors", () => {
  const task = {
    taskId: "task-1",
    sourceFamily: "Import",
    function: "facts.source.import",
    status: "Running",
    interruptible: true,
    rerunSupported: false,
  };
  expect(
    mergeTaskListPage(
      [],
      { tasks: [task], nextSequence: 8, hasMore: true },
      0,
      false,
    ),
  ).toEqual({ tasks: [task], nextSequence: 8, hasMore: true });
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
      [],
      { tasks: [], nextSequence: 8, hasMore: true },
      8,
      true,
    ),
  ).toThrow("Task continuation cursor is invalid.");
  expect(() =>
    mergeTaskListPage(
      [],
      { tasks: [], nextSequence: null, hasMore: false },
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
        sourceFamily: "Planning",
        function: "plan",
        status: "Running",
        interruptible: true,
        rerunSupported: false,
      },
      {
        taskId: "2",
        sourceFamily: "Planning",
        function: "plan",
        status: "Failed",
        interruptible: false,
        rerunSupported: true,
      },
      {
        taskId: "3",
        sourceFamily: "Import",
        function: "load",
        status: "Succeeded",
        interruptible: false,
        rerunSupported: true,
      },
      {
        taskId: "4",
        sourceFamily: "Import",
        function: "load",
        status: "Waiting",
        interruptible: false,
        rerunSupported: false,
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
      running: 0,
      succeeded: 1,
      other: 1,
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

it("reads and cancels only an exactly selected authorized job", async () => {
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
        return new Response(JSON.stringify({ job_id: id, status: "running" }));
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
      catalog={catalog}
    />,
  );
  await waitFor(() =>
    expect(
      screen.getByText("No visible durable tasks for this application."),
    ).toBeInTheDocument(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Show jobs" }));
  expect(screen.queryByLabelText("Typed V2 program")).not.toBeInTheDocument();
  const jobChoice = await screen.findByRole("button", { name: /running/i });
  expect(
    screen.queryByRole("button", { name: /accepted/i }),
  ).not.toBeInTheDocument();
  expect(screen.queryByText(id)).not.toBeInTheDocument();
  fireEvent.click(jobChoice);
  await waitFor(() => expect(screen.getByText("running")).toBeInTheDocument());
  fireEvent.click(
    screen.getByLabelText("I reviewed cancellation of this current job."),
  );
  fireEvent.click(screen.getByRole("button", { name: "Request cancellation" }));
  await waitFor(() =>
    expect(screen.getByText("cancel_requested")).toBeInTheDocument(),
  );
  expect(bodies).toContainEqual({
    url: "/api/cancel",
    body: jobCancelBody({ workspaceId: "ws", applicationId: "app" }, id),
  });
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
