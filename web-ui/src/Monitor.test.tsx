import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import {
  Monitor,
  jobCancelBody,
  jobReadBody,
  jobSubmitBody,
  mergeTaskListPage,
  mergeTaskLogPage,
  taskProgressRows,
  taskInterruptBody,
  taskListBody,
  taskRerunBody,
} from "./Monitor";
import serverContracts from "./server-contract-fixtures.json";

afterEach(() => vi.unstubAllGlobals());

const catalog = {
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: { "facts.expression.calculate": {} },
  revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
};

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

it("preserves confirmed interruption and distinct rerun contracts", () => {
  const scope = { workspaceId: "ws", applicationId: "app" };
  expect(taskInterruptBody(scope, "task-1")).toEqual({
    ...scope,
    taskId: "task-1",
    confirmed: true,
  });
  expect(taskRerunBody(scope, "task-1", "rerun-1")).toEqual({
    ...scope,
    taskId: "task-1",
    idempotencyKey: "rerun-1",
    confirmed: true,
  });
});

it("preserves typed submission, read and confirmed cancellation contracts", () => {
  const scope = { workspaceId: "ws", applicationId: "app" };
  const program = {
    languageVersion: 2,
    function: "facts.expression.calculate",
    arguments: {},
  };
  expect(jobSubmitBody(scope, program, "job-key-1")).toEqual({
    ...scope,
    program,
    idempotencyKey: "job-key-1",
    dependsOnJobIds: [],
    confirmed: true,
  });
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
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body));
      bodies.push(body);
      if (url === "/api/task-logs")
        return new Response(JSON.stringify(serverContracts.taskLogs));
      if (url === "/api/task-rerun")
        return new Response(
          JSON.stringify({
            taskId: "task-2",
            sourceTaskId: taskId,
            status: "Accepted",
          }),
        );
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
    expect(screen.getByRole("button", { name: taskId })).toBeEnabled(),
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
  fireEvent.click(screen.getByRole("button", { name: taskId }));
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

  vi.spyOn(window, "confirm").mockReturnValue(true);
  fireEvent.change(screen.getByLabelText("Distinct rerun key"), {
    target: { value: "uat-rerun-1" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this exact distinct rerun"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Create distinct rerun" }),
  );
  await waitFor(() =>
    expect(bodies).toContainEqual({
      workspaceId: "ws",
      applicationId: "app",
      taskId,
      idempotencyKey: "uat-rerun-1",
      confirmed: true,
    }),
  );
});

it("submits and cancels only an exactly reviewed authorized job", async () => {
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
      if (url === "/api/preview")
        return new Response(
          JSON.stringify({
            previewToken: "sealed-preview-token",
            programDigest: "1".repeat(64),
            revisionVector: { data: 7 },
          }),
        );
      if (url === "/api/submit")
        return new Response(JSON.stringify({ jobId: id, status: "accepted" }));
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
  fireEvent.click(screen.getByRole("button", { name: "Open job controls" }));
  fireEvent.change(screen.getByLabelText("Idempotency key"), {
    target: { value: "job-key-1" },
  });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact typed job and idempotency key",
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Preview and submit" }));
  await waitFor(() => expect(screen.getByText("accepted")).toBeInTheDocument());
  expect(bodies).toContainEqual({
    url: "/api/submit",
    body: {
      ...jobSubmitBody(
        { workspaceId: "ws", applicationId: "app" },
        {
          languageVersion: 2,
          function: "facts.expression.calculate",
          arguments: {},
        },
        "job-key-1",
      ),
      previewToken: "sealed-preview-token",
    },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Read authoritative status" }),
  );
  await waitFor(() => expect(screen.getByText("running")).toBeInTheDocument());
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed cancellation of this exact current job state",
    ),
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
