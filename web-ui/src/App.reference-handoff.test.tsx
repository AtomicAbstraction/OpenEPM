import { browserIdentityFixture } from "./test-setup";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { App, readPresentationRoute } from "./App";
import {
  parseReferenceHandoff,
  referenceHandoffHash,
} from "./reference-handoff";
import type {
  AnalyticalRead,
  ReferenceHandoff,
  SavedViewContext,
} from "./reference-handoff";
import type { ApplicationSummary } from "./types";
import {
  resetUnsavedWorkForTests,
  setUnsavedWork,
  unsavedWorkSnapshot,
} from "./unsaved-work";
import { resetBrowserLifecycleForTests } from "./browser-lifecycle";

const fixture = vi.hoisted(() => ({
  contexts: new Map<string, (context: SavedViewContext | null) => void>(),
}));
vi.mock("./Analyze", () => ({
  Analyze: ({
    app,
    targetViewId,
    targetViewDigest,
    targetAnalyticalRead,
    onViewContextChange,
  }: {
    app?: ApplicationSummary;
    targetViewId?: string;
    targetViewDigest?: string;
    targetAnalyticalRead?: AnalyticalRead;
    onViewContextChange?: (context: SavedViewContext | null) => void;
  }) => {
    if (app && onViewContextChange)
      fixture.contexts.set(app.applicationId, onViewContextChange);
    return (
      <section aria-label="Grid fixture">
        <p>Grid application: {app?.applicationId}</p>
        <p>Requested view: {targetViewId || "none"}</p>
        <p>Requested policy: {targetAnalyticalRead?.semantics || "none"}</p>
        <button
          onClick={() =>
            onViewContextChange?.({
              viewId: targetViewId || "capacity_by_team",
              viewDigest: targetViewDigest || "d".repeat(64),
              analyticalRead: targetAnalyticalRead || { semantics: "own" },
            })
          }
        >
          Resolve saved view
        </button>
        <button onClick={() => onViewContextChange?.(null)}>
          Edit local draft
        </button>
      </section>
    );
  },
}));

afterEach(() => {
  resetUnsavedWorkForTests();
  resetBrowserLifecycleForTests();
  fixture.contexts.clear();
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

const handoff: ReferenceHandoff = {
  format: "openepm.reference-handoff/v1",
  scope: { workspaceId: "ws", applicationId: "alpha" },
  origin: { kind: "task", taskId: "origin-task" },
  target: { kind: "savedView", viewId: "capacity_by_team" },
  returnTo: { kind: "task", taskId: "origin-task" },
  observed: { viewDigest: "d".repeat(64) },
  pendingOperation: null,
  analyticalRead: { semantics: "own" },
};

function setup(
  taskStatus = 200,
  extraFunctions: Record<string, unknown> = {},
  options: {
    originStatus?: number;
    originTaskId?: string;
    listedTaskId?: string;
  } = {},
) {
  const calls: { url: string; body: Record<string, unknown> | null }[] = [];
  const clipboard = vi.fn(async (_text: string) => undefined);
  vi.stubGlobal("navigator", {
    ...window.navigator,
    clipboard: { writeText: clipboard },
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const url = String(input);
      const body = init?.body ? JSON.parse(String(init.body)) : null;
      calls.push({ url, body });
      const response = (value: unknown, status = 200) =>
        new Response(JSON.stringify(value), { status });
      if (url.startsWith("/api/applications"))
        return response({
          applications: ["alpha", "beta"].map((applicationId) => ({
            workspaceId: "ws",
            applicationId,
            name: `${applicationId} model`,
            status: "Active",
          })),
          nextAfter: null,
        });
      if (url === "/api/session-identity")
        return response({
          ...browserIdentityFixture("receiver"),
          displayIdentity: "receiver@example.com",
        });
      if (url === "/api/runtime")
        return response({
          build: { sourceCommit: "a".repeat(40), packagedSchema: 281 },
        });
      if (url === "/api/catalog")
        return response({
          applicationAccess: {
            role: "Administrator",
            workspaceAdministrator: false,
          },
          enabledCapabilities: [],
          functions: {
            ...extraFunctions,
            "grid.definition.read": {},
            "facts.cube.resolved.read": {},
          },
          revisions: {
            metadata: 1,
            data: 1,
            policy: 1,
            security: 1,
            commit: 1,
          },
        });
      if (
        url === "/api/read" &&
        body.program.function === "application.rule.list"
      )
        return response({
          result: {
            rows: [],
            hasMore: false,
            nextAfterRuleId: null,
            metadataRevision: 1,
            policyRevision: 1,
          },
        });
      if (
        url === "/api/python-program" &&
        body.program.function === "python.program.list"
      )
        return response({ result: { programs: [], nextAfterProgramId: null } });
      if (url === "/api/platform/browser/catalog") return response({}, 403);
      if (url === "/api/tasks")
        return response({
          tasks: options.listedTaskId
            ? [
                {
                  taskId: options.listedTaskId,
                  sequence: 1,
                  function: "list.task",
                  sourceFamily: "Job",
                  status: "Succeeded",
                  progressState: "succeeded",
                  interruptible: false,
                  rerunSupported: false,
                  events: [],
                },
              ]
            : [],
          nextSequence: options.listedTaskId ? 1 : 0,
          hasMore: false,
        });
      if (url === "/api/task") {
        const status =
          body.taskId === options.originTaskId
            ? (options.originStatus ?? 200)
            : taskStatus;
        return status === 200
          ? response({
              taskId: body.taskId,
              sequence: 1,
              function: "referenced.task",
              sourceFamily: "Job",
              status: "Succeeded",
              progressState: "succeeded",
              interruptible: false,
              rerunSupported: false,
              events: [],
            })
          : response({ error: "TASK_UNAVAILABLE" }, status);
      }
      if (url === "/api/read") {
        const fn = body.program.function;
        if (fn === "application.workflow.worklist")
          return response({ result: { items: [], nextCursor: null } });
        if (fn === "application.workflow.occurrence.read")
          return options.originStatus && options.originStatus !== 200
            ? response({ error: "WORKFLOW_UNAVAILABLE" }, options.originStatus)
            : response({
                result: {
                  occurrenceId: body.program.arguments.occurrenceId,
                  flowId: "origin-flow",
                  flowStateToken: "a".repeat(64),
                  definitionDigest: "b".repeat(64),
                  status: "Completed",
                  occurrenceStateToken: "c".repeat(64),
                  lastEventOrdinal: 1,
                  currentReturns: [],
                  activities: [
                    {
                      activityId: "review",
                      kind: "Review",
                      status: "Completed",
                      activityStateToken: "d".repeat(64),
                    },
                  ],
                  events: [],
                },
              });
        if (fn === "application.workflow.read")
          return response({
            result: {
              flowId: "origin-flow",
              stateToken: "a".repeat(64),
              definitionDigest: "b".repeat(64),
              definition: {
                name: "Original planning review",
                activities: [
                  {
                    activityId: "review",
                    name: "Original review activity",
                    kind: "Review",
                    dependsOn: [],
                    returnTo: null,
                    evidenceContract: {
                      kind: "ManualAttestation",
                      statement: "Reviewed original plan",
                    },
                  },
                ],
              },
            },
          });
      }
      throw new Error(`Unexpected request ${url}`);
    }),
  );
  return { calls, clipboard };
}

async function changeHash(hash: string) {
  await act(async () => {
    window.history.pushState(null, "", hash);
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  });
}

function copiedReference(clipboard: ReturnType<typeof vi.fn>, index = -1) {
  const text = clipboard.mock.calls.at(index)?.[0];
  return parseReferenceHandoff(
    text.startsWith("{")
      ? text
      : new URLSearchParams(new URL(text).hash.split("?")[1]).get("handoff"),
  );
}

it("copies an internally opened saved view with its separate actual read policy", async () => {
  const { clipboard } = setup();
  window.history.replaceState(
    null,
    "",
    "#/grid/0?workspace=ws&application=alpha",
  );
  render(<App />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Resolve saved view" }),
  );
  await screen.findByRole("button", { name: "Copy client references" });
  fireEvent.click(
    screen.getByRole("button", { name: "Copy link to this view" }),
  );
  await waitFor(() => expect(clipboard).toHaveBeenCalledTimes(1));
  const value = copiedReference(clipboard);
  expect(value.scope).toEqual({ workspaceId: "ws", applicationId: "alpha" });
  expect(value.target).toEqual({
    kind: "savedView",
    viewId: "capacity_by_team",
  });
  expect(value.analyticalRead).toEqual({ semantics: "own" });
  expect(value.observed.viewDigest).toBe("d".repeat(64));
  fireEvent.click(
    screen.getByRole("button", { name: "Copy client references" }),
  );
  await waitFor(() => expect(clipboard).toHaveBeenCalledTimes(2));
  expect(copiedReference(clipboard)).toEqual(value);
});

it("does not silently export a draft or retain the previous saved-view target after editing", async () => {
  const { clipboard } = setup();
  window.history.replaceState(null, "", referenceHandoffHash(handoff));
  render(<App />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Resolve saved view" }),
  );
  await screen.findByRole("button", { name: "Copy client references" });
  fireEvent.click(screen.getByRole("button", { name: "Edit local draft" }));
  expect(
    screen.queryByRole("button", { name: "Copy client references" }),
  ).toBeNull();
  fireEvent.click(
    screen.getByRole("button", { name: "Copy link to this view" }),
  );
  await waitFor(() => expect(clipboard).toHaveBeenCalledOnce());
  expect(clipboard.mock.calls[0][0]).toMatch(
    /#\/grid\/0\?workspace=ws&application=alpha$/,
  );
  expect(
    await screen.findByText(
      "Page link copied. Unsaved or unresolved grid context is not included.",
    ),
  ).toBeVisible();
});

it("passes the exact received read policy and digest without substituting another application's view", async () => {
  setup();
  window.history.replaceState(
    null,
    "",
    referenceHandoffHash({
      ...handoff,
      scope: { workspaceId: "ws", applicationId: "beta" },
      analyticalRead: { semantics: "stored" },
    }),
  );
  render(<App />);
  expect(await screen.findByText("Grid application: beta")).toBeVisible();
  expect(screen.getByText("Requested view: capacity_by_team")).toBeVisible();
  expect(screen.getByText("Requested policy: stored")).toBeVisible();
  expect(readPresentationRoute().focus.viewDigest).toBe("d".repeat(64));
});

it("discards a late prior-application context callback and clears origin on an explicit switch", async () => {
  const { clipboard } = setup();
  window.history.replaceState(null, "", referenceHandoffHash(handoff));
  render(<App />);
  await screen.findByText("Grid application: alpha");
  const oldContext = fixture.contexts.get("alpha")!;
  await changeHash("#/grid/1?workspace=ws&application=beta");
  await screen.findByText("Grid application: beta");
  await act(async () =>
    oldContext({
      viewId: "old-private-view",
      viewDigest: "a".repeat(64),
      analyticalRead: { semantics: "own" },
    }),
  );
  expect(
    screen.queryByRole("button", { name: "Copy client references" }),
  ).toBeNull();
  expect(screen.queryByRole("button", { name: "Return to task" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Resolve saved view" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Copy client references" }),
  );
  await waitFor(() => expect(clipboard).toHaveBeenCalledOnce());
  const value = copiedReference(clipboard);
  expect(value.scope.applicationId).toBe("beta");
  expect(value.origin).toBeNull();
  expect(value.target).toEqual({
    kind: "savedView",
    viewId: "capacity_by_team",
  });
});

it("refuses an inaccessible application without reading the object in a visible application", async () => {
  const { calls } = setup();
  window.history.replaceState(
    null,
    "",
    referenceHandoffHash({
      ...handoff,
      scope: { workspaceId: "ws", applicationId: "retired" },
    }),
  );
  render(<App />);
  expect(
    await screen.findByRole("heading", { name: "Application unavailable" }),
  ).toBeVisible();
  expect(screen.queryByRole("region", { name: "Grid fixture" })).toBeNull();
  expect(calls.some(({ url }) => url === "/api/task")).toBe(false);
  expect(calls.filter(({ url }) => url === "/api/catalog")).toHaveLength(0);
});

it.each([
  "returnTask=origin-task",
  "returnOccurrence=origin&returnActivity=review",
])(
  "keeps legacy return links in an unavailable application from falling back to a visible application: %s",
  async (returnQuery) => {
    const { calls } = setup();
    window.history.replaceState(
      null,
      "",
      `#/grid/0?workspace=ws&application=retired&${returnQuery}`,
    );
    render(<App />);
    await screen.findByRole("heading", { name: "Application unavailable" });
    const button = screen.getByRole("button", { name: /^Return to / });
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(window.location.hash).toContain("application=retired");
    expect(
      calls.some(({ url }) => ["/api/task", "/api/read"].includes(url)),
    ).toBe(false);
  },
);

it("does not crash or silently discard an oversized legacy origin when copying a resolved view", async () => {
  setup();
  window.history.replaceState(
    null,
    "",
    `#/grid/0?workspace=ws&application=alpha&returnTask=${"a".repeat(501)}`,
  );
  render(<App />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Resolve saved view" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "unsupported reference",
  );
  expect(
    screen.queryByRole("button", { name: "Copy client references" }),
  ).toBeNull();
  expect(screen.getByRole("region", { name: "Grid fixture" })).toBeVisible();
});

it.each([
  `#/reference?${new URLSearchParams({ handoff: JSON.stringify({ ...handoff, credentials: "forbidden" }) })}`,
  `${referenceHandoffHash(handoff)}&application=beta`,
  "#/reference?handoff=not-json",
])(
  "refuses malformed handoff input without opening a default object: %s",
  async (hash) => {
    setup();
    window.history.replaceState(null, "", hash);
    render(<App />);
    expect(
      await screen.findByRole("heading", { name: "Reference unavailable" }),
    ).toBeVisible();
    expect(screen.queryByRole("region", { name: "Grid fixture" })).toBeNull();
    expect(window.location.hash).toBe("#/reference?invalid=1");
  },
);

it.each([403, 404])(
  "returns to an exact unavailable origin without accepting or replaying it (%i)",
  async (status) => {
    const { calls } = setup(status);
    window.history.replaceState(null, "", referenceHandoffHash(handoff));
    render(<App />);
    await screen.findByText("Grid application: alpha");
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Return to task" }),
      ).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Return to task" }));
    await waitFor(() =>
      expect(calls.some(({ url }) => url === "/api/task")).toBe(true),
    );
    await screen.findByRole("alert");
    expect(calls.filter(({ url }) => url === "/api/task")).toEqual([
      {
        url: "/api/task",
        body: {
          workspaceId: "ws",
          applicationId: "alpha",
          taskId: "origin-task",
          afterEvent: 0,
          eventLimit: 100,
        },
      },
    ]);
    expect(
      screen.queryByRole("complementary", { name: "Selected task detail" }),
    ).toBeNull();
    expect(
      screen.queryByRole("button", { name: "Copy client references" }),
    ).toBeNull();
    expect(
      calls.some(({ url }) =>
        ["/api/program", "/api/cancel", "/api/authorize"].includes(url),
      ),
    ).toBe(false);
  },
);

it("carries an inspected task through Grid and a canonical view back to the exact current task", async () => {
  const { calls, clipboard } = setup();
  window.history.replaceState(
    null,
    "",
    "#/monitor/0?workspace=ws&application=alpha&task=origin-task",
  );
  render(<App />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Open Grid from this task" }),
  );
  await screen.findByText("Grid application: alpha");
  expect(window.location.hash).toContain("returnTask=origin-task");
  fireEvent.click(screen.getByRole("button", { name: "Resolve saved view" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Copy client references" }),
  );
  await waitFor(() => expect(clipboard).toHaveBeenCalledOnce());
  expect(copiedReference(clipboard).returnTo).toEqual({
    kind: "task",
    taskId: "origin-task",
  });
  fireEvent.click(screen.getByRole("button", { name: "Return to task" }));
  await screen.findByRole("heading", { name: "referenced.task" });
  expect(calls.filter(({ url }) => url === "/api/task")).toHaveLength(2);
  expect(
    calls.some(({ url }) =>
      ["/api/program", "/api/cancel", "/api/authorize"].includes(url),
    ),
  ).toBe(false);
});

it("inspects a pending operation's existing task reference without inheriting replay authority", async () => {
  const { calls } = setup();
  window.history.replaceState(
    null,
    "",
    referenceHandoffHash({
      ...handoff,
      pendingOperation: { kind: "task", taskId: "existing-operation" },
    }),
  );
  render(<App />);
  await screen.findByText("Grid application: alpha");
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Inspect referenced operation" }),
    ).toBeEnabled(),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Inspect referenced operation" }),
  );
  await screen.findByRole("heading", { name: "referenced.task" });
  expect(
    calls
      .filter(({ url }) => url === "/api/task")
      .map(({ body }) => body?.taskId),
  ).toEqual(["existing-operation"]);
  expect(
    calls.some(({ url }) =>
      ["/api/program", "/api/cancel", "/api/authorize"].includes(url),
    ),
  ).toBe(false);
});

it.each([
  {
    section: "rules",
    button: "Open Calculation rules",
    heading: "Calculation rules",
    returnTo: { kind: "task", taskId: "origin-task" },
  },
  {
    section: "python",
    button: "Open Python programs",
    heading: "Python programs",
    returnTo: {
      kind: "workflowActivity",
      occurrenceId: "origin-occurrence",
      activityId: "review",
    },
  },
] as const)(
  "clears the legacy handoff before opening $section and preserves its explicit return destination",
  async ({ section, button, heading, returnTo }) => {
    const { calls } = setup(200, {
      "application.rule.read": {},
      "application.rule.list": {},
      "python.program.list": {},
      "python.program.read": {},
    });
    const reference: ReferenceHandoff = {
      ...handoff,
      returnTo,
      target: {
        kind: "definition",
        artifactKind: "ApplicationSequence",
        artifactId: "private-old-id",
      },
      observed: {
        stateToken: "a".repeat(64),
        definitionDigest: "b".repeat(64),
      },
    };
    delete reference.analyticalRead;
    window.history.replaceState(null, "", referenceHandoffHash(reference));
    render(<App />);
    await screen.findByText(/saved sequence is a retired artifact/);
    expect(
      calls.some((call) =>
        JSON.stringify(call.body).includes("private-old-id"),
      ),
    ).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: button }));
    await waitFor(() =>
      expect(readPresentationRoute().focus.section).toBe(section),
    );
    const route = readPresentationRoute();
    expect(route.focus.artifactKind).toBeUndefined();
    expect(route.focus.artifactId).toBeUndefined();
    expect(route.focus.artifactStateToken).toBeUndefined();
    expect(route.focus.artifactDigest).toBeUndefined();
    expect(route.focus.referenceHandoff).toBeUndefined();
    expect(route.focus.workspaceId).toBe("ws");
    expect(route.focus.applicationId).toBe("alpha");
    if (returnTo.kind === "task")
      expect(route.focus.returnTaskId).toBe(returnTo.taskId);
    else {
      expect(route.focus.occurrenceId).toBe(returnTo.occurrenceId);
      expect(route.focus.activityId).toBe(returnTo.activityId);
    }
    await screen.findByRole("heading", { name: heading });
    expect(window.location.hash).not.toContain("private-old-id");
    expect(window.location.hash).not.toContain("handoff");
    expect(
      calls.some(
        (call) =>
          (call.body?.program as { function?: string })?.function ===
          "application.rule.read",
      ),
    ).toBe(false);
    expect(
      calls.some((call) =>
        JSON.stringify(call.body).includes("private-old-id"),
      ),
    ).toBe(false);
  },
);

const operationTask = "x:" + "1".repeat(32);
const originalTask = "y:" + "2".repeat(32);
const workflowOrigin = {
  kind: "workflowActivity" as const,
  occurrenceId: "3".repeat(32),
  activityId: "review",
};
const workflowReadFunctions = {
  "application.workflow.worklist": {},
  "application.workflow.read": {},
  "application.workflow.occurrence.read": {},
};
function taskHandoff(returnTo: ReferenceHandoff["returnTo"]): ReferenceHandoff {
  return {
    format: handoff.format,
    scope: handoff.scope,
    origin: returnTo,
    target: { kind: "task", taskId: operationTask },
    returnTo,
    observed: {},
    pendingOperation: null,
  };
}
function assertOnlyInspection(calls: ReturnType<typeof setup>["calls"]) {
  expect(
    calls.every(({ url }) =>
      [
        "/api/applications",
        "/api/session-identity",
        "/api/runtime",
        "/api/catalog",
        "/api/platform/browser/catalog",
        "/api/tasks",
        "/api/task",
        "/api/read",
      ].includes(url),
    ),
  ).toBe(true);
  expect(
    calls
      .filter(({ url }) => url === "/api/read")
      .every(({ body }) =>
        Object.hasOwn(
          workflowReadFunctions,
          (body!.program as { function: string }).function,
        ),
      ),
  ).toBe(true);
}

it.each(["x:", "y:"])(
  "closes explicit %s task detail to its exact workflow origin through actual App and Monitor",
  async (prefix) => {
    const { calls } = setup(200, workflowReadFunctions);
    const reference = taskHandoff(workflowOrigin);
    reference.target = { kind: "task", taskId: prefix + "1".repeat(32) };
    window.history.replaceState(null, "", referenceHandoffHash(reference));
    render(<App />);
    const close = await screen.findByRole("button", {
      name: "Close task detail",
    });
    close.focus();
    fireEvent.click(close);
    expect(
      await screen.findByRole("heading", { name: "Original review activity" }),
    ).toBeVisible();
    expect(
      screen.getByRole("heading", { name: "Activity history" }),
    ).toBeVisible();
    expect(readPresentationRoute().page).toBe("flows");
    expect(document.getElementById("main-content")).toHaveFocus();
    expect(readPresentationRoute().focus.referenceHandoff).toMatchObject({
      scope: reference.scope,
      target: workflowOrigin,
      returnTo: null,
      origin: reference.target,
    });
    expect(
      calls
        .filter(({ url }) => url === "/api/read")
        .map(
          ({ body }) =>
            body!.program as { function: string; arguments: unknown },
        ),
    ).toContainEqual({
      languageVersion: 2,
      function: "application.workflow.occurrence.read",
      arguments: {
        occurrenceId: workflowOrigin.occurrenceId,
        afterEventOrdinal: 0,
        eventLimit: 50,
        includeCurrentReturns: true,
      },
    });
    expect(
      document.querySelector(".task-companion .step-list li.current strong"),
    ).toHaveTextContent("Original review activity");
    expect(
      screen.queryByRole("complementary", { name: "Selected task detail" }),
    ).toBeNull();
    assertOnlyInspection(calls);
  },
);

it("closes an explicit task handoff to the exact currently read originating task", async () => {
  const { calls } = setup();
  const reference = taskHandoff({ kind: "task", taskId: originalTask });
  window.history.replaceState(null, "", referenceHandoffHash(reference));
  render(<App />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Close task detail" }),
  );
  await waitFor(() =>
    expect(
      calls
        .filter(({ url }) => url === "/api/task")
        .map(({ body }) => body!.taskId),
    ).toEqual([operationTask, originalTask]),
  );
  expect(
    await screen.findByRole("complementary", { name: "Selected task detail" }),
  ).toBeVisible();
  expect(readPresentationRoute().focus.referenceHandoff?.target).toEqual({
    kind: "task",
    taskId: originalTask,
  });
  expect(readPresentationRoute().focus.referenceHandoff?.returnTo).toBeNull();
  assertOnlyInspection(calls);
});

it.each([403, 404])(
  "refuses the exact task origin after Close when its current read returns %i",
  async (status) => {
    const { calls } = setup(
      200,
      {},
      { originStatus: status, originTaskId: originalTask },
    );
    window.history.replaceState(
      null,
      "",
      referenceHandoffHash(taskHandoff({ kind: "task", taskId: originalTask })),
    );
    render(<App />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Close task detail" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "TASK_UNAVAILABLE",
    );
    expect(readPresentationRoute().focus.referenceHandoff?.target).toEqual({
      kind: "task",
      taskId: originalTask,
    });
    expect(
      calls
        .filter(({ url }) => url === "/api/task")
        .map(({ body }) => body!.taskId),
    ).toEqual([operationTask, originalTask]);
    expect(
      screen.queryByRole("complementary", { name: "Selected task detail" }),
    ).toBeNull();
    assertOnlyInspection(calls);
  },
);

it.each([403, 404])(
  "refuses the exact workflow origin after Close when its current read returns %i",
  async (status) => {
    const { calls } = setup(200, workflowReadFunctions, {
      originStatus: status,
    });
    window.history.replaceState(
      null,
      "",
      referenceHandoffHash(taskHandoff(workflowOrigin)),
    );
    render(<App />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Close task detail" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "WORKFLOW_UNAVAILABLE",
    );
    expect(readPresentationRoute().focus.referenceHandoff?.target).toEqual(
      workflowOrigin,
    );
    expect(
      calls.filter(
        ({ url, body }) =>
          url === "/api/read" &&
          (body!.program as { function: string }).function ===
            "application.workflow.occurrence.read",
      ),
    ).toHaveLength(1);
    expect(
      screen.queryByRole("heading", { name: "Activity history" }),
    ).toBeNull();
    expect(
      screen.queryByRole("heading", { name: "Original review activity" }),
    ).toBeNull();
    expect(
      screen.queryByRole("complementary", { name: "Selected task detail" }),
    ).toBeNull();
    assertOnlyInspection(calls);
  },
);

it.each([false, true])(
  "keeps Close local for a list-opened task even with a different handed-off task (%s)",
  async (hasHandoff) => {
    const listedTaskId = "y:" + "4".repeat(32);
    const { calls } = setup(200, workflowReadFunctions, { listedTaskId });
    const hash = hasHandoff
      ? referenceHandoffHash(taskHandoff(workflowOrigin))
      : "#/monitor/0?workspace=ws&application=alpha";
    window.history.replaceState(null, "", hash);
    render(<App />);
    if (hasHandoff)
      await screen.findByRole("button", { name: "Close task detail" });
    const listed = await screen.findByRole("button", { name: "list.task" });
    await waitFor(() => expect(listed).toBeEnabled());
    fireEvent.click(listed);
    expect(
      await screen.findByRole("complementary", {
        name: "Selected task detail",
      }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Close task detail" }));
    expect(
      screen.queryByRole("complementary", { name: "Selected task detail" }),
    ).toBeNull();
    expect(readPresentationRoute().page).toBe("monitor");
    expect(window.location.hash).toBe(hash);
    expect(screen.getByRole("button", { name: "list.task" })).toBeVisible();
    expect(calls.filter(({ url }) => url === "/api/read")).toHaveLength(0);
    assertOnlyInspection(calls);
  },
);

it("keeps explicit task detail and its origin unchanged when Close navigation is cancelled, then transitions once", async () => {
  const { calls } = setup(200, workflowReadFunctions);
  const hash = referenceHandoffHash(taskHandoff(workflowOrigin));
  window.history.replaceState(null, "", hash);
  render(<App />);
  const close = await screen.findByRole("button", {
    name: "Close task detail",
  });
  act(() => setUnsavedWork("unpreserved-editor", "Unpreserved editor", true));
  const push = vi.spyOn(window.history, "pushState");
  try {
    fireEvent.click(close);
    expect(await screen.findByRole("alertdialog")).toHaveTextContent(
      "Unpreserved editor",
    );
    fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
    expect(window.location.hash).toBe(hash);
    expect(
      screen.getByRole("complementary", { name: "Selected task detail" }),
    ).toBeVisible();
    expect(unsavedWorkSnapshot()).toEqual([
      { id: "unpreserved-editor", label: "Unpreserved editor" },
    ]);
    expect(calls.filter(({ url }) => url === "/api/read")).toHaveLength(0);
    expect(push).not.toHaveBeenCalled();
    fireEvent.click(close);
    fireEvent.click(
      await screen.findByRole("button", { name: "Discard and continue" }),
    );
    expect(
      await screen.findByRole("heading", { name: "Original review activity" }),
    ).toBeVisible();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(push).toHaveBeenCalledTimes(1);
    expect(unsavedWorkSnapshot()).toEqual([]);
    assertOnlyInspection(calls);
  } finally {
    push.mockRestore();
  }
});

it.each([200, 403])(
  "rereads current authority when Close returns to the same task (%i)",
  async (status) => {
    const options = { originStatus: 200, originTaskId: operationTask };
    const { calls } = setup(200, {}, options);
    window.history.replaceState(
      null,
      "",
      referenceHandoffHash(
        taskHandoff({ kind: "task", taskId: operationTask }),
      ),
    );
    render(<App />);
    const close = await screen.findByRole("button", {
      name: "Close task detail",
    });
    options.originStatus = status;
    fireEvent.click(close);
    await waitFor(() =>
      expect(
        calls
          .filter(({ url }) => url === "/api/task")
          .map(({ body }) => body!.taskId),
      ).toEqual([operationTask, operationTask]),
    );
    expect(readPresentationRoute().focus.referenceHandoff?.returnTo).toBeNull();
    if (status === 403) {
      expect(await screen.findByRole("alert")).toHaveTextContent(
        "TASK_UNAVAILABLE",
      );
      expect(
        screen.queryByRole("complementary", { name: "Selected task detail" }),
      ).toBeNull();
    } else {
      expect(
        await screen.findByRole("complementary", {
          name: "Selected task detail",
        }),
      ).toBeVisible();
    }
    assertOnlyInspection(calls);
  },
);
