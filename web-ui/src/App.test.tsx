import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  App,
  applicationPageVisible,
  browserLogoutPath,
  editableShortcutTarget,
  Overview,
  presentationRouteHash,
  readPresentationRoute,
  runtimeBuildFingerprint,
  shareableViewUrl,
} from "./App";
import { MyWork } from "./MyWork";
import { resetUnsavedWorkForTests, setUnsavedWork } from "./unsaved-work";
import {
  resetBrowserLifecycleForTests,
  setBrowserLifecycle,
} from "./browser-lifecycle";
import { resolveWorkflowDestination } from "./workflow-destination";

afterEach(() => {
  resetUnsavedWorkForTests();
  resetBrowserLifecycleForTests();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

it("uses the server-side browser gateway logout boundary", () => {
  expect(browserLogoutPath()).toBe("/oidc/sign_out");
});

it("compares only authoritative runtime build identity for release reload", () => {
  expect(
    runtimeBuildFingerprint({
      sourceCommit: "a".repeat(40),
      packagedSchema: 262,
    }),
  ).toBe(
    runtimeBuildFingerprint({
      packagedSchema: 262,
      sourceCommit: "a".repeat(40),
    }),
  );
  expect(runtimeBuildFingerprint({ sourceCommit: "a".repeat(40) })).not.toBe(
    runtimeBuildFingerprint({ sourceCommit: "b".repeat(40) }),
  );
});

it("keeps generic authoring and administration navigation role aware", () => {
  const reader = {
    applicationAccess: { role: "Reader", workspaceAdministrator: false },
    enabledCapabilities: [],
    functions: {},
    revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
  };
  expect(applicationPageVisible("metadata", reader)).toBe(false);
  expect(applicationPageVisible("lists", reader)).toBe(false);
  expect(applicationPageVisible("rules", reader)).toBe(false);
  expect(applicationPageVisible("administration", reader)).toBe(false);
  expect(applicationPageVisible("monitor", reader)).toBe(true);
  expect(
    applicationPageVisible("rules", {
      ...reader,
      applicationAccess: { role: "Editor", workspaceAdministrator: false },
    }),
  ).toBe(true);
  expect(
    applicationPageVisible("administration", {
      ...reader,
      applicationAccess: {
        role: "Administrator",
        workspaceAdministrator: false,
      },
    }),
  ).toBe(true);
});

it("creates a canonical view link without cache-busting query data", () => {
  expect(
    shareableViewUrl({
      origin: "https://app.openepm.dev",
      pathname: "/",
      hash: "#/grid/2",
    } as Location),
  ).toBe("https://app.openepm.dev/#/grid/2");
});

it("builds exact generic flow destinations without changing server contracts", () => {
  expect(
    presentationRouteHash("grid", 2, {
      workspaceId: "north region",
      applicationId: "forecast/2027",
    }),
  ).toBe("#/grid/2?workspace=north+region&application=forecast%2F2027");
  expect(
    presentationRouteHash("flows", 1, {
      occurrenceId: "close:2027-03",
      activityId: "review & approve",
    }),
  ).toBe("#/flows/1?occurrence=close%3A2027-03&activity=review+%26+approve");
  expect(
    presentationRouteHash("grid", 1, {
      occurrenceId: "occurrence-1",
      activityId: "review",
      viewId: "review-view",
      viewVersion: 3,
      viewDigest: "d".repeat(64),
    }),
  ).toBe(
    `#/grid/1?view=review-view&viewVersion=3&viewDigest=${"d".repeat(64)}&returnOccurrence=occurrence-1&returnActivity=review`,
  );
  window.history.replaceState(
    null,
    "",
    `/#/grid/1?view=review-view&viewVersion=3&viewDigest=${"d".repeat(64)}&returnOccurrence=occurrence-1&returnActivity=review`,
  );
  expect(readPresentationRoute().focus).toMatchObject({
    occurrenceId: "occurrence-1",
    activityId: "review",
    viewId: "review-view",
    viewVersion: 3,
    viewDigest: "d".repeat(64),
  });
});

it("resolves only exact authorized workflow destinations", () => {
  const catalog = {
    applicationAccess: { role: "Reader", workspaceAdministrator: false },
    enabledCapabilities: [],
    functions: {
      "grid.definition.read": {},
      "application.rule.run": {},
    },
    revisions: { metadata: 1, data: 2, policy: 3, security: 4, commit: 5 },
  };
  expect(
    resolveWorkflowDestination(
      {
        kind: "CubeView",
        viewId: "review-view",
        version: 3,
        digest: "d".repeat(64),
      },
      catalog,
    ),
  ).toEqual({
    supported: true,
    page: "grid",
    focus: {
      viewId: "review-view",
      viewVersion: 3,
      viewDigest: "d".repeat(64),
    },
  });
  for (const [artifactKind, readFunction] of [
    ["ApplicationSequence", "rules.numeric_sequence.version.read"],
    ["ApplicationSchedule", "schedule.version.read"],
  ] as const) {
    const artifactCatalog = {
      ...catalog,
      functions: { ...catalog.functions, [readFunction]: {} },
    };
    expect(
      resolveWorkflowDestination(
        {
          kind: "Artifact",
          artifactKind,
          artifactId: "close.nightly",
          version: 4,
          digest: "b".repeat(64),
        },
        artifactCatalog,
      ),
    ).toEqual({
      supported: true,
      page: "rules",
      focus: {
        artifactKind,
        artifactId: "close.nightly",
        artifactVersion: 4,
        artifactDigest: "b".repeat(64),
      },
    });
  }
  const calculatedMemberCatalog = {
    ...catalog,
    functions: {
      ...catalog.functions,
      "calculated.member.version.read": {},
    },
  };
  expect(
    resolveWorkflowDestination(
      {
        kind: "Artifact",
        artifactKind: "CalculatedMember",
        artifactId: "margin.calculated",
        version: 2,
        digest: "a".repeat(64),
      },
      calculatedMemberCatalog,
    ),
  ).toEqual({
    supported: true,
    page: "rules",
    focus: {
      artifactKind: "CalculatedMember",
      artifactId: "margin.calculated",
      artifactVersion: 2,
      artifactDigest: "a".repeat(64),
    },
  });
  expect(
    resolveWorkflowDestination(
      {
        kind: "Function",
        function: "application.rule.run",
        argumentsDigest: "e".repeat(64),
      },
      catalog,
    ),
  ).toMatchObject({
    supported: false,
    code: "WORKFLOW_FUNCTION_DESTINATION_NOT_INSPECTABLE",
  });
  expect(
    resolveWorkflowDestination(
      {
        kind: "Artifact",
        artifactKind: "ApplicationRule",
        artifactId: "close.rule",
        version: 3,
        digest: "f".repeat(64),
      },
      catalog,
    ),
  ).toMatchObject({
    supported: false,
    code: "WORKFLOW_ARTIFACT_DESTINATION_UNAUTHORIZED",
  });
  const applicationRuleCatalog = {
    ...catalog,
    functions: {
      ...catalog.functions,
      "application.rule.version.read": {},
    },
  };
  expect(
    resolveWorkflowDestination(
      {
        kind: "Artifact",
        artifactKind: "ApplicationRule",
        artifactId: "close.rule",
        version: 3,
        digest: "f".repeat(64),
      },
      applicationRuleCatalog,
    ),
  ).toEqual({
    supported: true,
    page: "rules",
    focus: {
      artifactKind: "ApplicationRule",
      artifactId: "close.rule",
      artifactVersion: 3,
      artifactDigest: "f".repeat(64),
    },
  });
  expect(
    resolveWorkflowDestination(
      {
        kind: "CubeView",
        viewId: "review-view",
        version: 3,
        digest: "not-a-digest",
      },
      catalog,
    ),
  ).toMatchObject({
    supported: false,
    code: "WORKFLOW_CUBE_VIEW_DESTINATION_INVALID",
  });
});

it("does not route retired domain workspace hashes into the generic shell", () => {
  window.history.replaceState(null, "", "/#/plan/0");
  expect(readPresentationRoute().page).toBe("home");
  window.history.replaceState(null, "", "/#/consolidate/0");
  expect(readPresentationRoute().page).toBe("home");
  window.history.replaceState(null, "", "/#/workflow/0");
  expect(readPresentationRoute().page).toBe("flows");
});

it("opens each My Work item at its exact generic flow identity", async () => {
  const open = vi.fn();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/tasks")
        return new Response(
          JSON.stringify({
            tasks: [
              {
                taskId: "h:11111111111111111111111111111111/approve",
                sourceFamily: "ApplicationWorkflowActivity",
                sourceId: "occ-7/approve",
                status: "Waiting",
              },
              {
                taskId: "h:11111111111111111111111111111111/post",
                sourceFamily: "ApplicationWorkflowActivity",
                sourceId: "occ-7/post",
                status: "Waiting",
              },
              {
                taskId: "j:22222222222222222222222222222222",
                sourceFamily: "Job",
                sourceId: "22222222222222222222222222222222",
                status: "Waiting",
              },
            ],
          }),
        );
      if (body.program.function === "application.workflow.worklist")
        return new Response(
          JSON.stringify({
            result: {
              items: [
                {
                  occurrenceId: "occ-7",
                  activityId: "approve",
                  name: "Approve forecast",
                  flowId: "forecast-close",
                  version: 3,
                },
              ],
            },
          }),
        );
      throw new Error(`Unexpected function ${body.program.function}`);
    }),
  );
  render(
    <MyWork
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Planner", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {
          "application.workflow.worklist": {},
        },
        revisions: { metadata: 1, data: 2, policy: 3, security: 4, commit: 5 },
      }}
      open={open}
    />,
  );

  await screen.findByText("Approve forecast");
  const continueButtons = screen.getAllByRole("button", {
    name: "Continue exact work →",
  });
  fireEvent.click(continueButtons[0]);
  expect(open).toHaveBeenCalledWith("flows", {
    workspaceId: "ws",
    applicationId: "app",
    occurrenceId: "occ-7",
    activityId: "approve",
  });
  fireEvent.click(continueButtons[1]);
  expect(open).toHaveBeenCalledWith("flows", {
    workspaceId: "ws",
    applicationId: "app",
    occurrenceId: "occ-7",
    activityId: "post",
  });
  expect(
    screen.getByText("Waiting on an earlier workflow dependency"),
  ).toBeInTheDocument();
  expect(
    screen.queryByText("approve", { selector: "strong" }),
  ).not.toBeInTheDocument();
});

it("prefers generic programmable workflow work over retained planning flows", async () => {
  const open = vi.fn();
  const occurrence = "1".repeat(32);
  const functions: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/tasks")
        return new Response(
          JSON.stringify({
            tasks: [
              {
                taskId: `y:${occurrence}/prepare`,
                sourceFamily: "ApplicationWorkflowActivity",
                sourceId: `${occurrence}/prepare`,
                status: "Waiting",
              },
              {
                taskId: `y:${occurrence}/review`,
                sourceFamily: "ApplicationWorkflowActivity",
                sourceId: `${occurrence}/review`,
                status: "Waiting",
              },
            ],
          }),
        );
      functions.push(body.program.function);
      if (body.program.function === "application.workflow.worklist")
        return new Response(
          JSON.stringify({
            result: {
              items: [
                {
                  occurrenceId: occurrence,
                  activityId: "prepare",
                  name: "Prepare selected cube slice",
                  flowId: "generic-review",
                  version: 1,
                },
              ],
            },
          }),
        );
      throw new Error(`Unexpected function ${body.program.function}`);
    }),
  );
  render(
    <MyWork
      app={{
        workspaceId: "ws",
        applicationId: "cube",
        name: "Cube",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {
          "application.workflow.worklist": {},
          "application.taskflow.worklist": {},
          "planning.slice.worklist": {},
        },
        revisions: { metadata: 1, data: 2, policy: 3, security: 4, commit: 5 },
      }}
      open={open}
    />,
  );

  await screen.findByText("Prepare selected cube slice");
  expect(functions).toEqual(["application.workflow.worklist"]);
  expect(
    screen.getByText("review", { selector: "strong" }),
  ).toBeInTheDocument();
  expect(screen.queryByText(/planning assignment/i)).not.toBeInTheDocument();
  fireEvent.click(
    screen.getAllByRole("button", { name: "Continue exact work →" })[0],
  );
  expect(open).toHaveBeenCalledWith("flows", {
    workspaceId: "ws",
    applicationId: "cube",
    occurrenceId: occurrence,
    activityId: "prepare",
  });
});

it("does not intercept command shortcuts from editable controls", () => {
  expect(editableShortcutTarget(document.createElement("input"))).toBe(true);
  expect(editableShortcutTarget(document.createElement("textarea"))).toBe(true);
  expect(editableShortcutTarget(document.createElement("select"))).toBe(true);
  expect(editableShortcutTarget(document.createElement("button"))).toBe(false);
});

it("keeps business work prominent and technical revisions in details", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/tasks")
        return new Response(
          JSON.stringify({
            tasks: [
              {
                taskId: "task-1",
                function: "facts.cube.aggregate.request",
                status: "Running",
                initiatorKind: "MCP agent",
              },
              {
                taskId: "task-2",
                function: "facts.source.begin",
                status: "Failed",
                initiatorKind: "Human",
              },
            ],
          }),
        );
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "planning.slice.worklist")
        return new Response(
          JSON.stringify({
            result: {
              assignmentItems: [{ assignmentId: "a" }],
              assignedReviewItems: [{ lockId: "l" }],
            },
          }),
        );
      return new Response(
        JSON.stringify({ result: { items: [{ activityId: "w" }] } }),
      );
    }),
  );
  render(
    <Overview
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Planner", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {
          "planning.slice.worklist": {},
          "application.taskflow.worklist": {},
        },
        revisions: { metadata: 1, data: 2, policy: 3, security: 4, commit: 5 },
      }}
      go={vi.fn()}
    />,
  );
  await waitFor(() =>
    expect(screen.getByText("Ready for you")).toBeInTheDocument(),
  );
  expect(screen.getByText("Reviews waiting")).toBeInTheDocument();
  expect(screen.getByText("Work running")).toBeInTheDocument();
  expect(screen.getByText("Needs attention")).toBeInTheDocument();
  expect(screen.getByText("facts.cube.aggregate.request")).toBeInTheDocument();
  expect(screen.getByText("Technical model details")).toBeInTheDocument();
  expect(screen.queryByText("Authorized functions")).not.toBeInTheDocument();
  expect(screen.queryByText("Current revision")).not.toBeInTheDocument();
});

it("renders the agent-first shell from existing read contracts", async () => {
  const writeText = vi.fn(async () => undefined);
  let runtimeCommit = "a".repeat(40);
  let sessionSubject = "owner";
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText },
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.startsWith("/api/applications"))
        return new Response(
          JSON.stringify({
            applications: [
              {
                workspaceId: "ws-pilot",
                applicationId: "pilot-fpna",
                name: "Pilot FP&A",
                status: "active",
                kind: "blank",
              },
            ],
            nextAfter: null,
          }),
        );
      if (url === "/api/session-identity")
        return new Response(
          JSON.stringify({
            subject: sessionSubject,
            displayIdentity: `${sessionSubject}@example.com`,
            applicationMcpEndpoint: "https://mcp.example/epu_personal",
          }),
        );
      if (url === "/api/runtime")
        return new Response(
          JSON.stringify({
            readOnlyReview: false,
            build: { sourceCommit: runtimeCommit, packagedSchema: 262 },
          }),
        );
      if (url === "/api/catalog")
        return new Response(
          JSON.stringify({
            applicationAccess: {
              role: "Administrator",
              workspaceAdministrator: true,
            },
            enabledCapabilities: [],
            functions: { "facts.cube.scan": {} },
            revisions: {
              metadata: 1,
              data: 2,
              policy: 3,
              security: 4,
              commit: 5,
            },
          }),
        );
      return new Response("{}", { status: 404 });
    }),
  );
  render(<App />);
  await waitFor(() =>
    expect(screen.getAllByText("Pilot FP&A").length).toBeGreaterThan(0),
  );
  await waitFor(() =>
    expect(
      vi
        .mocked(fetch)
        .mock.calls.some(([input]) => String(input) === "/api/runtime"),
    ).toBe(true),
  );
  runtimeCommit = "b".repeat(40);
  fireEvent(document, new Event("visibilitychange"));
  expect(
    await screen.findByText("A newer Open EPM release is ready"),
  ).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Account" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Account" })).toHaveAttribute(
    "aria-controls",
    "account-card",
  );
  fireEvent.click(screen.getByRole("button", { name: "Account" }));
  expect(
    screen.getByRole("region", { name: "Your account" }),
  ).toBeInTheDocument();
  fireEvent.pointerDown(document.body);
  expect(
    screen.queryByRole("region", { name: "Your account" }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Collapse sidebar" }),
  ).toHaveAttribute("aria-controls", "primary-navigation");
  expect(
    screen.getByRole("button", { name: "Collapse sidebar" }),
  ).toHaveAttribute("aria-expanded", "true");
  expect(
    screen.getByRole("link", { name: "Skip to main content" }),
  ).toHaveAttribute("href", "#main-content");
  expect(screen.getByRole("button", { name: "Home" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  expect(screen.getByRole("button", { name: "Grid" })).toBeEnabled();
  expect(screen.queryByText("Plan")).not.toBeInTheDocument();
  expect(screen.getByText("Agent ready")).toBeInTheDocument();
  expect(screen.queryByText("Consolidate")).not.toBeInTheDocument();
  act(() =>
    setUnsavedWork("test/editor", "Unsaved metadata attribute value", true),
  );
  const beforeUnload = new Event("beforeunload", { cancelable: true });
  window.dispatchEvent(beforeUnload);
  expect(beforeUnload.defaultPrevented).toBe(true);
  const reloadRelease = screen.getByRole("button", {
    name: "Review and reload",
  });
  reloadRelease.focus();
  fireEvent.click(reloadRelease);
  expect(
    screen.getByRole("alertdialog", { name: "Discard unsaved changes?" }),
  ).toBeInTheDocument();
  const keepEditing = screen.getByRole("button", { name: "Keep editing" });
  const discard = screen.getByRole("button", {
    name: "Discard and continue",
  });
  expect(keepEditing).toHaveFocus();
  discard.focus();
  fireEvent.keyDown(discard, { key: "Tab" });
  expect(keepEditing).toHaveFocus();
  fireEvent.keyDown(keepEditing, { key: "Escape" });
  expect(
    screen.queryByRole("alertdialog", { name: "Discard unsaved changes?" }),
  ).not.toBeInTheDocument();
  expect(reloadRelease).toHaveFocus();
  fireEvent.click(screen.getByRole("button", { name: "Account" }));
  fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
  expect(
    screen.getByRole("alertdialog", { name: "Discard unsaved changes?" }),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  fireEvent.click(screen.getByRole("button", { name: "Grid" }));
  expect(screen.getByRole("button", { name: "Grid" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  fireEvent.click(screen.getByRole("button", { name: "Home" }));
  expect(screen.getByRole("button", { name: "Home" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  act(() =>
    setUnsavedWork("test/editor", "Unsaved metadata attribute value", true),
  );
  act(() => {
    window.history.replaceState(null, "", "#/home/0");
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  });
  expect(screen.getByRole("button", { name: "Home" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  act(() => setUnsavedWork("test/editor", "", false));
  fireEvent.click(screen.getByRole("button", { name: "Grid" }));
  const print = vi.spyOn(window, "print").mockImplementation(() => undefined);
  fireEvent.click(screen.getByRole("button", { name: "Print current view" }));
  expect(print).toHaveBeenCalledOnce();
  vi.useFakeTimers();
  await act(async () => {
    fireEvent.click(
      screen.getByRole("button", { name: "Copy link to this view" }),
    );
    await Promise.resolve();
  });
  expect(screen.getByText("Link copied")).toBeInTheDocument();
  expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/#/grid/0`);
  act(() => vi.advanceTimersByTime(2500));
  expect(screen.queryByText("Link copied")).not.toBeInTheDocument();
  vi.useRealTimers();
  fireEvent.keyDown(window, { key: "k", ctrlKey: true });
  const searchInput = screen.getByPlaceholderText(
    "Search applications, pages or authorized functions",
  );
  expect(searchInput).toBeInTheDocument();
  searchInput.focus();
  fireEvent.keyDown(window, { key: "Tab" });
  expect(screen.getByRole("button", { name: "Close search" })).toHaveFocus();
  fireEvent.keyDown(window, { key: "Escape" });
  expect(
    screen.queryByPlaceholderText(
      "Search applications, pages or authorized functions",
    ),
  ).not.toBeInTheDocument();
  fireEvent.keyDown(window, { key: "?" });
  expect(
    screen.getByRole("dialog", { name: "Keyboard help" }),
  ).toBeInTheDocument();
  expect(
    screen.getByText("Move through Open EPM efficiently"),
  ).toBeInTheDocument();
  expect(screen.getByText("Move between visible cells")).toBeInTheDocument();
  fireEvent.keyDown(window, { key: "Escape" });
  expect(
    screen.queryByRole("dialog", { name: "Keyboard help" }),
  ).not.toBeInTheDocument();
  const editable = document.createElement("input");
  document.body.append(editable);
  editable.focus();
  fireEvent.keyDown(editable, { key: "?" });
  expect(
    screen.queryByRole("dialog", { name: "Keyboard help" }),
  ).not.toBeInTheDocument();
  editable.remove();
  const searchButton = screen.getByRole("button", { name: "Search" });
  searchButton.focus();
  fireEvent.click(searchButton);
  fireEvent.click(screen.getByRole("button", { name: "Close search" }));
  expect(searchButton).toHaveFocus();
  fireEvent.click(screen.getByRole("button", { name: "My Work" }));
  expect(window.location.hash).toBe("#/work/0");
  await waitFor(() =>
    expect(screen.getByText("No work is currently ready")).toBeInTheDocument(),
  );
  expect(
    screen.getByRole("group", { name: "Filter work by state" }),
  ).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "All 0" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  fireEvent.click(screen.getByRole("button", { name: "Waiting 0" }));
  expect(screen.getByRole("button", { name: "Waiting 0" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  expect(
    screen.getByText("No work waiting on dependencies"),
  ).toBeInTheDocument();
  expect(
    screen.queryByText("No work is currently ready"),
  ).not.toBeInTheDocument();
  act(() => setUnsavedWork("test/offline-draft", "Unsaved grid value", true));
  sessionSubject = "replacement-owner";
  fireEvent(document, new Event("visibilitychange"));
  expect(await screen.findByText("Identity changed")).toBeInTheDocument();
  expect(
    screen.getByRole("list", { name: "Unpublished browser work" }),
  ).toHaveTextContent("Unsaved grid value");
  fireEvent.click(
    screen.getByRole("button", { name: "Discard drafts and continue" }),
  );
  expect(
    screen.queryByRole("list", { name: "Unpublished browser work" }),
  ).not.toBeInTheDocument();
  act(() => setUnsavedWork("test/offline-draft", "Unsaved grid value", true));
  act(() => setBrowserLifecycle("unavailable", "HTTP_503"));
  expect(
    await screen.findByText("Open EPM is temporarily unavailable"),
  ).toBeInTheDocument();
  expect(screen.getAllByText("Pilot FP&A").length).toBeGreaterThan(0);
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  expect(document.querySelector(".shell")).toHaveAttribute(
    "aria-hidden",
    "true",
  );
  expect(
    screen.getByRole("list", { name: "Unpublished browser work" }),
  ).toHaveTextContent("Unsaved grid value");
  expect(
    screen.getByRole("button", { name: "Retry connection" }),
  ).toBeInTheDocument();
});
