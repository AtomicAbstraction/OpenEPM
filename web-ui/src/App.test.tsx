import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { StrictMode } from "react";
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
import type {
  MetadataDestination,
  MetadataSection,
} from "./metadata-navigation";
import type { ApplicationSummary } from "./types";

vi.mock("./MetadataWorkspace", () => ({
  MetadataWorkspace: ({
    app,
    section,
    dimensionId,
    onNavigate,
  }: {
    app?: ApplicationSummary;
    section: MetadataSection;
    dimensionId?: string;
    onNavigate: (destination: MetadataDestination) => void;
  }) => (
    <section aria-label="Metadata navigation fixture">
      <p>Metadata application: {app?.applicationId || "none"}</p>
      <p>Metadata section: {section}</p>
      <p>Metadata dimension: {dimensionId || "none"}</p>
      <button
        onClick={() =>
          onNavigate({ section: "members", dimensionId: "Account" })
        }
      >
        Open account members
      </button>
      <button
        onClick={() =>
          onNavigate({ section: "relationships", dimensionId: "Account" })
        }
      >
        Open account relationships
      </button>
    </section>
  ),
}));

afterEach(() => {
  resetUnsavedWorkForTests();
  resetBrowserLifecycleForTests();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

it.each([
  ["data", "Data", "import"],
  ["rules", "Rules", "python"],
  ["lists", "Member Lists", "lists"],
  ["security", "Users & Security", "security"],
  ["administration", "Administration", "lifecycle"],
])(
  "navigates %s breadcrumb ancestors within the exact application",
  async (page, label, defaultSection) => {
    metadataNavigationFixture();
    window.history.replaceState(
      null,
      "",
      `#/${page}/0?section=reference&workspace=ws&application=beta`,
    );
    render(<App />);
    const trail = within(
      screen.getByRole("navigation", { name: "Breadcrumb" }),
    );
    await waitFor(() =>
      expect(trail.getByRole("link", { name: "Beta model" })).toHaveAttribute(
        "href",
        "#/overview/1?workspace=ws&application=beta",
      ),
    );
    expect(trail.getByText("Function reference")).toHaveAttribute(
      "aria-current",
      "page",
    );
    fireEvent.click(trail.getByRole("link", { name: label }));
    await waitFor(() =>
      expect(window.location.hash).toBe(
        `#/${page}/1?section=${defaultSection}&workspace=ws&application=beta`,
      ),
    );
    fireEvent.click(trail.getByRole("link", { name: "Beta model" }));
    await waitFor(() =>
      expect(window.location.hash).toBe(
        "#/overview/1?workspace=ws&application=beta",
      ),
    );
  },
);

it("guards breadcrumb navigation and clears deeper metadata selections only after acceptance", async () => {
  metadataNavigationFixture();
  window.history.replaceState(
    null,
    "",
    "#/metadata/0?workspace=ws&application=alpha&metadataSection=relationships&dimension=Account&member=Revenue",
  );
  render(<App />);
  await screen.findByText("Metadata section: relationships");
  const trail = within(screen.getByRole("navigation", { name: "Breadcrumb" }));
  const original = window.location.hash;
  act(() => setUnsavedWork("breadcrumb-test", "Unsaved hierarchy", true));
  const dimension = trail.getByRole("link", { name: "Account" });
  dimension.focus();
  fireEvent.click(dimension);
  expect(await screen.findByRole("alertdialog")).toHaveTextContent(
    "Unsaved hierarchy",
  );
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(window.location.hash).toBe(original);
  expect(dimension).toHaveFocus();
  fireEvent.click(dimension);
  fireEvent.click(screen.getByRole("button", { name: "Discard and continue" }));
  await waitFor(() =>
    expect(window.location.hash).toBe(
      "#/metadata/0?workspace=ws&application=alpha&metadataSection=members&dimension=Account",
    ),
  );
  fireEvent.click(trail.getByRole("link", { name: "Metadata" }));
  await waitFor(() =>
    expect(window.location.hash).toBe(
      "#/metadata/0?workspace=ws&application=alpha&metadataSection=dimensions",
    ),
  );
  expect(
    trail.queryByRole("link", { name: "Account" }),
  ).not.toBeInTheDocument();
});

it("uses the global home ancestor outside an application", async () => {
  metadataNavigationFixture();
  window.history.replaceState(null, "", "#/applications/0");
  render(<App />);
  await screen.findByRole("button", {
    name: "Choose application; current Alpha model",
  });
  const trail = within(screen.getByRole("navigation", { name: "Breadcrumb" }));
  expect(trail.queryByText("Alpha model")).not.toBeInTheDocument();
  expect(trail.getByRole("link", { name: "Open EPM" })).toHaveAttribute(
    "href",
    "#/home/0",
  );
  fireEvent.click(trail.getByRole("link", { name: "Open EPM" }));
  await waitFor(() => expect(window.location.hash).toBe("#/home/0"));
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
      viewDigest: "d".repeat(64),
    }),
  ).toBe(
    `#/grid/1?view=review-view&viewDigest=${"d".repeat(64)}&returnOccurrence=occurrence-1&returnActivity=review`,
  );
  window.history.replaceState(
    null,
    "",
    `/#/grid/1?view=review-view&viewDigest=${"d".repeat(64)}&returnOccurrence=occurrence-1&returnActivity=review`,
  );
  expect(readPresentationRoute().focus).toMatchObject({
    occurrenceId: "occurrence-1",
    activityId: "review",
    viewId: "review-view",
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
        digest: "d".repeat(64),
      },
      catalog,
    ),
  ).toEqual({
    supported: true,
    page: "grid",
    focus: {
      viewId: "review-view",
      viewDigest: "d".repeat(64),
    },
  });
  for (const [artifactKind, readFunction] of [
    ["ApplicationSequence", "rules.numeric_sequence.read"],
    ["ApplicationSchedule", "schedule.read"],
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
          stateToken: "c".repeat(64),
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
        artifactStateToken: "c".repeat(64),
        artifactDigest: "b".repeat(64),
      },
    });
  }
  const calculatedMemberCatalog = {
    ...catalog,
    functions: {
      ...catalog.functions,
      "calculated.member.read": {},
    },
  };
  expect(
    resolveWorkflowDestination(
      {
        kind: "Artifact",
        artifactKind: "CalculatedMember",
        artifactId: "margin.calculated",
        stateToken: "c".repeat(64),
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
      artifactStateToken: "c".repeat(64),
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
        stateToken: "c".repeat(64),
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
      "application.rule.read": {},
    },
  };
  expect(
    resolveWorkflowDestination(
      {
        kind: "Artifact",
        artifactKind: "ApplicationRule",
        artifactId: "close.rule",
        stateToken: "c".repeat(64),
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
      artifactStateToken: "c".repeat(64),
      artifactDigest: "f".repeat(64),
    },
  });
  expect(
    resolveWorkflowDestination(
      {
        kind: "CubeView",
        viewId: "review-view",
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
    name: "Open activity →",
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
          "cube.write.scope.worklist": {},
        },
        revisions: { metadata: 1, data: 2, policy: 3, security: 4, commit: 5 },
      }}
      open={open}
    />,
  );

  await screen.findByText("Prepare selected cube slice");
  expect(functions).toEqual(["application.workflow.worklist"]);
  expect(
    screen.getByText("Workflow activity", { selector: "strong" }),
  ).toBeInTheDocument();
  expect(screen.queryByText("review")).not.toBeInTheDocument();
  expect(screen.queryByText(/planning assignment/i)).not.toBeInTheDocument();
  fireEvent.click(
    screen.getAllByRole("button", { name: "Open activity →" })[0],
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
      if (body.program.function === "cube.write.scope.worklist")
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
          "cube.write.scope.worklist": {},
        },
        revisions: { metadata: 1, data: 2, policy: 3, security: 4, commit: 5 },
      }}
      go={vi.fn()}
    />,
  );
  await waitFor(() =>
    expect(screen.getByText("Ready for you")).toBeInTheDocument(),
  );
  expect(screen.queryByText("Reviews waiting")).not.toBeInTheDocument();
  expect(
    screen.getByText(/Counts reflect the loaded worklist/),
  ).toBeInTheDocument();
  expect(screen.getByText("Work running")).toBeInTheDocument();
  expect(screen.getByText("Needs attention")).toBeInTheDocument();
  expect(screen.getByText("facts.cube.aggregate.request")).toBeInTheDocument();
  expect(screen.getByText("Application details")).toBeInTheDocument();
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
  expect(
    screen.getByText("Programmable multidimensional platform"),
  ).toBeInTheDocument();
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
  expect(
    screen.getByRole("alertdialog", { name: "Discard unsaved changes?" }),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Discard and continue" }));
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
  expect(writeText).toHaveBeenCalledWith(
    `${window.location.origin}/#/grid/0?workspace=ws-pilot&application=pilot-fpna`,
  );
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
  expect(window.location.hash).toBe(
    "#/work/0?workspace=ws-pilot&application=pilot-fpna",
  );
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

it("round-trips metadata pages with exact application, dimension and member identity", () => {
  const route = presentationRouteHash("metadata", 9, {
    workspaceId: "ws north",
    applicationId: "forecast-2027",
    metadataSection: "relationships",
    dimensionId: "Account",
    memberId: "Sales & services",
  });
  window.history.replaceState(null, "", route);
  expect(readPresentationRoute()).toMatchObject({
    page: "metadata",
    applicationIndex: 9,
    focus: {
      workspaceId: "ws north",
      applicationId: "forecast-2027",
      metadataSection: "relationships",
      dimensionId: "Account",
      memberId: "Sales & services",
    },
  });
  window.history.replaceState(
    null,
    "",
    "#/metadata/0?metadataSection=invalid&dimension=Account&member=Sales",
  );
  expect(readPresentationRoute().focus).toMatchObject({
    metadataSection: "dimensions",
    dimensionId: undefined,
    memberId: undefined,
  });
});

function metadataNavigationFixture(
  catalogRead?: (
    scope: { workspaceId: string; applicationId: string },
    signal?: AbortSignal,
  ) => Promise<Response>,
) {
  const applications = [
    {
      workspaceId: "ws",
      applicationId: "alpha",
      name: "Alpha model",
      status: "Active",
    },
    {
      workspaceId: "ws",
      applicationId: "beta",
      name: "Beta model",
      status: "Active",
    },
  ];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.startsWith("/api/applications"))
        return new Response(JSON.stringify({ applications, nextAfter: null }));
      if (url === "/api/session-identity")
        return new Response(
          JSON.stringify({
            subject: "designer",
            displayIdentity: "designer@example.com",
          }),
        );
      if (url === "/api/runtime")
        return new Response(
          JSON.stringify({
            build: { sourceCommit: "a".repeat(40), packagedSchema: 281 },
          }),
        );
      if (url === "/api/catalog" && catalogRead)
        return catalogRead(
          JSON.parse(String(init?.body)),
          init?.signal || undefined,
        );
      if (url === "/api/catalog")
        return new Response(
          JSON.stringify({
            applicationAccess: {
              role: "Administrator",
              workspaceAdministrator: false,
            },
            enabledCapabilities: [],
            functions: {
              "metadata.dimension.list": {},
              "metadata.member.list": {},
            },
            revisions: {
              metadata: 1,
              data: 1,
              policy: 1,
              security: 1,
              commit: 1,
            },
          }),
        );
      if (url === "/api/platform/browser/catalog")
        return new Response("{}", { status: 403 });
      return new Response("{}", { status: 404 });
    }),
  );
}

it("resolves metadata application identity rather than a stale positional index", async () => {
  metadataNavigationFixture();
  window.history.replaceState(
    null,
    "",
    "#/metadata/0?workspace=ws&application=beta&metadataSection=members&dimension=Account",
  );
  render(<App />);
  expect(
    await screen.findByText("Metadata application: beta"),
  ).toBeInTheDocument();
  expect(
    screen.queryByText("Metadata application: alpha"),
  ).not.toBeInTheDocument();
  await waitFor(() => expect(window.location.hash).toContain("#/metadata/1?"));
});

it("does not render fallback metadata for an unknown explicit application", async () => {
  metadataNavigationFixture();
  window.history.replaceState(
    null,
    "",
    "#/metadata/0?workspace=ws&application=missing&metadataSection=members&dimension=Account",
  );
  render(<App />);
  expect(
    await screen.findByRole("heading", { name: "Application unavailable" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("region", { name: "Metadata navigation fixture" }),
  ).not.toBeInTheDocument();
});

it.each(["overview", "grid", "data", "rules", "flows", "monitor"])(
  "rejects an unknown explicit application on %s instead of reading the selected fallback",
  async (page) => {
    metadataNavigationFixture();
    window.history.replaceState(
      null,
      "",
      `#/${page}/0?workspace=ws&application=missing`,
    );
    render(<App />);
    expect(
      await screen.findByRole("heading", { name: "Application unavailable" }),
    ).toBeInTheDocument();
    expect(
      vi
        .mocked(fetch)
        .mock.calls.filter(([url]) => String(url) === "/api/catalog"),
    ).toHaveLength(0);
  },
);

it("guards leaving a non-metadata workspace and preserves the route on cancel", async () => {
  metadataNavigationFixture();
  window.history.replaceState(
    null,
    "",
    "#/overview/0?workspace=ws&application=alpha",
  );
  render(<App />);
  await screen.findByRole("heading", { name: "Alpha model" });
  act(() => setUnsavedWork("test/rule", "Unsaved calculation", true));
  fireEvent.click(screen.getByRole("button", { name: "Home" }));
  expect(await screen.findByRole("alertdialog")).toHaveTextContent(
    "Unsaved calculation",
  );
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(window.location.hash).toContain("#/overview/");
  fireEvent.click(screen.getByRole("button", { name: "Home" }));
  fireEvent.click(screen.getByRole("button", { name: "Discard and continue" }));
  await waitFor(() => expect(window.location.hash).toContain("#/home/"));
});

it("opens the exact newly created application rather than the previous model", async () => {
  metadataNavigationFixture(async () => {
    const value = await catalogResponse().json();
    value.applicationAccess.workspaceAdministrator = true;
    return new Response(JSON.stringify(value));
  });
  const original = vi.mocked(fetch).getMockImplementation()!;
  const created = {
    workspaceId: "ws",
    applicationId: "scenario",
    name: "New scenario",
    status: "Active",
    enabledCapabilities: [],
    capabilityRevision: 0,
  };
  let committed = false;
  vi.mocked(fetch).mockImplementation(async (input, init) => {
    if (String(input) === "/api/workspace-application") {
      committed = true;
      return new Response(JSON.stringify(created));
    }
    const response = await original(input, init);
    if (committed && String(input).startsWith("/api/applications")) {
      const value = await response.json();
      value.applications.push(created);
      return new Response(JSON.stringify(value));
    }
    return response;
  });
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Applications" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Create application" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Create application" }));
  fireEvent.change(screen.getByLabelText("Stable application ID"), {
    target: { value: "scenario" },
  });
  fireEvent.change(screen.getByLabelText("Application name"), {
    target: { value: "New scenario" },
  });
  fireEvent.click(screen.getByLabelText(/I reviewed the workspace/));
  fireEvent.click(screen.getByRole("button", { name: "Create and open" }));
  expect(
    await screen.findByRole("heading", { name: "New scenario" }),
  ).toBeInTheDocument();
  await waitFor(() =>
    expect(window.location.hash).toBe(
      "#/overview/2?workspace=ws&application=scenario",
    ),
  );
  expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  confirm.mockRestore();
});

it("guards section changes and leaving metadata before unmounting dirty work", async () => {
  metadataNavigationFixture();
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Metadata" }));
  expect(
    await screen.findByText("Metadata section: dimensions"),
  ).toBeInTheDocument();
  const original = window.location.hash;
  act(() =>
    setUnsavedWork("metadata-test", "Unsaved account properties", true),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open account members" }));
  expect(
    screen.getByRole("alertdialog", { name: "Discard unsaved changes?" }),
  ).toBeInTheDocument();
  expect(window.location.hash).toBe(original);
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(screen.getByText("Metadata section: dimensions")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Open account members" }));
  fireEvent.click(screen.getByRole("button", { name: "Discard and continue" }));
  expect(
    await screen.findByText("Metadata section: members"),
  ).toBeInTheDocument();
  expect(window.location.hash).toContain(
    "workspace=ws&application=alpha&metadataSection=members&dimension=Account",
  );
  act(() => setUnsavedWork("metadata-test", "Unsaved member changes", true));
  fireEvent.click(screen.getByRole("button", { name: "Home" }));
  expect(
    screen.getByRole("alertdialog", { name: "Discard unsaved changes?" }),
  ).toBeInTheDocument();
  expect(screen.getByText("Metadata section: members")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(screen.getByText("Metadata section: members")).toBeInTheDocument();
});

it("restores the current metadata URL on cancelled Back and resumes Back after explicit discard", async () => {
  metadataNavigationFixture();
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Metadata" }));
  expect(
    await screen.findByText("Metadata section: dimensions"),
  ).toBeInTheDocument();
  const dimensionsRoute = window.location.hash;
  fireEvent.click(screen.getByRole("button", { name: "Open account members" }));
  expect(
    await screen.findByText("Metadata section: members"),
  ).toBeInTheDocument();
  const membersRoute = window.location.hash;
  act(() => setUnsavedWork("metadata-test", "Unsaved member changes", true));
  act(() => window.history.back());
  expect(
    await screen.findByRole("alertdialog", {
      name: "Discard unsaved changes?",
    }),
  ).toBeInTheDocument();
  await waitFor(() => expect(window.location.hash).toBe(membersRoute));
  expect(screen.getByText("Metadata section: members")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  act(() => window.history.back());
  expect(
    await screen.findByRole("alertdialog", {
      name: "Discard unsaved changes?",
    }),
  ).toBeInTheDocument();
  await waitFor(() => expect(window.location.hash).toBe(membersRoute));
  fireEvent.click(screen.getByRole("button", { name: "Discard and continue" }));
  await waitFor(() => expect(window.location.hash).toBe(dimensionsRoute));
  expect(
    await screen.findByText("Metadata section: dimensions"),
  ).toBeInTheDocument();
});

type PendingCatalogRead = {
  applicationId: string;
  signal?: AbortSignal;
  resolve: (response: Response) => void;
  reject: (error: unknown) => void;
};

function deferredCatalogFixture() {
  const reads: PendingCatalogRead[] = [];
  metadataNavigationFixture(
    (scope, signal) =>
      new Promise<Response>((resolve, reject) => {
        reads.push({
          applicationId: scope.applicationId,
          signal,
          resolve,
          reject,
        });
      }),
  );
  return reads;
}

function catalogResponse(role = "Administrator") {
  return new Response(
    JSON.stringify({
      applicationAccess: { role, workspaceAdministrator: false },
      enabledCapabilities: [],
      functions: { "metadata.dimension.list": {}, "metadata.member.list": {} },
      revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
    }),
  );
}

function openMetadataHash(application: string) {
  act(() => {
    window.history.replaceState(
      null,
      "",
      `#/metadata/0?workspace=ws&application=${application}&metadataSection=dimensions`,
    );
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  });
}

it.each(["cancelled request", "late error", "late success"])(
  "does not expose a superseded catalogue %s after switching application",
  async (outcome) => {
    const reads = deferredCatalogFixture();
    render(<App />);
    await waitFor(() => expect(reads).toHaveLength(1));
    expect(reads[0].applicationId).toBe("alpha");
    openMetadataHash("beta");
    await waitFor(() => expect(reads).toHaveLength(2));
    expect(reads[0].signal?.aborted).toBe(true);
    expect(reads[1].applicationId).toBe("beta");
    await act(async () => reads[1].resolve(catalogResponse()));
    expect(
      await screen.findByRole("button", { name: "Metadata" }),
    ).toBeInTheDocument();
    await act(async () => {
      if (outcome === "cancelled request")
        reads[0].reject(
          new DOMException("signal is aborted without reason", "AbortError"),
        );
      else if (outcome === "late error")
        reads[0].resolve(
          new Response(
            JSON.stringify({ code: "OLD_APPLICATION_CATALOG_ERROR" }),
            { status: 400 },
          ),
        );
      else reads[0].resolve(catalogResponse("Reader"));
    });
    expect(screen.getByText("Metadata application: beta")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Metadata" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("signal is aborted without reason"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("OLD_APPLICATION_CATALOG_ERROR"),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  },
);

it("shows a current catalogue error and removes its scope when another application opens", async () => {
  const reads = deferredCatalogFixture();
  render(<App />);
  await waitFor(() => expect(reads).toHaveLength(1));
  await act(async () =>
    reads[0].resolve(
      new Response(JSON.stringify({ code: "CURRENT_CATALOG_ERROR" }), {
        status: 400,
      }),
    ),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "CURRENT_CATALOG_ERROR",
  );
  openMetadataHash("beta");
  await waitFor(() => expect(reads).toHaveLength(2));
  expect(screen.queryByText("CURRENT_CATALOG_ERROR")).not.toBeInTheDocument();
  await act(async () => reads[1].resolve(catalogResponse()));
  expect(
    await screen.findByRole("button", { name: "Metadata" }),
  ).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it("ignores an initial platform catalogue cancellation during StrictMode remount", async () => {
  metadataNavigationFixture();
  const original = vi.mocked(fetch).getMockImplementation()!;
  let platformReads = 0;
  vi.mocked(fetch).mockImplementation((input, init) => {
    if (
      String(input) === "/api/platform/browser/catalog" &&
      ++platformReads === 1
    ) {
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () =>
            reject(
              new DOMException(
                "signal is aborted without reason",
                "AbortError",
              ),
            ),
          { once: true },
        );
      });
    }
    return original(input, init);
  });
  render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
  expect(
    await screen.findByRole("button", { name: "Metadata" }),
  ).toBeInTheDocument();
  expect(platformReads).toBe(2);
  expect(
    screen.queryByText("signal is aborted without reason"),
  ).not.toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it("hides server administration for an explicit unauthorized catalogue", async () => {
  metadataNavigationFixture();
  const original = vi.mocked(fetch).getMockImplementation()!;
  vi.mocked(fetch).mockImplementation((input, init) => {
    if (String(input) === "/api/platform/browser/catalog")
      return Promise.resolve(
        new Response(
          JSON.stringify({
            languageVersion: 2,
            authorized: false,
            functions: {},
          }),
        ),
      );
    return original(input, init);
  });
  render(<App />);
  expect(
    await screen.findByRole("button", { name: "Metadata" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Server Administration" }),
  ).not.toBeInTheDocument();
});

it("retains named hierarchy identity through refresh and same-dimension breadcrumbs", async () => {
  metadataNavigationFixture();
  window.history.replaceState(
    null,
    "",
    presentationRouteHash("metadata", 0, {
      workspaceId: "ws",
      applicationId: "alpha",
      metadataSection: "relationships",
      dimensionId: "Account",
      memberId: "Revenue",
      hierarchyId: "H_REPORTING",
    }),
  );
  expect(readPresentationRoute().focus.hierarchyId).toBe("H_REPORTING");
  render(<App />);
  await screen.findByText("Metadata section: relationships");
  const trail = within(screen.getByRole("navigation", { name: "Breadcrumb" }));
  expect(trail.getByRole("link", { name: "Account" })).toHaveAttribute(
    "href",
    expect.stringContaining("hierarchy=H_REPORTING"),
  );
  fireEvent.click(trail.getByRole("link", { name: "Account" }));
  await waitFor(() =>
    expect(readPresentationRoute().focus).toMatchObject({
      metadataSection: "members",
      hierarchyId: "H_REPORTING",
      memberId: undefined,
    }),
  );
  fireEvent.click(trail.getByRole("link", { name: "Metadata" }));
  await waitFor(() => expect(window.location.hash).not.toContain("hierarchy="));
});
