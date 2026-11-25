import { browserIdentityFixture } from "./test-setup";
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
  MetadataNavigationDimension,
  MetadataSection,
} from "./metadata-navigation";
import type { ApplicationCatalog, ApplicationSummary } from "./types";

it("keeps inspected tasks available while assigned work is pending and after its read fails", async () => {
  let finishWork: (value: Response) => void = () => undefined;
  const work = new Promise<Response>((resolve) => {
    finishWork = resolve;
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url) => {
      if (String(url) === "/api/tasks")
        return new Response(
          JSON.stringify({
            tasks: [
              {
                taskId: "one",
                sequence: 1,
                function: "facts.numeric.batch",
                status: "Running",
                progressState: "inProgress",
              },
            ],
            hasMore: false,
            nextSequence: 1,
          }),
        );
      return work;
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
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: { "application.workflow.worklist": {} },
        revisions: { metadata: 1, data: 2, policy: 3, security: 4, commit: 5 },
      }}
      go={vi.fn()}
    />,
  );
  await screen.findByText("facts.numeric.batch");
  expect(screen.getByText("Loading assigned work…")).toBeVisible();
  expect(
    screen.getByText("Ready for you").parentElement?.querySelector("strong"),
  ).toHaveTextContent(/^—$/);
  await act(async () =>
    finishWork(
      new Response(JSON.stringify({ error: "WORK_READ_FAILED" }), {
        status: 400,
      }),
    ),
  );
  expect(
    await screen.findByText("Assigned work could not be loaded."),
  ).toBeVisible();
  expect(screen.getByText("facts.numeric.batch")).toBeVisible();
  expect(
    screen.getByText("In progress").parentElement?.querySelector("strong"),
  ).toHaveTextContent(/^1$/);
});

vi.mock("./MetadataWorkspace", () => ({
  MetadataWorkspace: ({
    app,
    catalog,
    section,
    dimensionId,
    onNavigate,
    onDimensionsChange,
  }: {
    app?: ApplicationSummary;
    catalog: ApplicationCatalog | null;
    section: MetadataSection;
    dimensionId?: string;
    onNavigate: (destination: MetadataDestination) => void;
    onDimensionsChange: (
      dimensions: MetadataNavigationDimension[],
      metadataRevision: number,
    ) => void;
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
      <button
        onClick={() =>
          onDimensionsChange(
            [
              {
                dimension_id: "Account",
                name: "Current catalogue dimension",
                model_role: "Account",
                status: "Active",
              },
            ],
            catalog?.revisions.metadata ?? 0,
          )
        }
      >
        Publish metadata navigation
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
  expect(applicationPageVisible("security", reader)).toBe(false);
  const reviewer = {
    ...reader,
    applicationAccess: {
      role: "Assigned",
      authorizationModel: "group_assignments" as const,
      roles: ["Access Reviewer"],
      workspaceAdministrator: false,
    },
    functions: { "security.application.effective-access.list": {} },
  };
  expect(applicationPageVisible("security", reviewer)).toBe(true);
  for (const page of [
    "metadata",
    "rules",
    "grid",
    "administration",
    "monitor",
  ] as const)
    expect(applicationPageVisible(page, reviewer)).toBe(false);
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
    ["ApplicationSchedule", "schedule.read"],
  ] as const) {
    const artifactCatalog = {
      ...catalog,
      functions: {
        ...catalog.functions,
        [readFunction]: {
          availability: {
            version: 1,
            kind: "current-definition-owner",
            ownerFunction: "rules.numeric_sequence.template",
            status: "available",
            code: null,
          },
        },
      },
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
  expect(
    resolveWorkflowDestination(
      {
        kind: "Artifact",
        artifactKind: "ApplicationSequence",
        artifactId: "old-sequence",
        stateToken: "c".repeat(64),
        digest: "b".repeat(64),
      },
      { ...catalog, functions: { "rules.numeric_sequence.read": {} } },
    ),
  ).toMatchObject({ supported: false, code: "APPLICATION_FUNCTION_RETIRED" });
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
    code: "WORKFLOW_ARTIFACT_DESTINATION_UNAVAILABLE",
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
            hasMore: false,
            nextSequence: 0,
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
  fireEvent.click(
    screen.getByRole("button", { name: "Open activity Approve forecast" }),
  );
  expect(open).toHaveBeenCalledWith("flows", {
    workspaceId: "ws",
    applicationId: "app",
    occurrenceId: "occ-7",
    activityId: "approve",
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Open activity Workflow activity" }),
  );
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
            hasMore: false,
            nextSequence: 0,
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
    screen.getByRole("button", {
      name: "Open activity Prepare selected cube slice",
    }),
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
                sequence: 2,
                function: "facts.cube.aggregate.request",
                status: "Running",
                progressState: "inProgress",
                initiatorKind: "MCP agent",
              },
              {
                taskId: "task-2",
                sequence: 1,
                function: "facts.source.begin",
                status: "Failed",
                progressState: "attention",
                initiatorKind: "Human",
              },
            ],
            nextSequence: 1,
            hasMore: false,
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
  expect(await screen.findByText("facts.cube.aggregate.request")).toBeVisible();
  expect(
    screen.getByText(
      "The current application catalogue does not include assigned work.",
    ),
  ).toBeVisible();
  expect(
    screen.getByText("Ready for you").parentElement?.querySelector("strong"),
  ).toHaveTextContent(/^—$/);
  expect(screen.getByText("In progress")).toBeInTheDocument();
  expect(screen.getByText("Needs attention")).toBeInTheDocument();
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
            ...browserIdentityFixture(sessionSubject),
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
  expect(
    screen.getByText(
      "Page link copied. Unsaved or unresolved grid context is not included.",
    ),
  ).toBeInTheDocument();
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
    expect(
      screen.getByText(
        "The current application catalogue does not include assigned work.",
      ),
    ).toBeInTheDocument(),
  );
  expect(
    screen.getByRole("group", { name: "Filter work by state" }),
  ).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "All —" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  const unavailableWaiting = screen.getByRole("button", { name: "Waiting —" });
  expect(unavailableWaiting).toBeDisabled();
  fireEvent.click(unavailableWaiting);
  expect(unavailableWaiting).toHaveAttribute("aria-pressed", "false");
  expect(
    screen.queryByText("No work waiting on dependencies"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByText("No work is currently ready"),
  ).not.toBeInTheDocument();
  act(() => setUnsavedWork("test/offline-draft", "Unsaved grid value", true));
  sessionSubject = "replacement-owner";
  fireEvent(document, new Event("visibilitychange"));
  expect(await screen.findByText("Identity changed")).toBeInTheDocument();
  expect(
    screen.queryByRole("list", { name: "Unpublished browser work" }),
  ).not.toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Discard drafts and continue" }),
  );
  await waitFor(() =>
    expect(document.querySelector(".shell")).not.toHaveAttribute("inert"),
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
  act(() => setBrowserLifecycle("offline", "NETWORK_UNAVAILABLE"));
  expect(await screen.findByText("You are offline")).toBeInTheDocument();
  expect(
    screen.getByText(
      /Unconfirmed operations may have completed; reconnect and reconcile their original status/,
    ),
  ).toBeInTheDocument();
  expect(
    screen.queryByText(/nothing has been published/),
  ).not.toBeInTheDocument();
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
            ...browserIdentityFixture("designer"),
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
              "security.application.access.list": {},
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

it.each([650, 651, 684, 950, 951])(
  "keeps sidebar state and metadata destinations coherent at %ipx",
  async (width) => {
    metadataNavigationFixture();
    vi.stubGlobal("matchMedia", (query: string) => ({
      matches: width <= Number(/max-width: (\d+)px/.exec(query)?.[1]),
      media: query,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }));
    window.history.replaceState(
      null,
      "",
      "#/metadata/0?workspace=ws&application=alpha&metadataSection=members&dimension=Account",
    );
    render(<App />);
    await screen.findByText("Metadata application: alpha");
    const compact = width <= 950;
    const toggle = screen.getByRole("button", {
      name: compact ? "Expand sidebar" : "Collapse sidebar",
    });
    expect(toggle).toHaveAttribute("aria-expanded", String(!compact));
    if (compact) {
      expect(screen.queryByRole("button", { name: "Dimensions" })).toBeNull();
      fireEvent.click(toggle);
    }
    expect(
      await screen.findByRole("button", { name: "Dimensions" }),
    ).toBeVisible();
    if (width === 650) {
      const close = screen.getByRole("button", { name: "Close sidebar" });
      close.focus();
      fireEvent.click(close);
      expect(
        screen.getByRole("button", { name: "Expand sidebar" }),
      ).toHaveFocus();
      expect(screen.queryByRole("button", { name: "Dimensions" })).toBeNull();
      fireEvent.click(screen.getByRole("button", { name: "Expand sidebar" }));
    }
    const reference = screen.getByRole("button", {
      name: "Function reference",
    });
    reference.focus();
    fireEvent.click(reference);
    await screen.findByText("Metadata section: reference");
    expect(window.location.hash).toContain("application=alpha");
    expect(
      screen.getByRole("button", {
        name: compact ? "Expand sidebar" : "Collapse sidebar",
      }),
    ).toHaveAttribute("aria-expanded", String(!compact));
    if (compact)
      expect(
        screen.getByRole("button", { name: "Expand sidebar" }),
      ).toHaveFocus();
  },
);

it.each([
  {
    statuses: ["Cancelled", "Completed"],
    states: ["other", "other"],
    hasMore: true,
    running: "0",
    attention: "0",
  },
  {
    statuses: ["Running", "Failed"],
    states: ["inProgress", "attention"],
    hasMore: true,
    running: "1",
    attention: "1",
  },
  {
    statuses: ["InterruptRequested", "NeedsInspection"],
    states: ["attention", "attention"],
    hasMore: false,
    running: "0",
    attention: "2",
  },
])(
  "reports only inspected status counts for $statuses with hasMore=$hasMore",
  async ({ statuses, states, hasMore, running, attention }) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async (input: RequestInfo | URL) =>
          new Response(
            JSON.stringify(
              String(input) === "/api/tasks"
                ? {
                    hasMore,
                    nextSequence: 1,
                    tasks: statuses.map((status, index) => ({
                      taskId: `task-${index}`,
                      sequence: statuses.length - index,
                      function: "example.read",
                      status,
                      progressState: states[index],
                    })),
                  }
                : {
                    result: {
                      items: [{ activityId: "assigned" }],
                      nextCursor: "next-work-page",
                    },
                  },
            ),
          ),
      ),
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
          functions: { "application.workflow.worklist": {} },
          revisions: {
            metadata: 1,
            data: 1,
            policy: 1,
            security: 1,
            commit: 1,
          },
        }}
        go={vi.fn()}
      />,
    );
    await screen.findByText(/count matches in 2 inspected tasks/);
    expect(
      screen.getByText("In progress").parentElement?.querySelector("strong"),
    ).toHaveTextContent(new RegExp(`^${running}$`));
    expect(
      screen
        .getByText("Needs attention")
        .parentElement?.querySelector("strong"),
    ).toHaveTextContent(new RegExp(`^${attention}$`));
    expect(
      screen.getByText("Ready for you").parentElement?.querySelector("strong"),
    ).toHaveTextContent(/^1\+$/);
    expect(
      screen.getByText(
        hasMore
          ? /Their progress and attention counts are unknown/
          : /No further tasks were reported/,
      ),
    ).toBeInTheDocument();
  },
);

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

it("keeps an unavailable metadata destination at its exact application and restores it after revalidation", async () => {
  let role = "Reader";
  metadataNavigationFixture(async () => {
    const value = await catalogResponse().json();
    value.applicationAccess.role = role;
    value.functions["metadata.dimension.list"] = {};
    return Response.json(value);
  });
  const destination =
    "#/metadata/1?workspace=ws&application=beta&metadataSection=members&dimension=Account";
  window.history.replaceState(null, "", destination);
  render(<App />);
  expect(
    await screen.findByRole("heading", { name: "Metadata unavailable" }),
  ).toBeVisible();
  expect(window.location.hash).toBe(destination);
  expect(
    screen.getByRole("button", { name: "Open application overview" }),
  ).toBeVisible();
  expect(
    screen.queryByRole("region", { name: "Metadata navigation fixture" }),
  ).toBeNull();

  role = "Administrator";
  act(() => window.dispatchEvent(new Event("online")));
  expect(await screen.findByText("Metadata application: beta")).toBeVisible();
  expect(screen.getByText("Metadata dimension: Account")).toBeVisible();
  expect(window.location.hash).toBe(destination);
});

it.each(["security revision", "current access context"] as const)(
  "withdraws previous dimension names when the %s changes",
  async (change) => {
    let refreshed = false;
    metadataNavigationFixture(async () => {
      const value = await catalogResponse().json();
      value.functions["metadata.dimension.list"] = {};
      value.revisions.security =
        refreshed && change === "security revision" ? 2 : 1;
      value.accessContext =
        refreshed && change === "current access context"
          ? "b".repeat(64)
          : "a".repeat(64);
      return Response.json(value);
    });
    const destination =
      "#/metadata/0?workspace=ws&application=alpha&metadataSection=members&dimension=Account";
    window.history.replaceState(null, "", destination);
    render(<App />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Publish metadata navigation",
      }),
    );
    const breadcrumb = within(
      screen.getByRole("navigation", { name: "Breadcrumb" }),
    );
    expect(
      breadcrumb.getByRole("link", { name: "Current catalogue dimension" }),
    ).toBeVisible();

    refreshed = true;
    act(() => window.dispatchEvent(new Event("online")));
    await waitFor(() => expect(breadcrumb.getByText("Account")).toBeVisible());
    expect(breadcrumb.queryByText("Current catalogue dimension")).toBeNull();
    expect(breadcrumb.getByRole("link", { name: "Account" })).toBeVisible();
    expect(
      screen.queryByRole("button", {
        name: "Collapse Current catalogue dimension metadata",
      }),
    ).toBeNull();
    expect(window.location.hash).toBe(destination);
    fireEvent.click(
      screen.getByRole("button", { name: "Publish metadata navigation" }),
    );
    expect(
      breadcrumb.getByRole("link", { name: "Current catalogue dimension" }),
    ).toBeVisible();
  },
);

it.each([
  "overview",
  "grid",
  "data",
  "rules",
  "flows",
  "monitor",
  "security",
  "administration",
])(
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

it("rechecks the same Monitor reference when application authority changes", async () => {
  let downgraded = false;
  let holdPrevious = false;
  metadataNavigationFixture(async () => {
    const value = await catalogResponse().json();
    value.applicationAccess.role = downgraded ? "Reader" : "Administrator";
    value.revisions.security = downgraded ? 2 : 1;
    return new Response(JSON.stringify(value));
  });
  const fixture = vi.mocked(fetch).getMockImplementation()!;
  const task = {
    taskId: "exact-monitor-origin",
    sequence: 1,
    sourceFamily: "Job",
    function: "previously.visible.task",
    status: "Running",
    progressState: "inProgress",
    latestEvent: null,
  };
  const held: Array<{ signal?: AbortSignal | null; settle: () => void }> = [];
  const currentReads: string[] = [];
  vi.mocked(fetch).mockImplementation(async (input, init) => {
    const path = String(input);
    if (path === "/api/events")
      return new Promise<Response>((resolve) => {
        held.push({
          signal: init?.signal,
          settle: () =>
            resolve(
              new Response(
                JSON.stringify({
                  events: [
                    {
                      sequence: 1,
                      job_id: "a".repeat(32),
                      status: "private-job-state",
                    },
                  ],
                  nextSequence: 1,
                  hasMore: false,
                }),
              ),
            ),
        });
      });
    if (path !== "/api/tasks" && path !== "/api/task")
      return fixture(input, init);
    const body = JSON.parse(String(init?.body));
    expect(body.applicationId).toBe("alpha");
    const result = () =>
      new Response(
        JSON.stringify(
          path === "/api/tasks"
            ? {
                tasks: [task],
                nextSequence: 1,
                hasMore: false,
              }
            : task,
        ),
      );
    if (!downgraded && holdPrevious)
      return new Promise<Response>((resolve) => {
        held.push({ signal: init?.signal, settle: () => resolve(result()) });
      });
    if (!downgraded) return result();
    currentReads.push(path);
    return path === "/api/tasks"
      ? new Response(
          JSON.stringify({ tasks: [], nextSequence: 0, hasMore: false }),
        )
      : new Response(JSON.stringify({ code: "TASK_UNAVAILABLE" }), {
          status: 403,
        });
  });
  window.history.replaceState(
    null,
    "",
    "#/monitor/0?workspace=ws&application=alpha&task=exact-monitor-origin",
  );
  render(<App />);
  await screen.findByRole("region", { name: "Client handoff" });
  holdPrevious = true;
  fireEvent.click(screen.getByRole("button", { name: "Show jobs" }));
  const refresh = screen.getByRole("button", { name: "Refresh" });
  refresh.focus();
  fireEvent.click(refresh);
  await waitFor(() => expect(held).toHaveLength(3));
  downgraded = true;
  act(() => window.dispatchEvent(new Event("online")));
  await waitFor(() =>
    expect(currentReads).toEqual(["/api/tasks", "/api/task"]),
  );
  expect(window.location.hash).toContain("task=exact-monitor-origin");
  expect(screen.queryByRole("region", { name: "Client handoff" })).toBeNull();
  expect(held.every(({ signal }) => signal?.aborted)).toBe(true);
  await act(async () => held.forEach(({ settle }) => settle()));
  expect(await screen.findByText("TASK_UNAVAILABLE")).toBeVisible();
  expect(screen.queryByText(task.function)).toBeNull();
  expect(screen.queryByText("private-job-state")).toBeNull();
  expect(
    screen.queryByRole("complementary", { name: "Selected task detail" }),
  ).toBeNull();
  expect(document.getElementById("main-content")).toHaveFocus();
});

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

it.each([
  { surface: "search", removed: false },
  { surface: "search", removed: true },
  { surface: "workspace selector", removed: false },
  { surface: "workspace selector", removed: true },
])(
  "preserves the application chosen in $surface before inventory revalidation (target removed: $removed)",
  async ({ surface, removed }) => {
    metadataNavigationFixture();
    const original = vi.mocked(fetch).getMockImplementation()!;
    const current = {
      workspaceId: "a",
      applicationId: "plan",
      name: "Current model",
      status: "Active",
    };
    const target = { ...current, workspaceId: "c", name: "Requested model" };
    const alternative = { ...current, workspaceId: "b", name: "Another model" };
    let holdListing = false;
    let releaseListing: (() => void) | undefined;
    vi.mocked(fetch).mockImplementation(async (input, init) => {
      if (String(input) !== "/api/applications") return original(input, init);
      const result = (applications: (typeof current)[]) =>
        new Response(JSON.stringify({ applications, nextAfter: null }));
      if (!holdListing) return result([current, target]);
      return new Promise<Response>((resolve) => {
        releaseListing = () =>
          resolve(
            result(
              removed ? [current, alternative] : [current, alternative, target],
            ),
          );
      });
    });
    window.history.replaceState(
      null,
      "",
      "#/overview/0?workspace=a&application=plan",
    );
    render(<App />);
    await screen.findByRole("heading", { name: current.name });
    if (surface === "workspace selector")
      fireEvent.click(screen.getByRole("button", { name: "Applications" }));
    act(() => setUnsavedWork("exact-switch", "Unsubmitted calculation", true));
    if (surface === "search") {
      fireEvent.click(screen.getByRole("button", { name: "Search" }));
      const search = screen.getByRole("dialog", { name: "Search Open EPM" });
      fireEvent.change(within(search).getByRole("textbox"), {
        target: { value: target.name },
      });
      fireEvent.click(
        within(search).getByRole("button", { name: /Requested model/ }),
      );
    } else {
      fireEvent.change(await screen.findByLabelText("Workspace selector"), {
        target: { value: target.workspaceId },
      });
    }
    const confirm = await screen.findByRole("button", {
      name: "Discard and continue",
    });
    holdListing = true;
    act(() => window.dispatchEvent(new Event("online")));
    await waitFor(() => expect(releaseListing).toBeDefined());
    await act(async () => releaseListing!());

    const previousRequests = vi.mocked(fetch).mock.calls.length;
    fireEvent.click(confirm);
    expect(
      await screen.findByRole("heading", {
        name: removed
          ? "Application unavailable"
          : surface === "search"
            ? target.name
            : target.workspaceId,
      }),
    ).toBeVisible();
    expect(readPresentationRoute().focus).toMatchObject({
      workspaceId: target.workspaceId,
      applicationId: target.applicationId,
    });
    if (!removed) expect(readPresentationRoute().applicationIndex).toBe(2);
    expect(
      screen.queryByRole("heading", { name: alternative.name }),
    ).toBeNull();
    const catalogCalls = vi
      .mocked(fetch)
      .mock.calls.slice(previousRequests)
      .filter(([url]) => String(url) === "/api/catalog")
      .map(([, init]) => JSON.parse(String(init?.body)).workspaceId);
    expect(catalogCalls).toEqual(removed ? [] : [target.workspaceId]);
    if (surface === "search")
      expect(document.getElementById("main-content")).toHaveFocus();
    if (removed) {
      fireEvent.click(
        within(screen.getByRole("main")).getByRole("button", {
          name: "Choose application",
        }),
      );
      expect(await screen.findByLabelText("Workspace selector")).toBeVisible();
      expect(readPresentationRoute().focus.workspaceId).toBeUndefined();
    }
  },
);

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
    kind: "multidimensional",
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

it.each([
  ["an invalid successful response", () => new Response("{}")],
  [
    "a gateway refusal",
    () =>
      new Response(JSON.stringify({ code: "WEB_ORIGIN_REQUIRED" }), {
        status: 403,
      }),
  ],
] as const)("offers an exact context retry after %s", async (_, failure) => {
  const reads = deferredCatalogFixture();
  openMetadataHash("alpha");
  render(<App />);
  await waitFor(() => expect(reads).toHaveLength(1));
  expect(screen.getByText("Checking the application context…")).toBeVisible();
  expect(screen.queryByText("Metadata application: alpha")).toBeNull();
  await act(async () => reads[0].resolve(failure()));
  expect(
    await screen.findByRole("heading", {
      name: "Application context unavailable",
    }),
  ).toBeVisible();
  expect(screen.queryByText("Checking the application context…")).toBeNull();
  expect(screen.queryByText(/linked application is unavailable/)).toBeNull();
  expect(window.location.hash).toContain("application=alpha");
  fireEvent.click(screen.getByRole("button", { name: "Retry context check" }));
  await waitFor(() => expect(reads).toHaveLength(2));
  expect(reads[1].applicationId).toBe("alpha");
  expect(screen.getByText("Checking the application context…")).toBeVisible();
  await act(async () => reads[1].resolve(catalogResponse()));
  expect(await screen.findByText("Metadata application: alpha")).toBeVisible();
  expect(screen.queryByRole("alert")).toBeNull();
});

it("ignores an initial session identity cancellation during StrictMode remount", async () => {
  metadataNavigationFixture();
  const original = vi.mocked(fetch).getMockImplementation()!;
  let sessionReads = 0;
  vi.mocked(fetch).mockImplementation((input, init) => {
    if (String(input) === "/api/session-identity" && ++sessionReads === 1) {
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
  expect(sessionReads).toBe(2);
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

it("offers only server and global destinations to a directory operator with no application grants", async () => {
  metadataNavigationFixture();
  const original = vi.mocked(fetch).getMockImplementation()!;
  vi.mocked(fetch).mockImplementation((input, init) => {
    if (String(input) === "/api/applications")
      return Promise.resolve(
        Response.json({ applications: [], nextAfter: null }),
      );
    if (String(input) === "/api/platform/browser/catalog")
      return Promise.resolve(
        Response.json({
          languageVersion: 2,
          authorized: true,
          functions: { "identity.native-user.list": {} },
        }),
      );
    return original(input, init);
  });
  render(<App />);
  expect(
    await screen.findByRole("heading", { name: "No applications available" }),
  ).toBeVisible();
  expect(
    screen.getByRole("button", { name: "Open Server Administration" }),
  ).toBeVisible();
  expect(
    screen.queryByRole("navigation", { name: "Application navigation" }),
  ).toBeNull();
  expect(screen.queryByRole("button", { name: "Notifications" })).toBeNull();
  expect(screen.queryByRole("button", { name: /Explore data/ })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Search" }));
  const query = screen.getByRole("textbox", {
    name: "Search applications, pages or authorized functions",
  });
  const dialog = screen.getByRole("dialog", { name: "Search Open EPM" });
  const status = within(dialog).getByRole("status");
  fireEvent.change(query, { target: { value: "Grid" } });
  expect(status).toHaveTextContent("No accessible result matches your search.");
  fireEvent.change(query, { target: { value: "Server Administration" } });
  expect(status).toBeEmptyDOMElement();
  fireEvent.click(
    within(screen.getByRole("dialog", { name: "Search Open EPM" })).getByRole(
      "button",
      { name: /Server Administration/ },
    ),
  );
  expect(
    await screen.findByRole("heading", { name: "Identity directory" }),
  ).toBeVisible();
  expect(document.querySelector("#main-content")).toHaveFocus();
  expect(vi.mocked(fetch).mock.calls.map(([url]) => url)).not.toContain(
    "/api/tasks",
  );
  expect(vi.mocked(fetch).mock.calls.map(([url]) => url)).not.toContain(
    "/api/catalog",
  );
});

it("restarts open notifications on a same-application change in authority", async () => {
  let downgraded = false;
  metadataNavigationFixture(async () => {
    const value = await catalogResponse(
      downgraded ? "Reader" : "Administrator",
    ).json();
    value.revisions.security = downgraded ? 2 : 1;
    return Response.json(value);
  });
  const original = vi.mocked(fetch).getMockImplementation()!;
  let finish!: (response: Response) => void;
  vi.mocked(fetch).mockImplementation(async (input, init) => {
    if (String(input) !== "/api/tasks") return original(input, init);
    if (downgraded)
      return new Promise<Response>((resolve) => {
        finish = resolve;
      });
    return Response.json({
      tasks: [
        {
          taskId: "old-admin-notice",
          function: "admin-only notice",
          sourceFamily: "Job",
          status: "Failed",
          progressState: "attention",
          sequence: 9,
        },
      ],
      nextSequence: 9,
      hasMore: false,
    });
  });
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Notifications" }));
  expect(await screen.findByText("admin-only notice")).toBeVisible();
  downgraded = true;
  act(() => window.dispatchEvent(new Event("online")));
  await waitFor(() => expect(finish).toBeDefined());
  const panel = await screen.findByRole("dialog", { name: "Notifications" });
  expect(within(panel).queryByText("admin-only notice")).toBeNull();
  expect(within(panel).getByRole("status")).toHaveTextContent(
    "Reading task status",
  );
  await act(async () =>
    finish(Response.json({ tasks: [], nextSequence: 0, hasMore: false })),
  );
  expect(
    await screen.findByText("No task currently needs attention"),
  ).toBeVisible();
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

it("keeps a visible application cue in the compact rail and names every shell destination", async () => {
  metadataNavigationFixture();
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: query === "(max-width: 950px)",
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
  window.history.replaceState(
    null,
    "",
    "#/metadata/0?workspace=ws&application=alpha&metadataSection=members&dimension=Account",
  );
  const { container } = render(<App />);
  await screen.findByText("Metadata application: alpha");
  expect(
    container.querySelector(".application-switcher-compact-label"),
  ).toHaveTextContent("Choose application");
  expect(container.querySelector(".sidebar-toggle-label")).toHaveTextContent(
    "Menu",
  );
  for (const control of container.querySelectorAll(
    ".sidebar button, .topbar button, .topbar nav a",
  )) {
    expect(control).toHaveAccessibleName();
  }
});

it("returns compact-rail focus before crossing into the off-canvas sidebar", async () => {
  metadataNavigationFixture();
  const listeners = new Map<string, (event: { matches: boolean }) => void>();
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: query === "(max-width: 950px)",
    media: query,
    addEventListener: (
      _event: string,
      listener: (event: { matches: boolean }) => void,
    ) => listeners.set(query, listener),
    removeEventListener: vi.fn(),
  }));
  window.history.replaceState(
    null,
    "",
    "#/metadata/0?workspace=ws&application=alpha&metadataSection=members&dimension=Account",
  );
  render(<App />);
  await screen.findByText("Metadata application: alpha");
  const destination = within(
    screen.getByRole("navigation", { name: "Global navigation" }),
  ).getByRole("button", { name: "Applications" });
  destination.focus();
  expect(destination).toHaveFocus();
  act(() => listeners.get("(max-width: 650px)")?.({ matches: true }));
  expect(screen.getByRole("button", { name: "Expand sidebar" })).toHaveFocus();
  expect(window.location.hash).toContain("#/metadata/");
});

function mobileNavigationFixture() {
  metadataNavigationFixture();
  const listeners = new Map<string, (event: { matches: boolean }) => void>();
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: true,
    media: query,
    addEventListener: (
      _event: string,
      listener: (event: { matches: boolean }) => void,
    ) => listeners.set(query, listener),
    removeEventListener: vi.fn(),
  }));
  window.history.replaceState(
    null,
    "",
    "#/metadata/0?workspace=ws&application=alpha&metadataSection=members&dimension=Account",
  );
  return listeners;
}

it("mobile navigation moves focus inside, isolates background and contains keyboard focus", async () => {
  mobileNavigationFixture();
  const { container } = render(<App />);
  await screen.findByText("Metadata application: alpha");
  const menu = screen.getByRole("button", { name: "Expand sidebar" });
  menu.focus();
  fireEvent.click(menu);
  const modal = screen.getByRole("dialog", { name: "Application navigation" });
  expect(modal).toHaveAttribute("aria-modal", "true");
  const close = within(modal).getByRole("button", { name: "Close sidebar" });
  expect(close).toHaveFocus();
  for (const node of container.querySelectorAll(".topbar, main, .skip-link"))
    expect(node).toHaveAttribute("inert");
  const controls = within(modal).getAllByRole("button");
  const last = controls.at(-1)!;
  fireEvent.keyDown(close, { key: "Tab", shiftKey: true });
  expect(last).toHaveFocus();
  fireEvent.keyDown(last, { key: "Tab" });
  expect(close).toHaveFocus();
  fireEvent.keyDown(close, { key: "k", ctrlKey: true });
  expect(
    screen.queryByRole("dialog", { name: "Search Open EPM" }),
  ).not.toBeInTheDocument();
  fireEvent.keyDown(close, { key: "Escape" });
  expect(menu).toHaveFocus();
  expect(
    screen.queryByRole("dialog", { name: "Application navigation" }),
  ).not.toBeInTheDocument();
  for (const node of container.querySelectorAll(".topbar, main, .skip-link"))
    expect(node).not.toHaveAttribute("inert");
});

it("mobile navigation closes on resize with focus restored and desktop rail unchanged", async () => {
  const listeners = mobileNavigationFixture();
  const { container } = render(<App />);
  await screen.findByText("Metadata application: alpha");
  const menu = screen.getByRole("button", { name: "Expand sidebar" });
  fireEvent.click(menu);
  expect(screen.getByRole("button", { name: "Close sidebar" })).toHaveFocus();
  act(() => listeners.get("(max-width: 650px)")?.({ matches: false }));
  expect(menu).toHaveFocus();
  expect(
    screen.queryByRole("dialog", { name: "Application navigation" }),
  ).not.toBeInTheDocument();
  fireEvent.click(menu);
  expect(container.querySelector(".shell")).not.toHaveClass("collapsed");
  expect(container.querySelector(".sidebar")).not.toHaveAttribute("aria-modal");
  expect(container.querySelector("main")).not.toHaveAttribute("inert");
});

it("mobile navigation gives discard confirmation priority and restores a valid trigger", async () => {
  const listeners = mobileNavigationFixture();
  const { container } = render(<App />);
  await screen.findByText("Metadata application: alpha");
  const menu = screen.getByRole("button", { name: "Expand sidebar" });
  fireEvent.click(menu);
  act(() => setUnsavedWork("mobile-guard", "Unsaved navigation fixture", true));
  const target = within(
    screen.getByRole("navigation", { name: "Global navigation" }),
  ).getByRole("button", { name: "Applications" });
  target.focus();
  fireEvent.click(target);
  const dialog = await screen.findByRole("alertdialog");
  const keep = within(dialog).getByRole("button", { name: "Keep editing" });
  expect(keep).toHaveFocus();
  expect(container.querySelector(".sidebar")).toHaveAttribute("inert");
  expect(container.querySelector(".sidebar")).not.toHaveAttribute("aria-modal");
  fireEvent.keyDown(keep, { key: "Tab", shiftKey: true });
  expect(
    within(dialog).getByRole("button", { name: "Discard and continue" }),
  ).toHaveFocus();
  fireEvent.keyDown(document.activeElement!, { key: "Escape" });
  expect(target).toHaveFocus();
  expect(container.querySelector(".sidebar")).not.toHaveAttribute("inert");
  expect(container.querySelector(".sidebar")).toHaveAttribute(
    "aria-modal",
    "true",
  );
  fireEvent.click(target);
  act(() => listeners.get("(max-width: 650px)")?.({ matches: false }));
  expect(screen.getByRole("button", { name: "Keep editing" })).toHaveFocus();
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(menu).toHaveFocus();
  act(() => listeners.get("(max-width: 650px)")?.({ matches: true }));
  fireEvent.click(menu);
  target.focus();
  fireEvent.click(target);
  fireEvent.click(screen.getByRole("button", { name: "Discard and continue" }));
  await waitFor(() =>
    expect(window.location.hash).toContain("#/applications/"),
  );
  expect(menu).toHaveFocus();
  expect(container.querySelector("main")).not.toHaveAttribute("inert");
  expect(container.querySelector(".shell")).toHaveClass("collapsed");
});

it("preserves the exact placement in a scoped metadata route and clears it in unrelated navigation", () => {
  for (const metadataSection of ["relationships", "tree"] as const) {
    const focus = {
      workspaceId: "ws north",
      applicationId: "forecast-2027",
      metadataSection,
      dimensionId: "Account",
      memberId: "Cash",
      hierarchyId: "Reporting & legal",
      relationshipId: "Cash / Flow",
    };
    window.history.replaceState(
      null,
      "",
      presentationRouteHash("metadata", 0, focus),
    );
    expect(readPresentationRoute().focus).toMatchObject(focus);
    window.history.replaceState(
      null,
      "",
      presentationRouteHash("metadata", 1, {
        workspaceId: "ws south",
        applicationId: "other",
        metadataSection: "relationships",
        dimensionId: "Entity",
      }),
    );
    expect(readPresentationRoute().focus.relationshipId).toBeUndefined();
    expect(window.location.hash).not.toContain("relationship=");
  }
});

it("opens an administered workspace route when the identity has zero admitted applications", async () => {
  metadataNavigationFixture();
  const original = vi.mocked(fetch).getMockImplementation()!;
  vi.mocked(fetch).mockImplementation((input, init) => {
    const url = String(input);
    if (url === "/api/applications")
      return Promise.resolve(
        Response.json({ applications: [], nextAfter: null }),
      );
    if (url === "/api/applications?view=managedWorkspaces")
      return Promise.resolve(
        Response.json({
          workspaces: [
            { workspaceId: "empty", workspaceName: "Empty workspace" },
          ],
          nextAfter: null,
        }),
      );
    if (url === "/api/workspace-catalog")
      return Promise.resolve(
        Response.json({
          workspaceId: "empty",
          functions: [
            "security.workspace.people.list",
            "security.workspace.person-applications.list",
            "security.workspace.bootstrap-groups.list",
            "workspace.application.create",
          ],
        }),
      );
    return original(input, init);
  });
  window.history.replaceState({}, "", "#/applications/0?workspace=empty");
  render(<App />);
  expect(
    await screen.findByRole("heading", { name: "Empty workspace" }),
  ).toBeInTheDocument();
  expect(
    await screen.findByRole("button", {
      name: "Review people and administrators",
    }),
  ).toBeEnabled();
  expect(
    screen.queryByRole("heading", { name: "Application unavailable" }),
  ).toBeNull();
  expect(
    screen.getByRole("button", { name: "Create application" }),
  ).toBeEnabled();
  expect(
    vi.mocked(fetch).mock.calls.map((call) => String(call[0])),
  ).not.toContain("/api/catalog");
});
