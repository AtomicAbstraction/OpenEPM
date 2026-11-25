import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  Applications,
  applicationCreateProgram,
  applicationPreferenceKey,
} from "./Applications";
import { applicationPurgeRecoveryKey } from "./ApplicationPurge";
import type { ApplicationCatalog } from "./types";
import {
  resetUnsavedWorkForTests,
  setUnsavedWork,
  unsavedWorkSnapshot,
} from "./unsaved-work";

const applications = [
  {
    workspaceId: "ws-pilot",
    applicationId: "pilot-fpna",
    name: "Pilot FP&A",
    status: "Active",
    kind: "blank",
  },
];

const catalog = {
  applicationAccess: {
    role: "Administrator",
    workspaceAdministrator: true,
  },
  enabledCapabilities: [],
  functions: {},
  revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
};

afterEach(() => {
  resetUnsavedWorkForTests();
  window.localStorage.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it("passes the verified issuer through to workspace deletion recovery", () => {
  const issuer = "https://authority.example";
  const key = applicationPurgeRecoveryKey(issuer, "same-subject", "ws-pilot")!;
  const witness = JSON.stringify({
    workspaceId: "ws-pilot",
    idempotencyKey: "original-purge-operation",
    program: {
      languageVersion: 2,
      function: "workspace.application.purge.apply",
      arguments: {
        applicationId: "original-target",
        createdAt: "2026-11-08T11:00:00Z",
      },
    },
  });
  localStorage.setItem(key, witness);
  const props = {
    applications,
    selected: 0,
    catalog,
    issuer,
    subject: "same-subject",
    choose: vi.fn(),
    created: vi.fn(),
    deleted: vi.fn(),
  };
  const view = render(<Applications {...props} />);
  expect(screen.getByLabelText("Application ID to delete")).toHaveValue(
    "original-target",
  );
  view.rerender(
    <Applications {...props} issuer="https://other-authority.example" />,
  );
  expect(screen.getByLabelText("Application ID to delete")).toHaveValue(
    "pilot-fpna",
  );
  expect(screen.getByLabelText("Application ID to delete")).toBeEnabled();
  expect(screen.queryByText(/original-target/)).not.toBeInTheDocument();
  expect(localStorage.getItem(key)).toBe(witness);
});

it("retains the committed application when opening fails and retries without another create", async () => {
  const application = {
    workspaceId: "ws-pilot",
    applicationId: "model-2027",
    name: "Model 2027",
    kind: "multidimensional",
    status: "Active",
    enabledCapabilities: [],
    capabilityRevision: 0,
  };
  const otherDraft = { id: "another-editor", label: "Unsaved grid values" };
  setUnsavedWork(otherDraft.id, otherDraft.label, true);
  const created = vi.fn(async () => {
    expect(unsavedWorkSnapshot()).toEqual([otherDraft]);
    if (created.mock.calls.length === 1)
      throw new Error("Catalogue refresh unavailable");
  });
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  const fetch = vi.fn(async () => new Response(JSON.stringify(application)));
  vi.stubGlobal("fetch", fetch);
  render(
    <Applications
      applications={applications}
      selected={0}
      catalog={catalog}
      choose={vi.fn()}
      created={created}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Create application" }));
  fireEvent.change(screen.getByLabelText("Stable application ID"), {
    target: { value: "model-2027" },
  });
  fireEvent.change(screen.getByLabelText("Application name"), {
    target: { value: "Model 2027" },
  });
  fireEvent.click(screen.getByLabelText(/I reviewed the workspace/));
  fireEvent.click(screen.getByRole("button", { name: "Create and open" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "The application was created, but it could not be opened: Catalogue refresh unavailable",
  );
  expect(
    screen.getByRole("heading", { name: "Application created" }),
  ).toBeVisible();
  expect(screen.getByRole("status")).toHaveTextContent(
    "Model 2027 (ws-pilot / model-2027) was created successfully.",
  );
  expect(
    screen.queryByRole("button", { name: "Create and open" }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Create application" }),
  ).toBeDisabled();
  expect(unsavedWorkSnapshot()).toEqual([otherDraft]);
  fireEvent.click(screen.getByRole("button", { name: "Refresh and open" }));
  await waitFor(() =>
    expect(screen.getByRole("status")).toHaveTextContent(
      "Model 2027 was created and opened.",
    ),
  );
  expect(created).toHaveBeenCalledTimes(2);
  expect(created).toHaveBeenNthCalledWith(
    1,
    application,
    expect.any(AbortSignal),
    true,
  );
  expect(created).toHaveBeenNthCalledWith(
    2,
    application,
    expect.any(AbortSignal),
    true,
  );
  expect(fetch).toHaveBeenCalledOnce();
  expect(confirm).toHaveBeenCalledOnce();
  expect(
    screen.getByRole("button", { name: "Create application" }),
  ).toBeEnabled();
});

it("restores an unconfirmed creation after navigation and replays only its original request", async () => {
  const application = {
    workspaceId: "ws-pilot",
    applicationId: "capacity",
    name: "Capacity planning",
    kind: "multidimensional",
    status: "Active",
    enabledCapabilities: [],
    capabilityRevision: 0,
  };
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  const sent: unknown[] = [];
  const fetch = vi.fn(async (path: string, init: RequestInit) => {
    expect(path).toBe("/api/workspace-application");
    sent.push(JSON.parse(String(init.body)));
    if (sent.length === 1) throw new TypeError("Response interrupted");
    if (sent.length === 2)
      return Response.json({ ...application, applicationId: "other" });
    return Response.json(application);
  });
  vi.stubGlobal("fetch", fetch);
  const props = {
    applications,
    selected: 0,
    catalog,
    issuer: "https://authority.example",
    subject: "original-owner",
    choose: vi.fn(),
    created: vi.fn(async () => {}),
  };
  const first = render(<Applications {...props} />);
  fireEvent.click(screen.getByRole("button", { name: "Create application" }));
  fireEvent.change(screen.getByLabelText("Stable application ID"), {
    target: { value: "capacity" },
  });
  fireEvent.change(screen.getByLabelText("Application name"), {
    target: { value: "Capacity planning" },
  });
  fireEvent.click(
    screen.getByRole("checkbox", { name: /^I reviewed the workspace/ }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Create and open" }));
  expect(
    await screen.findByRole("heading", {
      name: "Application creation unconfirmed",
    }),
  ).toBeVisible();
  expect(
    screen.getByRole("button", { name: "Create application" }),
  ).toBeDisabled();
  expect(
    screen.queryByRole("textbox", { name: "Application name" }),
  ).not.toBeInTheDocument();
  first.unmount();

  const other = render(
    <Applications {...props} issuer="https://other-authority.example" />,
  );
  expect(
    screen.queryByText("Capacity planning (capacity)"),
  ).not.toBeInTheDocument();
  other.unmount();
  const returned = render(<Applications {...props} />);
  const replay = await screen.findByRole("button", {
    name: "Retry original creation",
  });
  fireEvent.click(replay);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "could not confirm the original application",
  );
  expect(props.created).not.toHaveBeenCalled();
  returned.rerender(
    <Applications
      {...props}
      catalog={{
        ...catalog,
        applicationAccess: {
          ...catalog.applicationAccess,
          workspaceAdministrator: false,
        },
      }}
    />,
  );
  expect(replay).toBeDisabled();
  returned.rerender(<Applications {...props} />);
  fireEvent.click(replay);
  await waitFor(() => expect(props.created).toHaveBeenCalledOnce());
  expect(props.created).toHaveBeenCalledWith(
    application,
    expect.any(AbortSignal),
    false,
  );
  expect(
    screen.queryByRole("button", { name: "Retry original creation" }),
  ).not.toBeInTheDocument();
  expect(confirm).toHaveBeenCalledOnce();
  expect(sent).toHaveLength(3);
  expect(sent[1]).toEqual(sent[0]);
  expect(sent[2]).toEqual(sent[0]);
});

it("requires another review and a new identity after a definitive creation refusal", async () => {
  const send = vi.fn(async (_path: string, _init: RequestInit) =>
    Response.json({ code: "APPLICATION_ID_OR_NAME_EXISTS" }, { status: 409 }),
  );
  vi.stubGlobal("fetch", send);
  vi.spyOn(window, "confirm").mockReturnValue(true);
  render(
    <Applications
      applications={applications}
      selected={0}
      catalog={catalog}
      choose={vi.fn()}
      created={vi.fn()}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Create application" }));
  fireEvent.change(screen.getByLabelText("Stable application ID"), {
    target: { value: "capacity" },
  });
  const name = () => screen.getByLabelText("Application name");
  const review = () =>
    screen.getByRole("checkbox", { name: /^I reviewed the workspace/ });
  const submit = () => screen.getByRole("button", { name: "Create and open" });
  fireEvent.change(name(), { target: { value: "Capacity A" } });
  fireEvent.click(review());
  fireEvent.click(submit());
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "APPLICATION_ID_OR_NAME_EXISTS",
  );
  expect(
    screen.queryByRole("button", { name: "Retry original creation" }),
  ).not.toBeInTheDocument();
  fireEvent.change(name(), { target: { value: "Capacity B" } });
  expect(review()).not.toBeChecked();
  expect(submit()).toBeDisabled();
  fireEvent.click(review());
  fireEvent.click(submit());
  await waitFor(() => expect(send).toHaveBeenCalledTimes(2));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "APPLICATION_ID_OR_NAME_EXISTS",
  );
  const [first, second] = send.mock.calls.map(([, init]) =>
    JSON.parse(String(init.body)),
  );
  expect(first.idempotencyKey).not.toBe(second.idempotencyKey);
  expect(second.program.arguments.name).toBe("Capacity B");
});

it("filters the authoritative application catalogue without changing access", () => {
  render(
    <Applications
      applications={[
        ...applications,
        {
          workspaceId: "ws-forecast",
          applicationId: "rolling-plan",
          name: "Rolling Forecast",
          status: "Active",
          kind: "blank",
        },
      ]}
      selected={1}
      catalog={catalog}
      subject="owner-subject"
      choose={vi.fn()}
      created={vi.fn()}
    />,
  );
  fireEvent.change(screen.getByLabelText("Search applications"), {
    target: { value: "forecast" },
  });
  expect(
    screen.getByRole("button", { name: "Open Rolling Forecast" }),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Open Pilot FP&A" }),
  ).not.toBeInTheDocument();
  expect(screen.getByText(/1 of 2 applications shown/)).toBeInTheDocument();
});

it("stores identity-scoped favorites without opening the application", () => {
  const choose = vi.fn();
  render(
    <Applications
      applications={applications}
      selected={0}
      catalog={catalog}
      subject="owner-subject"
      choose={choose}
      created={vi.fn()}
    />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Add Pilot FP&A to favorites" }),
  );
  expect(choose).not.toHaveBeenCalled();
  expect(
    screen.getByRole("button", { name: "Remove Pilot FP&A from favorites" }),
  ).toHaveAttribute("aria-pressed", "true");
  expect(
    JSON.parse(
      window.localStorage.getItem(applicationPreferenceKey("owner-subject")) ||
        "{}",
    ),
  ).toEqual({ favorites: ["ws-pilot/pilot-fpna"], recent: [] });
  fireEvent.click(screen.getByRole("button", { name: "Favorites (1)" }));
  expect(screen.getByRole("button", { name: "Open Pilot FP&A" })).toBeVisible();
});

it("records an explicit open as recent and preserves the original catalogue index", () => {
  const choose = vi.fn();
  const expanded = [
    ...applications,
    {
      workspaceId: "ws-forecast",
      applicationId: "rolling-plan",
      name: "Rolling Forecast",
      status: "Active",
      kind: "blank",
    },
  ];
  render(
    <Applications
      applications={expanded}
      selected={1}
      catalog={catalog}
      subject="owner-subject"
      choose={choose}
      created={vi.fn()}
    />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Open Rolling Forecast" }),
  );
  expect(choose).toHaveBeenCalledWith(1);
  expect(
    JSON.parse(
      window.localStorage.getItem(applicationPreferenceKey("owner-subject")) ||
        "{}",
    ),
  ).toEqual({ favorites: [], recent: ["ws-forecast/rolling-plan"] });
});

it("uses the workspace selector to choose the first accessible application", () => {
  const choose = vi.fn();
  render(
    <Applications
      applications={[
        ...applications,
        {
          workspaceId: "ws-forecast",
          applicationId: "rolling-plan",
          name: "Rolling Forecast",
          status: "Active",
        },
      ]}
      selected={0}
      catalog={catalog}
      choose={choose}
      created={vi.fn()}
    />,
  );
  fireEvent.change(screen.getByLabelText("Workspace selector"), {
    target: { value: "ws-forecast" },
  });
  expect(choose).toHaveBeenCalledWith(1);
});

it("builds the single programmable multidimensional lifecycle program", () => {
  expect(applicationCreateProgram("model-2027", "Model 2027")).toEqual({
    languageVersion: 2,
    function: "workspace.application.create",
    arguments: {
      applicationId: "model-2027",
      name: "Model 2027",
      kind: "multidimensional",
    },
  });
});

it("requires workspace authority, valid fields and an exact review", () => {
  render(
    <Applications
      applications={applications}
      selected={0}
      catalog={{
        ...catalog,
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: false,
        },
      }}
      choose={vi.fn()}
      created={vi.fn()}
    />,
  );
  expect(
    screen.getByRole("button", { name: "Create application" }),
  ).toBeDisabled();
  expect(
    screen.getByText(/requires Workspace Administrator access/),
  ).toBeInTheDocument();
});

it("submits the reviewed contract then hands the result to catalogue refresh", async () => {
  const created = vi.fn(async () => undefined);
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  vi.stubGlobal("crypto", { randomUUID: () => "create-app-1" });
  const fetch = vi.fn(
    async () =>
      new Response(
        JSON.stringify({
          workspaceId: "ws-pilot",
          applicationId: "model-2027",
          name: "Model 2027",
          kind: "multidimensional",
          status: "Active",
          enabledCapabilities: [],
          capabilityRevision: 0,
          blueprintVersion: 2,
          metadataRevision: 1,
          dimensions: [
            "Account",
            "Entity",
            "Year",
            "Period",
            "View",
            "Value",
            "Scenario",
            "DataType",
          ],
        }),
      ),
  );
  vi.stubGlobal("fetch", fetch);
  render(
    <Applications
      applications={applications}
      selected={0}
      catalog={catalog}
      choose={vi.fn()}
      created={created}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Create application" }));
  fireEvent.change(screen.getByLabelText(/Stable application ID/), {
    target: { value: "model-2027" },
  });
  fireEvent.change(screen.getByLabelText("Application name"), {
    target: { value: "Model 2027" },
  });
  const review = screen.getByLabelText(/I reviewed the workspace/);
  expect(review).toBeEnabled();
  fireEvent.click(review);
  fireEvent.click(screen.getByRole("button", { name: "Create and open" }));

  await waitFor(() => expect(created).toHaveBeenCalledOnce());
  expect(confirm).toHaveBeenCalledWith(
    "Create Model 2027 (model-2027) in ws-pilot?",
  );
  expect(fetch).toHaveBeenCalledWith(
    "/api/workspace-application",
    expect.objectContaining({
      method: "POST",
      credentials: "same-origin",
      body: JSON.stringify({
        workspaceId: "ws-pilot",
        confirmed: true,
        idempotencyKey: "application-ui-create-app-1",
        program: applicationCreateProgram("model-2027", "Model 2027"),
      }),
    }),
  );
});

it("invalidates approval when a reviewed field changes", () => {
  render(
    <Applications
      applications={applications}
      selected={0}
      catalog={catalog}
      choose={vi.fn()}
      created={vi.fn()}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Create application" }));
  const id = screen.getByLabelText(/Stable application ID/);
  fireEvent.change(id, { target: { value: "plan-2027" } });
  fireEvent.change(screen.getByLabelText("Application name"), {
    target: { value: "Plan 2027" },
  });
  const review = screen.getByLabelText(/I reviewed the workspace/);
  fireEvent.click(review);
  expect(review).toBeChecked();
  fireEvent.change(id, { target: { value: "plan-2028" } });
  expect(review).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Create and open" }),
  ).toBeDisabled();
});

it("uses the current blueprint preview without changing creation approval", () => {
  const props = {
    applications: [{ ...applications[0], workspaceName: "Pilot Workspace" }],
    selected: 0,
    choose: vi.fn(),
    created: vi.fn(),
  };
  const blueprint: ApplicationCatalog["applicationBlueprint"] = {
    version: 2,
    dimensions: [
      {
        dimensionId: "Entity",
        name: "Operating units",
        modelRole: "Entity",
        semanticRole: "Core entity",
        density: "Sparse",
        shortDescription: "The business objects being modeled.",
        detailedDescription: "Define their relationships with hierarchies.",
      },
    ],
  };
  const { rerender } = render(
    <Applications
      {...props}
      catalog={{ ...catalog, applicationBlueprint: blueprint }}
    />,
  );
  expect(
    screen.getByRole("heading", { name: "Pilot Workspace" }),
  ).toBeInTheDocument();
  expect(screen.getByText(/Stable workspace ID:/)).toHaveTextContent(
    "ws-pilot",
  );
  fireEvent.click(screen.getByRole("button", { name: "Create application" }));
  fireEvent.change(
    screen.getByRole("textbox", { name: "Stable application ID" }),
    {
      target: { value: "operating-model" },
    },
  );
  fireEvent.change(screen.getByRole("textbox", { name: "Application name" }), {
    target: { value: "Operating Model" },
  });
  const review = screen.getByRole("checkbox", {
    name: /^I reviewed the workspace/,
  });
  const create = screen.getByRole("button", { name: "Create and open" });
  const help = screen.getByRole("button", {
    name: "What is created automatically?",
  });
  expect(help).toHaveTextContent("What is created automatically?");
  expect(help.closest("label")).toBeNull();
  const helpContent = document.getElementById(
    help.getAttribute("aria-controls")!,
  );
  expect(helpContent).not.toBeVisible();
  expect(help).toHaveAttribute("aria-expanded", "false");
  help.focus();
  fireEvent.click(help);
  const disclosure = screen.getByRole("region", {
    name: "Automatic application blueprint",
  });
  expect(disclosure).toBe(helpContent);
  expect(help).toHaveAttribute("aria-expanded", "true");
  expect(disclosure).toHaveTextContent("Operating units");
  expect(disclosure).toHaveTextContent("The business objects being modeled.");
  expect(disclosure).not.toHaveTextContent("Scenario");
  expect(help).toHaveFocus();
  expect(review).not.toBeChecked();
  expect(create).toBeDisabled();
  rerender(<Applications {...props} catalog={catalog} />);
  expect(disclosure).toHaveTextContent(
    "The current workspace did not provide a blueprint preview.",
  );
  expect(disclosure).not.toHaveTextContent("Operating units");
  fireEvent.keyDown(help, { key: "Escape" });
  expect(help).toHaveFocus();
  expect(helpContent).not.toBeVisible();
  fireEvent.click(help);
  fireEvent.click(review);
  expect(helpContent).not.toBeVisible();
  expect(review).toBeChecked();
  expect(create).toBeEnabled();
});
