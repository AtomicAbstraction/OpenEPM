import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  Applications,
  applicationCreateProgram,
  applicationPreferenceKey,
} from "./Applications";

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
  window.localStorage.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
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
          blueprintVersion: 1,
          metadataRevision: 1,
          dimensions: ["Account", "Entity", "Year", "Period", "View", "Value"],
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

it("explains the exact automatic blueprint and dismisses help outside", () => {
  render(
    <Applications
      applications={[{ ...applications[0], workspaceName: "Pilot Workspace" }]}
      selected={0}
      catalog={catalog}
      choose={vi.fn()}
      created={vi.fn()}
    />,
  );
  expect(
    screen.getByRole("heading", { name: "Pilot Workspace" }),
  ).toBeInTheDocument();
  expect(screen.getByText(/Stable workspace ID:/)).toHaveTextContent(
    "ws-pilot",
  );
  fireEvent.click(screen.getByRole("button", { name: "Create application" }));
  const help = screen.getByRole("button", {
    name: "What is created automatically?",
  });
  fireEvent.click(help);
  expect(
    screen.getByRole("dialog", { name: "Automatic application blueprint" }),
  ).toHaveTextContent("Account, Entity, Year, Period, View and Value");
  expect(screen.getByRole("dialog")).toHaveTextContent(
    "No business members, hierarchies, formulas or custom attributes",
  );
  fireEvent.pointerDown(document.body);
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});
