import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { Applications } from "./Applications";
import {
  bootstrapGroups,
  personApplications,
  workspacePeople,
} from "./workspace-access";
import { resetUnsavedWorkForTests } from "./unsaved-work";
import type { ApplicationCatalog } from "./types";

const workspaceId = "operations";
const app = {
  workspaceId,
  applicationId: "selected",
  name: "Current model",
  status: "Active",
};
const catalog: ApplicationCatalog = {
  applicationAccess: {
    role: "Assigned",
    authorizationModel: "group_assignments",
    roles: ["Reviewer"],
    workspaceAdministrator: true,
  },
  workspaceFunctions: [workspacePeople, personApplications, bootstrapGroups],
  functions: {},
  enabledCapabilities: [],
  revisions: { metadata: 1, security: 1, policy: 1, commit: 1, data: 1 },
};
const base = {
  workspaceId,
  coverage: "complete_in_workspace",
  coverageReasons: [],
  asOf: "2026-11-25T10:00:00Z",
  nextCursor: null,
};
const person = {
  subjectId: "person-one",
  displayName: "Alex Planner",
  username: "alex-work",
  directoryStatus: "Active",
  workspaceAdministrator: true,
  originsComplete: true,
  origins: [
    {
      kind: "workspace_group",
      groupId: "operations-admin",
      groupName: "Operations managers",
    },
  ],
};
const props = {
  applications: [app],
  selected: 0,
  choose: vi.fn(),
  created: vi.fn(),
};
function reply(fn: string, data: unknown) {
  return new Response(
    JSON.stringify({ languageVersion: 2, function: fn, result: data }),
    { headers: { "Content-Type": "application/json" } },
  );
}
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  resetUnsavedWorkForTests();
  window.localStorage.clear();
});

it("finds a named workspace administrator and lists that exact person's applications across models", async () => {
  const fetch = vi.fn(async (url: string, init: RequestInit) => {
    expect(url).toBe("/api/workspace-access");
    const body = JSON.parse(String(init.body));
    expect(Object.keys(body).sort()).toEqual(["program", "workspaceId"]);
    expect(body.workspaceId).toBe(workspaceId);
    if (body.program.function === workspacePeople) {
      expect(body.program.arguments).toEqual({
        limit: 25,
        query: "Alex",
        administratorsOnly: true,
      });
      return reply(workspacePeople, { ...base, people: [person] });
    }
    expect(body.program.arguments).toEqual({
      limit: 25,
      subjectId: "person-one",
    });
    return reply(personApplications, {
      ...base,
      coverage: "partial",
      coverageReasons: ["directory_identity_unresolved"],
      applications: [
        {
          applicationId: "group-app",
          applicationName: "Capacity",
          roleNames: ["Data Reviewer", "Forecast Analyst"],
          rolesComplete: true,
          authorizationMode: "group_assignments",
          workspaceInherited: false,
          applicationRole: null,
        },
        {
          applicationId: "legacy-app",
          applicationName: "Budget",
          roleNames: ["Administrator"],
          rolesComplete: true,
          authorizationMode: "legacy",
          applicationRole: "Administrator",
          workspaceInherited: true,
        },
      ],
    });
  });
  vi.stubGlobal("fetch", fetch);
  render(<Applications {...props} catalog={catalog} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Review people and administrators" }),
  );
  fireEvent.change(
    screen.getByRole("searchbox", { name: "Name or username" }),
    { target: { value: "Alex" } },
  );
  fireEvent.click(screen.getByLabelText("Workspace administrators only"));
  fireEvent.click(
    screen.getByRole("button", { name: "Find person in workspace" }),
  );
  expect(
    await screen.findByText(/Workspace group · Operations managers/),
  ).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "View applications for Alex Planner" }),
  );
  expect(await screen.findByText("Capacity")).toBeInTheDocument();
  expect(screen.getByText("Budget")).toBeInTheDocument();
  expect(
    screen.getByText(/Data Reviewer, Forecast Analyst/),
  ).toBeInTheDocument();
  expect(
    screen.getByText(/Inherited through workspace administration/),
  ).toBeInTheDocument();
  expect(screen.getByText(/Partial workspace coverage/)).toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(2);
});

it("suppresses stale workspace people after a permission or context change and rejects a mismatched result", async () => {
  const fetch = vi.fn(async () =>
    reply(workspacePeople, {
      ...base,
      workspaceId: "another-workspace",
      people: [person],
    }),
  );
  vi.stubGlobal("fetch", fetch);
  const view = render(<Applications {...props} catalog={catalog} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Review people and administrators" }),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "List workspace people" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "unavailable or has changed",
  );
  expect(screen.queryByText("Alex Planner")).toBeNull();
  view.rerender(
    <Applications
      {...props}
      catalog={{ ...catalog, workspaceFunctions: [] }}
    />,
  );
  expect(
    screen.queryByRole("heading", { name: "Workspace access" }),
  ).toBeNull();
});

it("selects only an eligible administrator group and verifies the returned bootstrap before opening", async () => {
  vi.spyOn(window, "confirm").mockReturnValue(true);
  const created = vi.fn();
  const fetch = vi.fn(async (url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    if (url === "/api/workspace-access") {
      expect(body.program.function).toBe(bootstrapGroups);
      return reply(bootstrapGroups, {
        ...base,
        groups: [
          {
            groupId: "admin-team",
            groupName: "admins",
            displayName: "Model administrators",
            actorMember: false,
          },
        ],
      });
    }
    expect(url).toBe("/api/workspace-application");
    expect(body.program.arguments).toEqual({
      applicationId: "new-model",
      kind: "multidimensional",
      name: "New model",
      administratorGroupId: "admin-team",
    });
    return new Response(
      JSON.stringify({
        workspaceId,
        applicationId: "new-model",
        name: "New model",
        kind: "multidimensional",
        status: "Active",
        capabilityRevision: 0,
        enabledCapabilities: [],
        authorizationModel: "group_assignments",
        administratorGroupId: "admin-team",
      }),
    );
  });
  vi.stubGlobal("fetch", fetch);
  render(<Applications {...props} created={created} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Create application" }));
  fireEvent.change(screen.getByLabelText("Stable application ID"), {
    target: { value: "new-model" },
  });
  fireEvent.change(screen.getByLabelText("Application name"), {
    target: { value: "New model" },
  });
  expect(
    screen.getByRole("button", { name: "Create for selected group" }),
  ).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "List eligible groups" }));
  fireEvent.change(await screen.findByLabelText("Administrator group"), {
    target: { value: "admin-team" },
  });
  fireEvent.click(
    screen.getByRole("checkbox", { name: /I reviewed the workspace/ }),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Create for selected group" }),
  );
  await waitFor(() => expect(created).toHaveBeenCalledOnce());
  expect(created.mock.calls[0][2]).toBe(false);
});

it("keeps a missing or different bootstrap receipt unresolved and replays the identical request", async () => {
  vi.spyOn(window, "confirm").mockReturnValue(true);
  const created = vi.fn();
  const bodies: unknown[] = [];
  const fetch = vi.fn(async (url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    if (url === "/api/workspace-access")
      return reply(bootstrapGroups, {
        ...base,
        groups: [
          {
            groupId: "mine",
            groupName: "Mine",
            displayName: null,
            actorMember: true,
          },
        ],
      });
    bodies.push(body);
    return new Response(
      JSON.stringify({
        workspaceId,
        applicationId: "new-model",
        name: "New model",
        kind: "multidimensional",
        status: "Active",
        capabilityRevision: 0,
        enabledCapabilities: [],
        authorizationModel: "group_assignments",
        administratorGroupId: bodies.length === 1 ? "different" : "mine",
      }),
    );
  });
  vi.stubGlobal("fetch", fetch);
  render(<Applications {...props} created={created} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Create application" }));
  fireEvent.click(screen.getByRole("button", { name: "List eligible groups" }));
  fireEvent.change(await screen.findByLabelText("Administrator group"), {
    target: { value: "mine" },
  });
  fireEvent.change(screen.getByLabelText("Stable application ID"), {
    target: { value: "new-model" },
  });
  fireEvent.change(screen.getByLabelText("Application name"), {
    target: { value: "New model" },
  });
  fireEvent.click(
    screen.getByRole("checkbox", { name: /I reviewed the workspace/ }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Create and open" }));
  expect(
    await screen.findByRole("heading", {
      name: "Application creation unconfirmed",
    }),
  ).toBeInTheDocument();
  expect(created).not.toHaveBeenCalled();
  fireEvent.click(
    screen.getByRole("button", { name: /Retry original creation/ }),
  );
  await waitFor(() => expect(created).toHaveBeenCalledOnce());
  expect(bodies[1]).toEqual(bodies[0]);
});
