import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { Applications } from "./Applications";
import { presentationRouteHash } from "./App";
import {
  bootstrapGroups,
  personApplications,
  workspacePeople,
} from "./workspace-access";
import { resetUnsavedWorkForTests } from "./unsaved-work";
const name = "Operations",
  id = "ops";
const fns = [
  "workspace.application.create",
  workspacePeople,
  personApplications,
  bootstrapGroups,
];
const props = {
  applications: [],
  selected: -1,
  catalog: null,
  issuer: "idp",
  subject: "admin",
  choose: vi.fn(),
  created: vi.fn(),
};
const json = (body: unknown) =>
  new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json" },
  });
afterEach(() => {
  resetUnsavedWorkForTests();
  window.localStorage.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
it("discovers workspaces without an admitted application and creates an application for another eligible group", async () => {
  vi.spyOn(window, "confirm").mockReturnValue(true);
  const created = vi.fn();
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push(url);
      if (url === "/api/applications?view=managedWorkspaces")
        return json({
          workspaces: [{ workspaceId: id, workspaceName: name }],
          nextAfter: "opaque+/=",
        });
      if (
        url === "/api/applications?view=managedWorkspaces&after=opaque%2B%2F%3D"
      )
        return json({
          workspaces: [{ workspaceId: "second", workspaceName: "Another" }],
          nextAfter: null,
        });
      const body = JSON.parse(String(init.body));
      expect(body).not.toHaveProperty("applicationId");
      expect(body.workspaceId).toBe(id);
      if (url === "/api/workspace-catalog")
        return json({ workspaceId: id, functions: fns });
      if (url === "/api/workspace-access")
        return json({
          languageVersion: 2,
          function: body.program.function,
          result: {
            workspaceId: id,
            coverage: "complete_in_workspace",
            coverageReasons: [],
            asOf: "2026-11-25T12:00:00Z",
            nextCursor: null,
            groups: [
              {
                groupId: "other",
                groupName: "Another team",
                displayName: null,
                actorMember: false,
              },
            ],
          },
        });
      expect(url).toBe("/api/workspace-application");
      expect(body.program.arguments.administratorGroupId).toBe("other");
      return json({
        workspaceId: id,
        applicationId: "new",
        name: "New model",
        kind: "multidimensional",
        capabilityRevision: 0,
        enabledCapabilities: [],
        status: "Active",
        authorizationModel: "group_assignments",
        administratorGroupId: "other",
      });
    }),
  );
  render(<Applications {...props} created={created} />);
  expect(
    await screen.findByRole("button", {
      name: "Review people and administrators",
    }),
  ).toBeInTheDocument();
  expect(
    screen.getByText(
      "Your account has no admitted applications in this workspace.",
    ),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("option", { name: "Another (second)" }),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Create application" }));
  fireEvent.click(screen.getByRole("button", { name: "List eligible groups" }));
  fireEvent.change(await screen.findByLabelText("Administrator group"), {
    target: { value: "other" },
  });
  fireEvent.change(screen.getByLabelText("Stable application ID"), {
    target: { value: "new" },
  });
  fireEvent.change(screen.getByLabelText("Application name"), {
    target: { value: "New model" },
  });
  fireEvent.click(screen.getByRole("checkbox", { name: /I reviewed/ }));
  fireEvent.click(
    screen.getByRole("button", { name: "Create for selected group" }),
  );
  await waitFor(() => expect(created).toHaveBeenCalledOnce());
  expect(created.mock.calls[0][2]).toBe(false);
  expect(calls).not.toContain("/api/catalog");
});
it("preserves a workspace-only route and refuses a catalogue from another workspace", async () => {
  expect(
    presentationRouteHash("applications", 0, { workspaceId: "ops" }),
  ).toContain("workspace=ops");
  expect(
    presentationRouteHash("applications", 0, { workspaceId: "ops" }),
  ).not.toContain("application=");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) =>
      url === "/api/workspace-catalog"
        ? json({ workspaceId: "incorrect", functions: fns })
        : json({
            workspaces: [{ workspaceId: id, workspaceName: name }],
            nextAfter: null,
          }),
    ),
  );
  render(<Applications {...props} managedWorkspaceId={id} />);
  expect(
    await screen.findByText(/Workspace management is unavailable/),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Create application" }),
  ).toBeDisabled();
  expect(
    screen.queryByRole("button", { name: "Review people and administrators" }),
  ).toBeNull();
});
it("offers no workspace-level control when neither workspace nor application is granted", async () => {
  const fetch = vi.fn(async () => json({ workspaces: [], nextAfter: null }));
  vi.stubGlobal("fetch", fetch);
  render(<Applications {...props} />);
  await waitFor(() => expect(fetch).toHaveBeenCalledOnce());
  expect(screen.getByText("No accessible workspace")).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Create application" }),
  ).toBeDisabled();
  expect(
    screen.queryByRole("heading", { name: "Workspace access" }),
  ).toBeNull();
});
