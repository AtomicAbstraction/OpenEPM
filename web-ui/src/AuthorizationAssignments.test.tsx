import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { AuthorizationAssignments } from "./AuthorizationAssignments";
import { operationAdmissionResponse } from "./test-setup";
import { resetUnsavedWorkForTests, setDraftIdentity } from "./unsaved-work";
import type { ApplicationCatalog } from "./types";

const app = {
  workspaceId: "test",
  applicationId: "capacity",
  name: "Capacity",
  status: "Active",
};
const prefix = "security.application.authorization.";
const catalog: ApplicationCatalog = {
  functions: Object.fromEntries(
    ["read", "preview", "apply"].map((s) => [prefix + s, {}]),
  ),
  applicationAccess: {
    role: "Assigned",
    authorizationModel: "group_assignments",
    roles: ["Access Manager"],
    workspaceAdministrator: false,
  },
  revisions: { metadata: 1, data: 1, policy: 1, security: 4, commit: 1 },
  enabledCapabilities: [],
};
const config = {
  workspaceId: "test",
  applicationId: "capacity",
  revision: 4,
  authorizationMode: "group_assignments",
  complete: true,
  canManageRoles: true,
  canManageScopes: true,
  canManageAssignments: true,
  snapshotToken: "1".repeat(64),
  nextAfter: {
    roles: null,
    scopes: null,
    eligibleGroups: null,
    assignments: null,
  },
  actions: [
    {
      action: "facts.write",
      scopeKinds: ["dimension_tags"],
      canDelegate: true,
    },
    {
      action: "application.enter",
      scopeKinds: ["entire_application"],
      canDelegate: true,
    },
    { action: "views.read", scopeKinds: ["exact_object"], canDelegate: true },
  ],
  roles: [
    {
      roleId: "contributor",
      name: "Contributor",
      actions: ["facts.write", "application.enter"],
    },
  ],
  scopes: [
    {
      scopeId: "night",
      name: "Night shift",
      scopeKind: "dimension_tags",
      selector: { Shift: ["Night"] },
    },
    {
      scopeId: "all",
      name: "Open application",
      scopeKind: "entire_application",
      selector: {},
    },
  ],
  assignments: [],
  eligibleGroups: [
    {
      groupId: "planners",
      groupName: "planners",
      displayName: "Production planners",
    },
  ],
};
const digest = "a".repeat(64);

const benefit = {
  classification: "new_grant_path",
  grantsComplete: true,
  applicationEntry: "requires_entry",
  grants: [
    {
      groupId: "planners",
      assignmentId: "first-self-grant",
      action: "facts.write",
      scopeId: "night",
      scopeRevision: 2,
      scopeKind: "dimension_tags",
      selector: { Region: ["East"] },
      roleId: "contributor",
      reason: "new_grant_path",
    },
  ],
} as const;
function fixture(
  includeBenefit = false,
  loseReply = false,
  dutyReview?: "valid" | "missing",
) {
  const requests: Array<{
    path: string;
    program?: { function: string; arguments: Record<string, unknown> };
    idempotencyKey?: string;
    confirmed?: boolean;
  }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body));
      requests.push({ path, ...body });
      if (path === "/api/operation-admission")
        return operationAdmissionResponse("b");
      if (path !== "/api/security") throw new Error("Unexpected endpoint");
      let result;
      switch (body.program.function) {
        case prefix + "read":
          result = dutyReview
            ? {
                ...config,
                canManageWorkflowDuties: true,
                availableWorkflowDuties: ["Forecast:prepare"],
                workflowDutiesComplete: true,
                roles: config.roles.map((role) => ({
                  ...role,
                  actions: [...role.actions, "facts.read"],
                  workflowDuties: [],
                })),
                actions: [
                  ...config.actions,
                  {
                    action: "facts.read",
                    canDelegate: true,
                    scopeKinds: ["dimension_tags"],
                  },
                ],
              }
            : config;
          break;
        case prefix + "preview":
          result = {
            workspaceId: "test",
            applicationId: "capacity",
            authorizationMode: "group_assignments",
            ...body.program.arguments,
            reviewDigest: digest,
            impact: {
              ...(includeBenefit ? { requesterBenefit: benefit } : {}),
              ...(dutyReview === "valid"
                ? {
                    reviewedWorkflowDuties: [
                      {
                        roleId: "contributor",
                        addedDuties: ["Forecast:prepare"],
                        removedDuties: [],
                      },
                    ],
                  }
                : {}),
              changed: { scopes: [], roles: [], assignments: [] },
              affectedAssignments: [],
            },
          };
          break;
        case "security.application.receipt.read":
          result = {
            workspaceId: "test",
            applicationId: "capacity",
            operationId: body.program.arguments.operationId,
            outcome: "Committed",
            action: "application-authorization.apply",
            actorDigest: digest,
            commandDigest: digest,
            payloadDigest: digest,
            committedAt: "2026-11-25T08:00:00Z",
            authorizationMode: "group_assignments",
            requesterBenefit: benefit,
          };
          break;
        case prefix + "apply":
          if (loseReply) throw new TypeError("Network disconnected");
          result = {
            workspaceId: "test",
            applicationId: "capacity",
            changed: true,
            revision: 5,
            ...(includeBenefit
              ? {
                  authorizationMode: "group_assignments",
                  impact: { requesterBenefit: benefit },
                }
              : {}),
          };
          break;
        case "security.application.authorization.tags.list":
          result = {
            workspaceId: "test",
            applicationId: "capacity",
            snapshotToken: "fixture-token",
            nextAfter: null,
            tags: [
              {
                dimensionId: "Shift",
                dimensionName: "Shift",
                tagId: "Night",
                tagName: "Night",
              },
            ],
          };
          break;
        case "security.application.authorization.objects.list":
          result = {
            workspaceId: "test",
            applicationId: "capacity",
            snapshotToken: digest,
            nextAfter: null,
            objects: [
              {
                objectType: "saved_view",
                objectId: "press-capacity",
                objectName: "Press hours",
              },
            ],
          };
          break;
        default:
          throw new Error("Unexpected program");
      }
      return new Response(
        JSON.stringify({
          languageVersion: 2,
          function: body.program.function,
          result,
        }),
      );
    }),
  );
  setDraftIdentity("test-access-manager");
  return requests;
}

afterEach(() => {
  vi.unstubAllGlobals();
  resetUnsavedWorkForTests();
});

it.each(["valid", "missing"] as const)(
  "requires the server to review a linked duty before apply (%s)",
  async (review) => {
    const requests = fixture(false, false, review);
    render(<AuthorizationAssignments app={app} catalog={catalog} />);
    fireEvent.click(screen.getByRole("button", { name: "Read assignments" }));
    fireEvent.click(await screen.findByRole("button", { name: "Roles" }));
    fireEvent.change(screen.getByLabelText("Role definition"), {
      target: { value: "contributor" },
    });
    fireEvent.click(screen.getByRole("checkbox", { name: "Forecast:prepare" }));
    fireEvent.click(screen.getByRole("button", { name: "Preview role" }));
    if (review === "valid") {
      expect(
        await screen.findByText("Planning duties to add · Forecast:prepare"),
      ).toBeVisible();
      expect(
        screen.getByRole("button", { name: "Apply reviewed change" }),
      ).toBeEnabled();
    } else {
      expect(await screen.findByRole("alert")).toHaveTextContent(
        /could not approve/,
      );
      expect(
        screen.queryByRole("button", { name: "Apply reviewed change" }),
      ).not.toBeInTheDocument();
    }
    expect(
      requests.find((r) => r.program?.function === prefix + "preview")?.program
        ?.arguments.changes,
    ).toMatchObject([
      {
        op: "putRole",
        roleId: "contributor",
        workflowDuties: ["Forecast:prepare"],
      },
    ]);
    expect(requests.some((r) => r.path === "/api/operation-admission")).toBe(
      false,
    );
  },
);

it("reviews one group, role and exact scopes before sending an admitted effect", async () => {
  const requests = fixture(true);
  render(<AuthorizationAssignments app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read assignments" }));
  fireEvent.change(await screen.findByLabelText("Eligible group"), {
    target: { value: "planners" },
  });
  fireEvent.change(screen.getByLabelText("Application role"), {
    target: { value: "contributor" },
  });
  expect(
    screen.getByRole("button", { name: "Preview assignment" }),
  ).toBeDisabled();
  fireEvent.click(
    within(screen.getByRole("group", { name: "facts.write" })).getByRole(
      "checkbox",
      { name: /Night shift/ },
    ),
  );
  fireEvent.click(
    within(screen.getByRole("group", { name: "application.enter" })).getByRole(
      "checkbox",
      { name: /Open application/ },
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Preview assignment" }));
  expect(
    await screen.findByRole("heading", { name: "Proposed assignment" }),
  ).toBeVisible();
  expect(
    screen.getByRole("heading", { name: "Effect on your own access" }),
  ).toBeVisible();
  expect(
    screen.getByText("This change adds a grant through one of your groups."),
  ).toBeVisible();
  expect(
    screen.getByText(
      "The requester needs application entry before these grants can be used.",
    ),
  ).toBeVisible();
  expect(requests.some((r) => r.program?.function === prefix + "apply")).toBe(
    false,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Apply reviewed change" }),
  );
  await waitFor(() =>
    expect(
      requests.filter(
        (r) =>
          r.path === "/api/security" &&
          r.program?.function === prefix + "apply",
      ),
    ).toHaveLength(1),
  );
  expect(
    await screen.findByRole("heading", {
      name: "Effect on the requesting administrator",
    }),
  ).toBeVisible();
  const args = requests.find((r) => r.program?.function === prefix + "preview")!
    .program!.arguments;
  expect(args).toMatchObject({
    expectedRevision: 4,
    changes: [
      {
        op: "putAssignment",
        groupId: "planners",
        roleId: "contributor",
        privileges: [
          { action: "facts.write", scopeId: "night" },
          { action: "application.enter", scopeId: "all" },
        ],
      },
    ],
  });
  expect(
    requests.find((r) => r.path === "/api/operation-admission")!.program
      ?.arguments,
  ).toEqual({ ...args, reviewDigest: digest });
  expect(
    requests.find(
      (r) =>
        r.path === "/api/security" && r.program?.function === prefix + "apply",
    ),
  ).toMatchObject({
    confirmed: true,
    idempotencyKey: expect.stringMatching(/^oa1_/),
    program: { arguments: { ...args, reviewDigest: digest } },
  });
});

it("invalidates reviewed changes when a role or scope changes and never auto-activates a staged model", async () => {
  const requests = fixture();
  render(<AuthorizationAssignments app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read assignments" }));
  fireEvent.click(await screen.findByRole("button", { name: "Roles" }));
  fireEvent.change(screen.getByLabelText("Role name"), {
    target: { value: "Machine planner" },
  });
  fireEvent.click(screen.getByLabelText("facts.write"));
  fireEvent.click(screen.getByRole("button", { name: "Preview role" }));
  expect(
    await screen.findByRole("button", { name: "Apply reviewed change" }),
  ).toBeEnabled();
  fireEvent.change(screen.getByLabelText("Role name"), {
    target: { value: "Production planner" },
  });
  expect(
    screen.queryByRole("button", { name: "Apply reviewed change" }),
  ).toBeNull();
  expect(
    requests.filter((r) => r.path === "/api/operation-admission"),
  ).toHaveLength(0);
});

it("uses scoped tag choices to build a typed dimensional scope", async () => {
  const requests = fixture();
  render(
    <AuthorizationAssignments
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "security.application.authorization.tags.list": {},
        },
      }}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read assignments" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Resource scopes" }),
  );
  fireEvent.change(screen.getByLabelText("Scope name"), {
    target: { value: "Night coverage" },
  });
  fireEvent.change(screen.getByLabelText("Selection type"), {
    target: { value: "dimension_tags" },
  });
  expect(screen.getByRole("button", { name: "Preview scope" })).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Read available dimension tags" }),
  );
  fireEvent.click(await screen.findByRole("checkbox", { name: "Night" }));
  fireEvent.click(screen.getByRole("button", { name: "Preview scope" }));
  await screen.findByRole("button", { name: "Apply reviewed change" });
  expect(
    requests.find((r) => r.program?.function === prefix + "preview")!.program!
      .arguments,
  ).toMatchObject({
    changes: [
      {
        op: "putScope",
        name: "Night coverage",
        scopeKind: "dimension_tags",
        selector: { Shift: ["Night"] },
      },
    ],
  });
});

it("creates the first exact scope from an eligible saved view", async () => {
  const requests = fixture();
  render(
    <AuthorizationAssignments
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          [prefix + "objects.list"]: {},
        },
      }}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read assignments" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Resource scopes" }),
  );
  fireEvent.change(screen.getByLabelText("Scope name"), {
    target: { value: "Press view" },
  });
  fireEvent.change(screen.getByLabelText("Selection type"), {
    target: { value: "exact_object" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Read eligible saved views" }),
  );
  await screen.findByRole("option", { name: "Press hours · press-capacity" });
  fireEvent.change(screen.getByLabelText("Saved view"), {
    target: { value: "press-capacity" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Preview scope" }));
  await screen.findByRole("button", { name: "Apply reviewed change" });
  expect(
    requests.find((r) => r.program?.function === prefix + "preview")?.program
      ?.arguments,
  ).toMatchObject({
    changes: [
      {
        op: "putScope",
        name: "Press view",
        scopeKind: "exact_object",
        selector: { objectType: "saved_view", objectId: "press-capacity" },
      },
    ],
  });
});

it("keeps a partial configuration read-only and drops it if continuation becomes stale", async () => {
  const fetch = vi.fn(async (_path: string, init: RequestInit) => {
    const args = JSON.parse(String(init.body)).program.arguments;
    if (args.collection)
      return new Response(
        JSON.stringify({ code: "AUTHORIZATION_CONFIGURATION_STALE" }),
        { status: 409 },
      );
    return new Response(
      JSON.stringify({
        result: {
          ...config,
          complete: false,
          nextAfter: { ...config.nextAfter, roles: "contributor" },
        },
      }),
    );
  });
  vi.stubGlobal("fetch", fetch);
  render(<AuthorizationAssignments app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read assignments" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Load more roles" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "could not be continued",
  );
  expect(
    screen.queryByRole("button", { name: "Preview assignment" }),
  ).toBeNull();
  expect(
    JSON.parse(String(fetch.mock.calls[1][1].body)).program.arguments,
  ).toEqual({
    collection: "roles",
    after: "contributor",
    expectedSnapshot: config.snapshotToken,
    limit: 100,
  });
});

it("recovers recorded requester grant evidence after a lost response without a second application", async () => {
  const requests = fixture(true, true);
  render(
    <AuthorizationAssignments
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "security.application.receipt.read": {},
        },
      }}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read assignments" }));
  fireEvent.change(await screen.findByLabelText("Eligible group"), {
    target: { value: "planners" },
  });
  fireEvent.change(screen.getByLabelText("Application role"), {
    target: { value: "contributor" },
  });
  fireEvent.click(
    within(screen.getByRole("group", { name: "facts.write" })).getByRole(
      "checkbox",
      { name: /Night shift/ },
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Preview assignment" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Apply reviewed change" }),
  );
  const check = await screen.findByRole("button", {
    name: "Check original security change",
  });
  await waitFor(() => expect(check).toBeEnabled());
  fireEvent.click(check);
  expect(
    await screen.findByRole("heading", {
      name: "Effect on the requesting administrator",
    }),
  ).toBeVisible();
  expect(
    requests.filter(
      (r) =>
        r.path === "/api/security" && r.program?.function === prefix + "apply",
    ),
  ).toHaveLength(1);
});
