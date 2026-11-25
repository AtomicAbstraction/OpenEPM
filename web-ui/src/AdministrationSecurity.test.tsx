import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  installOperationAdmissionFixture,
  operationAdmissionResponse,
} from "./test-setup";
import {
  accessMutationBody,
  accessListArguments,
  auditListArguments,
  AdministrationSecurity,
  collectCompleteSecurityAudit,
  collectSecuritySubjects,
  dimensionAccessMutationBody,
  dimensionPolicyMutationBody,
  parseSecurityTags,
  ruleAccessMutationBody,
  securityAuditCsv,
} from "./AdministrationSecurity";

import {
  discardUnsavedWork,
  resetUnsavedWorkForTests,
  setDraftIdentity,
  setUnsavedWork,
  unsavedWorkSnapshot,
} from "./unsaved-work";

afterEach(() => {
  vi.unstubAllGlobals();
  resetUnsavedWorkForTests();
});

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "Active",
};

function securityWriteResponse(body: {
  workspaceId: string;
  applicationId: string;
  program: { function: string };
}) {
  return Response.json({
    languageVersion: 2,
    function: body.program.function,
    result: {
      workspaceId: body.workspaceId,
      applicationId: body.applicationId,
      changed: true,
    },
  });
}

const catalog = {
  applicationAccess: { role: "Administrator", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "security.application.access.list": {},
    "security.application.dimension-policy.read": {},
    "security.application.dimension-access.read": {},
    "security.application.dimension-tags.read": {},
  },
  revisions: { metadata: 1, data: 1, policy: 1, security: 7, commit: 1 },
};

it("reads complete subject catalogues beyond former caps", async () => {
  let subjectPage = 0;
  const subjects = await collectSecuritySubjects(async () => {
    const current = subjectPage++;
    return {
      grants: Array.from({ length: 100 }, (_unused, row) => ({
        subjectId: `s-${current}-${row}`,
        displayName: `Subject ${current}-${row}`,
        username: `subject-${current}-${row}`,
        role: "Reader",
        readTags: {},
        writeTags: {},
        rulePermissions: null,
        grantedAt: "2026-11-05T00:00:00Z",
      })),
      nextAfterSubjectId: current === 10 ? null : `s-cursor-${current + 1}`,
    };
  });
  expect(subjects.rows).toHaveLength(1100);
});

it("rejects malformed, repeated, duplicate, and stale security continuations", async () => {
  await expect(
    collectSecuritySubjects(async () => ({
      grants: [],
      nextAfterSubjectId: "" as never,
    })),
  ).rejects.toThrow("cursor is invalid");
  let subjectPage = 0;
  await expect(
    collectSecuritySubjects(async () => ({
      grants: [],
      nextAfterSubjectId: subjectPage++ < 1 ? "same" : "same",
    })),
  ).rejects.toThrow("cursor repeated");
});

it("preserves application-access pagination arguments", () => {
  expect(accessListArguments()).toEqual({ limit: 100 });
  expect(accessListArguments("subject-a")).toEqual({
    afterSubjectId: "subject-a",
    limit: 100,
  });
  expect(auditListArguments()).toEqual({ limit: 100 });
  expect(auditListArguments(42)).toEqual({ beforeAuditId: 42, limit: 100 });
});

it("exports the safe audit projection as exact CSV", () => {
  expect(
    securityAuditCsv([
      {
        auditId: 42,
        occurredAt: "2026-11-05T12:00:00+00:00",
        actorName: "Alice Owner",
        action: "Granted application access",
        targetName: "Bob Planner",
        outcome: "Accepted",
        detailsKey: 'receipt,"42"',
      },
    ]),
  ).toBe(
    "occurredAt,actor,action,target,outcome\r\n" +
      "2026-11-05T12:00:00+00:00,Alice Owner,Granted application access,Bob Planner,Accepted",
  );
});

it("retains requester benefit and staged status in the audit CSV action column", () => {
  const csv = securityAuditCsv([
    {
      auditId: 7,
      occurredAt: "2026-11-25",
      actorName: "Planner",
      action: "Changed group authorization",
      targetName: "Forecast",
      outcome: "Accepted",
      detailsKey: "internal-receipt",
      authorizationMode: "legacy",
      requesterBenefit: {
        classification: "new_grant_path",
        grants: [],
        grantsComplete: false,
      },
    },
  ]);
  expect(csv.split("\r\n")[0]).toBe("occurredAt,actor,action,target,outcome");
  expect(csv).toContain(
    "Changed group authorization · Staged · New grant through the requester’s group",
  );
  expect(csv).not.toContain("internal-receipt");
});

it("collects a complete strictly descending bounded security audit", async () => {
  const calls: Array<ReturnType<typeof auditListArguments>> = [];
  const events = await collectCompleteSecurityAudit(async (arguments_) => {
    calls.push(arguments_);
    const before = arguments_.beforeAuditId;
    return before
      ? {
          events: [
            {
              auditId: 8,
              occurredAt: "2026-11-05T11:00:00Z",
              actorName: "Alice Owner",
              action: "Changed rule permissions",
              targetName: "Plan",
              outcome: "Accepted" as const,
              detailsKey: "receipt-8",
            },
          ],
          nextBeforeAuditId: null,
        }
      : {
          events: [
            {
              auditId: 9,
              occurredAt: "2026-11-05T12:00:00Z",
              actorName: "Alice Owner",
              action: "Granted application access",
              targetName: "Bob Planner",
              outcome: "Accepted" as const,
              detailsKey: "receipt-9",
            },
          ],
          nextBeforeAuditId: 9,
        };
  });
  expect(events.map((event) => event.auditId)).toEqual([9, 8]);
  expect(calls).toEqual([{ limit: 100 }, { beforeAuditId: 9, limit: 100 }]);
});

it("rejects malformed, non-descending, duplicate and over-bound audit pages", async () => {
  await expect(
    collectCompleteSecurityAudit(async () => ({
      events: [
        {
          auditId: 2,
          occurredAt: "2026-11-05T12:00:00Z",
          actorName: "",
          action: "grant",
          targetName: "Plan",
          outcome: "Accepted",
          detailsKey: null,
        },
      ],
      nextBeforeAuditId: null,
    })),
  ).rejects.toThrow("invalid event");
  await expect(
    collectCompleteSecurityAudit(async () => ({
      events: [
        {
          auditId: 2,
          occurredAt: "2026-11-05T12:00:00Z",
          actorName: "Alice Owner",
          action: "grant",
          targetName: "Plan",
          outcome: "Accepted",
          detailsKey: null,
        },
        {
          auditId: 3,
          occurredAt: "2026-11-05T11:00:00Z",
          actorName: "Alice Owner",
          action: "grant",
          targetName: "Plan",
          outcome: "Accepted",
          detailsKey: null,
        },
      ],
      nextBeforeAuditId: null,
    })),
  ).rejects.toThrow("invalid event");
});

it("preserves the confirmed access mutation contract", () => {
  expect(
    accessMutationBody(app, "subject-a", "grant", "Editor", "key-1"),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "key-1",
    program: {
      languageVersion: 2,
      function: "security.application.access.set",
      arguments: {
        subjectId: "subject-a",
        action: "grant",
        role: "Editor",
      },
    },
  });
  expect(
    accessMutationBody(app, "subject-a", "revoke", "Editor", "key-2"),
  ).toEqual(
    expect.objectContaining({
      confirmed: true,
      idempotencyKey: "key-2",
      program: expect.objectContaining({
        arguments: {
          subjectId: "subject-a",
          action: "revoke",
          role: null,
        },
      }),
    }),
  );
});

it("preserves the confirmed rule-permission mutation contract", () => {
  const permissions = { design: true, publish: false, run: true };
  expect(
    ruleAccessMutationBody(app, "subject-a", "set", permissions, "rule-1"),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "rule-1",
    program: {
      languageVersion: 2,
      function: "security.rule.access.set",
      arguments: {
        subjectId: "subject-a",
        action: "set",
        permissions,
      },
    },
  });
  expect(
    ruleAccessMutationBody(app, "subject-a", "revoke", permissions, "rule-2")
      .program.arguments,
  ).toEqual({
    subjectId: "subject-a",
    action: "revoke",
    permissions: null,
  });
});

it("validates and preserves dimensional-assignment contracts", () => {
  expect(parseSecurityTags("Planning; North", ["North", "Planning"])).toEqual([
    "North",
    "Planning",
  ]);
  expect(() => parseSecurityTags("North; North", ["North"])).toThrow(
    "Duplicate dimensional-security tag.",
  );
  expect(() => parseSecurityTags("South", ["North"])).toThrow(
    "Unknown dimensional-security tag: South.",
  );
  expect(
    dimensionAccessMutationBody(
      app,
      "subject-a",
      { Entity: ["North"] },
      { Entity: ["WriteNorth"] },
      7,
      "dimension-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "dimension-1",
    program: {
      languageVersion: 2,
      function: "security.application.dimension-access.set",
      arguments: {
        subjectId: "subject-a",
        readTags: { Entity: ["North"] },
        writeTags: { Entity: ["WriteNorth"] },
        expectedSecurityRevision: 7,
      },
    },
  });
});

it("preserves exact dimensional-policy mutation contracts", () => {
  const policy = {
    acrossDimensions: "every_protected",
    withinDimension: "any_tag",
    untaggedMember: "deny",
    untaggedDenyPrecedence: "absolute",
    memberTagCardinality: "multiple",
    hierarchyTags: "selected_member_only",
    writeReadRelationship: "require_read",
    mixedSelection: "filter_reads_reject_writes",
    administratorTreatment: "require_assignment",
    factSideAuthority: "derived_query_aid_only",
  };
  expect(
    dimensionPolicyMutationBody(
      app,
      "save",
      "a".repeat(64),
      policy,
      7,
      "policy-save",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "policy-save",
    program: {
      languageVersion: 2,
      function: "security.application.dimension-policy.save",
      arguments: { expectedStateToken: "a".repeat(64), policy },
    },
  });
  expect(
    dimensionPolicyMutationBody(
      app,
      "activate",
      "a".repeat(64),
      null,
      7,
      "policy-activate",
    ).program,
  ).toEqual({
    languageVersion: 2,
    function: "security.application.dimension-policy.activate",
    arguments: {
      expectedStateToken: "a".repeat(64),
      expectedSecurityRevision: 7,
    },
  });
  expect(
    dimensionPolicyMutationBody(
      app,
      "deactivate",
      "a".repeat(64),
      null,
      7,
      "policy-deactivate",
    ).program,
  ).toEqual({
    languageVersion: 2,
    function: "security.application.dimension-policy.deactivate",
    arguments: {
      expectedStateToken: "a".repeat(64),
      expectedSecurityRevision: 7,
    },
  });
});

it("invalidates access review when the reviewed role changes", async () => {
  installSecurityFixture();
  render(<AdministrationSecurity app={app} catalog={editableCatalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  await screen.findByText("Alice Planner", { selector: "th" });
  fireEvent.click(screen.getByRole("button", { name: "Grant access" }));
  fireEvent.change(screen.getByLabelText("Application user"), {
    target: { value: "subject-a" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this user, action and role."),
  );
  expect(
    screen.getByRole("button", { name: "Apply reviewed access" }),
  ).toBeEnabled();
  fireEvent.change(screen.getByLabelText("Role"), {
    target: { value: "Editor" },
  });
  expect(
    screen.getByRole("button", { name: "Apply reviewed access" }),
  ).toBeDisabled();
});

it("reads grants, active policy and exact dimensional assignments", async () => {
  const calls: Array<{
    program: { function: string; arguments: Record<string, unknown> };
  }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe("/api/security");
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      switch (body.program.function) {
        case "security.application.access.list":
          return new Response(
            JSON.stringify({
              result: {
                grants: [
                  {
                    subjectId: "subject-owner",
                    displayName: "Application Owner",
                    username: "owner",
                    role: "Administrator",
                    readTags: { Entity: ["North"] },
                    writeTags: { Entity: ["WriteNorth"] },
                    rulePermissions: {
                      design: true,
                      publish: true,
                      run: true,
                    },
                    grantedAt: "2026-11-02T00:00:00Z",
                  },
                ],
                nextAfterSubjectId: null,
              },
            }),
          );
        case "security.application.dimension-policy.read":
          return new Response(
            JSON.stringify({
              result: {
                stateToken: "a".repeat(64),
                policyDigest: "b".repeat(64),
                policy: {
                  acrossDimensions: "every_protected",
                  withinDimension: "any_tag",
                  untaggedMember: "deny",
                  untaggedDenyPrecedence: "absolute",
                  memberTagCardinality: "multiple",
                  hierarchyTags: "selected_member_only",
                  writeReadRelationship: "require_read",
                  mixedSelection: "filter_reads_reject_writes",
                  administratorTreatment: "require_assignment",
                  factSideAuthority: "derived_query_aid_only",
                },
                securityRevision: 7,
                authorizationEffect: true,
                status: "Active",
              },
            }),
          );
        case "security.application.dimension-access.read":
          return new Response(
            JSON.stringify({
              result: {
                subjectId: "subject-owner",
                role: "Administrator",
                readTags: { Entity: ["North"] },
                writeTags: { Entity: ["WriteNorth"] },
                securityRevision: 7,
              },
            }),
          );
        default:
          return new Response(
            JSON.stringify({
              result: {
                dimensions: [
                  {
                    order: 1,
                    dimensionId: "Entity",
                    name: "Entity",
                    modelRole: "Entity",
                    readTags: ["North", "South"],
                    writeTags: ["WriteNorth"],
                  },
                ],
                securityRevision: 7,
              },
            }),
          );
      }
    }),
  );
  const policyCatalog = {
    ...catalog,
    functions: {
      ...catalog.functions,
      "security.application.dimension-policy.save": {},
      "security.application.dimension-policy.activate": {},
      "security.application.dimension-policy.deactivate": {},
    },
  };
  const workspace = render(
    <AdministrationSecurity app={app} catalog={policyCatalog} />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  await screen.findByText("Application Owner", { selector: "th" });
  expect(screen.queryByLabelText("Active policy")).not.toBeInTheDocument();
  expect(screen.getByText("design, publish, run")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Inspect" }));
  expect(await screen.findByLabelText("Dimensional access")).toHaveTextContent(
    "North",
  );
  expect(screen.getByLabelText("Dimensional access")).toHaveTextContent(
    "WriteNorth",
  );
  workspace.rerender(
    <AdministrationSecurity app={app} catalog={policyCatalog} view="policy" />,
  );
  expect(
    screen.queryByText("Application Owner", { selector: "th" }),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Read policy" }));
  expect(await screen.findByLabelText("Active policy")).toHaveTextContent(
    "Active",
  );
  expect(screen.getByLabelText("Active policy")).toHaveTextContent("Active");
  expect(
    screen.queryByLabelText("Policy withinDimension"),
  ).not.toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Change dimensional policy" }),
  );
  expect(calls.map((call) => call.program)).toEqual([
    {
      languageVersion: 2,
      function: "security.application.access.list",
      arguments: { limit: 100 },
    },
    {
      languageVersion: 2,
      function: "security.application.dimension-access.read",
      arguments: { subjectId: "subject-owner" },
    },
    {
      languageVersion: 2,
      function: "security.application.dimension-tags.read",
      arguments: {},
    },
    {
      languageVersion: 2,
      function: "security.application.dimension-policy.read",
      arguments: {},
    },
  ]);
  expect(calls.every((call) => !("confirmed" in call))).toBe(true);
  const save = screen.getByRole("button", { name: "Save current policy" });
  expect(save).toBeDisabled();
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed all ten choices for this current policy.",
    ),
  );
  expect(save).toBeEnabled();
  fireEvent.change(screen.getByLabelText("Policy withinDimension"), {
    target: { value: "all_tags" },
  });
  expect(save).toBeDisabled();
});

it("paginates human-readable security audit events without technical details", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "security.application.access.list")
        return new Response(
          JSON.stringify({
            result: { grants: [], nextAfterSubjectId: null },
          }),
        );
      const before = body.program.arguments.beforeAuditId;
      return new Response(
        JSON.stringify({
          result: before
            ? {
                events: [
                  {
                    auditId: 8,
                    occurredAt: "2026-11-05T11:00:00Z",
                    actorName: "Alice Owner",
                    action: "Changed rule permissions",
                    targetName: "Plan",
                    outcome: "Accepted",
                    detailsKey: "receipt-8",
                  },
                ],
                nextBeforeAuditId: null,
              }
            : {
                events: [
                  {
                    auditId: 9,
                    occurredAt: "2026-11-05T12:00:00Z",
                    actorName: "Alice Owner",
                    action: "Granted application access",
                    targetName: "Bob Planner",
                    outcome: "Accepted",
                    detailsKey: "receipt-9",
                  },
                ],
                nextBeforeAuditId: 9,
              },
        }),
      );
    }),
  );
  render(
    <AdministrationSecurity
      app={app}
      view="audit"
      catalog={{
        ...catalog,
        functions: {
          "security.application.access.list": {},
          "security.application.audit.list": {},
        },
      }}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read audit" }));
  await screen.findByText("Granted application access");
  expect(screen.queryByText("receipt-9")).not.toBeInTheDocument();
  expect(
    screen.queryByRole("columnheader", { name: "Details" }),
  ).not.toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", {
      name: "Load older security events",
    }),
  );
  await screen.findByText("Changed rule permissions");
  expect(screen.queryByText("receipt-8")).not.toBeInTheDocument();
  expect(
    screen.getByRole("article", { name: "Security audit" }),
  ).toHaveTextContent("Granted application access");
  expect(
    screen.getByRole("article", { name: "Security audit" }),
  ).toHaveTextContent("Changed rule permissions");
});

it("stays absent when the server does not authorize grant listing", () => {
  const { container } = render(
    <AdministrationSecurity
      app={app}
      catalog={{ ...catalog, functions: {} }}
    />,
  );
  expect(container).toBeEmptyDOMElement();
});

const editableCatalog = {
  ...catalog,
  functions: {
    ...catalog.functions,
    "security.application.access.set": {},
    "security.application.subject.list": {},
    "security.rule.access.set": {},
    "security.application.dimension-access.set": {},
    "security.application.dimension-policy.save": {},
    "security.application.dimension-policy.activate": {},
    "security.application.dimension-policy.deactivate": {},
  },
};
const sampleGrant = {
  subjectId: "subject-a",
  displayName: "Alice Planner",
  username: "alice",
  role: "Reader",
  readTags: {},
  writeTags: {},
  rulePermissions: { design: false, publish: false, run: true },
  grantedAt: "2026-11-07T08:00:00Z",
};
const samplePolicy = {
  acrossDimensions: "every_protected",
  withinDimension: "any_tag",
  untaggedMember: "deny",
  untaggedDenyPrecedence: "absolute",
  memberTagCardinality: "multiple",
  hierarchyTags: "selected_member_only",
  writeReadRelationship: "require_read",
  mixedSelection: "filter_reads_reject_writes",
  administratorTreatment: "require_assignment",
  factSideAuthority: "derived_query_aid_only",
};
function securityFixture(functionName: string) {
  if (functionName === "security.application.access.list")
    return { grants: [sampleGrant], nextAfterSubjectId: null };
  if (functionName === "security.application.subject.list")
    return {
      subjects: [
        {
          selectionKey: sampleGrant.subjectId,
          displayName: sampleGrant.displayName,
          username: sampleGrant.username,
        },
      ],
      nextAfterSelectionKey: null,
    };
  if (functionName === "security.application.dimension-policy.read")
    return {
      stateToken: "a".repeat(64),
      policyDigest: "b".repeat(64),
      policy: samplePolicy,
      securityRevision: 7,
      authorizationEffect: true,
      status: "Active",
    };
  if (functionName === "security.application.dimension-access.read")
    return { ...sampleGrant, securityRevision: 7 };
  if (functionName === "security.application.dimension-tags.read")
    return {
      dimensions: [
        {
          order: 1,
          dimensionId: "Entity",
          name: "Entity",
          modelRole: "Entity",
          readTags: ["North"],
          writeTags: ["WriteNorth"],
        },
      ],
      securityRevision: 7,
    };
  throw new Error(`Unexpected fixture read: ${functionName}`);
}
function installSecurityFixture() {
  const fetch = vi.fn(
    async (_input: RequestInfo | URL, init?: RequestInit) =>
      new Response(
        JSON.stringify({
          result: securityFixture(
            JSON.parse(String(init?.body)).program.function,
          ),
        }),
      ),
  );
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

it("keeps access tasks deliberate and clears all discarded local drafts when opening another editor", async () => {
  const fetch = installSecurityFixture();
  let accept: (() => void) | undefined;
  render(
    <AdministrationSecurity
      app={app}
      catalog={editableCatalog}
      onRequestTransition={(action) => {
        if (unsavedWorkSnapshot().length) accept = action;
        else action();
      }}
    />,
  );
  expect(screen.queryByLabelText("Application user")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  await screen.findByText("Alice Planner", { selector: "th" });
  const grant = screen.getByRole("button", { name: "Grant access" });
  grant.focus();
  fireEvent.click(grant);
  expect(
    screen.getByRole("heading", { name: "Reviewed application access" }),
  ).toHaveFocus();
  fireEvent.change(screen.getByLabelText("Application user"), {
    target: { value: "subject-a" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Close access editor" }));
  expect(screen.getByLabelText("Application user")).toHaveValue("subject-a");
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  act(() => {
    discardUnsavedWork();
    accept?.();
  });
  expect(screen.queryByLabelText("Application user")).not.toBeInTheDocument();
  expect(grant).toHaveFocus();
  fireEvent.click(grant);
  expect(screen.getByLabelText("Application user")).toHaveValue("");
  fireEvent.change(screen.getByLabelText("Application user"), {
    target: { value: "subject-a" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Manage" }));
  expect(screen.getByLabelText("Application user")).toHaveValue("subject-a");
  act(() => {
    discardUnsavedWork();
    accept?.();
  });
  expect(screen.queryByLabelText("Application user")).not.toBeInTheDocument();
  expect(
    screen.getByRole("heading", { name: "Rule permissions · Alice Planner" }),
  ).toHaveFocus();
  expect(unsavedWorkSnapshot()).toEqual([]);
  fireEvent.click(screen.getByLabelText("Design"));
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  expect(fetch).toHaveBeenCalledTimes(2);
});

it("guards closing a changed dimensional policy and reopens the saved baseline without stale review", async () => {
  installSecurityFixture();
  let accept: (() => void) | undefined;
  render(
    <AdministrationSecurity
      app={app}
      catalog={editableCatalog}
      view="policy"
      onRequestTransition={(action) => {
        if (unsavedWorkSnapshot().length) accept = action;
        else action();
      }}
    />,
  );
  expect(
    screen.queryByLabelText("Policy withinDimension"),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Read policy" }));
  const change = await screen.findByRole("button", {
    name: "Change dimensional policy",
  });
  fireEvent.click(change);
  fireEvent.change(screen.getByLabelText("Policy withinDimension"), {
    target: { value: "all_tags" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Close policy editor" }));
  expect(screen.getByLabelText("Policy withinDimension")).toHaveValue(
    "all_tags",
  );
  act(() => {
    discardUnsavedWork();
    accept?.();
  });
  expect(
    screen.queryByLabelText("Policy withinDimension"),
  ).not.toBeInTheDocument();
  expect(unsavedWorkSnapshot()).toEqual([]);
  fireEvent.click(change);
  expect(screen.getByLabelText("Policy withinDimension")).toHaveValue(
    "any_tag",
  );
  expect(
    screen.getByRole("button", { name: "Save current policy" }),
  ).toBeDisabled();
});

it("locks an access mutation and retains committed status separately when its inventory refresh fails", async () => {
  let commit!: (response: Response) => void;
  let writes = 0;
  let initialReads = 0;
  const bodies: Array<Record<string, any>> = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      bodies.push(body);
      if (body.confirmed) {
        writes += 1;
        return new Promise<Response>((resolve) => {
          commit = resolve;
        });
      }
      if (initialReads < 2) {
        initialReads += 1;
        return new Response(
          JSON.stringify({ result: securityFixture(body.program.function) }),
        );
      }
      return new Response(JSON.stringify({ code: "ACCESS_READ_FAILED" }), {
        status: 422,
      });
    }),
  );
  installOperationAdmissionFixture("c");
  render(<AdministrationSecurity app={app} catalog={editableCatalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  await screen.findByText("Alice Planner", { selector: "th" });
  fireEvent.click(screen.getByRole("button", { name: "Grant access" }));
  fireEvent.change(screen.getByLabelText("Application user"), {
    target: { value: "subject-a" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this user, action and role."),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Apply reviewed access" }),
  );
  expect(screen.getByLabelText("Application user")).toBeDisabled();
  expect(screen.getByLabelText("Role")).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Close access editor" }),
  ).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Application user"), {
    target: { value: "" },
  });
  expect(screen.getByLabelText("Application user")).toHaveValue("subject-a");
  await waitFor(() => expect(writes).toBe(1));
  const writeBody = bodies.find((body) => body.confirmed)!;
  await act(async () =>
    commit(
      securityWriteResponse({
        workspaceId: writeBody.workspaceId,
        applicationId: writeBody.applicationId,
        program: writeBody.program,
      }),
    ),
  );
  expect(await screen.findByRole("status")).toHaveTextContent(
    "application access change was committed",
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "ACCESS_READ_FAILED",
  );
  expect(screen.queryByLabelText("Application user")).not.toBeInTheDocument();
  expect(unsavedWorkSnapshot()).toEqual([]);
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  await waitFor(() => expect(bodies.length).toBeGreaterThanOrEqual(5));
  expect(writes).toBe(1);
  expect(writeBody?.program).toEqual({
    languageVersion: 2,
    function: "security.application.access.set",
    arguments: { subjectId: "subject-a", action: "grant", role: "Reader" },
  });
  expect(writeBody?.idempotencyKey).toMatch(/^oa1_/);
});

const protectedAuditEvent = {
  auditId: 9,
  occurredAt: "2026-11-05T12:00:00Z",
  actorName: "Protected audit actor",
  action: "Granted application access",
  targetName: "Protected audit subject",
  outcome: "Accepted",
  detailsKey: null,
};

it.each([
  [
    "access",
    "Read access",
    "Application access",
    "security.application.access.list",
    { grants: [sampleGrant], nextAfterSubjectId: null },
  ],
  [
    "groups",
    "Read access",
    "Application group access",
    "security.application.group-access.list",
    {
      grants: [
        {
          ...sampleGrant,
          groupId: "group-a",
          groupName: "planners",
          directoryStatus: "Active",
        },
      ],
      nextAfterGroupId: null,
    },
  ],
  [
    "policy",
    "Read policy",
    "Active policy",
    "security.application.dimension-policy.read",
    securityFixture("security.application.dimension-policy.read"),
  ],
  [
    "audit",
    "Read audit",
    "Scrollable security records",
    "security.application.audit.list",
    { events: [protectedAuditEvent], nextBeforeAuditId: null },
  ],
] as const)(
  "withdraws the previous %s snapshot while a new read is pending or denied",
  async (view, button, snapshot, functionName, result) => {
    let finishRead!: (value: Response) => void;
    const fetch = vi
      .fn()
      .mockImplementationOnce(async () => Response.json({ result }))
      .mockImplementationOnce(
        () =>
          new Promise<Response>((resolve) => {
            finishRead = resolve;
          }),
      )
      .mockImplementationOnce(async () => Response.json({ result }));
    vi.stubGlobal("fetch", fetch);
    render(
      <AdministrationSecurity
        app={app}
        view={view}
        catalog={{ ...catalog, functions: { [functionName]: {} } }}
      />,
    );
    const refresh = screen.getByRole("button", { name: button });
    fireEvent.click(refresh);
    await screen.findByLabelText(snapshot);

    refresh.focus();
    fireEvent.click(refresh);
    expect(screen.getByRole("status")).toHaveTextContent("Loading");
    expect(screen.queryByLabelText(snapshot)).not.toBeInTheDocument();
    expect(refresh).toHaveFocus();
    fireEvent.click(refresh);
    expect(fetch).toHaveBeenCalledTimes(2);
    await act(async () =>
      finishRead(
        Response.json({ error: "APPLICATION_ACCESS_DENIED" }, { status: 403 }),
      ),
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "unavailable under your current access",
    );
    expect(screen.queryByLabelText(snapshot)).not.toBeInTheDocument();
    expect(refresh).toHaveFocus();

    fireEvent.click(refresh);
    expect(await screen.findByLabelText(snapshot)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(3);
    for (const [path, init] of fetch.mock.calls) {
      expect(path).toBe("/api/security");
      expect(JSON.parse(init.body)).toMatchObject({
        workspaceId: "ws",
        applicationId: "app",
        program: { function: functionName },
      });
    }
  },
);

it.each([
  [
    "Load older security events",
    403,
    "APPLICATION_ACCESS_DENIED",
    "unavailable under your current access",
  ],
  [
    "Export complete CSV",
    403,
    "APPLICATION_ACCESS_DENIED",
    "unavailable under your current access",
  ],
  [
    "Load older security events",
    409,
    "SECURITY_READ_AUTHORIZATION_STALE",
    "Security access changed while loading",
  ],
  [
    "Export complete CSV",
    409,
    "SECURITY_READ_AUTHORIZATION_STALE",
    "Security access changed while loading",
  ],
])(
  "clears already loaded sensitive audit rows when %s returns %s",
  async (action, status, code, guidance) => {
    const fetch = vi
      .fn()
      .mockImplementationOnce(async () =>
        Response.json({
          result: { events: [protectedAuditEvent], nextBeforeAuditId: 9 },
        }),
      )
      .mockImplementationOnce(async () => Response.json({ code }, { status }))
      .mockImplementationOnce(async () =>
        Response.json({ result: { events: [], nextBeforeAuditId: null } }),
      );
    vi.stubGlobal("fetch", fetch);
    render(
      <AdministrationSecurity
        app={app}
        view="audit"
        catalog={{
          ...catalog,
          functions: { "security.application.audit.list": {} },
        }}
      />,
    );
    const read = screen.getByRole("button", { name: "Read audit" });
    fireEvent.click(read);
    await screen.findByText(protectedAuditEvent.actorName);
    const trigger = screen.getByRole("button", { name: action });
    trigger.focus();
    fireEvent.click(trigger);
    expect(await screen.findByRole("alert")).toHaveTextContent(guidance);
    expect(
      screen.queryByText(protectedAuditEvent.actorName),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Load older security events" }),
    ).not.toBeInTheDocument();
    expect(
      action === "Load older security events" ? read : trigger,
    ).toHaveFocus();
    fireEvent.click(read);
    expect(
      await screen.findByText(
        "No application security audit events were returned.",
      ),
    ).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(3);
  },
);

it("withdraws the access list when an inspect request loses current authority", async () => {
  const fetch = vi.fn(async (_path: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    if (body.program.function === "security.application.dimension-access.read")
      return Response.json(
        { error: "APPLICATION_ACCESS_DENIED" },
        { status: 403 },
      );
    return Response.json({ result: securityFixture(body.program.function) });
  });
  vi.stubGlobal("fetch", fetch);
  render(<AdministrationSecurity app={app} catalog={catalog} />);
  const read = screen.getByRole("button", { name: "Read access" });
  fireEvent.click(read);
  const inspect = await screen.findByRole("button", { name: "Inspect" });
  inspect.focus();
  fireEvent.click(inspect);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "unavailable under your current access",
  );
  expect(screen.queryByText(sampleGrant.displayName)).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Inspect" }),
  ).not.toBeInTheDocument();
  expect(read).toHaveFocus();
});

it("keeps the current audit page and can retry a throttled continuation", async () => {
  const firstPage = { events: [protectedAuditEvent], nextBeforeAuditId: 9 };
  const older = {
    ...protectedAuditEvent,
    auditId: 8,
    actorName: "Older audit actor",
  };
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(Response.json({ result: firstPage }))
    .mockResolvedValueOnce(
      Response.json(
        { error: "CAPACITY_LIMIT", message: "Try reading older events again." },
        { status: 429 },
      ),
    )
    .mockResolvedValueOnce(
      Response.json({ result: { events: [older], nextBeforeAuditId: null } }),
    );
  vi.stubGlobal("fetch", fetch);
  render(
    <AdministrationSecurity
      app={app}
      view="audit"
      catalog={{
        ...catalog,
        functions: { "security.application.audit.list": {} },
      }}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read audit" }));
  await screen.findByText(protectedAuditEvent.actorName);
  const loadOlder = screen.getByRole("button", {
    name: "Load older security events",
  });
  loadOlder.focus();
  fireEvent.click(loadOlder);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Try reading older events again.",
  );
  expect(loadOlder).toHaveFocus();
  expect(screen.getByText(protectedAuditEvent.actorName)).toBeInTheDocument();
  fireEvent.click(loadOlder);
  expect(await screen.findByText(older.actorName)).toBeInTheDocument();
  expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual(
    JSON.parse(fetch.mock.calls[2][1].body),
  );
});

it("cancels an abandoned security read without exposing it in the next application", async () => {
  let resolveOld!: (response: Response) => void;
  let signal: AbortSignal | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (body.applicationId === "app") {
        signal = init?.signal as AbortSignal;
        return new Promise<Response>((resolve) => {
          resolveOld = resolve;
        });
      }
      return new Response(
        JSON.stringify({
          result: {
            grants: [
              {
                ...sampleGrant,
                subjectId: "beta-user",
                displayName: "Beta User",
                username: "beta",
              },
            ],
            nextAfterSubjectId: null,
          },
        }),
      );
    }),
  );
  const workspace = render(
    <AdministrationSecurity app={app} catalog={catalog} />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  workspace.rerender(
    <AdministrationSecurity
      app={{ ...app, applicationId: "beta" }}
      catalog={catalog}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  expect(
    await screen.findByText("Beta User", { selector: "th" }),
  ).toBeInTheDocument();
  expect(signal?.aborted).toBe(true);
  await act(async () =>
    resolveOld(
      new Response(
        JSON.stringify({
          result: { grants: [sampleGrant], nextAfterSubjectId: null },
        }),
      ),
    ),
  );
  expect(
    screen.queryByText("Alice Planner", { selector: "th" }),
  ).not.toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it("renders fifty loaded users per page while retaining the chosen user's exact permission context", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const functionName = JSON.parse(String(init?.body)).program.function;
      return new Response(
        JSON.stringify({
          result:
            functionName === "security.application.subject.list"
              ? {
                  subjects: [],
                  nextAfterSelectionKey: null,
                }
              : {
                  grants: Array.from({ length: 61 }, (_, index) => ({
                    ...sampleGrant,
                    subjectId: `subject-${String(index).padStart(2, "0")}`,
                    displayName: `User ${String(index).padStart(2, "0")}`,
                    username: `user-${String(index).padStart(2, "0")}`,
                  })),
                  nextAfterSubjectId: null,
                },
        }),
      );
    }),
  );
  render(<AdministrationSecurity app={app} catalog={editableCatalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  const table = await screen.findByRole("table", {
    name: "Application access",
  });
  expect(within(table).getAllByRole("row")).toHaveLength(51);
  fireEvent.click(screen.getByRole("button", { name: "Next users" }));
  expect(within(table).getAllByRole("row")).toHaveLength(12);
  fireEvent.click(
    within(within(table).getByRole("row", { name: /User 60/ })).getByRole(
      "button",
      { name: "Manage" },
    ),
  );
  expect(
    screen.getByRole("heading", { name: "Rule permissions · User 60" }),
  ).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Find an application user"), {
    target: { value: "User 00" },
  });
  expect(within(table).getAllByRole("row")).toHaveLength(2);
  expect(
    screen.getByRole("heading", { name: "Rule permissions · User 60" }),
  ).toBeInTheDocument();
});

it("keeps unrelated retained drafts when clean security inventory actions open or close an editor", async () => {
  installSecurityFixture();
  setUnsavedWork("retained-rule", "Unsaved rule definition", true);
  const requestTransition = vi.fn((action: () => void) => {
    discardUnsavedWork();
    action();
  });
  render(
    <AdministrationSecurity
      app={app}
      catalog={editableCatalog}
      onRequestTransition={requestTransition}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  await screen.findByText("Alice Planner", { selector: "th" });
  fireEvent.click(screen.getByRole("button", { name: "Grant access" }));
  fireEvent.click(screen.getByRole("button", { name: "Close access editor" }));
  fireEvent.click(screen.getByRole("button", { name: "Manage" }));
  fireEvent.click(
    screen.getByRole("button", { name: "Close rule permissions" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Inspect" }));
  await screen.findByRole("button", { name: "Close dimensional access" });
  fireEvent.click(
    screen.getByRole("button", { name: "Close dimensional access" }),
  );
  expect(requestTransition).not.toHaveBeenCalled();
  expect(unsavedWorkSnapshot()).toEqual([
    { id: "retained-rule", label: "Unsaved rule definition" },
  ]);
});

const groupCatalog = {
  ...catalog,
  functions: {
    "security.application.group-access.list": {},
    "security.application.group-access.set": {},
    "security.application.group-dimension-access.read": {},
    "security.application.group-dimension-access.set": {},
    "security.application.dimension-tags.read": {},
    "security.rule.group-access.set": {},
  },
};
const planningGroup = {
  groupId: "hidden-keycloak-group-id",
  groupName: "finance-planning",
  displayName: "Finance Planning",
  directoryStatus: "Active",
  role: "Reader",
  readTags: {},
  writeTags: {},
  rulePermissions: { design: false, publish: false, run: true },
  grantedAt: "2026-11-07T08:00:00Z",
};

it("reviews named group grants without opening the platform directory", async () => {
  const writes: Array<{
    workspaceId: string;
    applicationId: string;
    idempotencyKey: string;
    program: { function: string; arguments: Record<string, unknown> };
  }> = [];
  const calls: string[] = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(String(input));
      const body = JSON.parse(String(init?.body));
      if (body.confirmed) {
        writes.push(body);
        return securityWriteResponse(body);
      }
      switch (body.program.function) {
        case "security.application.group-access.list":
          return Response.json({
            result: {
              grants: [
                planningGroup,
                {
                  ...planningGroup,
                  groupId: "hidden-separate-group-id",
                  groupName: "regional-finance",
                },
                {
                  ...planningGroup,
                  groupId: "hidden-orphan-group-id",
                  displayName: null,
                  groupName: null,
                  directoryStatus: null,
                },
              ],
              nextAfterGroupId: null,
            },
          });
        case "security.application.group-dimension-access.read":
          return Response.json({
            result: {
              groupId: planningGroup.groupId,
              role: "Reader",
              readTags: {},
              writeTags: {},
              securityRevision: 7,
            },
          });
        case "security.application.dimension-tags.read":
          return Response.json({
            result: securityFixture(body.program.function),
          });
        default:
          throw new Error("Unexpected group security call");
      }
    }),
  );
  installOperationAdmissionFixture("g");
  render(
    <AdministrationSecurity app={app} catalog={groupCatalog} view="groups" />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  const table = await screen.findByRole("table", {
    name: "Application group access",
  });
  const planningLabel = `${planningGroup.displayName} (${planningGroup.groupName})`;
  expect(within(table).getByText(planningLabel)).toBeInTheDocument();
  expect(
    within(table).getByText("Finance Planning (regional-finance)"),
  ).toBeInTheDocument();
  expect(
    within(table).getByText("Unavailable directory identity"),
  ).toBeInTheDocument();
  expect(document.body).not.toHaveTextContent("hidden-keycloak-group-id");
  expect(document.body).not.toHaveTextContent("hidden-orphan-group-id");
  expect(
    screen.queryByRole("button", { name: "Read eligible groups" }),
  ).not.toBeInTheDocument();

  fireEvent.click(
    within(table).getByRole("button", {
      name: `Inspect dimensional access for ${planningLabel}`,
    }),
  );
  const readTags = await screen.findByRole("textbox", {
    name: "Entity assigned read tags",
  });
  fireEvent.change(readTags, { target: { value: "North" } });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact group and dimensional assignment.",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Apply reviewed dimensional access" }),
  );
  await screen.findByText(/dimensional assignments change was committed/);

  const active = await screen.findByRole("button", {
    name: `Manage rule permissions for ${planningLabel}`,
  });
  fireEvent.click(active);
  fireEvent.click(screen.getByLabelText("Design"));
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact group, action and permission set.",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Apply reviewed rule permissions" }),
  );
  await screen.findByText(/rule permissions change was committed/);

  fireEvent.click(
    await screen.findByRole("button", {
      name: `Manage role for ${planningLabel}`,
    }),
  );
  fireEvent.change(screen.getByLabelText("Action"), {
    target: { value: "revoke" },
  });
  expect(screen.getByText(/revoke this group grant/)).toBeInTheDocument();
  fireEvent.click(
    screen.getByLabelText("I reviewed this group, action and role."),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Apply reviewed access" }),
  );
  await screen.findByText(/application access change was committed/);

  expect(writes).toHaveLength(3);
  expect(writes.map(({ program }) => program)).toEqual([
    {
      languageVersion: 2,
      function: "security.application.group-dimension-access.set",
      arguments: {
        groupId: planningGroup.groupId,
        readTags: { Entity: ["North"] },
        writeTags: {},
        expectedSecurityRevision: 7,
      },
    },
    {
      languageVersion: 2,
      function: "security.rule.group-access.set",
      arguments: {
        groupId: planningGroup.groupId,
        action: "set",
        permissions: { design: true, publish: false, run: true },
      },
    },
    {
      languageVersion: 2,
      function: "security.application.group-access.set",
      arguments: {
        groupId: planningGroup.groupId,
        action: "revoke",
        role: null,
      },
    },
  ]);
  for (const write of writes) {
    expect(write.idempotencyKey).toMatch(/^oa1_/);
    expect([write.workspaceId, write.applicationId]).toEqual(["ws", "app"]);
  }
  expect(calls).not.toContain("/api/platform/browser/read");
});

it("loads only eligible new groups through the separately granted server directory", async () => {
  let directoryCalls = 0;
  let applied: unknown;
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/platform/browser/read") {
        directoryCalls += 1;
        expect(body.program.function).toBe("identity.group.list");
        return Response.json({
          items: [
            {
              groupId: "managed-finance",
              groupName: "forecast",
              displayName: "Forecast Reviewers",
              shortDescription: "",
              semanticDescription: "",
              status: "Active",
            },
            {
              groupId: "retired-finance",
              groupName: "retired",
              displayName: "Archived Group",
              shortDescription: "",
              semanticDescription: "",
              status: "Inactive",
            },
          ],
          nextOffset: null,
        });
      }
      if (body.confirmed) {
        applied = body;
        return securityWriteResponse(body);
      }
      expect(body.program.function).toBe(
        "security.application.group-access.list",
      );
      return Response.json({ result: { grants: [], nextAfterGroupId: null } });
    }),
  );
  installOperationAdmissionFixture("b");
  render(
    <AdministrationSecurity
      app={app}
      catalog={groupCatalog}
      view="groups"
      canReadDirectoryGroups
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  await screen.findByText("No application groups were returned.");
  fireEvent.click(screen.getByRole("button", { name: "Review group access" }));
  expect(directoryCalls).toBe(0);
  fireEvent.click(screen.getByRole("button", { name: "Read eligible groups" }));
  await screen.findByRole("option", { name: "Forecast Reviewers (forecast)" });
  expect(
    screen.queryByRole("option", { name: "Archived Group (retired)" }),
  ).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Application group"), {
    target: { value: "managed-finance" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this group, action and role."),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Apply reviewed access" }),
  );
  await screen.findByText(/application access change was committed/);
  expect(applied).toMatchObject({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    program: {
      function: "security.application.group-access.set",
      arguments: {
        groupId: "managed-finance",
        action: "grant",
        role: "Reader",
      },
    },
  });
  expect(directoryCalls).toBe(1);
});

const recoveryCatalog = {
  ...groupCatalog,
  functions: {
    ...groupCatalog.functions,
    "security.application.receipt.read": {},
    "security.application.audit.list": {},
  },
};

function reviewExistingGroupRole() {
  fireEvent.click(
    screen.getByRole("button", {
      name: "Manage role for Finance Planning (finance-planning)",
    }),
  );
  fireEvent.change(screen.getByLabelText("Role"), {
    target: { value: "Editor" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this group, action and role."),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Apply reviewed access" }),
  );
}

function groupAccessResponse() {
  return Response.json({
    result: { grants: [planningGroup], nextAfterGroupId: null },
  });
}

type RecordedSecurityRequest = {
  workspaceId: string;
  applicationId: string;
  idempotencyKey: string;
  confirmed?: boolean;
  program: { function: string; arguments: Record<string, unknown> };
};

it("restores the original security receipt check across app, actor and section changes without writing again", async () => {
  const effects: RecordedSecurityRequest[] = [];
  const receiptReads: RecordedSecurityRequest[] = [];
  let admissions = 0;
  const copy = vi.fn(async () => {});
  vi.stubGlobal("navigator", { clipboard: { writeText: copy } });
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as RecordedSecurityRequest;
      if (String(input) === "/api/operation-admission") {
        admissions += 1;
        return operationAdmissionResponse();
      }
      if (body.confirmed) {
        effects.push(body);
        throw new TypeError("Connection lost after commit");
      }
      if (body.program.function === "security.application.receipt.read") {
        receiptReads.push(body);
        return Response.json({
          result: {
            workspaceId: app.workspaceId,
            applicationId:
              receiptReads.length === 1 ? "different-app" : app.applicationId,
            outcome: "Committed",
            operationId: effects[0].idempotencyKey,
            actorDigest: "a".repeat(64),
            commandDigest: "b".repeat(64),
            payloadDigest: "c".repeat(64),
            committedAt: "2026-11-19T12:00:00Z",
          },
        });
      }
      if (body.program.function === "security.application.audit.list")
        return Response.json({
          result: { events: [], nextBeforeAuditId: null },
        });
      return groupAccessResponse();
    }),
  );

  setDraftIdentity("original-admin");
  const renderScope = (
    target = app,
    view: "groups" | "audit" = "groups",
    key = "owner",
  ) => (
    <AdministrationSecurity
      key={key}
      app={target}
      catalog={recoveryCatalog}
      view={view}
    />
  );
  const workspace = render(renderScope());
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  await screen.findByRole("rowheader", {
    name: "Finance Planning (finance-planning)",
  });
  reviewExistingGroupRole();
  await screen.findByText("The reply did not confirm the security change.");
  expect(
    screen.getByRole("button", { name: "Apply reviewed access" }),
  ).toBeDisabled();
  expect(
    screen.queryByRole("button", { name: "Retry original security change" }),
  ).toBeNull();

  workspace.rerender(renderScope({ ...app, applicationId: "independent" }));
  expect(
    screen.queryByRole("region", { name: "Original security change" }),
  ).toBeNull();
  setDraftIdentity("different-admin");
  workspace.rerender(renderScope(app, "groups", "other"));
  expect(
    screen.queryByRole("region", { name: "Original security change" }),
  ).toBeNull();

  setDraftIdentity("original-admin");
  workspace.rerender(renderScope(app, "audit"));
  await screen.findByText("The original security change is unconfirmed.");
  const check = screen.getByRole("button", {
    name: "Check original security change",
  });
  await waitFor(() => expect(check).toBeEnabled());
  fireEvent.click(
    screen.getByRole("button", { name: "Copy receipt check for MCP" }),
  );
  const expectedProgram = {
    languageVersion: 2,
    function: "security.application.receipt.read",
    arguments: { operationId: effects[0].idempotencyKey },
  };
  await waitFor(() =>
    expect(copy).toHaveBeenCalledWith(
      JSON.stringify({
        workspace_id: app.workspaceId,
        application_id: app.applicationId,
        program: expectedProgram,
      }),
    ),
  );
  fireEvent.click(check);
  await screen.findByText(
    "The receipt could not confirm the original security change.",
  );
  fireEvent.click(check);
  await screen.findByText(
    "The original application access change was recorded.",
  );
  expect(receiptReads).toEqual(
    Array.from({ length: 2 }, () => ({
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
      program: expectedProgram,
    })),
  );
  expect(admissions).toBe(1);
  expect(effects).toHaveLength(1);
  expect(unsavedWorkSnapshot()).toEqual([]);
});

it.each([
  { status: 403, code: "APPLICATION_GRANT_REQUIRED" },
  { status: 400, code: "OPERATION_ADMISSION_EXPIRED" },
])(
  "replays only the original admitted security packet after missing receipt and keeps uncertainty on $code",
  async ({ status, code }) => {
    const effects: RecordedSecurityRequest[] = [];
    let admissions = 0;
    vi.stubGlobal(
      "confirm",
      vi.fn(() => true),
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body)) as RecordedSecurityRequest;
        if (String(input) === "/api/operation-admission") {
          admissions += 1;
          return operationAdmissionResponse();
        }
        if (body.confirmed) {
          effects.push(body);
          return effects.length === 1
            ? Response.json({ code: "GATEWAY_UNAVAILABLE" }, { status: 502 })
            : Response.json({ code }, { status });
        }
        if (body.program.function === "security.application.receipt.read")
          return Response.json(
            { code: "SECURITY_RECEIPT_UNAVAILABLE" },
            { status: 400 },
          );
        return groupAccessResponse();
      }),
    );

    render(
      <AdministrationSecurity
        app={app}
        catalog={recoveryCatalog}
        view="groups"
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Read access" }));
    await screen.findByRole("rowheader", {
      name: "Finance Planning (finance-planning)",
    });
    reviewExistingGroupRole();
    await screen.findByText("The reply did not confirm the security change.");
    fireEvent.click(
      screen.getByRole("button", { name: "Check original security change" }),
    );
    await screen.findByText(
      "There is no visible receipt yet. The original outcome is still unknown.",
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Retry original security change" }),
    );
    await screen.findByText(
      "The retry could not confirm the original security change.",
    );
    expect(admissions).toBe(1);
    expect(effects).toEqual([effects[0], effects[0]]);
    expect(
      screen.getByRole("button", { name: "Apply reviewed access" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Check original security change" }),
    ).toBeEnabled();
  },
);

it("keeps a first scoped rejection separate from an unknown security change", async () => {
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      return body.confirmed
        ? Response.json({ code: "APPLICATION_GRANT_REQUIRED" }, { status: 403 })
        : groupAccessResponse();
    }),
  );
  installOperationAdmissionFixture("e");
  render(
    <AdministrationSecurity
      app={app}
      catalog={recoveryCatalog}
      view="groups"
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  await screen.findByRole("rowheader", {
    name: "Finance Planning (finance-planning)",
  });
  reviewExistingGroupRole();
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "APPLICATION_GRANT_REQUIRED",
  );
  expect(
    screen.queryByRole("region", { name: "Original security change" }),
  ).toBeNull();
  expect(
    screen.getByRole("button", { name: "Apply reviewed access" }),
  ).toBeEnabled();
});
