import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { installOperationAdmissionFixture } from "./test-setup";
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
  await act(async () =>
    commit(new Response(JSON.stringify({ result: { changed: true } }))),
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
  const writeBody = bodies.find((body) => body.confirmed);
  expect(writeBody?.program).toEqual({
    languageVersion: 2,
    function: "security.application.access.set",
    arguments: { subjectId: "subject-a", action: "grant", role: "Reader" },
  });
  expect(writeBody?.idempotencyKey).toMatch(/^oa1_/);
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
