import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  accessMutationBody,
  accessListArguments,
  auditListArguments,
  AdministrationSecurity,
  collectCompleteSecurityAudit,
  collectPolicyVersions,
  collectSecuritySubjects,
  dimensionAccessMutationBody,
  dimensionPolicyMutationBody,
  parseSecurityTags,
  policyListArguments,
  ruleAccessMutationBody,
  securityAuditCsv,
} from "./AdministrationSecurity";

afterEach(() => vi.unstubAllGlobals());

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
    "security.application.dimension-policy.active.read": {},
    "security.application.dimension-policy.version.list": {},
    "security.application.dimension-access.read": {},
    "security.application.dimension-tags.read": {},
  },
  revisions: { metadata: 1, data: 1, policy: 1, security: 7, commit: 1 },
};

it("reads complete subject and policy-version catalogues beyond former caps", async () => {
  let subjectPage = 0;
  const subjects = await collectSecuritySubjects(async () => {
    const current = subjectPage++;
    return {
      grants: Array.from({ length: 100 }, (_unused, row) => ({
        subjectId: `s-${current}-${row}`,
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

  let versionPage = 0;
  const versions = await collectPolicyVersions(7, async (arguments_) => {
    const current = versionPage++;
    if (current) expect(arguments_.afterVersion).toBe(current);
    return {
      items: Array.from({ length: 100 }, (_unused, row) => ({
        policyVersion: current * 100 + row + 1,
        policy: {},
      })),
      nextAfterVersion: current === 10 ? null : current + 1,
      securityRevision: 7,
    };
  });
  expect(versions.rows).toHaveLength(1100);
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
  let versionPage = 0;
  await expect(
    collectPolicyVersions(7, async () => ({
      items: [{ policyVersion: 1, policy: {} }],
      nextAfterVersion: versionPage++ < 1 ? 1 : null,
      securityRevision: 7,
    })),
  ).rejects.toThrow("repeated a row");
  await expect(
    collectPolicyVersions(7, async () => ({
      items: [],
      nextAfterVersion: null,
      securityRevision: 8,
    })),
  ).rejects.toThrow("Security revision changed");
  await expect(
    collectPolicyVersions(7, async () => ({
      items: [],
      nextAfterVersion: 0,
      securityRevision: 7,
    })),
  ).rejects.toThrow("version cursor is invalid");
});

it("preserves application-access pagination arguments", () => {
  expect(accessListArguments()).toEqual({ limit: 100 });
  expect(accessListArguments("subject-a")).toEqual({
    afterSubjectId: "subject-a",
    limit: 100,
  });
  expect(policyListArguments()).toEqual({ limit: 100 });
  expect(policyListArguments(2)).toEqual({ afterVersion: 2, limit: 100 });
  expect(auditListArguments()).toEqual({ limit: 100 });
  expect(auditListArguments(42)).toEqual({ beforeAuditId: 42, limit: 100 });
});

it("exports the safe audit projection as exact CSV", () => {
  expect(
    securityAuditCsv([
      {
        auditId: 42,
        occurredAt: "2026-11-05T12:00:00+00:00",
        actorDigest: "actor-digest",
        action: "application.grant",
        targetDigest: "target-digest",
        outcome: "Accepted",
        operationId: 'receipt,"42"',
      },
    ]),
  ).toBe(
    "auditId,occurredAt,action,outcome,actorDigest,targetDigest,operationId\r\n" +
      '42,2026-11-05T12:00:00+00:00,application.grant,Accepted,actor-digest,target-digest,"receipt,""42"""',
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
              actorDigest: "8".repeat(64),
              action: "rule.set",
              targetDigest: null,
              outcome: "Accepted" as const,
              operationId: "receipt-8",
            },
          ],
          nextBeforeAuditId: null,
        }
      : {
          events: [
            {
              auditId: 9,
              occurredAt: "2026-11-05T12:00:00Z",
              actorDigest: "9".repeat(64),
              action: "application.grant",
              targetDigest: "a".repeat(64),
              outcome: "Accepted" as const,
              operationId: "receipt-9",
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
          actorDigest: "not-a-digest",
          action: "grant",
          targetDigest: null,
          outcome: "Accepted",
          operationId: null,
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
          actorDigest: "2".repeat(64),
          action: "grant",
          targetDigest: null,
          outcome: "Accepted",
          operationId: null,
        },
        {
          auditId: 3,
          occurredAt: "2026-11-05T11:00:00Z",
          actorDigest: "3".repeat(64),
          action: "grant",
          targetDigest: null,
          outcome: "Accepted",
          operationId: null,
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
    dimensionPolicyMutationBody(app, "save", 2, policy, 7, "policy-save"),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "policy-save",
    program: {
      languageVersion: 2,
      function: "security.application.dimension-policy.version.save",
      arguments: { policyVersion: 2, policy },
    },
  });
  expect(
    dimensionPolicyMutationBody(app, "activate", 2, null, 7, "policy-activate")
      .program,
  ).toEqual({
    languageVersion: 2,
    function: "security.application.dimension-policy.activate",
    arguments: { policyVersion: 2, expectedSecurityRevision: 7 },
  });
  expect(
    dimensionPolicyMutationBody(
      app,
      "deactivate",
      null,
      null,
      7,
      "policy-deactivate",
    ).program,
  ).toEqual({
    languageVersion: 2,
    function: "security.application.dimension-policy.deactivate",
    arguments: { expectedSecurityRevision: 7 },
  });
});

it("invalidates access review when the reviewed role changes", () => {
  render(
    <AdministrationSecurity
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "security.application.access.set": {},
        },
      }}
    />,
  );
  fireEvent.change(screen.getByLabelText("Verified subject"), {
    target: { value: "subject-a" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this exact identity, action and role."),
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
        case "security.application.dimension-policy.active.read":
          return new Response(
            JSON.stringify({
              result: {
                policyVersion: 1,
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
        case "security.application.dimension-policy.version.list":
          return new Response(
            JSON.stringify({
              result: {
                items: [
                  {
                    policyVersion: 1,
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
                    policyDigest: "policy-digest-1",
                    status: "Active",
                  },
                ],
                nextAfterVersion: null,
                securityRevision: 7,
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
  render(
    <AdministrationSecurity
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "security.application.dimension-policy.version.save": {},
          "security.application.dimension-policy.activate": {},
          "security.application.dimension-policy.deactivate": {},
        },
      }}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  await waitFor(() =>
    expect(
      screen.getByText("subject-owner", { selector: "th" }),
    ).toBeInTheDocument(),
  );
  expect(screen.getByLabelText("Active policy")).toHaveTextContent("Active");
  fireEvent.click(
    screen.getByText("Review 1 saved policy version", { selector: "summary" }),
  );
  expect(screen.getByLabelText("Active policy")).toHaveTextContent(
    "every_protected",
  );
  expect(screen.getByText("design, publish, run")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Inspect" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Dimensional access")).toHaveTextContent(
      "North",
    ),
  );
  expect(screen.getByLabelText("Dimensional access")).toHaveTextContent(
    "WriteNorth",
  );
  expect(calls.map((call) => call.program)).toEqual([
    {
      languageVersion: 2,
      function: "security.application.access.list",
      arguments: { limit: 100 },
    },
    {
      languageVersion: 2,
      function: "security.application.dimension-policy.active.read",
      arguments: {},
    },
    {
      languageVersion: 2,
      function: "security.application.dimension-policy.version.list",
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
  ]);
  expect(calls.every((call) => !("confirmed" in call))).toBe(true);
  expect(screen.getByText("Next immutable version: 2")).toBeInTheDocument();
  const save = screen.getByRole("button", { name: "Save immutable version" });
  expect(save).toBeDisabled();
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed all ten choices for this exact immutable version.",
    ),
  );
  expect(save).toBeEnabled();
  fireEvent.change(screen.getByLabelText("Policy withinDimension"), {
    target: { value: "all_tags" },
  });
  expect(save).toBeDisabled();
});

it("paginates safe security audit events and exposes receipt correlation", async () => {
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
      if (body.program.function === "security.application.receipt.read")
        return new Response(
          JSON.stringify({
            result: {
              workspaceId: "ws",
              applicationId: "app",
              operationId: body.program.arguments.operationId,
              action: "application.grant",
              outcome: "Committed",
              committedAt: "2026-11-05T12:00:01Z",
              commandDigest: "c".repeat(64),
              payloadDigest: "d".repeat(64),
              actorDigest: "9".repeat(64),
            },
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
                    actorDigest: "8".repeat(64),
                    action: "rule.set",
                    targetDigest: "a".repeat(64),
                    outcome: "Accepted",
                    operationId: "receipt-8",
                  },
                ],
                nextBeforeAuditId: null,
              }
            : {
                events: [
                  {
                    auditId: 9,
                    occurredAt: "2026-11-05T12:00:00Z",
                    actorDigest: "9".repeat(64),
                    action: "application.grant",
                    targetDigest: "b".repeat(64),
                    outcome: "Accepted",
                    operationId: "receipt-9",
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
      catalog={{
        ...catalog,
        functions: {
          "security.application.access.list": {},
          "security.application.audit.list": {},
          "security.application.receipt.read": {},
        },
      }}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read access" }));
  await screen.findByText("receipt-9");
  fireEvent.click(
    screen.getByRole("button", {
      name: "Load older security events",
    }),
  );
  await screen.findByText("receipt-8");
  fireEvent.click(
    screen.getByRole("button", { name: "Inspect security receipt receipt-9" }),
  );
  expect(await screen.findByLabelText("Security receipt")).toHaveTextContent(
    "Committed security receipt",
  );
  expect(screen.getByLabelText("Security receipt")).toHaveTextContent(
    "application.grant",
  );
  expect(screen.getByLabelText("Security audit")).toHaveTextContent(
    "application.grant",
  );
  expect(screen.getByLabelText("Security audit")).toHaveTextContent("rule.set");
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
