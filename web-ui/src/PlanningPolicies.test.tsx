import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { CapabilityArea } from "./CapabilityArea";
import { PlanningPolicies } from "./PlanningPolicies";
import { canonicalProgramDigest } from "./canonical-program-digest";
import {
  policyFunctions as f,
  policyPage,
  authoredDefinition,
} from "./planning-policy";
import { operationAdmissionResponse } from "./test-setup";
import type { ApplicationCatalog } from "./types";
import {
  firstSecuritySection,
  resolveWorkspaceSection,
} from "./workspace-navigation";
import { setDraftIdentity } from "./unsaved-work";

const app = {
  workspaceId: "ws",
  applicationId: "plan",
  name: "Plan",
  status: "Active",
};
const token = "1".repeat(64),
  digest = "a".repeat(64),
  candidateToken = "2".repeat(64),
  candidateDigest = "b".repeat(64);
const receiptFn = "application.operation.receipt.read";
const actor = { issuer: "https://ident.example", subjectId: "müller" };
const rule = {
  ruleId: "sales",
  priority: 100,
  effect: "Allow",
  actions: ["Set"],
  workflowRoles: ["Forecast:prepare"],
  memberSelectors: { Region: ["East"] },
  scenarioBound: null,
  periodBound: null,
  effectiveFrom: null,
  effectiveTo: null,
};
const definition = {
  workspaceId: "ws",
  applicationId: "plan",
  policyId: "budget",
  effectiveFrom: "2026-01-20",
  effectiveTo: null,
  rules: [rule],
};
const active = {
  policyId: "budget",
  stateToken: token,
  canonicalDigest: digest,
  status: "Active",
  active: true,
  actor,
  operationId: "old-op",
  updatedAt: "2026-01-01T00:00:00Z",
  definition,
};
const pending = {
  ...active,
  stateToken: candidateToken,
  canonicalDigest: candidateDigest,
  status: "Saved",
  active: false,
  definition: {
    ...definition,
    rules: [{ ...rule, workflowRoles: ["Forecast:review"] }],
  },
};
const both = { ...active, pendingDraft: pending };
const catalog = (effects: string[], legacy = false): ApplicationCatalog => ({
  functions: Object.fromEntries(
    [f.list, f.read, receiptFn, ...effects].map((k) => [k, {}]),
  ),
  revisions: { metadata: 1, data: 2, policy: 2, security: 3, commit: 9 },
  enabledCapabilities: [],
  applicationAccess: {
    role: legacy ? "Admin" : "Assigned",
    authorizationModel: legacy ? "legacy" : "group_assignments",
    ...actor,
    workspaceAdministrator: legacy,
  },
});
type Post = {
  path: string;
  workspaceId: string;
  applicationId: string;
  idempotencyKey: string;
  confirmed: boolean;
  program: { function: string; arguments: Record<string, unknown> };
};
function fixture(
  options: {
    row?: unknown;
    failFirst?: boolean;
    stale?: boolean;
    receipt?: (post: Post) => unknown | Promise<unknown>;
    list?: (post: Post) => unknown;
  } = {},
) {
  setDraftIdentity("policy-fixture");
  const calls: Post[] = [];
  const row = options.row ?? both;
  const reply = (data: unknown, status = 200) =>
    new Response(JSON.stringify(data), { status });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string, init: RequestInit) => {
      const body: Post = { ...JSON.parse(String(init.body)), path };
      calls.push(body);
      if (path === "/api/operation-admission")
        return operationAdmissionResponse();
      if (path === "/api/read" && body.program.function === f.list)
        return reply({
          result: options.list
            ? options.list(body)
            : {
                policies: [row],
                collectionToken: token,
                nextAfterPolicyId: null,
              },
        });
      if (path === "/api/read" && body.program.function === f.read)
        return reply({ result: row });
      if (path === "/api/read" && body.program.function === receiptFn) {
        if (options.receipt)
          return reply({
            result: await options.receipt(
              calls.find((c) => c.path === "/api/planning-policy")!,
            ),
          });
        return reply({ error: "OPERATION_RECEIPT_NOT_FOUND" }, 404);
      }
      if (path !== "/api/planning-policy")
        throw new Error("Unexpected endpoint");
      if (options.stale)
        return reply({ error: "PLANNING_POLICY_STATE_STALE" }, 409);
      if (
        options.failFirst &&
        calls.filter((c) => c.path === path).length === 1
      )
        throw new Error("Lost reply");
      return reply({
        languageVersion: 2,
        function: body.program.function,
        result: {
          policyId:
            body.program.arguments.policyId ??
            (body.program.arguments.definition as typeof definition)?.policyId,
          status: body.program.function === f.activate ? "Active" : "Saved",
          policyRevision: 3,
          stateToken: "3".repeat(64),
          canonicalDigest:
            body.program.arguments.canonicalDigest ?? candidateDigest,
        },
      });
    }),
  );
  return calls;
}
afterEach(() => vi.unstubAllGlobals());
const button = (name: string) => screen.getByRole("button", { name });
const click = (name: string) => fireEvent.click(button(name));
const effects = (calls: Post[]) =>
  calls.filter((c) => c.path === "/api/planning-policy");
async function open() {
  fireEvent.click(await screen.findByRole("button", { name: "budget" }));
  await screen.findByRole("region", { name: "Policy details" });
}
it("discovers planning as the only Security section available through a governance role", () => {
  expect(
    firstSecuritySection({ [f.list]: {}, [f.read]: {}, [f.save]: {} }),
  ).toBe("planning-policies");
  expect(resolveWorkspaceSection("security", "planning-policies")).toBe(
    "planning-policies",
  );
});
it("edits the pending draft with its own state, invalidates review on edit and keeps active controls out of the editor", async () => {
  const calls = fixture();
  render(
    <PlanningPolicies
      app={app}
      catalog={catalog([f.save, f.activate, f.deactivate])}
    />,
  );
  await open();
  expect(
    within(screen.getByRole("region", { name: "Active policy" })).getByText(
      /Forecast:prepare/,
      { selector: "li" },
    ),
  ).toBeVisible();
  expect(
    within(screen.getByRole("region", { name: "Pending draft" })).getByText(
      /Forecast:review/,
      { selector: "li" },
    ),
  ).toBeVisible();
  click("Edit draft");
  expect(
    screen.queryByRole("button", { name: "Review deactivation" }),
  ).toBeNull();
  const duties = screen.getByLabelText("Workflow duty IDs (comma-separated)");
  expect(duties).toHaveValue("Forecast:review");
  click("Review draft");
  fireEvent.change(duties, { target: { value: "Forecast:new" } });
  expect(
    screen.queryByRole("button", { name: "Save reviewed draft" }),
  ).toBeNull();
  click("Review draft");
  click("Save reviewed draft");
  await screen.findByText(
    "Draft saved. It is available for activation review.",
  );
  expect(effects(calls)[0].program).toMatchObject({
    function: f.save,
    arguments: {
      expectedStateToken: candidateToken,
      definition: { rules: [{ workflowRoles: ["Forecast:new"] }] },
    },
  });
  expect(effects(calls)).toHaveLength(1);
});
it("lets a drafter stage from the active token while hiding activation and deactivation", async () => {
  const calls = fixture({ row: active });
  render(<PlanningPolicies app={app} catalog={catalog([f.save])} />);
  await open();
  expect(
    screen.queryByRole("button", { name: "Review deactivation" }),
  ).toBeNull();
  click("Draft a revision");
  click("Review draft");
  click("Save reviewed draft");
  await waitFor(() => expect(effects(calls)).toHaveLength(1));
  expect(effects(calls)[0].program.arguments.expectedStateToken).toBe(token);
});
it.each([
  [
    "Review activation",
    "Activate reviewed policy",
    f.activate,
    candidateToken,
    candidateDigest,
  ],
  [
    "Review deactivation",
    "Deactivate reviewed policy",
    f.deactivate,
    token,
    digest,
  ],
])(
  "binds %s to the displayed version for activation-only authority",
  async (label, confirm, name, expectedStateToken, canonicalDigest) => {
    const calls = fixture();
    render(
      <PlanningPolicies
        app={app}
        catalog={catalog([f.activate, f.deactivate])}
      />,
    );
    await open();
    expect(
      screen.queryByRole("button", { name: "New policy draft" }),
    ).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit draft" })).toBeNull();
    click(label);
    expect(effects(calls)).toHaveLength(0);
    click(confirm);
    await waitFor(() => expect(effects(calls)).toHaveLength(1));
    expect(effects(calls)[0]).toMatchObject({
      workspaceId: "ws",
      applicationId: "plan",
      confirmed: true,
      program: {
        function: name,
        arguments: { policyId: "budget", expectedStateToken, canonicalDigest },
      },
    });
  },
);
it("protects an active legacy definition by requiring a different policy ID when copying", async () => {
  const calls = fixture({ row: active });
  render(<PlanningPolicies app={app} catalog={catalog([f.save], true)} />);
  await open();
  click("Copy to a new policy draft");
  const id = screen.getByLabelText("Policy ID");
  fireEvent.change(id, { target: { value: "budget" } });
  expect(button("Review draft")).toBeDisabled();
  fireEvent.change(id, { target: { value: "budget-next" } });
  click("Review draft");
  click("Save reviewed draft");
  await waitFor(() => expect(effects(calls)).toHaveLength(1));
  expect(
    effects(calls)[0].program.arguments.expectedStateToken,
  ).toBeUndefined();
  expect(effects(calls)[0].program.arguments.definition).toMatchObject({
    policyId: "budget-next",
  });
});
it("creates a policy with named rules and effective dates from an empty listing", async () => {
  const calls = fixture({
    list: () => ({
      policies: [],
      nextAfterPolicyId: null,
      collectionToken: token,
    }),
  });
  render(<PlanningPolicies app={app} catalog={catalog([f.save])} />);
  await screen.findByText("No policies were found.");
  click("New policy draft");
  expect(button("Review draft")).toBeDisabled();
  for (const [name, value] of [
    ["Policy ID", "forecast"],
    ["Rule ID", "inputs"],
    ["Workflow duty IDs (comma-separated)", "team:forecast"],
    ["Effective from", "2026-02-01"],
  ])
    fireEvent.change(screen.getByLabelText(name), { target: { value } });
  click("Review draft");
  click("Save reviewed draft");
  await waitFor(() => expect(effects(calls)).toHaveLength(1));
  expect(effects(calls)[0].program.arguments.definition).toMatchObject({
    policyId: "forecast",
    rules: [{ ruleId: "inputs", workflowRoles: ["team:forecast"] }],
  });
});
it("uses receipt absence before retrying the same signed program and admission", async () => {
  const calls = fixture({ failFirst: true });
  render(<PlanningPolicies app={app} catalog={catalog([f.activate])} />);
  await open();
  click("Review activation");
  click("Activate reviewed policy");
  await screen.findByRole("button", {
    name: "Check original planning policy receipt",
  });
  expect(
    screen.queryByRole("button", {
      name: "Retry original planning policy change",
    }),
  ).toBeNull();
  click("Check original planning policy receipt");
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Retry original planning policy change",
    }),
  );
  await screen.findByText("Policy activation recorded.");
  expect(effects(calls)).toHaveLength(2);
  expect(effects(calls)[0]).toEqual(effects(calls)[1]);
  expect(
    calls.filter((c) => c.path === "/api/operation-admission"),
  ).toHaveLength(1);
});
it.each([true, false])(
  "verifies historical policy receipts against the signed command and original action (%s)",
  async (valid) => {
    const calls = fixture({
      failFirst: true,
      receipt: async (post) => ({
        operationId: post.idempotencyKey,
        actorId: actor.subjectId,
        committedAt: "2026-01-01T00:00:00Z",
        committedRevision: 10,
        commandDigest: await canonicalProgramDigest(
          {
            scope: ["ws", "plan"],
            actor: [actor.issuer, actor.subjectId],
            function: f.activate,
            ...post.program.arguments,
            idempotencyKey: post.idempotencyKey,
          },
          true,
        ),
        outcome: {
          function: valid ? f.activate : f.deactivate,
          status: "Active",
        },
      }),
    });
    render(<PlanningPolicies app={app} catalog={catalog([f.activate])} />);
    await open();
    click("Review activation");
    click("Activate reviewed policy");
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Check original planning policy receipt",
      }),
    );
    if (valid) await screen.findByText("Policy activation recorded.");
    else await screen.findByText(/receipt could not confirm/i);
    expect(effects(calls)).toHaveLength(1);
  },
);
it("fails closed on mismatched scope, draft identity or collection continuation", () => {
  expect(() =>
    policyPage(
      {
        policies: [
          { ...both, pendingDraft: { ...pending, policyId: "other" } },
        ],
        collectionToken: token,
        nextAfterPolicyId: null,
      },
      app,
    ),
  ).toThrow();
  expect(() =>
    policyPage(
      {
        policies: [
          { ...active, definition: { ...definition, applicationId: "other" } },
        ],
        collectionToken: token,
        nextAfterPolicyId: null,
      },
      app,
    ),
  ).toThrow();
  expect(() =>
    policyPage(
      { policies: [active], collectionToken: token, nextAfterPolicyId: null },
      app,
      { policies: [], collectionToken: digest, nextAfterPolicyId: "aa" },
    ),
  ).toThrow();
});
it("strips server-generated pins while preserving authored hierarchy selectors", () => {
  const levelSelector = {
    dimensionId: "Org",
    rootMemberId: "Total",
    depth: 2,
    hierarchyStateToken: digest,
    metadataRevision: 7,
    schemaEpoch: 4,
    resolutionDigest: token,
    resolvedMemberIds: ["East"],
  };
  const record = {
    ...active,
    definition: {
      ...definition,
      format: "openepm-planning-workflow-policy-v2",
      authoredIntentDigest: digest,
      rules: [{ ...rule, levelSelector }],
    },
  };
  const row = policyPage(
    { policies: [record], collectionToken: token, nextAfterPolicyId: null },
    app,
  ).policies[0];
  const authored = authoredDefinition(row);
  expect(authored.rules[0].levelSelector).toEqual({
    dimensionId: "Org",
    rootMemberId: "Total",
    depth: 2,
  });
  expect(authored).not.toHaveProperty("authoredIntentDigest");
});

it("opens the policy workspace from the normal security navigation for a governance-only actor", async () => {
  fixture();
  render(
    <CapabilityArea
      area="security"
      app={app}
      catalog={catalog([f.save])}
      index={0}
    />,
  );
  expect(
    screen.getByRole("button", { name: "Planning policies" }),
  ).toHaveAttribute("aria-current", "page");
  expect(screen.queryByRole("button", { name: "Role assignments" })).toBeNull();
  await open();
  expect(screen.getByRole("region", { name: "Pending draft" })).toBeVisible();
});
it("requires an exact reread following a stale activation", async () => {
  const calls = fixture({ stale: true });
  render(<PlanningPolicies app={app} catalog={catalog([f.activate])} />);
  await open();
  click("Review activation");
  click("Activate reviewed policy");
  await screen.findByRole("region", { name: "Policy review expired" });
  expect(button("Review activation")).toBeDisabled();
  click("Reread policy");
  await screen.findByRole("region", { name: "Pending draft" });
  expect(button("Review activation")).toBeEnabled();
  expect(calls.filter((c) => c.program?.function === f.read)).toHaveLength(2);
  expect(effects(calls)).toHaveLength(1);
});

it("continues using the server cursor and collection token and clears stale pages", async () => {
  const calls = fixture({
    list: (post) =>
      post.program.arguments.afterPolicyId
        ? {
            policies: [active],
            collectionToken: digest,
            nextAfterPolicyId: null,
          }
        : {
            policies: [active],
            collectionToken: token,
            nextAfterPolicyId: "budget",
          },
  });
  render(<PlanningPolicies app={app} catalog={catalog([f.save])} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Next policy page" }),
  );
  await screen.findByText("The policy collection changed. Refresh the list.");
  expect(
    calls.filter((c) => c.program?.function === f.list).at(-1)?.program
      .arguments,
  ).toEqual({
    limit: 25,
    afterPolicyId: "budget",
    expectedCollectionToken: token,
  });
  expect(screen.queryByRole("button", { name: "budget" })).toBeNull();
  click("Refresh policies");
  await screen.findByRole("button", { name: "budget" });
});
it("does not reveal previously reviewed policies after application access is withdrawn", async () => {
  const calls = fixture();
  const view = render(
    <CapabilityArea
      area="security"
      section="planning-policies"
      app={app}
      catalog={catalog([f.activate])}
      index={0}
    />,
  );
  await open();
  click("Review activation");
  view.rerender(
    <CapabilityArea
      area="security"
      section="planning-policies"
      app={app}
      catalog={{ ...catalog([]), functions: {} }}
      index={0}
    />,
  );
  expect(screen.queryByRole("region", { name: "Policy details" })).toBeNull();
  expect(
    screen.queryByRole("button", { name: "Activate reviewed policy" }),
  ).toBeNull();
  expect(screen.queryByText("budget")).toBeNull();
  expect(effects(calls)).toHaveLength(0);
});
