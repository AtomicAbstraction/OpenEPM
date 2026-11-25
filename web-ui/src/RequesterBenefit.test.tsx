import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  RequesterBenefitAudit,
  RequesterBenefitDetails,
  validRequesterBenefit,
} from "./RequesterBenefit";
import { AdministrationSecurity } from "./AdministrationSecurity";
import type { RequesterBenefit } from "./authorization-config";
import type { ApplicationCatalog } from "./types";

const app = {
  workspaceId: "ops",
  applicationId: "cube",
  name: "Cube",
  status: "Active",
};
const benefit: RequesterBenefit = {
  classification: "additional_grant_path",
  grantsComplete: true,
  applicationEntry: "admitted",
  grants: [
    {
      groupId: "team",
      assignmentId: "extra",
      action: "facts.read",
      scopeId: "east",
      scopeRevision: 2,
      scopeKind: "dimension_tags",
      selector: { Region: ["East"] },
      roleId: "reader",
      reason: "additional_grant_path",
    },
  ],
};
const summary = { ...benefit, grantsComplete: false, grants: [] };
const events = [
  {
    auditId: 12,
    occurredAt: "2026-11-25T08:00:00Z",
    action: "Application authorization changed",
    actorName: "Group manager",
    targetName: "Model",
    outcome: "Accepted",
    detailsKey: "op-001",
    authorizationMode: "group_assignments",
    requesterBenefit: summary,
  },
];
const catalog: ApplicationCatalog = {
  applicationAccess: {
    role: "Assigned",
    workspaceAdministrator: false,
    authorizationModel: "group_assignments",
    roles: ["Access Reviewer"],
  },
  enabledCapabilities: [],
  functions: {
    "security.application.audit.list": {},
    "security.application.receipt.read": {},
  },
  revisions: { metadata: 1, security: 1, policy: 1, data: 1, commit: 1 },
};
const receipt = {
  ...app,
  operationId: "op-001",
  outcome: "Committed",
  action: "application-authorization.apply",
  committedAt: "2026-11-25T08:00:00Z",
  actorDigest: "a".repeat(64),
  commandDigest: "b".repeat(64),
  payloadDigest: "c".repeat(64),
  authorizationMode: "group_assignments",
  requesterBenefit: benefit,
};
const reply = (result: unknown) => Response.json({ result });
afterEach(() => vi.unstubAllGlobals());
it("shows an audit summary, then loads only its scoped receipt for the full granting paths", async () => {
  const reads = vi.fn(async (url: string, init: RequestInit) => {
    expect(url).toBe("/api/security");
    const body = JSON.parse(String(init.body));
    expect(body).toMatchObject({ workspaceId: "ops", applicationId: "cube" });
    if (body.program.function === "security.application.audit.list")
      return reply({ events, nextBeforeAuditId: null });
    expect(body.program).toEqual({
      languageVersion: 2,
      function: "security.application.receipt.read",
      arguments: { operationId: "op-001" },
    });
    return reply(receipt);
  });
  vi.stubGlobal("fetch", reads);
  render(<AdministrationSecurity app={app} view="audit" catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read audit" }));
  expect(
    await screen.findByText(
      "Additional grant with equivalent existing coverage.",
    ),
  ).toBeVisible();
  expect(reads).toHaveBeenCalledTimes(1);
  fireEvent.click(
    screen.getByRole("button", { name: "Read recorded grant details" }),
  );
  const details = await screen.findByText(
    "View granting groups, actions and scopes",
  );
  fireEvent.click(details);
  expect(screen.getByText("extra")).toBeVisible();
  expect(screen.getByText("east")).toBeVisible();
  expect(reads).toHaveBeenCalledTimes(2);
});
it("keeps a receipt from a different application out of the review", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => reply({ ...receipt, applicationId: "another" })),
  );
  render(
    <RequesterBenefitAudit
      scope={app}
      receiptKey="op-001"
      evidence={{
        authorizationMode: "group_assignments",
        requesterBenefit: summary,
      }}
    />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Read recorded grant details" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent("unavailable");
  expect(screen.queryByText("extra")).toBeNull();
});

it("shows the recorded role duty change even when the administrator did not benefit", async () => {
  const none = {
    classification: "none" as const,
    grantsComplete: true,
    grants: [],
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      reply({
        ...receipt,
        requesterBenefit: none,
        reviewedWorkflowDuties: [
          {
            roleId: "planner",
            addedDuties: ["Forecast:prepare"],
            removedDuties: [],
          },
        ],
      }),
    ),
  );
  render(
    <RequesterBenefitAudit
      scope={app}
      receiptKey="op-001"
      evidence={{
        authorizationMode: "group_assignments",
        requesterBenefit: none,
      }}
    />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Read recorded grant details" }),
  );
  expect(
    await screen.findByRole("region", {
      name: "Recorded planning duty changes",
    }),
  ).toHaveTextContent("Added · Forecast:prepare");
});
it("separates legacy staging and application entry from any claim of immediately usable access", () => {
  const b: RequesterBenefit = {
    ...benefit,
    classification: "new_application_entry",
    grants: [{ ...benefit.grants[0], reason: "new_application_entry" }],
  };
  const view = render(
    <RequesterBenefitDetails
      preview
      evidence={{ authorizationMode: "legacy", requesterBenefit: b }}
    />,
  );
  expect(screen.getByText(/These assignments are staged/)).toBeVisible();
  expect(
    screen.getByText("New application entry can activate existing grants."),
  ).toBeVisible();
  view.rerender(
    <RequesterBenefitDetails
      preview
      evidence={{
        authorizationMode: "group_assignments",
        requesterBenefit: {
          classification: "none",
          grants: [],
          grantsComplete: true,
        },
      }}
    />,
  );
  expect(
    screen.getByText(
      "No new or expanded grant through the requester’s groups.",
    ),
  ).toBeVisible();
  expect(screen.queryByText(/These assignments are staged/)).toBeNull();
});
it("accepts bounded audit summaries and rejects contradictory or malformed benefit evidence", () => {
  expect(validRequesterBenefit(summary)).toBe(true);
  expect(validRequesterBenefit(benefit)).toBe(true);
  for (const candidate of [
    { ...benefit, classification: "none" },
    { ...benefit, grants: [] },
    { ...benefit, applicationEntry: "unknown" },
    { ...benefit, grants: [{ ...benefit.grants[0], groupId: undefined }] },
  ])
    expect(validRequesterBenefit(candidate)).toBe(false);
});
