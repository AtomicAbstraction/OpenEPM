import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi, onTestFinished } from "vitest";
import { useState } from "react";
import { discardUnsavedWork, unsavedWorkSnapshot } from "./unsaved-work";
import { operationAdmissionResponse } from "./test-setup";
import type { ApplicationCatalog } from "./types";
import {
  collectMetadataRelationships,
  metadataActionBody,
  MetadataRelationships,
  placementPatchChanges,
} from "./MetadataRelationships";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
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
    "metadata.relationship.list": {},
    "metadata.relationship.create": {},
    "metadata.relationship.rename": {},
    "metadata.relationship.describe": {},
    "metadata.relationship.status.set": {},
    "metadata.hierarchy.build": {},
  },
  revisions: { metadata: 46, data: 1, policy: 1, security: 1, commit: 1 },
};

const relationship = (id: string) => ({
  relationship_id: id,
  dimension_id: "Account",
  parent_member_id: "Total",
  child_member_id: id,
  status: "Active" as const,
});

const recoveryCatalog: ApplicationCatalog = {
  ...catalog,
  applicationAccess: {
    ...catalog.applicationAccess,
    issuer: "https://issuer.example",
    subjectId: "owner",
  },
  functions: {
    ...catalog.functions,
    "application.operation.receipt.read": {},
  },
};
const recoveryMembers = [
  { member_id: "Total", name: "Total", status: "Active" },
  { member_id: "Sales", name: "Sales", status: "Active" },
];

function reviewRelationshipRename(name: string) {
  fireEvent.change(screen.getByLabelText("Relationship display name"), {
    target: { value: name },
  });
  fireEvent.click(
    screen.getByLabelText(/I reviewed this exact relationship name/),
  );
  fireEvent.click(screen.getByRole("button", { name: "Rename relationship" }));
}

it("recovers a committed relationship rename and preserves unsent fields across remount", async () => {
  const calls: Array<{ path: string; body: any }> = [];
  let operationId = "";
  let receiptActor = "another-user";
  let committed = false;
  const change = vi.fn();
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      calls.push({ path, body });
      if (path === "/api/operation-admission")
        return operationAdmissionResponse("c");
      if (path === "/api/metadata-action") {
        operationId = body.idempotencyKey;
        committed = true;
        throw new TypeError("Failed to fetch");
      }
      if (body.program.function === "application.operation.receipt.read") {
        return Response.json({
          result: {
            operationId,
            commandDigest: "c".repeat(64),
            actorId: receiptActor,
            committedRevision: 50,
            committedAt: "2026-11-21T11:00:00Z",
            outcome: { changedCount: 1 },
          },
        });
      }
      const current = committed && body.applicationId === app.applicationId;
      return Response.json({
        result: {
          rows: [
            {
              ...relationship("Sales"),
              name: current ? "Reporting sales" : "Sales placement",
              short_description: "Current description",
              detailed_description: "Current semantic detail",
              semantic_description: "Historical owner note",
            },
          ],
          metadataRevision: current ? 47 : 46,
          nextCursor: null,
        },
      });
    }),
  );
  function Editor({ currentApp = app, access = recoveryCatalog } = {}) {
    const [revision, setRevision] = useState(46);
    return (
      <MetadataRelationships
        app={currentApp}
        catalog={access}
        dimensionId="Account"
        members={recoveryMembers}
        metadataRevision={revision}
        selectedMemberId="Sales"
        selectedRelationshipId="Sales"
        onChanged={async () => {
          change();
          setRevision(47);
        }}
      />
    );
  }

  const original = render(<Editor />);
  await screen.findByText(/1 current relationships/);
  expect(
    screen.getByLabelText("Relationship semantic description"),
  ).toHaveValue("Current semantic detail");
  expect(screen.getByText("Historical owner note")).toBeVisible();
  fireEvent.change(screen.getByLabelText("Relationship short description"), {
    target: { value: "Unsent description" },
  });
  reviewRelationshipRename("Reporting sales");
  const heading = await screen.findByRole("heading", {
    name: "Relationship change awaiting confirmation",
  });
  await waitFor(() => expect(heading).toHaveFocus());
  expect(
    screen.getByRole("button", { name: "Rename relationship" }),
  ).toBeDisabled();
  expect(
    screen.queryByRole("button", {
      name: "Retry original relationship change",
    }),
  ).toBeNull();
  original.unmount();

  const other = render(
    <Editor currentApp={{ ...app, applicationId: "other" }} />,
  );
  await screen.findByText(/1 current relationships/);
  expect(
    screen.queryByRole("button", {
      name: "Check original relationship receipt",
    }),
  ).toBeNull();
  expect(screen.getByLabelText("Relationship short description")).toHaveValue(
    "Current description",
  );
  other.unmount();

  const recovered = render(<Editor />);
  const check = await screen.findByRole("button", {
    name: "Check original relationship receipt",
  });
  await waitFor(() => expect(check).toBeEnabled());
  fireEvent.click(check);
  await screen.findByText(
    "The receipt could not confirm the original relationship change.",
  );
  expect(change).not.toHaveBeenCalled();

  receiptActor = "owner";
  fireEvent.click(check);
  const recorded = await screen.findByText(
    "The original relationship change was recorded.",
  );
  await waitFor(() => expect(recorded).toHaveFocus());
  expect(change).toHaveBeenCalledTimes(1);
  await waitFor(() =>
    expect(screen.getByLabelText("Relationship display name")).toHaveValue(
      "Reporting sales",
    ),
  );
  expect(screen.getByLabelText("Relationship short description")).toHaveValue(
    "Unsent description",
  );
  expect(
    screen.getByRole("button", { name: "Save relationship descriptions" }),
  ).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Review against current metadata" }),
  ).toBeVisible();
  expect(
    calls.filter(({ path }) => path === "/api/operation-admission"),
  ).toHaveLength(1);
  const writes = calls.filter(({ path }) => path === "/api/metadata-action");
  expect(writes).toHaveLength(1);
  expect(writes[0].body).toMatchObject({
    idempotencyKey: operationId,
    program: {
      function: "metadata.relationship.rename",
      arguments: {
        relationshipId: "Sales",
        name: "Reporting sales",
        expectedMetadataRevision: 46,
      },
    },
  });
  expect(
    calls
      .filter(
        ({ body }) =>
          body.program.function === "application.operation.receipt.read",
      )
      .map(({ body }) => [
        body.workspaceId,
        body.applicationId,
        body.program.arguments,
      ]),
  ).toEqual([
    ["ws", "app", { operationId }],
    ["ws", "app", { operationId }],
  ]);
  recovered.unmount();
});

it("replays the exact relationship packet after a missing receipt while current write access permits it", async () => {
  const sent: any[] = [];
  let admissions = 0;
  const change = vi.fn(async () => {});
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      if (path === "/api/operation-admission") {
        admissions += 1;
        return operationAdmissionResponse("d");
      }
      if (path === "/api/metadata-action") {
        sent.push(body);
        if (sent.length === 1) throw new TypeError("Failed to fetch");
        return Response.json({
          languageVersion: 2,
          function: body.program.function,
          result: {
            operationId: body.idempotencyKey,
            committedRevision: 50,
            changedCount: 1,
          },
        });
      }
      if (body.program.function === "application.operation.receipt.read")
        return Response.json(
          { code: "OPERATION_RECEIPT_NOT_FOUND" },
          { status: 400 },
        );
      return Response.json({
        result: {
          rows: [relationship("Sales")],
          metadataRevision: 46,
          nextCursor: null,
        },
      });
    }),
  );
  function editor(access: ApplicationCatalog) {
    return (
      <MetadataRelationships
        app={app}
        catalog={access}
        dimensionId="Account"
        members={recoveryMembers}
        metadataRevision={46}
        selectedMemberId="Sales"
        selectedRelationshipId="Sales"
        onChanged={change}
      />
    );
  }
  const view = render(editor(recoveryCatalog));
  await screen.findByText(/1 current relationships/);
  reviewRelationshipRename("Reviewed sales");
  const check = await screen.findByRole("button", {
    name: "Check original relationship receipt",
  });
  await waitFor(() => expect(check).toBeEnabled());
  expect(
    screen.queryByRole("button", {
      name: "Retry original relationship change",
    }),
  ).toBeNull();
  const { "metadata.relationship.rename": _rename, ...readerFunctions } =
    recoveryCatalog.functions;
  view.rerender(
    editor({
      ...recoveryCatalog,
      functions: readerFunctions,
      applicationAccess: {
        ...recoveryCatalog.applicationAccess,
        role: "Reader",
      },
    }),
  );
  fireEvent.click(check);
  await screen.findByText(/No receipt is visible yet/);
  expect(
    screen.queryByRole("button", {
      name: "Retry original relationship change",
    }),
  ).toBeNull();

  view.rerender(editor(recoveryCatalog));
  fireEvent.click(check);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Retry original relationship change",
    }),
  );
  await screen.findByText("The reviewed relationship change was applied.");
  expect(admissions).toBe(1);
  expect(sent).toHaveLength(2);
  expect(sent[1]).toEqual(sent[0]);
  expect(change).toHaveBeenCalledTimes(1);
});

it("keeps text and clears review after a definite stale relationship refusal", async () => {
  const change = vi.fn(async () => {});
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path === "/api/operation-admission")
      return operationAdmissionResponse("e");
    if (path === "/api/metadata-action")
      return Response.json(
        { code: "STALE_METADATA_REVISION" },
        { status: 409 },
      );
    expect(path).toBe("/api/read");
    return Response.json({
      result: {
        rows: [relationship("Sales")],
        metadataRevision: 46,
        nextCursor: null,
      },
    });
  });
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal("fetch", fetcher);
  render(
    <MetadataRelationships
      app={app}
      catalog={recoveryCatalog}
      dimensionId="Account"
      members={recoveryMembers}
      metadataRevision={46}
      selectedMemberId="Sales"
      selectedRelationshipId="Sales"
      onChanged={change}
    />,
  );
  await screen.findByText(/1 current relationships/);
  reviewRelationshipRename("Keep this draft");
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "STALE_METADATA_REVISION",
  );
  expect(
    screen.queryByRole("button", {
      name: "Check original relationship receipt",
    }),
  ).toBeNull();
  expect(screen.getByLabelText("Relationship display name")).toHaveValue(
    "Keep this draft",
  );
  expect(
    screen.getByLabelText(/I reviewed this exact relationship name/),
  ).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Rename relationship" }),
  ).toBeDisabled();
  expect(change).not.toHaveBeenCalled();
  expect(fetcher.mock.calls.map(([path]) => path)).toEqual([
    "/api/read",
    "/api/operation-admission",
    "/api/metadata-action",
  ]);
});

it("reads every relationship beyond the former browser bound", async () => {
  let page = 0;
  const result = await collectMetadataRelationships("Account", 46, async () => {
    const current = page++;
    return {
      rows: Array.from({ length: 100 }, (_unused, row) =>
        relationship(`r-${current}-${row}`),
      ),
      nextCursor: current === 100 ? null : `cursor-${current + 1}`,
      metadataRevision: 46,
    };
  });
  expect(result.rows).toHaveLength(10100);
});

it("rejects malformed, repeated, duplicate, and stale relationship pages", async () => {
  await expect(
    collectMetadataRelationships("Account", 46, async () => ({
      rows: [],
      nextCursor: "" as never,
      metadataRevision: 46,
    })),
  ).rejects.toThrow("cursor is invalid");
  let page = 0;
  await expect(
    collectMetadataRelationships("Account", 46, async () => ({
      rows: [],
      nextCursor: page++ < 1 ? "same" : "same",
      metadataRevision: 46,
    })),
  ).rejects.toThrow("cursor repeated");
  let duplicatePage = 0;
  await expect(
    collectMetadataRelationships("Account", 46, async () => ({
      rows: [relationship("same")],
      nextCursor: duplicatePage++ < 1 ? "more" : null,
      metadataRevision: 46,
    })),
  ).rejects.toThrow("repeated a row");
  await expect(
    collectMetadataRelationships("Account", 46, async () => ({
      rows: [],
      nextCursor: null,
      metadataRevision: 47,
    })),
  ).rejects.toThrow("Metadata changed");
});

it("preserves the governed relationship-create envelope", () => {
  expect(
    metadataActionBody(
      app,
      "metadata.relationship.create",
      {
        dimensionId: "Account",
        relationshipId: "sales-total",
        parentMemberId: "Total",
        childMemberId: "Sales",
        expectedMetadataRevision: 46,
      },
      "relationship-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "relationship-1",
    program: {
      languageVersion: 2,
      function: "metadata.relationship.create",
      arguments: {
        dimensionId: "Account",
        relationshipId: "sales-total",
        parentMemberId: "Total",
        childMemberId: "Sales",
        expectedMetadataRevision: 46,
      },
    },
  });
});

it("preserves status and hierarchy-build contracts", () => {
  expect(
    metadataActionBody(
      app,
      "metadata.relationship.rename",
      {
        relationshipId: "sales-total",
        name: "Sales reporting placement",
        expectedMetadataRevision: 46,
      },
      "rename-1",
    ).program,
  ).toEqual({
    languageVersion: 2,
    function: "metadata.relationship.rename",
    arguments: {
      relationshipId: "sales-total",
      name: "Sales reporting placement",
      expectedMetadataRevision: 46,
    },
  });
  expect(
    metadataActionBody(
      app,
      "metadata.relationship.describe",
      {
        relationshipId: "sales-total",
        shortDescription: "Reporting placement",
        detailedDescription: "Semantic reporting placement",
        expectedMetadataRevision: 46,
      },
      "describe-1",
    ).program,
  ).toEqual({
    languageVersion: 2,
    function: "metadata.relationship.describe",
    arguments: {
      relationshipId: "sales-total",
      shortDescription: "Reporting placement",
      detailedDescription: "Semantic reporting placement",
      expectedMetadataRevision: 46,
    },
  });
  expect(
    metadataActionBody(
      app,
      "metadata.relationship.status.set",
      {
        relationshipId: "sales-total",
        status: "Inactive",
        expectedMetadataRevision: 46,
      },
      "status-1",
    ).program,
  ).toEqual({
    languageVersion: 2,
    function: "metadata.relationship.status.set",
    arguments: {
      relationshipId: "sales-total",
      status: "Inactive",
      expectedMetadataRevision: 46,
    },
  });
  expect(
    metadataActionBody(
      app,
      "metadata.hierarchy.build",
      { dimensionId: "Account", expectedMetadataRevision: 46 },
      "build-1",
    ).program,
  ).toEqual({
    languageVersion: 2,
    function: "metadata.hierarchy.build",
    arguments: { dimensionId: "Account", expectedMetadataRevision: 46 },
  });
});

const placementDraft = {
  relationshipId: "placement-new",
  parentMemberId: "Reporting",
  childMemberId: "Sales",
};

it("compiles a new placement as one create change", () => {
  expect(
    placementPatchChanges({ action: "create", ...placementDraft }),
  ).toEqual([
    {
      action: "Create",
      relationshipId: "placement-new",
      parentMemberId: "Reporting",
      childMemberId: "Sales",
    },
  ]);
});

it("compiles a copied placement as one create change", () => {
  expect(placementPatchChanges({ action: "copy", ...placementDraft })).toEqual([
    {
      action: "Create",
      relationshipId: "placement-new",
      parentMemberId: "Reporting",
      childMemberId: "Sales",
    },
  ]);
});

it("compiles a move as one atomic deactivate-create patch", () => {
  expect(
    placementPatchChanges({
      action: "move",
      sourceRelationshipId: "placement-old",
      ...placementDraft,
    }),
  ).toEqual([
    { action: "Deactivate", relationshipId: "placement-old" },
    {
      action: "Create",
      relationshipId: "placement-new",
      parentMemberId: "Reporting",
      childMemberId: "Sales",
    },
  ]);
});

it("refuses to compile a move without its exact source placement", () => {
  expect(() =>
    placementPatchChanges({
      action: "move",
      ...placementDraft,
    }),
  ).toThrow("exact current placement");
});

it("uses one signed atomic placement changeset without exposing its backend ID", async () => {
  const calls: Array<{ path: string; body: Record<string, any> }> = [];
  const hierarchyStateToken = "a".repeat(64);
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal("crypto", {
    randomUUID: () => "11111111-1111-4111-8111-111111111111",
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      calls.push({ path, body });
      if (path === "/api/operation-admission")
        return operationAdmissionResponse("atomic-placement");
      const functionName = body.program?.function;
      const result =
        functionName === "metadata.hierarchy.list"
          ? {
              dimensionId: "Account",
              metadataRevision: 46,
              rows: [
                {
                  hierarchyId: "default",
                  name: "Account hierarchy",
                  status: "Active",
                  membershipMode: "all_active",
                  isDefault: true,
                  stateToken: hierarchyStateToken,
                  builtMetadataRevision: 46,
                  current: true,
                },
              ],
              hasMore: false,
              nextAfterId: null,
            }
          : functionName === "metadata.hierarchy.members.list"
            ? {
                dimensionId: "Account",
                hierarchyId: "default",
                metadataRevision: 46,
                rows: [
                  { memberId: "Sales", status: "Active" },
                  { memberId: "Total", status: "Active" },
                ],
                hasMore: false,
                nextAfterId: null,
              }
            : functionName === "metadata.relationship.list"
              ? {
                  rows: [],
                  metadataRevision: 46,
                  nextCursor: null,
                  hierarchyId: "default",
                }
              : functionName === "metadata.hierarchy.relationships.preview"
                ? {
                    previewToken: "signed-preview",
                    hierarchyId: "default",
                    graphDigest: "a".repeat(64),
                    closureDigest: "b".repeat(64),
                    memberCount: 2,
                    edgeCount: 1,
                    closureCount: 3,
                    affectedPathCount: 1,
                    affectedRelationshipIds: ["hidden"],
                  }
                : {
                    kind: "hierarchy.build",
                    operation: "relationship.patch",
                    hierarchyId: "default",
                    metadataRevision: 47,
                    committedRevision: 48,
                    stateToken: "c".repeat(64),
                    graphDigest: "a".repeat(64),
                    closureDigest: "b".repeat(64),
                    memberCount: 2,
                    edgeCount: 1,
                    closureCount: 3,
                    affectedPathCount: 1,
                    affectedRelationshipIds: ["hidden"],
                  };
      return new Response(
        JSON.stringify({ languageVersion: 2, function: functionName, result }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      );
    }),
  );
  const governedCatalog = {
    ...catalog,
    applicationAccess: {
      ...catalog.applicationAccess,
      issuer: "https://issuer",
      subjectId: "owner",
    },
    functions: {
      ...catalog.functions,
      "metadata.hierarchy.list": {},
      "metadata.hierarchy.members.list": {},
      "metadata.hierarchy.relationships.preview": {},
      "metadata.hierarchy.relationships.apply": {},
    },
  };
  const onChanged = vi.fn(async () => undefined);
  render(
    <MetadataRelationships
      app={app}
      catalog={governedCatalog}
      dimensionId="Account"
      members={[
        { member_id: "Total", name: "Total", status: "Active" },
        { member_id: "Sales", name: "Sales", status: "Active" },
      ]}
      metadataRevision={46}
      onChanged={onChanged}
    />,
  );
  await screen.findByText(/0 current relationships/);
  expect(screen.queryByLabelText("Stable ID")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Tree View" }));
  const child = screen.getByRole("button", {
    name: "Select Sales in hierarchy",
  });
  const parent = screen.getByRole("button", {
    name: "Select Total in hierarchy",
  });
  fireEvent.dragStart(child);
  fireEvent.dragOver(parent);
  fireEvent.drop(parent);
  expect(
    screen.getByText("Draft: Create Sales under Total"),
  ).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact changes" }),
  );
  await screen.findByText("Exact server preview");
  const preview = calls.find(
    (call) =>
      call.body.program?.function ===
      "metadata.hierarchy.relationships.preview",
  );
  expect(preview?.body.program.arguments).toMatchObject({
    dimensionId: "Account",
    hierarchyId: "default",
    expectedMetadataRevision: 46,
    expectedHierarchyStateToken: hierarchyStateToken,
    changes: [
      {
        action: "Create",
        parentMemberId: "Total",
        childMemberId: "Sales",
      },
    ],
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Apply reviewed changeset" }),
  );
  await waitFor(() => expect(onChanged).toHaveBeenCalledOnce());
  const apply = calls.find(
    (call) =>
      call.body.program?.function === "metadata.hierarchy.relationships.apply",
  );
  expect(apply?.body.program.arguments.previewToken).toBe("signed-preview");
});

it("synchronizes member and exact placement selection across List and Tree views", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              rows: [
                {
                  relationship_id: "total-sales",
                  dimension_id: "Account",
                  name: "Total sales placement",
                  short_description: "Primary reporting placement",
                  semantic_description: "Sales rolls into Total",
                  parent_member_id: "Total",
                  child_member_id: "Sales",
                  status: "Active",
                },
                {
                  relationship_id: "reporting-sales",
                  dimension_id: "Account",
                  name: "Reporting sales placement",
                  parent_member_id: "Reporting",
                  child_member_id: "Sales",
                  status: "Active",
                },
              ],
              metadataRevision: 46,
              nextCursor: null,
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    ),
  );
  const selected = vi.fn();
  function GuardedRelationships() {
    const [pending, setPending] = useState<(() => void) | null>(null);
    return (
      <>
        <MetadataRelationships
          app={app}
          catalog={catalog}
          dimensionId="Account"
          members={[
            { member_id: "Total", name: "Total", status: "Active" },
            { member_id: "Reporting", name: "Reporting", status: "Active" },
            {
              member_id: "Sales",
              name: "Sales",
              status: "Active",
              short_description: "Customer revenue",
              detailed_description: "Authoritative sales account",
              numeric_value_kind: "amount",
            },
          ]}
          metadataRevision={46}
          onChanged={async () => undefined}
          onSelectedMemberIdChange={selected}
          onRequestTransition={(action) => {
            if (unsavedWorkSnapshot().length) setPending(() => action);
            else action();
          }}
        />
        {pending && (
          <div role="alertdialog" aria-label="Unsaved placement changes">
            <button onClick={() => setPending(null)}>Keep editing</button>
            <button
              onClick={() => {
                discardUnsavedWork();
                pending();
                setPending(null);
              }}
            >
              Discard and continue
            </button>
          </div>
        )}
      </>
    );
  }
  render(<GuardedRelationships />);

  expect(
    await screen.findByText(/2 current relationships/),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Reporting" }));
  expect(selected).toHaveBeenLastCalledWith("Sales", "reporting-sales");
  const pane = screen.getByLabelText("Selected metadata properties");
  expect(pane).toHaveTextContent("Customer revenue");
  await waitFor(() => {
    expect(pane).toHaveTextContent("Sales under Reporting");
    expect(pane).toHaveTextContent("Reporting");
    expect(pane).toHaveTextContent("Reporting sales placement");
  });

  const relationshipName = screen.getByLabelText("Relationship display name");
  fireEvent.change(relationshipName, {
    target: { value: "Management reporting sales" },
  });
  const renameReview = screen.getByLabelText(
    "I reviewed this exact relationship name against the current model.",
  );
  fireEvent.click(renameReview);
  expect(renameReview).toBeChecked();
  expect(
    screen.getByRole("button", { name: "Rename relationship" }),
  ).toBeEnabled();
  fireEvent.change(relationshipName, {
    target: { value: "Management reporting revenue" },
  });
  expect(renameReview).not.toBeChecked();

  fireEvent.click(screen.getByRole("button", { name: "Tree View" }));
  const salesPlacements = screen.getAllByRole("button", {
    name: /Select Sales in hierarchy under/,
  });
  expect(salesPlacements).toHaveLength(2);
  fireEvent.click(salesPlacements[0]);
  expect(
    screen.getByRole("alertdialog", { name: "Unsaved placement changes" }),
  ).toBeInTheDocument();
  expect(pane).toHaveTextContent("Sales under Reporting");
  expect(relationshipName).toHaveValue("Management reporting revenue");
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(pane).toHaveTextContent("Sales under Reporting");
  expect(relationshipName).toHaveValue("Management reporting revenue");
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  fireEvent.click(salesPlacements[0]);
  fireEvent.click(screen.getByRole("button", { name: "Discard and continue" }));
  expect(selected).toHaveBeenLastCalledWith("Sales", "total-sales");
  expect(pane).toHaveTextContent("Sales under Total");
  expect(pane).toHaveTextContent("Total");
  expect(relationshipName).toHaveValue("Total sales placement");
});

it("separates member and placement workspaces without duplicating editors", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              rows: [relationship("Sales")],
              metadataRevision: 46,
              nextCursor: null,
            },
          }),
        ),
    ),
  );
  const props = {
    app,
    catalog,
    dimensionId: "Account",
    members: [
      { member_id: "Total", name: "Total", status: "Active" },
      { member_id: "Sales", name: "Sales", status: "Active" },
    ],
    metadataRevision: 46,
    onChanged: async () => undefined,
  };
  const view = render(<MetadataRelationships {...props} mode="members" />);
  expect(
    await screen.findByRole("table", { name: "Member attribute grid" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("table", {
      name: "Relationship placement attribute grid",
    }),
  ).toBeNull();
  expect(screen.queryByRole("button", { name: "Tree View" })).toBeNull();
  expect(
    screen.queryByRole("button", { name: "Create relationship" }),
  ).toBeNull();
  expect(screen.queryByLabelText("Selected metadata properties")).toBeNull();
  view.rerender(<MetadataRelationships {...props} mode="relationships" />);
  expect(
    await screen.findByRole("table", {
      name: "Relationship placement attribute grid",
    }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("table", { name: "Member attribute grid" }),
  ).toBeNull();
  expect(screen.getByRole("button", { name: "Tree View" })).toBeInTheDocument();
  expect(screen.queryByLabelText("Stable ID")).toBeNull();
  expect(screen.queryByText("MEMBER PROPERTIES")).toBeNull();
});

it("keeps a restored placement rename when fresh relationship data arrives", async () => {
  let revision = 46;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              rows: [
                {
                  ...relationship("Sales"),
                  name: revision === 46 ? "Old placement" : "Updated elsewhere",
                },
              ],
              metadataRevision: revision,
              nextCursor: null,
            },
          }),
        ),
    ),
  );
  const props = {
    app,
    catalog,
    dimensionId: "Account",
    members: [
      { member_id: "Total", name: "Total", status: "Active" },
      { member_id: "Sales", name: "Sales", status: "Active" },
    ],
    selectedMemberId: "Sales",
    onChanged: async () => undefined,
    mode: "relationships" as const,
  };
  const first = render(
    <MetadataRelationships {...props} metadataRevision={46} />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Relationship display name")).toHaveValue(
      "Old placement",
    ),
  );
  fireEvent.change(screen.getByLabelText("Relationship display name"), {
    target: { value: "Retained placement name" },
  });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact relationship name against the current model.",
    ),
  );
  first.unmount();
  revision = 47;
  render(<MetadataRelationships {...props} metadataRevision={47} />);
  await screen.findByText(/1 current relationships/);
  await waitFor(() =>
    expect(screen.getByLabelText("Relationship display name")).toHaveValue(
      "Retained placement name",
    ),
  );
  expect(
    screen.getByLabelText(
      "I reviewed this exact relationship name against the current model.",
    ),
  ).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Rename relationship" }),
  ).toBeDisabled();
});

it("does not navigate from initial reads, refreshes, or inspector closure", async () => {
  let revision = 46;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              rows: [relationship("Sales")],
              metadataRevision: revision,
              nextCursor: null,
            },
          }),
        ),
    ),
  );
  const navigate = vi.fn();
  const props = {
    app,
    catalog,
    dimensionId: "Account",
    members: [
      { member_id: "Total", name: "Total", status: "Active" },
      { member_id: "Sales", name: "Sales", status: "Active" },
    ],
    selectedMemberId: "",
    onSelectedMemberIdChange: navigate,
    onChanged: async () => undefined,
    mode: "members" as const,
  };
  const view = render(
    <MetadataRelationships {...props} metadataRevision={46} />,
  );
  await screen.findByRole("button", { name: "Select member Sales (Sales)" });
  expect(navigate).not.toHaveBeenCalled();
  revision = 47;
  view.rerender(<MetadataRelationships {...props} metadataRevision={47} />);
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Total" })).toBeInTheDocument(),
  );
  expect(navigate).not.toHaveBeenCalled();
  fireEvent.click(
    screen.getByRole("button", { name: "Select member Sales (Sales)" }),
  );
  expect(navigate).toHaveBeenLastCalledWith("Sales", "Sales");
  navigate.mockClear();
  view.rerender(
    <MetadataRelationships
      {...props}
      selectedMemberId="Sales"
      metadataRevision={47}
    />,
  );
  view.rerender(
    <MetadataRelationships
      {...props}
      selectedMemberId=""
      metadataRevision={47}
    />,
  );
  await act(async () => undefined);
  expect(navigate).not.toHaveBeenCalled();
});

it("preserves the exact placement chosen while a relationship refresh is pending", async () => {
  const rows = [
    {
      relationship_id: "total-sales",
      dimension_id: "Account",
      name: "Total sales placement",
      parent_member_id: "Total",
      child_member_id: "Sales",
      status: "Active",
    },
    {
      relationship_id: "reporting-sales",
      dimension_id: "Account",
      name: "Reporting sales placement",
      parent_member_id: "Reporting",
      child_member_id: "Sales",
      status: "Active",
    },
  ];
  const response = (metadataRevision: number) =>
    new Response(
      JSON.stringify({ result: { rows, metadataRevision, nextCursor: null } }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  let completeRefresh!: (value: Response) => void;
  const fetcher = vi
    .fn()
    .mockResolvedValueOnce(response(46))
    .mockImplementationOnce(
      () =>
        new Promise<Response>((resolve) => {
          completeRefresh = resolve;
        }),
    );
  vi.stubGlobal("fetch", fetcher);
  const members = [
    { member_id: "Total", name: "Total", status: "Active" },
    { member_id: "Reporting", name: "Reporting", status: "Active" },
    { member_id: "Sales", name: "Sales", status: "Active" },
  ];
  const props = {
    app,
    catalog,
    dimensionId: "Account",
    members,
    onChanged: async () => undefined,
  };
  const view = render(
    <MetadataRelationships {...props} metadataRevision={46} />,
  );
  await screen.findByText(/2 current relationships/);
  fireEvent.click(screen.getByRole("button", { name: "Total" }));
  expect(
    screen.getByLabelText("Selected metadata properties"),
  ).toHaveTextContent("Sales under Total");
  view.rerender(<MetadataRelationships {...props} metadataRevision={47} />);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  fireEvent.click(screen.getByRole("button", { name: "Reporting" }));
  expect(
    screen.getByLabelText("Selected metadata properties"),
  ).toHaveTextContent("Sales under Reporting");
  await act(async () => {
    completeRefresh(response(47));
  });
  expect(
    screen.getByLabelText("Selected metadata properties"),
  ).toHaveTextContent("Sales under Reporting");
});

it("falls back when the exact selected placement disappears from a refreshed snapshot", async () => {
  const rows = [
    {
      relationship_id: "total-sales",
      dimension_id: "Account",
      name: "Total sales placement",
      parent_member_id: "Total",
      child_member_id: "Sales",
      status: "Active",
    },
    {
      relationship_id: "reporting-sales",
      dimension_id: "Account",
      name: "Reporting sales placement",
      parent_member_id: "Reporting",
      child_member_id: "Sales",
      status: "Active",
    },
  ];
  const response = (metadataRevision: number) =>
    new Response(
      JSON.stringify({
        result: {
          rows: metadataRevision === 47 ? rows.slice(0, 1) : rows,
          metadataRevision,
          nextCursor: null,
        },
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  let completeRefresh!: (value: Response) => void;
  const fetcher = vi
    .fn()
    .mockResolvedValueOnce(response(46))
    .mockImplementationOnce(
      () =>
        new Promise<Response>((resolve) => {
          completeRefresh = resolve;
        }),
    );
  vi.stubGlobal("fetch", fetcher);
  const members = [
    { member_id: "Total", name: "Total", status: "Active" },
    { member_id: "Reporting", name: "Reporting", status: "Active" },
    { member_id: "Sales", name: "Sales", status: "Active" },
  ];
  const props = {
    app,
    catalog,
    dimensionId: "Account",
    members,
    onChanged: async () => undefined,
  };
  const view = render(
    <MetadataRelationships {...props} metadataRevision={46} />,
  );
  await screen.findByText(/2 current relationships/);
  fireEvent.click(screen.getByRole("button", { name: "Reporting" }));
  await waitFor(() =>
    expect(
      screen.getByLabelText("Selected metadata properties"),
    ).toHaveTextContent("Sales under Reporting"),
  );
  view.rerender(<MetadataRelationships {...props} metadataRevision={47} />);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  await act(async () => {
    completeRefresh(response(47));
  });
  expect(
    screen.getByLabelText("Selected metadata properties"),
  ).toHaveTextContent("Sales under Total");
});

it.each([false, true])(
  "keeps the exact placement selected before loaded-read effects settle (controlled=%s)",
  async (controlled) => {
    const rows = [
      {
        relationship_id: "total-sales",
        dimension_id: "Account",
        name: "Total sales placement",
        parent_member_id: "Total",
        child_member_id: "Sales",
        status: "Active",
      },
      {
        relationship_id: "reporting-sales",
        dimension_id: "Account",
        name: "Reporting sales placement",
        parent_member_id: "Reporting",
        child_member_id: "Sales",
        status: "Active",
      },
    ];
    const members = [
      { member_id: "Total", name: "Total", status: "Active" },
      { member_id: "Reporting", name: "Reporting", status: "Active" },
      { member_id: "Sales", name: "Sales", status: "Active" },
    ];
    const fetcher = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: { rows, metadataRevision: 46, nextCursor: null },
          }),
        ),
    );
    vi.stubGlobal("fetch", fetcher);
    const selected = vi.fn();
    function CurrentSelection() {
      const [memberId, setMemberId] = useState("Total");
      return (
        <MetadataRelationships
          app={app}
          catalog={catalog}
          dimensionId="Account"
          members={members}
          metadataRevision={46}
          onChanged={async () => undefined}
          {...(controlled ? { selectedMemberId: memberId } : {})}
          onSelectedMemberIdChange={(next) => {
            selected(next);
            if (controlled) setMemberId(next);
          }}
          onRequestTransition={(action) => action()}
        />
      );
    }
    let clicked = false;
    // The control is user-reachable as soon as the relationship rows commit.
    // Dispatch before passive effects, without changing their scheduling or state.
    const observer = new MutationObserver(() => {
      if (clicked || !screen.queryByText(/2 current relationships/)) return;
      const placement = screen.queryByRole("button", {
        name: "Reporting",
      });
      if (!placement) return;
      clicked = true;
      observer.disconnect();
      placement.click();
    });
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
    });
    onTestFinished(() => observer.disconnect());
    render(<CurrentSelection />);
    await waitFor(() => expect(clicked).toBe(true));
    expect(selected).toHaveBeenLastCalledWith("Sales");
    await waitFor(() =>
      expect(
        screen.getByLabelText("Selected metadata properties"),
      ).toHaveTextContent("Sales under Reporting"),
    );
    expect(screen.getByLabelText("Relationship display name")).toHaveValue(
      "Reporting sales placement",
    );
    expect(fetcher).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Tree View" }));
    expect(
      screen.getByRole("button", {
        name: "Select Sales in hierarchy under Reporting",
      }),
    ).toHaveClass("selected");
    expect(
      screen.getByRole("button", {
        name: "Select Sales in hierarchy under Total",
      }),
    ).not.toHaveClass("selected");
  },
);

it.each([
  "missing",
  "member",
  "dimension",
  "application",
  "hierarchy",
  "malformed",
])(
  "refuses an explicit %s placement without silently selecting a different edge",
  async (fault) => {
    const members = [
      { member_id: "Total", name: "Total", status: "Active" },
      { member_id: "Reporting", name: "Reporting", status: "Active" },
      { member_id: "Sales", name: "Sales", status: "Active" },
    ];
    const row = {
      ...relationship("Sales"),
      relationship_id: "total-sales",
      hierarchy_id: "H",
      name: "Exact total placement",
    };
    const functions = {
      ...catalog.functions,
      "metadata.hierarchy.list": {},
      "metadata.hierarchy.members.list": {},
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url, init) => {
        const body = JSON.parse(String(init.body));
        const fn = body.program.function;
        const h = fault === "hierarchy" ? "OTHER" : "H";
        let result;
        if (fn === "metadata.hierarchy.list")
          result = {
            rows: [
              {
                hierarchyId: h,
                name: h,
                status: "Active",
                membershipMode: "all_active",
                isDefault: true,
                stateToken: null,
                builtMetadataRevision: null,
                current: false,
              },
            ],
            dimensionId: body.program.arguments.dimensionId,
            metadataRevision: 46,
            hasMore: false,
            nextAfterId: null,
          };
        else if (fn === "metadata.hierarchy.members.list")
          result = {
            rows: [],
            hierarchyId: h,
            dimensionId: body.program.arguments.dimensionId,
            metadataRevision: 46,
            hasMore: false,
            nextAfterId: null,
          };
        else if (fn === "metadata.relationship.list")
          result = {
            rows: ["dimension", "application", "hierarchy"].includes(fault)
              ? []
              : [row],
            hierarchyId: h,
            metadataRevision: 46,
            nextCursor: null,
          };
        else throw new Error("UNEXPECTED_READ");
        return new Response(JSON.stringify({ result }));
      }),
    );
    render(
      <MetadataRelationships
        app={fault === "application" ? { ...app, applicationId: "other" } : app}
        catalog={{ ...catalog, functions }}
        dimensionId={fault === "dimension" ? "Entity" : "Account"}
        hierarchyId={fault === "hierarchy" ? "OTHER" : "H"}
        members={members}
        metadataRevision={46}
        selectedMemberId={fault === "member" ? "Reporting" : "Sales"}
        selectedRelationshipId={
          fault === "missing"
            ? "missing-edge"
            : fault === "malformed"
              ? ""
              : "total-sales"
        }
        onChanged={async () => undefined}
        mode="tree"
      />,
    );
    expect(
      await screen.findByText(
        "The selected placement is unavailable for this member and hierarchy. Choose a current placement.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Relationship display name")).toBeNull();
    expect(
      screen.getByLabelText("Selected metadata properties"),
    ).toHaveTextContent("This member has no selected parent-child placement.");
    expect(
      document.querySelectorAll(
        '.hierarchy-tree-node.selected[aria-label*=" under "]',
      ),
    ).toHaveLength(0);
    const select = screen.queryByLabelText("Relationship", { exact: true });
    if (select) expect(select).toHaveValue("");
  },
);

it("retains a routed placement on current refresh and refuses a late prior-scope response", async () => {
  const members = [
    { member_id: "Total", name: "Total", status: "Active" },
    { member_id: "Reporting", name: "Reporting", status: "Active" },
    { member_id: "Sales", name: "Sales", status: "Active" },
  ];
  const rows = [
    {
      ...relationship("Sales"),
      relationship_id: "total-sales",
      name: "Total placement",
    },
    {
      ...relationship("Sales"),
      relationship_id: "reporting-sales",
      parent_member_id: "Reporting",
      name: "Reporting placement",
    },
  ];
  const response = (rows: unknown[], revision: number) =>
    new Response(
      JSON.stringify({
        result: { rows, metadataRevision: revision, nextCursor: null },
      }),
    );
  let finish!: (value: Response) => void;
  let oldSignal: AbortSignal | undefined;
  const fetcher = vi.fn(async (_input, init) => {
    const body = JSON.parse(String(init.body));
    if (body.applicationId === "other") return response([], 47);
    if (fetcher.mock.calls.length === 1) return response(rows, 46);
    oldSignal = init.signal;
    return new Promise<Response>((resolve) => {
      finish = resolve;
    });
  });
  vi.stubGlobal("fetch", fetcher);
  const props = {
    app,
    catalog,
    dimensionId: "Account",
    members,
    onChanged: async () => undefined,
    selectedMemberId: "Sales",
    selectedRelationshipId: "reporting-sales",
    mode: "tree" as const,
  };
  const view = render(
    <MetadataRelationships {...props} metadataRevision={46} />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Relationship display name")).toHaveValue(
      "Reporting placement",
    ),
  );
  view.rerender(<MetadataRelationships {...props} metadataRevision={47} />);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  expect(
    screen.getByLabelText("Selected metadata properties"),
  ).toHaveTextContent("Sales under Reporting");
  await act(async () => {
    finish(response(rows, 47));
  });
  expect(screen.getByLabelText("Relationship display name")).toHaveValue(
    "Reporting placement",
  );
  view.rerender(<MetadataRelationships {...props} metadataRevision={48} />);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(3));
  view.rerender(
    <MetadataRelationships
      {...props}
      app={{ ...app, applicationId: "other" }}
      metadataRevision={47}
    />,
  );
  expect(
    await screen.findByText(
      "The selected placement is unavailable for this member and hierarchy. Choose a current placement.",
    ),
  ).toBeInTheDocument();
  expect(oldSignal?.aborted).toBe(true);
  await act(async () => {
    finish(response(rows, 48));
  });
  expect(screen.queryByLabelText("Relationship display name")).toBeNull();
  expect(
    screen.getByLabelText("Selected metadata properties"),
  ).not.toHaveTextContent("Sales under Reporting");
});
