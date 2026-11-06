import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  collectMetadataRelationships,
  metadataActionBody,
  MetadataRelationships,
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

it("keeps relationship changes disabled until the authoritative snapshot is read", () => {
  render(
    <MetadataRelationships
      app={app}
      catalog={catalog}
      dimensionId="Account"
      members={[
        { member_id: "Total", name: "Total", status: "Active" },
        { member_id: "Sales", name: "Sales", status: "Active" },
      ]}
      metadataRevision={46}
      onChanged={async () => undefined}
    />,
  );
  const id = screen.getByLabelText("Stable ID");
  fireEvent.change(id, { target: { value: "sales-total" } });
  expect(
    screen.getByLabelText(
      "I reviewed this exact parent-child relationship and metadata revision.",
    ),
  ).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Create relationship" }),
  ).toBeDisabled();
  expect(screen.queryByRole("button", { name: "Build hierarchy" })).toBeNull();
});

it("invalidates an exact relationship review when intent changes", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              rows: [],
              metadataRevision: 46,
              nextCursor: null,
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    ),
  );
  render(
    <MetadataRelationships
      app={app}
      catalog={catalog}
      dimensionId="Account"
      members={[
        { member_id: "Total", name: "Total", status: "Active" },
        { member_id: "Sales", name: "Sales", status: "Active" },
      ]}
      metadataRevision={46}
      onChanged={async () => undefined}
    />,
  );
  expect(await screen.findByText(/0 relationships/)).toBeInTheDocument();
  const id = screen.getByLabelText("Stable ID");
  fireEvent.change(id, { target: { value: "sales-total" } });
  const review = screen.getByLabelText(
    "I reviewed this exact parent-child relationship and metadata revision.",
  );
  fireEvent.click(review);
  expect(review).toBeChecked();
  expect(
    screen.getByRole("button", { name: "Create relationship" }),
  ).toBeEnabled();
  fireEvent.change(id, { target: { value: "sales-total-v2" } });
  expect(review).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Create relationship" }),
  ).toBeDisabled();
});

it("offers both list and drag-and-drop tree authoring", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              rows: [],
              metadataRevision: 46,
              nextCursor: null,
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    ),
  );
  render(
    <MetadataRelationships
      app={app}
      catalog={catalog}
      dimensionId="Account"
      members={[
        { member_id: "Total", name: "Total", status: "Active" },
        { member_id: "Sales", name: "Sales", status: "Active" },
      ]}
      metadataRevision={46}
      onChanged={async () => undefined}
    />,
  );
  expect(screen.getByRole("button", { name: "List View" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  expect(await screen.findByText(/0 relationships/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Tree View" }));
  expect(screen.getByLabelText("Metadata Tree View")).toBeInTheDocument();
  const child = screen.getByRole("button", {
    name: "Select Sales in hierarchy",
  });
  const parent = screen.getByRole("button", {
    name: "Select Total in hierarchy",
  });
  fireEvent.dragStart(child);
  fireEvent.dragOver(parent);
  fireEvent.drop(parent);
  expect(screen.getByText("Draft: Total → Sales")).toBeInTheDocument();
  expect(screen.getByLabelText("Stable ID")).toHaveValue("Total-Sales");
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
  render(
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
    />,
  );

  expect(await screen.findByText(/2 relationships/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Reporting" }));
  expect(selected).toHaveBeenLastCalledWith("Sales");
  const pane = screen.getByLabelText("Selected metadata properties");
  expect(pane).toHaveTextContent("Customer revenue");
  await waitFor(() => {
    expect(pane).toHaveTextContent("reporting-sales");
    expect(pane).toHaveTextContent("Reporting");
    expect(pane).toHaveTextContent("Reporting sales placement");
  });

  const relationshipName = screen.getByLabelText("Relationship display name");
  fireEvent.change(relationshipName, {
    target: { value: "Management reporting sales" },
  });
  const renameReview = screen.getByLabelText(
    "I reviewed this exact relationship name and metadata revision.",
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
    name: "Select Sales in hierarchy",
  });
  expect(salesPlacements).toHaveLength(2);
  fireEvent.click(salesPlacements[0]);
  expect(selected).toHaveBeenLastCalledWith("Sales");
  expect(pane).toHaveTextContent("total-sales");
  expect(pane).toHaveTextContent("Total");
});
