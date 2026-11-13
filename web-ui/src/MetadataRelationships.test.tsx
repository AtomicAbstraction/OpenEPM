import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { useState } from "react";
import { discardUnsavedWork, unsavedWorkSnapshot } from "./unsaved-work";
import { operationAdmissionResponse } from "./test-setup";
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
      "I reviewed this exact parent-child relationship against the current model.",
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
  expect(
    await screen.findByText(/0 current relationships/),
  ).toBeInTheDocument();
  const id = screen.getByLabelText("Stable ID");
  fireEvent.change(id, { target: { value: "sales-total" } });
  const review = screen.getByLabelText(
    "I reviewed this exact parent-child relationship against the current model.",
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
  expect(
    await screen.findByText(/0 current relationships/),
  ).toBeInTheDocument();
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
    name: "Select Sales in hierarchy",
  });
  expect(salesPlacements).toHaveLength(2);
  fireEvent.click(salesPlacements[0]);
  expect(
    screen.getByRole("alertdialog", { name: "Unsaved placement changes" }),
  ).toBeInTheDocument();
  expect(pane).toHaveTextContent("reporting-sales");
  expect(relationshipName).toHaveValue("Management reporting revenue");
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(pane).toHaveTextContent("reporting-sales");
  expect(relationshipName).toHaveValue("Management reporting revenue");
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  fireEvent.click(salesPlacements[0]);
  fireEvent.click(screen.getByRole("button", { name: "Discard and continue" }));
  expect(selected).toHaveBeenLastCalledWith("Sales");
  expect(pane).toHaveTextContent("total-sales");
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
  expect(
    screen.getByRole("button", { name: "Create relationship" }),
  ).toBeInTheDocument();
  expect(screen.queryByText("MEMBER PROPERTIES")).toBeNull();
});

it("retains a relationship draft while revoking review after a revision change", async () => {
  let revision = 46;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: { rows: [], metadataRevision: revision, nextCursor: null },
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
    onChanged: async () => undefined,
    mode: "relationships" as const,
  };
  const view = render(
    <MetadataRelationships {...props} metadataRevision={46} />,
  );
  await screen.findByText(/0 current relationships/);
  fireEvent.change(screen.getByLabelText("Stable ID"), {
    target: { value: "total-sales" },
  });
  const review = screen.getByLabelText(
    "I reviewed this exact parent-child relationship against the current model.",
  );
  fireEvent.click(review);
  expect(review).toBeChecked();
  revision = 47;
  view.rerender(<MetadataRelationships {...props} metadataRevision={47} />);
  await screen.findByText(/0 current relationships/);
  expect(screen.getByLabelText("Stable ID")).toHaveValue("total-sales");
  expect(review).not.toBeChecked();
  expect(review).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Review against current metadata" }),
  );
  expect(review).toBeEnabled();
  expect(
    screen.getByRole("button", { name: "Create relationship" }),
  ).toBeDisabled();
});

it("restores relationship entries without restoring a prior create approval", async () => {
  let revision = 46;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: { rows: [], metadataRevision: revision, nextCursor: null },
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
    onChanged: async () => undefined,
    mode: "relationships" as const,
  };
  const first = render(
    <MetadataRelationships {...props} metadataRevision={46} />,
  );
  await screen.findByText(/0 current relationships/);
  fireEvent.change(screen.getByLabelText("Stable ID"), {
    target: { value: "retained-placement" },
  });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact parent-child relationship against the current model.",
    ),
  );
  first.unmount();
  revision = 47;
  render(<MetadataRelationships {...props} metadataRevision={47} />);
  await waitFor(() =>
    expect(screen.getByLabelText("Stable ID")).toHaveValue(
      "retained-placement",
    ),
  );
  expect(
    screen.getByLabelText(
      "I reviewed this exact parent-child relationship against the current model.",
    ),
  ).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Create relationship" }),
  ).toBeDisabled();
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
  expect(navigate).toHaveBeenLastCalledWith("Sales");
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

it("keeps refreshed relationships visible when a same-dimension save finishes", async () => {
  let revision = 46;
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/api/operation-admission")
        return operationAdmissionResponse("4");
      const body = JSON.parse(String(init?.body));
      const result =
        body.program.function === "metadata.relationship.list"
          ? {
              rows: revision === 46 ? [] : [relationship("Sales")],
              metadataRevision: revision,
              nextCursor: null,
            }
          : { receiptId: "relationship-created" };
      return new Response(JSON.stringify({ result }));
    }),
  );
  let completeRefresh: () => void = () => undefined;
  const onChanged = vi.fn(
    () =>
      new Promise<void>((resolve) => {
        completeRefresh = resolve;
      }),
  );
  const props = {
    app,
    catalog,
    dimensionId: "Account",
    members: [
      { member_id: "Total", name: "Total", status: "Active" },
      { member_id: "Sales", name: "Sales", status: "Active" },
    ],
    onChanged,
    mode: "relationships" as const,
  };
  const view = render(
    <MetadataRelationships {...props} metadataRevision={46} />,
  );
  await screen.findByText(/0 current relationships/);
  fireEvent.change(screen.getByLabelText("Stable ID"), {
    target: { value: "Sales" },
  });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact parent-child relationship against the current model.",
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Create relationship" }));
  await waitFor(() => expect(onChanged).toHaveBeenCalledOnce());
  revision = 47;
  view.rerender(<MetadataRelationships {...props} metadataRevision={47} />);
  await screen.findByText(/1 current relationships/);
  await act(async () => completeRefresh());
  expect(screen.getByText(/1 current relationships/)).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Select relationship Sales (Sales)" }),
  ).toBeInTheDocument();
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
  ).toHaveTextContent("total-sales");
  view.rerender(<MetadataRelationships {...props} metadataRevision={47} />);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  fireEvent.click(screen.getByRole("button", { name: "Reporting" }));
  expect(
    screen.getByLabelText("Selected metadata properties"),
  ).toHaveTextContent("reporting-sales");
  await act(async () => {
    completeRefresh(response(47));
  });
  expect(
    screen.getByLabelText("Selected metadata properties"),
  ).toHaveTextContent("reporting-sales");
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
    ).toHaveTextContent("reporting-sales"),
  );
  view.rerender(<MetadataRelationships {...props} metadataRevision={47} />);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  await act(async () => {
    completeRefresh(response(47));
  });
  expect(
    screen.getByLabelText("Selected metadata properties"),
  ).toHaveTextContent("total-sales");
});
