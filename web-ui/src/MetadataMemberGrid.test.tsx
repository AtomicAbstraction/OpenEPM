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
  MetadataMemberGrid,
  metadataAttributeValue,
} from "./MetadataMemberGrid";
import { operationAdmissionResponse } from "./test-setup";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Cube",
  status: "Active",
};

const catalog = {
  applicationAccess: { role: "Administrator", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "metadata.attribute-definition.list": {},
    "metadata.attribute-value.set": {},
  },
  revisions: { metadata: 46, data: 1, policy: 1, security: 1, commit: 1 },
};

it("preserves exact display semantics for typed custom values", () => {
  expect(metadataAttributeValue(undefined, "Text")).toBe("");
  expect(metadataAttributeValue(false, "Boolean")).toBe("False");
  expect(metadataAttributeValue("1.25000000", "Decimal")).toBe("1.25000000");
});

it("renders governed custom columns and submits one reviewed typed edit", async () => {
  const calls: Array<Record<string, unknown>> = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url) === "/api/operation-admission")
        return operationAdmissionResponse("b");
      const body = JSON.parse(String(init?.body)) as Record<string, any>;
      calls.push(body);
      if (body.program.function === "metadata.attribute-definition.list") {
        const isRelationship = body.program.arguments.scope === "Relationship";
        return new Response(
          JSON.stringify({
            result: {
              rows: [
                {
                  attribute_id: isRelationship
                    ? "PlacementCode"
                    : "ExternalCode",
                  display_name: isRelationship
                    ? "Placement Code"
                    : "External Code",
                  value_type: "Text",
                  validation_constraints: {},
                  status: "Active",
                  state_token: "a".repeat(64),
                },
              ],
              hasMore: false,
              nextAfterAttributeId: null,
              metadataRevision: 46,
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({ result: { operationId: "attribute-op-1" } }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }),
  );
  const changed = vi.fn(async () => undefined);
  render(
    <MetadataMemberGrid
      app={app}
      catalog={catalog}
      dimensionId="Account"
      members={[
        {
          member_id: "Sales",
          name: "Sales",
          status: "Active",
          custom_values: { ExternalCode: "FINANCE" },
        },
      ]}
      relationships={[
        {
          relationship_id: "sales-total",
          dimension_id: "Account",
          name: "Sales placement",
          parent_member_id: "TotalAccount",
          child_member_id: "Sales",
          status: "Active",
          custom_values: { PlacementCode: "PRIMARY" },
        },
      ]}
      metadataRevision={46}
      selectedMemberId="Sales"
      onSelectedMember={() => undefined}
      onChanged={changed}
    />,
  );
  expect((await screen.findAllByText("External Code")).length).toBe(2);
  expect(screen.getByText("FINANCE")).toBeInTheDocument();
  fireEvent.click(screen.getByLabelText("External Code for Sales"));
  fireEvent.change(screen.getByLabelText("Typed value"), {
    target: { value: "FINANCE-REVIEWED" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this exact typed value and target."),
  );
  fireEvent.click(screen.getByRole("button", { name: "Save reviewed value" }));
  await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
  const mutation = calls.find(
    (call) => (call.program as any).function === "metadata.attribute-value.set",
  ) as any;
  expect(mutation.program.arguments).toEqual({
    scope: "Member",
    dimensionId: "Account",
    attributeId: "ExternalCode",
    objectId: "Sales",
    value: "FINANCE-REVIEWED",
    expectedMetadataRevision: 46,
  });
  expect(
    await screen.findByText("The reviewed value was applied."),
  ).toBeInTheDocument();
});

it("renders relationship attributes and submits a relationship-scoped edit", async () => {
  const calls: Array<Record<string, unknown>> = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url) === "/api/operation-admission")
        return operationAdmissionResponse("c");
      const body = JSON.parse(String(init?.body)) as Record<string, any>;
      calls.push(body);
      if (body.program.function === "metadata.attribute-definition.list") {
        const isRelationship = body.program.arguments.scope === "Relationship";
        return new Response(
          JSON.stringify({
            result: {
              rows: isRelationship
                ? [
                    {
                      attribute_id: "PlacementCode",
                      display_name: "Placement Code",
                      value_type: "Text",
                      validation_constraints: {},
                      status: "Active",
                      state_token: "a".repeat(64),
                    },
                  ]
                : [],
              hasMore: false,
              nextAfterAttributeId: null,
              metadataRevision: 46,
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({ result: { operationId: "relationship-op-1" } }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }),
  );
  const changed = vi.fn(async () => undefined);
  render(
    <MetadataMemberGrid
      app={app}
      catalog={catalog}
      dimensionId="Account"
      members={[{ member_id: "Sales", name: "Sales", status: "Active" }]}
      relationships={[
        {
          relationship_id: "sales-total",
          dimension_id: "Account",
          name: "Sales placement",
          parent_member_id: "TotalAccount",
          child_member_id: "Sales",
          status: "Active",
          custom_values: { PlacementCode: "PRIMARY" },
        },
      ]}
      metadataRevision={46}
      selectedMemberId="Sales"
      onSelectedMember={() => undefined}
      onChanged={changed}
    />,
  );
  expect(await screen.findByText("PRIMARY")).toBeInTheDocument();
  fireEvent.click(screen.getByLabelText("Placement Code for Sales placement"));
  fireEvent.change(screen.getByLabelText("Typed value"), {
    target: { value: "SECONDARY" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this exact typed value and target."),
  );
  fireEvent.click(screen.getByRole("button", { name: "Save reviewed value" }));
  await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
  const mutation = calls.find(
    (call) => (call.program as any).function === "metadata.attribute-value.set",
  ) as any;
  expect(mutation.program.arguments).toEqual({
    scope: "Relationship",
    dimensionId: "Account",
    attributeId: "PlacementCode",
    objectId: "sales-total",
    value: "SECONDARY",
    expectedMetadataRevision: 46,
  });
  expect(
    await screen.findByText("The reviewed value was applied."),
  ).toBeInTheDocument();
});

it("preserves typed input and original pins while invalidating an edit after metadata changes", async () => {
  let serverRevision = 46;
  const calls: Array<Record<string, unknown>> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, any>;
      calls.push(body);
      return new Response(
        JSON.stringify({
          result: {
            rows:
              body.program.arguments.scope === "Member"
                ? [
                    {
                      attribute_id: "ExternalCode",
                      display_name: "External Code",
                      value_type: "Text",
                      validation_constraints: {},
                      status: "Active",
                      state_token: "a".repeat(64),
                    },
                  ]
                : [],
            hasMore: false,
            nextAfterAttributeId: null,
            metadataRevision: serverRevision,
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }),
  );
  const props = {
    app,
    catalog,
    dimensionId: "Account",
    members: [
      {
        member_id: "Sales",
        name: "Sales",
        status: "Active",
        custom_values: { ExternalCode: "ERP-001" },
      },
    ],
    relationships: [],
    selectedMemberId: "Sales",
    onSelectedMember: () => undefined,
    onChanged: async () => undefined,
  };
  const { rerender } = render(
    <MetadataMemberGrid {...props} metadataRevision={46} />,
  );
  fireEvent.click(await screen.findByLabelText("External Code for Sales"));
  fireEvent.change(screen.getByLabelText("Typed value"), {
    target: { value: "ERP-002" },
  });
  expect(screen.getByLabelText("Attribute cell editor")).toBeInTheDocument();
  fireEvent.click(
    screen.getByLabelText("I reviewed this exact typed value and target."),
  );

  serverRevision = 47;
  rerender(<MetadataMemberGrid {...props} metadataRevision={47} />);
  expect(screen.getByLabelText("Typed value")).toHaveValue("ERP-002");
  expect(
    screen.getByLabelText("I reviewed this exact typed value and target."),
  ).not.toBeChecked();
  expect(
    screen.getByLabelText("I reviewed this exact typed value and target."),
  ).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Save reviewed value" }),
  ).toBeDisabled();
  expect(screen.queryByText(/metadata revision 46/)).not.toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent(
    "Your typed value is preserved",
  );
  expect(
    calls.filter(
      (call) =>
        (call.program as any).function === "metadata.attribute-value.set",
    ),
  ).toHaveLength(0);
});

const replayProps = {
  app,
  catalog,
  dimensionId: "Account",
  members: [
    {
      member_id: "Sales",
      name: "Sales",
      status: "Active",
      custom_values: { ExternalCode: "ERP-001" },
    },
  ],
  relationships: [],
  selectedMemberId: "Sales",
  metadataRevision: 46,
  onSelectedMember: () => undefined,
  onChanged: async () => undefined,
};

function attributeResponse(revision = 46) {
  return new Response(
    JSON.stringify({
      result: {
        rows: [
          {
            attribute_id: "ExternalCode",
            display_name: "External Code",
            value_type: "Text",
            validation_constraints: {},
            status: "Active",
            state_token: "a".repeat(64),
          },
        ],
        hasMore: false,
        nextAfterAttributeId: null,
        metadataRevision: revision,
      },
    }),
  );
}

it("restores a grid draft without its review and replays an uncertain write with its original key", async () => {
  const writes: Array<Record<string, any>> = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url) === "/api/operation-admission")
        return operationAdmissionResponse("d");
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "metadata.attribute-definition.list")
        return attributeResponse();
      writes.push(body);
      if (writes.length === 1) throw new Error("Response interrupted");
      return new Response(
        JSON.stringify({ result: { receiptId: "same-operation" } }),
      );
    }),
  );
  const first = render(<MetadataMemberGrid {...replayProps} mode="members" />);
  fireEvent.click(await screen.findByLabelText("External Code for Sales"));
  fireEvent.change(screen.getByLabelText("Typed value"), {
    target: { value: "ERP-002" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this exact typed value and target."),
  );
  fireEvent.click(screen.getByRole("button", { name: "Save reviewed value" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Response interrupted",
  );
  first.unmount();

  render(<MetadataMemberGrid {...replayProps} mode="members" />);
  await waitFor(() =>
    expect(screen.getByLabelText("Typed value")).toHaveValue("ERP-002"),
  );
  const review = screen.getByLabelText(
    "I reviewed this exact typed value and target.",
  );
  await waitFor(() => expect(review).toBeEnabled());
  expect(review).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Save reviewed value" }),
  ).toBeDisabled();
  fireEvent.click(review);
  fireEvent.click(screen.getByRole("button", { name: "Save reviewed value" }));
  await waitFor(() => expect(writes).toHaveLength(2));
  expect(writes[1]).toEqual(writes[0]);
  expect(writes[1].program.arguments.expectedMetadataRevision).toBe(46);
});

it("preserves a draft but removes its review when access changes", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => attributeResponse()),
  );
  const { rerender } = render(<MetadataMemberGrid {...replayProps} />);
  fireEvent.click(await screen.findByLabelText("External Code for Sales"));
  fireEvent.change(screen.getByLabelText("Typed value"), {
    target: { value: "ERP-002" },
  });
  const review = screen.getByLabelText(
    "I reviewed this exact typed value and target.",
  );
  fireEvent.click(review);
  rerender(
    <MetadataMemberGrid
      {...replayProps}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 2 } }}
    />,
  );
  expect(screen.getByLabelText("Typed value")).toHaveValue("ERP-002");
  expect(review).not.toBeChecked();
  expect(review).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Save reviewed value" }),
  ).toBeDisabled();
});

it("does not unlock a pending mutation when a concurrent definition refresh finishes", async () => {
  let revision = 46;
  let finishWrite: (response: Response) => void = () => undefined;
  const started = vi.fn();
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url) === "/api/operation-admission")
        return operationAdmissionResponse("e");
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "metadata.attribute-definition.list")
        return attributeResponse(revision);
      started();
      return new Promise<Response>((resolve) => {
        finishWrite = resolve;
      });
    }),
  );
  const { rerender } = render(<MetadataMemberGrid {...replayProps} />);
  fireEvent.click(await screen.findByLabelText("External Code for Sales"));
  fireEvent.change(screen.getByLabelText("Typed value"), {
    target: { value: "ERP-002" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this exact typed value and target."),
  );
  fireEvent.click(screen.getByRole("button", { name: "Save reviewed value" }));
  await waitFor(() => expect(started).toHaveBeenCalledOnce());
  revision = 47;
  await act(async () => {
    rerender(<MetadataMemberGrid {...replayProps} metadataRevision={47} />);
  });
  expect(screen.getByLabelText("Typed value")).toBeDisabled();
  expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
  expect(screen.getByRole("status")).toHaveTextContent(
    "Saving reviewed metadata",
  );
  fireEvent.click(screen.getByLabelText("External Code for Sales"));
  expect(screen.getByLabelText("Typed value")).toHaveValue("ERP-002");
  await act(async () => {
    finishWrite(
      new Response(
        JSON.stringify({ result: { receiptId: "completed-write" } }),
      ),
    );
  });
  expect(screen.queryByLabelText("Attribute cell editor")).toBeNull();
});

it("shows one routed grid and provides native keyboard-focusable row selection", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => attributeResponse()),
  );
  const selected = vi.fn();
  const relationship = {
    relationship_id: "Sales-Total",
    dimension_id: "Account",
    name: "Sales placement",
    parent_member_id: "Total",
    child_member_id: "Sales",
    status: "Active" as const,
  };
  const props = {
    ...replayProps,
    relationships: [relationship],
    onSelectedMember: selected,
  };
  const { rerender } = render(<MetadataMemberGrid {...props} mode="members" />);
  expect(
    screen.getByRole("table", { name: "Member attribute grid" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("table", {
      name: "Relationship placement attribute grid",
    }),
  ).toBeNull();
  const member = screen.getByRole("button", {
    name: "Select member Sales (Sales)",
  });
  member.focus();
  expect(member).toHaveFocus();
  expect(member.tabIndex).toBe(0);
  fireEvent.click(member);
  expect(selected).toHaveBeenCalledExactlyOnceWith("Sales", relationship);
  selected.mockClear();
  rerender(<MetadataMemberGrid {...props} mode="relationships" />);
  expect(
    screen.queryByRole("table", { name: "Member attribute grid" }),
  ).toBeNull();
  expect(
    screen.getByRole("table", {
      name: "Relationship placement attribute grid",
    }),
  ).toBeInTheDocument();
  const placement = screen.getByRole("button", {
    name: "Select relationship Sales placement (Sales-Total)",
  });
  placement.focus();
  expect(placement).toHaveFocus();
  fireEvent.click(placement);
  expect(selected).toHaveBeenCalledExactlyOnceWith("Sales", relationship);
});

it("windows large member catalogues instead of rendering every row", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              rows: [],
              hasMore: false,
              nextAfterAttributeId: null,
              metadataRevision: 46,
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    ),
  );
  render(
    <MetadataMemberGrid
      app={app}
      catalog={catalog}
      dimensionId="Account"
      members={Array.from({ length: 120 }, (_, index) => ({
        member_id: `M${String(index).padStart(3, "0")}`,
        name: `Member ${index}`,
        status: "Active",
      }))}
      relationships={[]}
      metadataRevision={46}
      selectedMemberId="M000"
      onSelectedMember={() => undefined}
      onChanged={async () => undefined}
    />,
  );
  expect(await screen.findByText("Rows 1–50")).toBeInTheDocument();
  expect(screen.getByText("Member 49")).toBeInTheDocument();
  expect(screen.queryByText("Member 50")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Next rows" }));
  expect(screen.getByText("Rows 51–100")).toBeInTheDocument();
  expect(screen.getByText("Member 50")).toBeInTheDocument();
  expect(screen.queryByText("Member 49")).toBeNull();
});

it("filters the complete member snapshot without losing selection or a keyboard-opened cell draft", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => attributeResponse()),
  );
  const selected = vi.fn();
  render(
    <MetadataMemberGrid
      {...replayProps}
      mode="members"
      selectedMemberId="M000"
      onSelectedMember={selected}
      members={Array.from({ length: 120 }, (_, index) => ({
        member_id: `M${String(index).padStart(3, "0")}`,
        name: `Member ${index}`,
        status: index % 2 === 0 ? "Active" : "Inactive",
        custom_values: { ExternalCode: `ERP-${index}` },
      }))}
    />,
  );
  const cell = await screen.findByLabelText("External Code for Member 0");
  cell.focus();
  expect(cell).toHaveFocus();
  fireEvent.keyDown(cell, { key: "Enter" });
  fireEvent.change(screen.getByLabelText("Typed value"), {
    target: { value: "KEEP-DRAFT" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this exact typed value and target."),
  );
  const search = screen.getByRole("searchbox", { name: "Search members" });
  search.focus();
  expect(search).toHaveFocus();
  fireEvent.change(search, { target: { value: "m119" } });
  expect(screen.getByText("1 of 120 members")).toBeInTheDocument();
  expect(screen.getByText("Rows 1–1")).toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Select member Member 0 (M000)" }),
  ).toBeNull();
  expect(
    screen.getByRole("button", { name: "Select member Member 119 (M119)" }),
  ).toBeInTheDocument();
  expect(screen.getByLabelText("Typed value")).toHaveValue("KEEP-DRAFT");
  expect(screen.queryByText(/metadata revision 46/)).not.toBeInTheDocument();
  expect(
    screen.getByLabelText("I reviewed this exact typed value and target."),
  ).toBeChecked();
  expect(selected).not.toHaveBeenCalled();

  fireEvent.change(search, { target: { value: "" } });
  fireEvent.change(screen.getByLabelText("Member status"), {
    target: { value: "Active" },
  });
  expect(screen.getByText("60 of 120 members")).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Select member Member 0 (M000)" }),
  ).toHaveAttribute("aria-pressed", "true");
  fireEvent.click(screen.getByRole("button", { name: "Next rows" }));
  expect(screen.getByText("Rows 51–60")).toBeInTheDocument();
  expect(
    within(
      screen.getByRole("table", { name: "Member attribute grid" }),
    ).getAllByRole("row"),
  ).toHaveLength(11);
  fireEvent.change(screen.getByLabelText("Member status"), {
    target: { value: "Inactive" },
  });
  expect(screen.getByText("Rows 1–50")).toBeInTheDocument();
  expect(screen.getByLabelText("Typed value")).toHaveValue("KEEP-DRAFT");
  fireEvent.change(search, { target: { value: "missing" } });
  expect(screen.getByText("0 of 120 members")).toBeInTheDocument();
  expect(screen.getByText("Rows 0–0")).toBeInTheDocument();
  expect(
    screen.getByText("No members match the current filters."),
  ).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Next rows" })).toBeDisabled();
  expect(screen.getByLabelText("Typed value")).toHaveValue("KEEP-DRAFT");
});

it("filters relationship endpoints across all pages and retains its open draft", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => attributeResponse()),
  );
  const selected = vi.fn();
  render(
    <MetadataMemberGrid
      {...replayProps}
      mode="relationships"
      onSelectedMember={selected}
      relationships={Array.from({ length: 120 }, (_, index) => ({
        relationship_id: `R${String(index).padStart(3, "0")}`,
        dimension_id: "Account",
        name: `Placement ${index}`,
        parent_member_id: `Parent${Math.floor(index / 10)}`,
        child_member_id: `Child${index}`,
        status: index % 2 === 0 ? ("Active" as const) : ("Inactive" as const),
        custom_values: { ExternalCode: `ERP-${index}` },
      }))}
    />,
  );
  fireEvent.keyDown(
    await screen.findByLabelText("External Code for Placement 0"),
    { key: " " },
  );
  fireEvent.change(screen.getByLabelText("Typed value"), {
    target: { value: "PLACEMENT-DRAFT" },
  });
  const search = screen.getByRole("searchbox", {
    name: "Search relationships",
  });
  fireEvent.change(search, { target: { value: "child119" } });
  expect(
    screen.getByText("1 of 120 relationship placements"),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("button", {
      name: "Select relationship Placement 119 (R119)",
    }),
  ).toBeInTheDocument();
  expect(screen.getByLabelText("Typed value")).toHaveValue("PLACEMENT-DRAFT");
  fireEvent.change(search, { target: { value: "parent11" } });
  expect(
    screen.getByText("10 of 120 relationship placements"),
  ).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Relationship status"), {
    target: { value: "Active" },
  });
  expect(
    screen.getByText("5 of 120 relationship placements"),
  ).toBeInTheDocument();
  fireEvent.change(search, { target: { value: "" } });
  expect(
    screen.getByText("60 of 120 relationship placements"),
  ).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Next relationship rows" }),
  );
  expect(screen.getByText("Rows 51–60")).toBeInTheDocument();
  expect(
    within(
      screen.getByRole("table", {
        name: "Relationship placement attribute grid",
      }),
    ).getAllByRole("row"),
  ).toHaveLength(11);
  fireEvent.change(search, { target: { value: "placement 118" } });
  expect(screen.getByText("Rows 1–1")).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Previous relationship rows" }),
  ).toBeDisabled();
  expect(screen.getByLabelText("Typed value")).toHaveValue("PLACEMENT-DRAFT");
  expect(selected).not.toHaveBeenCalled();
});
