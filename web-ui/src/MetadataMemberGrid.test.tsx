import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  MetadataMemberGrid,
  metadataAttributeValue,
} from "./MetadataMemberGrid";

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
    vi.fn(async (_url: string, init?: RequestInit) => {
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
                  definition_version: 1,
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
    screen.getByLabelText(
      "I reviewed this exact typed value and metadata revision.",
    ),
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
  expect(await screen.findByText(/attribute-op-1/)).toBeInTheDocument();
});

it("renders relationship attributes and submits a relationship-scoped edit", async () => {
  const calls: Array<Record<string, unknown>> = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init?: RequestInit) => {
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
                      definition_version: 1,
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
    screen.getByLabelText(
      "I reviewed this exact typed value and metadata revision.",
    ),
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
  expect(await screen.findByText(/relationship-op-1/)).toBeInTheDocument();
});

it("invalidates an open cell edit when the authoritative metadata revision changes", async () => {
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
                      definition_version: 1,
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

  serverRevision = 47;
  rerender(<MetadataMemberGrid {...props} metadataRevision={47} />);
  await waitFor(() =>
    expect(screen.queryByLabelText("Attribute cell editor")).toBeNull(),
  );
  expect(
    calls.filter(
      (call) =>
        (call.program as any).function === "metadata.attribute-value.set",
    ),
  ).toHaveLength(0);
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
