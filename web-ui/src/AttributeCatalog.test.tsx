import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  AttributeCatalog,
  attributeListArguments,
  attributeMutationBody,
  parseAttributeConstraints,
  validAttributeId,
} from "./AttributeCatalog";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Model",
  status: "Active",
};

const catalog = {
  applicationAccess: { role: "Administrator", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "metadata.attribute-definition.list": {},
    "metadata.attribute-definition.create": {},
    "metadata.attribute-definition.update": {},
    "metadata.attribute-definition.status.set": {},
    "metadata.attribute-definition.usage.read": {},
  },
  revisions: { metadata: 7, data: 1, policy: 1, security: 1, commit: 7 },
};

const row = {
  attribute_id: "Custom01",
  default_name: "Custom01",
  display_name: "External code",
  short_description: "Source code",
  semantic_description: "Stable external identifier",
  value_type: "Text" as const,
  validation_constraints: { maximumLength: 20 },
  status: "Active" as const,
  state_token: "a".repeat(64),
};

it("builds scope-aware bounded reads and unchanged mutation envelopes", () => {
  expect(attributeListArguments("Dimension", "Entity", "", "All")).toEqual({
    scope: "Dimension",
    limit: 100,
  });
  expect(
    attributeListArguments("Member", "Entity", "ERP", "Active", "Custom01"),
  ).toEqual({
    scope: "Member",
    dimensionId: "Entity",
    query: "ERP",
    status: "Active",
    limit: 100,
    afterAttributeId: "Custom01",
  });
  expect(
    attributeMutationBody(
      app,
      "metadata.attribute-definition.status.set",
      { scope: "Dimension", attributeId: "Custom01" },
      "attribute-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "attribute-1",
    program: {
      languageVersion: 2,
      function: "metadata.attribute-definition.status.set",
      arguments: { scope: "Dimension", attributeId: "Custom01" },
    },
  });
});

it("validates stable IDs and JSON objects before fixed-core submission", () => {
  expect(validAttributeId("External.Code-1")).toBe(true);
  expect(validAttributeId("1External")).toBe(false);
  expect(validAttributeId("External code")).toBe(false);
  expect(parseAttributeConstraints('{"maximumLength":20}')).toEqual({
    maximumLength: 20,
  });
  expect(() => parseAttributeConstraints("[]")).toThrow(
    "Validation constraints must be a JSON object",
  );
});

it("renders the authoritative Attribute Catalog as an editable grid", async () => {
  const calls: Array<{
    program: { function: string; arguments: Record<string, unknown> };
  }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      return new Response(
        JSON.stringify({
          result: {
            rows: [row],
            nextAfterAttributeId: null,
            metadataRevision: 7,
          },
        }),
      );
    }),
  );
  render(
    <AttributeCatalog
      app={app}
      catalog={catalog}
      dimensions={[
        { dimension_id: "Entity", name: "Entity", status: "Active" },
      ]}
      dimensionId="Entity"
      metadataRevision={7}
      onChanged={async () => undefined}
    />,
  );
  await waitFor(() => expect(screen.getAllByText("Custom01")).toHaveLength(2));
  expect(screen.getByLabelText("Custom01 display name")).toHaveValue(
    "External code",
  );
  expect(screen.getByText("1 current rows")).toBeInTheDocument();
  expect(calls[0]).toEqual(
    expect.objectContaining({
      program: {
        languageVersion: 2,
        function: "metadata.attribute-definition.list",
        arguments: { scope: "Dimension", limit: 100 },
      },
    }),
  );
});

it("switches to the selected member context and inspects usage", async () => {
  const functions: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      functions.push(body.program.function);
      if (body.program.function === "metadata.attribute-definition.usage.read")
        return new Response(
          JSON.stringify({
            result: {
              valueCount: 1,
              sampleObjectIds: ["EntityA"],
              sampleTruncated: false,
              metadataRevision: 7,
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            rows: [row],
            nextAfterAttributeId: null,
            metadataRevision: 7,
          },
        }),
      );
    }),
  );
  render(
    <AttributeCatalog
      app={app}
      catalog={catalog}
      dimensions={[
        { dimension_id: "Entity", name: "Entity", status: "Active" },
      ]}
      dimensionId="Entity"
      metadataRevision={7}
      onChanged={async () => undefined}
    />,
  );
  await waitFor(() => expect(screen.getAllByText("Custom01")).toHaveLength(2));
  fireEvent.change(screen.getByLabelText("Attribute scope"), {
    target: { value: "Member" },
  });
  await waitFor(() =>
    expect(screen.getByLabelText("Attribute dimension")).toHaveValue("Entity"),
  );
  await waitFor(() => expect(functions.length).toBeGreaterThan(1));
  fireEvent.click(screen.getByRole("button", { name: "Usage" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Attribute usage")).toHaveTextContent(
      "populated on 1 object",
    ),
  );
  expect(functions).toContain("metadata.attribute-definition.usage.read");
});

it("keeps the workspace dimension and edited values until a scope transition is accepted", async () => {
  const reads: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      reads.push(body.program.arguments);
      return new Response(
        JSON.stringify({
          result: {
            rows: [row],
            nextAfterAttributeId: null,
            metadataRevision: 7,
          },
        }),
      );
    }),
  );
  let accept: (() => void) | undefined;
  render(
    <AttributeCatalog
      app={app}
      catalog={catalog}
      dimensions={[
        { dimension_id: "Entity", name: "Entity", status: "Active" },
      ]}
      dimensionId="Entity"
      metadataRevision={7}
      onChanged={async () => undefined}
      contextLocked
      initialScope="Member"
      onRequestTransition={(action) => {
        accept = action;
      }}
    />,
  );
  const label = await screen.findByLabelText("Custom01 display name");
  fireEvent.change(label, { target: { value: "Preserve my draft" } });
  expect(
    screen.queryByLabelText("Attribute dimension"),
  ).not.toBeInTheDocument();
  expect(reads[0]).toEqual({
    scope: "Member",
    dimensionId: "Entity",
    limit: 100,
  });
  fireEvent.change(screen.getByLabelText("Attribute scope"), {
    target: { value: "Dimension" },
  });
  expect(screen.getByLabelText("Attribute scope")).toHaveValue("Member");
  expect(label).toHaveValue("Preserve my draft");
  expect(reads).toHaveLength(1);
  expect(accept).toBeTypeOf("function");
  // The coordinator invokes this only after explicit discard or with no draft.
  act(() => accept?.());
  await waitFor(() =>
    expect(reads.at(-1)).toEqual({ scope: "Dimension", limit: 100 }),
  );
});
