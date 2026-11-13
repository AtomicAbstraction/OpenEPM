import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  SemanticAttributes,
  exactAllowedValues,
  exactSemanticValue,
  relationshipAttributeArguments,
  semanticAttributeArguments,
  semanticDefinitionArguments,
  semanticMutationBody,
} from "./SemanticAttributes";
import { operationAdmissionResponse } from "./test-setup";

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
    "metadata.semantic_column.list": {},
    "metadata.member.attributes.read": {},
    "metadata.relationship.semantic_column.list": {},
    "metadata.relationship.attributes.read": {},
    "metadata.semantic_column.create": {},
    "metadata.semantic_column.update": {},
    "metadata.relationship.semantic_column.create": {},
    "metadata.relationship.semantic_column.update": {},
    "metadata.member.attribute.set": {},
    "metadata.relationship.attribute.set": {},
  },
  revisions: {
    metadata: 12,
    data: 1,
    policy: 1,
    security: 1,
    commit: 1,
  },
};

const dimensions = [
  { dimension_id: "Account", name: "Account", status: "Active" },
];

it("preserves semantic read argument contracts", () => {
  expect(semanticDefinitionArguments("Account")).toEqual({
    dimensionId: "Account",
  });
  expect(semanticAttributeArguments("Account", "Sales")).toEqual({
    dimensionId: "Account",
    memberId: "Sales",
  });
  expect(relationshipAttributeArguments("Account", "sales-parent")).toEqual({
    dimensionId: "Account",
    relationshipId: "sales-parent",
  });
  expect(exactAllowedValues("North, South")).toEqual(["North", "South"]);
  expect(() => exactAllowedValues("North, North")).toThrow("duplicate");
  expect(exactSemanticValue("Text", "", false)).toBe("");
  expect(exactSemanticValue("Decimal", "12.500", false)).toBe("12.500");
  expect(exactSemanticValue("Boolean", "TRUE", false)).toBe(true);
  expect(exactSemanticValue("Text", "ignored", true)).toBeNull();
  expect(() => exactSemanticValue("Decimal", "1e3", false)).toThrow(
    "exact decimal",
  );
  expect(
    semanticMutationBody(
      app,
      "metadata.semantic_column.create",
      { dimensionId: "Account", slot: 1 },
      "semantic-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "semantic-1",
    program: {
      languageVersion: 2,
      function: "metadata.semantic_column.create",
      arguments: { dimensionId: "Account", slot: 1 },
    },
  });
});

it("reads definitions and member values through unchanged read programs", async () => {
  const calls: unknown[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body.program);
      if (body.program.function === "metadata.semantic_column.list")
        return new Response(
          JSON.stringify({
            result: {
              metadataRevision: 12,
              columns: [
                {
                  slot: 1,
                  key: "Custom01",
                  display_name: "Reporting class",
                  semantic_definition: "Management reporting classification",
                  population_guidance: "Choose one approved value",
                  restrictions: "Active members only",
                  properties: { valueType: "Text" },
                },
              ],
            },
          }),
        );
      if (
        body.program.function === "metadata.relationship.semantic_column.list"
      )
        return new Response(
          JSON.stringify({
            result: { metadataRevision: 12, columns: [] },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            metadataRevision: 12,
            attributes: [
              {
                slot: 1,
                key: "Custom01",
                display_name: "Reporting class",
                semantic_definition: "Management reporting classification",
                population_guidance: "Choose one approved value",
                restrictions: "Active members only",
                properties: { valueType: "Text" },
                value: "Revenue",
              },
            ],
          },
        }),
      );
    }),
  );
  render(
    <SemanticAttributes
      app={app}
      catalog={catalog}
      dimensionId="Account"
      dimensions={dimensions}
      members={[{ member_id: "Sales", name: "Sales", status: "Active" }]}
      metadataRevision={12}
      onChanged={vi.fn()}
    />,
  );
  await waitFor(() => expect(screen.getByText("Custom01")).toBeInTheDocument());
  fireEvent.click(screen.getByRole("button", { name: "Read values" }));
  await waitFor(() => expect(screen.getByText("Revenue")).toBeInTheDocument());
  expect(calls).toEqual([
    {
      languageVersion: 2,
      function: "metadata.semantic_column.list",
      arguments: { dimensionId: "Account" },
    },
    {
      languageVersion: 2,
      function: "metadata.relationship.semantic_column.list",
      arguments: { dimensionId: "Account" },
    },
    {
      languageVersion: 2,
      function: "metadata.member.attributes.read",
      arguments: { dimensionId: "Account", memberId: "Sales" },
    },
  ]);
});

it("reads relationship definitions and values through unchanged read programs", async () => {
  const functions: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      functions.push(body.program.function);
      if (body.program.function === "metadata.semantic_column.list")
        return new Response(
          JSON.stringify({
            result: { metadataRevision: 12, columns: [] },
          }),
        );
      if (
        body.program.function === "metadata.relationship.semantic_column.list"
      )
        return new Response(
          JSON.stringify({
            result: {
              metadataRevision: 12,
              columns: [
                {
                  slot: 1,
                  key: "Custom01",
                  display_name: "Placement note",
                  semantic_definition: "Meaning of this placement",
                  population_guidance: "Enter a short note",
                  restrictions: "",
                  properties: { valueType: "Text" },
                },
              ],
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            metadataRevision: 12,
            attributes: [
              {
                slot: 1,
                key: "Custom01",
                display_name: "Placement note",
                semantic_definition: "Meaning of this placement",
                population_guidance: "Enter a short note",
                restrictions: "",
                properties: { valueType: "Text" },
                value: "Primary rollup",
              },
            ],
          },
        }),
      );
    }),
  );
  render(
    <SemanticAttributes
      app={app}
      catalog={catalog}
      dimensionId="Account"
      dimensions={dimensions}
      members={[]}
      metadataRevision={12}
      onChanged={vi.fn()}
    />,
  );
  await waitFor(() =>
    expect(
      screen.getByText("Relationship", { selector: "td" }),
    ).toBeInTheDocument(),
  );
  fireEvent.change(screen.getByLabelText("Semantic attribute relationship"), {
    target: { value: "sales-parent" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Read relationship values" }),
  );
  await waitFor(() =>
    expect(screen.getByText("Primary rollup")).toBeInTheDocument(),
  );
  expect(functions).toEqual([
    "metadata.semantic_column.list",
    "metadata.relationship.semantic_column.list",
    "metadata.relationship.attributes.read",
  ]);
});

it("creates a reviewed semantic definition through the unchanged metadata action", async () => {
  const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ path: String(input), body });
      if (String(input) === "/api/operation-admission")
        return operationAdmissionResponse("5");
      if (body.program.function.endsWith("semantic_column.list"))
        return new Response(
          JSON.stringify({
            result: { metadataRevision: 12, columns: [] },
          }),
        );
      return new Response(
        JSON.stringify({ result: { receiptId: "semantic-receipt-1" } }),
      );
    }),
  );
  const onChanged = vi.fn(async () => undefined);
  render(
    <SemanticAttributes
      app={app}
      catalog={catalog}
      dimensionId="Account"
      dimensions={dimensions}
      members={[]}
      metadataRevision={12}
      onChanged={onChanged}
    />,
  );
  await waitFor(() =>
    expect(
      screen.getByText("No semantic attributes are defined."),
    ).toBeInTheDocument(),
  );
  fireEvent.change(screen.getByLabelText("Semantic definition display name"), {
    target: { value: "Reporting class" },
  });
  fireEvent.change(screen.getByLabelText("Semantic definition meaning"), {
    target: { value: "Management reporting classification" },
  });
  fireEvent.change(
    screen.getByLabelText("Semantic definition allowed values"),
    {
      target: { value: "Revenue, Expense" },
    },
  );
  const review = screen.getByLabelText(
    "I reviewed this exact new definition against the current model.",
  );
  await waitFor(() => expect(review).toBeEnabled());
  fireEvent.click(review);
  fireEvent.click(screen.getByRole("button", { name: "Create definition" }));
  await waitFor(() => expect(onChanged).toHaveBeenCalledOnce());
  const mutation = calls.find(
    (call) =>
      call.path === "/api/metadata-action" &&
      (call.body.program as { function?: string }).function ===
        "metadata.semantic_column.create",
  );
  expect(mutation?.body).toMatchObject({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    program: {
      languageVersion: 2,
      function: "metadata.semantic_column.create",
      arguments: {
        dimensionId: "Account",
        slot: 1,
        displayName: "Reporting class",
        semanticDefinition: "Management reporting classification",
        populationGuidance: "",
        restrictions: "",
        valueType: "Text",
        allowedValues: ["Revenue", "Expense"],
        expectedMetadataRevision: 12,
      },
    },
  });
});

it("sets and clears reviewed member values through the unchanged metadata action", async () => {
  const calls: Array<{ path: string; body: Record<string, any> }> = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ path: String(input), body });
      if (String(input) === "/api/operation-admission")
        return operationAdmissionResponse("6");
      if (body.program.function === "metadata.semantic_column.list")
        return new Response(
          JSON.stringify({
            result: {
              metadataRevision: 12,
              columns: [
                {
                  slot: 1,
                  key: "Custom01",
                  display_name: "Rate",
                  semantic_definition: "Exact planning rate",
                  population_guidance: "",
                  restrictions: "",
                  properties: { valueType: "Decimal" },
                },
              ],
            },
          }),
        );
      if (
        body.program.function === "metadata.relationship.semantic_column.list"
      )
        return new Response(
          JSON.stringify({ result: { metadataRevision: 12, columns: [] } }),
        );
      return new Response(JSON.stringify({ result: { receiptId: "value-1" } }));
    }),
  );
  render(
    <SemanticAttributes
      app={app}
      catalog={catalog}
      dimensionId="Account"
      dimensions={dimensions}
      members={[{ member_id: "Sales", name: "Sales", status: "Active" }]}
      metadataRevision={12}
      onChanged={vi.fn(async () => undefined)}
    />,
  );
  await waitFor(() => expect(screen.getByText("Custom01")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Define semantic attributes"));
  fireEvent.change(screen.getByLabelText("Semantic typed value"), {
    target: { value: "12.500" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this exact typed value and target."),
  );
  fireEvent.click(screen.getByRole("button", { name: "Set value" }));
  await waitFor(() =>
    expect(calls.at(-1)?.body.program.function).toBe(
      "metadata.member.attribute.set",
    ),
  );
  expect(calls.at(-1)?.path).toContain("/api/metadata-action");
  expect(calls.at(-1)?.body.program.arguments).toEqual({
    dimensionId: "Account",
    memberId: "Sales",
    slot: 1,
    value: "12.500",
    expectedMetadataRevision: 12,
  });
  fireEvent.click(screen.getByLabelText("Clear semantic value"));
  fireEvent.click(
    screen.getByLabelText("I reviewed this exact typed value and target."),
  );
  fireEvent.click(screen.getByRole("button", { name: "Clear value" }));
  await waitFor(() =>
    expect(calls.at(-1)?.body.program.arguments.value).toBeNull(),
  );
});

it("fails closed when definitions do not match the current metadata revision", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: { metadataRevision: 13, columns: [] },
          }),
        ),
    ),
  );
  render(
    <SemanticAttributes
      app={app}
      catalog={catalog}
      dimensionId="Account"
      dimensions={dimensions}
      members={[]}
      metadataRevision={12}
      onChanged={vi.fn()}
    />,
  );
  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent("Metadata changed"),
  );
  expect(screen.queryByText("No semantic attributes are defined.")).toBeNull();
});

it("stays hidden when the read capability is unavailable", () => {
  const { container } = render(
    <SemanticAttributes
      app={app}
      catalog={{ ...catalog, functions: {} }}
      dimensionId="Account"
      dimensions={dimensions}
      members={[]}
      metadataRevision={12}
      onChanged={vi.fn()}
    />,
  );
  expect(container).toBeEmptyDOMElement();
});
