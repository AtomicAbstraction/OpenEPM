import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  AttributeValueEditor,
  collectAttributeMemberObjects,
  collectAttributeRelationshipObjects,
  parseAttributeValue,
} from "./AttributeValueEditor";
import { resetUnsavedWorkForTests, unsavedWorkSnapshot } from "./unsaved-work";

afterEach(() => {
  resetUnsavedWorkForTests();
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
    "metadata.attribute-value.read": {},
    "metadata.attribute-value.set": {},
  },
  revisions: { metadata: 7, data: 1, policy: 1, security: 1, commit: 7 },
};
const definition = {
  attribute_id: "Custom01",
  display_name: "External code",
  value_type: "Text" as const,
  status: "Active" as const,
};

it("reads complete member and relationship object catalogues", async () => {
  let memberPage = 0;
  const members = await collectAttributeMemberObjects(
    "Entity",
    7,
    async (arguments_) => {
      const current = memberPage++;
      if (current) expect(arguments_.expectedMetadataRevision).toBe(7);
      return {
        rows: Array.from({ length: 100 }, (_unused, row) => ({
          member_id: `m-${current}-${row}`,
          name: "Member",
        })),
        nextAfterMemberId: current === 100 ? null : `m-cursor-${current + 1}`,
        metadataRevision: 7,
      };
    },
  );
  expect(members.rows).toHaveLength(10100);

  let relationshipPage = 0;
  const relationships = await collectAttributeRelationshipObjects(
    "Entity",
    7,
    async () => {
      const current = relationshipPage++;
      return {
        rows: Array.from({ length: 100 }, (_unused, row) => ({
          relationship_id: `r-${current}-${row}`,
        })),
        nextCursor: current === 100 ? null : `r-cursor-${current + 1}`,
        metadataRevision: 7,
      };
    },
  );
  expect(relationships.rows).toHaveLength(10100);
});

it("rejects malformed, repeated, duplicate, and stale object continuations", async () => {
  await expect(
    collectAttributeMemberObjects("Entity", 7, async () => ({
      rows: [],
      nextAfterMemberId: "" as never,
      metadataRevision: 7,
    })),
  ).rejects.toThrow("cursor is invalid");
  let page = 0;
  await expect(
    collectAttributeRelationshipObjects("Entity", 7, async () => ({
      rows: [],
      nextCursor: page++ < 1 ? "same" : "same",
      metadataRevision: 7,
    })),
  ).rejects.toThrow("cursor repeated");
  let duplicatePage = 0;
  await expect(
    collectAttributeMemberObjects("Entity", 7, async () => ({
      rows: [{ member_id: "same", name: "Member" }],
      nextAfterMemberId: duplicatePage++ < 1 ? "more" : null,
      metadataRevision: 7,
    })),
  ).rejects.toThrow("repeated a row");
  await expect(
    collectAttributeRelationshipObjects("Entity", 7, async () => ({
      rows: [],
      nextCursor: null,
      metadataRevision: 8,
    })),
  ).rejects.toThrow("Metadata changed");
});

it("preserves exact scalar types and clear as distinct absence", () => {
  expect(parseAttributeValue("Text", "", false)).toBe("");
  expect(parseAttributeValue("Text", "ignored", true)).toBeNull();
  expect(parseAttributeValue("Boolean", "false", false)).toBe(false);
  expect(parseAttributeValue("Decimal", "-12.50", false)).toBe("-12.50");
  expect(() => parseAttributeValue("Decimal", "1e3", false)).toThrow(
    "exact decimal",
  );
  expect(() => parseAttributeValue("MemberReference", "", false)).toThrow(
    "stable member ID",
  );
});

it("reads and writes a dimension value through the governed contracts", async () => {
  const calls: Array<{
    path: string;
    body: { program: { function: string; arguments: Record<string, unknown> } };
  }> = [];
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
      if (body.program.function === "metadata.attribute-value.read")
        return new Response(
          JSON.stringify({
            result: {
              objectId: "Entity",
              present: true,
              value: "ERP",
              metadataRevision: 7,
            },
          }),
        );
      return new Response(
        JSON.stringify({ result: { operationId: "value-1" } }),
      );
    }),
  );
  const changed = vi.fn(async () => undefined);
  render(
    <AttributeValueEditor
      app={app}
      catalog={catalog}
      scope="Dimension"
      dimensionId=""
      definitions={[definition]}
      dimensions={[
        { dimension_id: "Entity", name: "Entity", status: "Active" },
      ]}
      definitionRevision={7}
      onChanged={changed}
    />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Attribute object")).toHaveValue("Entity"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Read value" }));
  const input = await screen.findByLabelText("Typed attribute value");
  expect(input).toHaveValue("ERP");
  fireEvent.change(input, { target: { value: "" } });
  expect(unsavedWorkSnapshot()).toEqual([
    expect.objectContaining({ label: "Unsaved metadata attribute value" }),
  ]);
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact object, definition, typed value and metadata revision.",
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Save reviewed value" }));
  await waitFor(() =>
    expect(
      calls.some(
        (call) =>
          call.path === "/api/metadata-action" &&
          call.body.program.function === "metadata.attribute-value.set" &&
          call.body.program.arguments.scope === "Dimension" &&
          call.body.program.arguments.objectId === "Entity" &&
          call.body.program.arguments.attributeId === "Custom01" &&
          call.body.program.arguments.value === "" &&
          call.body.program.arguments.expectedMetadataRevision === 7,
      ),
    ).toBe(true),
  );
  expect(changed).toHaveBeenCalledOnce();
  await waitFor(() => expect(unsavedWorkSnapshot()).toEqual([]));
});

it("loads member objects under the exact dimension and revision", async () => {
  const bodies: Array<{
    program: { function: string; arguments: Record<string, unknown> };
  }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      bodies.push(body);
      return new Response(
        JSON.stringify({
          result: {
            rows: [{ member_id: "North", name: "North" }],
            nextAfterMemberId: null,
            metadataRevision: 7,
          },
        }),
      );
    }),
  );
  render(
    <AttributeValueEditor
      app={app}
      catalog={catalog}
      scope="Member"
      dimensionId="Entity"
      definitions={[definition]}
      dimensions={[]}
      definitionRevision={7}
      onChanged={async () => undefined}
    />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Attribute object")).toHaveValue("North"),
  );
  expect(bodies[0].program).toEqual({
    languageVersion: 2,
    function: "metadata.member.list",
    arguments: { dimension: "Entity", limit: 100 },
  });
});
