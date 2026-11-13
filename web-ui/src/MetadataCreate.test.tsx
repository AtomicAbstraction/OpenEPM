import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  MetadataCreate,
  metadataCreateBody,
  validMetadataText,
} from "./MetadataCreate";
import { operationAdmissionResponse } from "./test-setup";

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

it("validates bounded trimmed metadata identities", () => {
  expect(validMetadataText("Department")).toBe(true);
  expect(validMetadataText(" Department")).toBe(false);
  expect(validMetadataText("A\u0000B")).toBe(false);
  expect(validMetadataText("x".repeat(201))).toBe(false);
});

it("preserves the governed metadata-create envelope", () => {
  expect(
    metadataCreateBody(
      app,
      "member",
      {
        dimensionId: "Account",
        memberId: "GrossProfit",
        name: "Gross Profit",
        expectedMetadataRevision: 46,
      },
      "metadata-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "metadata-1",
    program: {
      languageVersion: 2,
      function: "metadata.member.create",
      arguments: {
        dimensionId: "Account",
        memberId: "GrossProfit",
        name: "Gross Profit",
        expectedMetadataRevision: 46,
      },
    },
  });
});

it("invalidates review when the proposed dimension changes", () => {
  render(
    <MetadataCreate
      app={app}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        functions: { "metadata.dimension.create": {} },
        revisions: {
          metadata: 46,
          data: 1,
          policy: 1,
          security: 1,
          commit: 1,
        },
      }}
      dimensions={[
        {
          dimension_id: "Account",
          name: "Account",
          model_role: "Account",
          status: "Active",
        },
      ]}
      metadataRevision={46}
      onCreated={async () => undefined}
    />,
  );
  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "Department" } });
  fireEvent.change(inputs[1], { target: { value: "Department" } });
  const review = screen.getByLabelText(
    "I reviewed this exact dimension against the current model.",
  );
  fireEvent.click(review);
  expect(
    screen.getByRole("button", { name: "Create dimension" }),
  ).toBeEnabled();
  fireEvent.change(inputs[1], { target: { value: "Cost center" } });
  expect(review).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Create dimension" }),
  ).toBeDisabled();
});

it("reuses the reviewed metadata intent key after an uncertain response", async () => {
  let uuid = 0;
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: { randomUUID: () => `metadata-intent-${++uuid}` },
  });
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  const keys: string[] = [];
  let attempts = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/api/operation-admission")
        return operationAdmissionResponse("2");
      const body = JSON.parse(String(init?.body));
      keys.push(body.idempotencyKey);
      attempts += 1;
      if (attempts === 1)
        return new Response(JSON.stringify({ error: "OUTCOME_UNCERTAIN" }), {
          status: 409,
        });
      return new Response(
        JSON.stringify({ result: { receiptId: "receipt-1" } }),
      );
    }),
  );
  render(
    <MetadataCreate
      app={app}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        functions: { "metadata.dimension.create": {} },
        revisions: {
          metadata: 46,
          data: 1,
          policy: 1,
          security: 1,
          commit: 1,
        },
      }}
      dimensions={[
        {
          dimension_id: "Account",
          name: "Account",
          model_role: "Account",
          status: "Active",
        },
      ]}
      metadataRevision={46}
      onCreated={async () => undefined}
    />,
  );
  const inputs = screen.getAllByRole("textbox");
  fireEvent.change(inputs[0], { target: { value: "Department" } });
  fireEvent.change(inputs[1], { target: { value: "Department" } });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact dimension against the current model.",
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Create dimension" }));
  await screen.findByText("OUTCOME_UNCERTAIN");
  fireEvent.click(screen.getByRole("button", { name: "Create dimension" }));
  await screen.findByText("The reviewed dimension was created.");
  expect(keys).toHaveLength(2);
  expect(keys[1]).toBe(keys[0]);
});

it("constrains a new member to the workspace dimension and preserves its exact request", async () => {
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  const fetch = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) =>
    String(input) === "/api/operation-admission"
      ? operationAdmissionResponse("3")
      : new Response(
          JSON.stringify({ result: { receiptId: "member-created" } }),
        ),
  );
  vi.stubGlobal("fetch", fetch);
  const dimensions = ["Account", "Entity"].map((id) => ({
    dimension_id: id,
    name: id,
    model_role: id,
    status: "Active",
  }));
  render(
    <MetadataCreate
      app={app}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        functions: { "metadata.member.create": {} },
        revisions: { metadata: 46, data: 1, policy: 1, security: 1, commit: 1 },
      }}
      dimensions={dimensions}
      metadataRevision={46}
      onCreated={async () => undefined}
      mode="member"
      dimensionId="Entity"
    />,
  );
  expect(screen.getByLabelText("Parent dimension")).toHaveValue("Entity");
  expect(screen.getByLabelText("Parent dimension")).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Member stable ID"), {
    target: { value: "Europe" },
  });
  fireEvent.change(screen.getByLabelText("Member name"), {
    target: { value: "Europe" },
  });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact member against the current model.",
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Create member" }));
  await screen.findByText("The reviewed member was created.");
  expect(
    JSON.parse(String(fetch.mock.calls[1]?.[1]?.body)).program.arguments
      .dimensionId,
  ).toBe("Entity");
});

it("restores creation values without rebasing a reviewed draft onto newer metadata", async () => {
  const props = {
    app,
    catalog: {
      applicationAccess: {
        role: "Administrator",
        workspaceAdministrator: false,
      },
      enabledCapabilities: [],
      functions: { "metadata.dimension.create": {} },
      revisions: { metadata: 46, data: 1, policy: 1, security: 1, commit: 1 },
    },
    dimensions: [
      {
        dimension_id: "Account",
        name: "Account",
        model_role: "Account",
        status: "Active",
      },
    ],
    onCreated: async () => undefined,
    mode: "dimension" as const,
  };
  const view = render(<MetadataCreate {...props} metadataRevision={46} />);
  fireEvent.change(screen.getByLabelText("Dimension stable ID"), {
    target: { value: "Product" },
  });
  fireEvent.change(screen.getByLabelText("Dimension name"), {
    target: { value: "Product" },
  });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact dimension against the current model.",
    ),
  );
  view.unmount();
  render(<MetadataCreate {...props} metadataRevision={47} />);
  await waitFor(() =>
    expect(screen.getByLabelText("Dimension name")).toHaveValue("Product"),
  );
  expect(
    screen.getByLabelText(
      "I reviewed this exact dimension against the current model.",
    ),
  ).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Create dimension" }),
  ).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Review against current metadata" }),
  );
  expect(
    screen.getByLabelText(
      "I reviewed this exact dimension against the current model.",
    ),
  ).toBeEnabled();
  expect(
    screen.getByRole("button", { name: "Create dimension" }),
  ).toBeDisabled();
});
