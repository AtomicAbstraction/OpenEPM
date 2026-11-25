import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ComponentProps } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { useLayoutReplacementRequest } from "./LayoutReplacementRequest";
import { MetadataDimensionCreateRows } from "./MetadataDimensionCreateRows";
import { operationAdmissionResponse } from "./test-setup";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function DimensionCreateFixture(
  props: Omit<
    ComponentProps<typeof MetadataDimensionCreateRows>,
    "replacement"
  >,
) {
  const replacement = useLayoutReplacementRequest(props.app, props.catalog);
  return <MetadataDimensionCreateRows {...props} replacement={replacement} />;
}

it("creates one reviewed dimension from the inline grid row", async () => {
  const writes: Array<Record<string, any>> = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url) === "/api/operation-admission")
        return operationAdmissionResponse("dimension-create");
      writes.push(JSON.parse(String(init?.body)) as Record<string, any>);
      return new Response(JSON.stringify({ result: { operationId: "op-1" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
  const closed = vi.fn();
  const changed = vi.fn(async () => undefined);
  render(
    <table>
      <tbody>
        <DimensionCreateFixture
          app={{
            workspaceId: "ws",
            applicationId: "app",
            name: "Plan",
            status: "Active",
          }}
          catalog={{
            applicationAccess: {
              role: "Administrator",
              workspaceAdministrator: false,
            },
            enabledCapabilities: [],
            functions: { "metadata.dimension.create": {} },
            revisions: {
              metadata: 7,
              data: 1,
              policy: 1,
              security: 1,
              commit: 1,
            },
          }}
          dimensions={[{ dimension_id: "Account", name: "Accounts" }]}
          metadataRevision={7}
          open
          onClose={closed}
          onCreated={changed}
        />
      </tbody>
    </table>,
  );

  fireEvent.change(screen.getByLabelText("New dimension stable ID"), {
    target: { value: "Product" },
  });
  fireEvent.change(screen.getByLabelText("New dimension name"), {
    target: { value: "Products" },
  });
  fireEvent.change(screen.getByLabelText("New dimension model role"), {
    target: { value: "Custom" },
  });
  fireEvent.click(screen.getByLabelText("Review new dimension"));
  fireEvent.click(screen.getByRole("button", { name: "Create dimension" }));

  await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
  expect(closed).toHaveBeenCalledTimes(1);
  expect(writes).toHaveLength(1);
  expect(writes[0].program).toEqual({
    languageVersion: 2,
    function: "metadata.dimension.create",
    arguments: {
      dimensionId: "Product",
      name: "Products",
      modelRole: "Custom",
      shortDescription: "",
      detailedDescription: "",
      expectedMetadataRevision: 7,
    },
  });
  expect(writes[0].confirmed).toBe(true);
});
