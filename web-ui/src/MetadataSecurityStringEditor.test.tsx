import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { MetadataSecurityStringEditor } from "./MetadataSecurityStringEditor";

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

function catalog(functions: string[]) {
  return {
    applicationAccess: {
      role: "Administrator" as const,
      workspaceAdministrator: false,
    },
    enabledCapabilities: [],
    functions: Object.fromEntries(functions.map((name) => [name, {}])),
    revisions: { metadata: 7, data: 1, policy: 1, security: 3, commit: 7 },
  };
}

it("reads and writes a dimension Security String through governed contracts", async () => {
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
      if (path === "/api/security")
        return new Response(
          JSON.stringify({
            result: {
              dimensionId: "Entity",
              name: "Entity",
              status: "Active",
              readTags: ["North"],
              writeTags: ["NorthWrite"],
              securityString: "read=North;write=NorthWrite",
              metadataRevision: 7,
              securityRevision: 3,
            },
          }),
        );
      return new Response(JSON.stringify({ result: { receiptId: "r-1" } }));
    }),
  );
  const changed = vi.fn(async () => undefined);
  render(
    <MetadataSecurityStringEditor
      app={app}
      catalog={catalog([
        "security.application.dimension-metadata-tags.read",
        "metadata.dimension.security-string.set",
      ])}
      targetKind="Dimension"
      targetId="Entity"
      onChanged={changed}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Edit Security String" }));
  const input = await screen.findByLabelText("Dimension Security String");
  expect(input).toHaveValue("read=North;write=NorthWrite");
  expect(calls[0]).toEqual({
    path: "/api/security",
    body: {
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "security.application.dimension-metadata-tags.read",
        arguments: { dimensionId: "Entity" },
      },
    },
  });
  fireEvent.change(input, { target: { value: "read=North;write=" } });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact dimension, metadata revision and canonical Security String.",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Compile and save Security String" }),
  );
  await waitFor(() =>
    expect(
      calls.some(
        (call) =>
          call.path === "/api/metadata-action" &&
          call.body.program.function ===
            "metadata.dimension.security-string.set" &&
          call.body.program.arguments.securityString === "read=North;write=" &&
          call.body.program.arguments.expectedMetadataRevision === 7,
      ),
    ).toBe(true),
  );
  expect(changed).toHaveBeenCalledOnce();
});

it("uses the relationship identity and hides itself without read authority", async () => {
  const { rerender } = render(
    <MetadataSecurityStringEditor
      app={app}
      catalog={catalog([])}
      targetKind="Relationship"
      targetId="edge-1"
      onChanged={async () => undefined}
    />,
  );
  expect(screen.queryByText("Relationship Security String")).toBeNull();
  rerender(
    <MetadataSecurityStringEditor
      app={app}
      catalog={catalog(["security.application.relationship-tags.read"])}
      targetKind="Relationship"
      targetId="edge-1"
      onChanged={async () => undefined}
    />,
  );
  expect(screen.getByText("Relationship Security String")).toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Compile and save Security String" }),
  ).toBeNull();
});
