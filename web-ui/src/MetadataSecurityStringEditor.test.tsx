import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { MetadataSecurityStringEditor } from "./MetadataSecurityStringEditor";
import { operationAdmissionResponse } from "./test-setup";

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
      if (path === "/api/operation-admission")
        return operationAdmissionResponse("7");
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
      "I reviewed this exact dimension and canonical Security String.",
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

it("restores a member draft with fresh review required and retains the exact key after an uncertain write", async () => {
  const calls: Array<{ path: string; body: Record<string, any> }> = [];
  const memberCatalog = catalog([
    "security.application.member-tags.read",
    "metadata.member.security-string.set",
  ]);
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
      if (path === "/api/operation-admission")
        return operationAdmissionResponse("8");
      if (path === "/api/security")
        return new Response(
          JSON.stringify({
            result: {
              dimensionId: "Account",
              memberId: "Revenue",
              status: "Active",
              readTags: ["North"],
              writeTags: ["NorthWrite"],
              securityString: "read=North;write=NorthWrite",
              metadataRevision: 7,
              securityRevision: 3,
            },
          }),
        );
      if (
        calls.filter((call) => call.path === "/api/metadata-action").length ===
        1
      )
        throw new Error("Response interrupted");
      return new Response(
        JSON.stringify({ result: { receiptId: "same-receipt" } }),
      );
    }),
  );
  const props = {
    app,
    catalog: memberCatalog,
    targetKind: "Member" as const,
    targetId: "Revenue",
    dimensionId: "Account",
    onChanged: async () => undefined,
  };
  const first = render(<MetadataSecurityStringEditor {...props} />);
  fireEvent.click(screen.getByRole("button", { name: "Edit Security String" }));
  const input = await screen.findByLabelText("Member Security String");
  fireEvent.change(input, { target: { value: "read=North;write=" } });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact member and canonical Security String.",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Compile and save Security String" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Response interrupted",
  );
  first.unmount();

  render(<MetadataSecurityStringEditor {...props} />);
  await waitFor(() =>
    expect(screen.getByLabelText("Member Security String")).toHaveValue(
      "read=North;write=",
    ),
  );
  const review = screen.getByLabelText(
    "I reviewed this exact member and canonical Security String.",
  );
  expect(review).not.toBeChecked();
  expect(review).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh current security" }),
  );
  await waitFor(() => expect(review).toBeEnabled());
  expect(screen.getByLabelText("Member Security String")).toHaveValue(
    "read=North;write=",
  );
  fireEvent.click(review);
  fireEvent.click(
    screen.getByRole("button", { name: "Compile and save Security String" }),
  );
  await waitFor(() =>
    expect(
      calls.filter((call) => call.path === "/api/metadata-action"),
    ).toHaveLength(2),
  );
  const writes = calls.filter((call) => call.path === "/api/metadata-action");
  expect(writes[1].body).toEqual(writes[0].body);
  expect(writes[1].body.program).toEqual({
    languageVersion: 2,
    function: "metadata.member.security-string.set",
    arguments: {
      dimensionId: "Account",
      memberId: "Revenue",
      securityString: "read=North;write=",
      expectedMetadataRevision: 7,
    },
  });
  expect(calls[0].body.program.arguments).toEqual({
    dimensionId: "Account",
    memberId: "Revenue",
  });
});

it("preserves typed security across changed revisions without silently rebasing its reviewed snapshot", async () => {
  let metadataRevision = 7;
  let securityRevision = 3;
  const securityCatalog = catalog([
    "security.application.dimension-metadata-tags.read",
    "metadata.dimension.security-string.set",
  ]);
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              dimensionId: "Entity",
              name: "Entity",
              status: "Active",
              readTags: ["North"],
              writeTags: ["NorthWrite"],
              securityString: "read=North;write=NorthWrite",
              metadataRevision,
              securityRevision,
            },
          }),
        ),
    ),
  );
  const props = {
    app,
    catalog: securityCatalog,
    targetKind: "Dimension" as const,
    targetId: "Entity",
    onChanged: async () => undefined,
  };
  const { rerender } = render(<MetadataSecurityStringEditor {...props} />);
  fireEvent.click(screen.getByRole("button", { name: "Edit Security String" }));
  fireEvent.change(await screen.findByLabelText("Dimension Security String"), {
    target: { value: "read=North;write=" },
  });
  const review = screen.getByLabelText(
    "I reviewed this exact dimension and canonical Security String.",
  );
  fireEvent.click(review);
  metadataRevision = 8;
  securityRevision = 4;
  rerender(
    <MetadataSecurityStringEditor
      {...props}
      catalog={{
        ...securityCatalog,
        revisions: {
          ...securityCatalog.revisions,
          metadata: metadataRevision,
          security: securityRevision,
        },
      }}
    />,
  );
  expect(screen.getByLabelText("Dimension Security String")).toHaveValue(
    "read=North;write=",
  );
  expect(review).not.toBeChecked();
  expect(review).toBeDisabled();
  expect(screen.queryByText(/metadata revision 7/)).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Compile and save Security String" }),
  ).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh current security" }),
  );
  await waitFor(() => expect(review).toBeEnabled());
  expect(screen.queryByText(/metadata revision 8/)).not.toBeInTheDocument();
  expect(screen.getByLabelText("Dimension Security String")).toHaveValue(
    "read=North;write=",
  );
  expect(review).not.toBeChecked();
});

it("rejects a security read for a different target and requires a member dimension", async () => {
  const memberCatalog = catalog([
    "security.application.member-tags.read",
    "metadata.member.security-string.set",
  ]);
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              dimensionId: "OtherDimension",
              memberId: "Revenue",
              status: "Active",
              readTags: [],
              writeTags: [],
              securityString: "read=;write=",
              metadataRevision: 7,
              securityRevision: 3,
            },
          }),
        ),
    ),
  );
  const props = {
    app,
    catalog: memberCatalog,
    targetKind: "Member" as const,
    targetId: "Revenue",
    onChanged: async () => undefined,
  };
  const { rerender } = render(<MetadataSecurityStringEditor {...props} />);
  expect(
    screen.queryByRole("button", { name: "Edit Security String" }),
  ).toBeNull();
  rerender(<MetadataSecurityStringEditor {...props} dimensionId="Account" />);
  fireEvent.click(screen.getByRole("button", { name: "Edit Security String" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "does not match the selected metadata object",
  );
  expect(screen.queryByLabelText("Member Security String")).toBeNull();
});
