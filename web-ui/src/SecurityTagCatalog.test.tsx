import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { operationAdmissionResponse } from "./test-setup";
import {
  SecurityTagCatalog,
  collectSecurityTags,
  securityTagListArguments,
  securityTagMutationBody,
  validSecurityTagId,
} from "./SecurityTagCatalog";

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
  applicationAccess: {
    role: "Administrator",
    workspaceAdministrator: false,
    issuer: "https://issuer.example",
    subjectId: "tag-admin",
  },
  enabledCapabilities: [],
  functions: {
    "metadata.security-tag.list": {},
    "metadata.security-tag.create": {},
    "metadata.security-tag.update": {},
    "metadata.security-tag.status.set": {},
    "application.operation.receipt.read": {},
  },
  revisions: { metadata: 6, data: 1, policy: 1, security: 1, commit: 6 },
};

it("preserves revision-pinned catalogue paging and governed mutation envelopes", () => {
  expect(securityTagListArguments("Entity")).toEqual({
    dimension: "Entity",
    limit: 100,
  });
  expect(securityTagListArguments("Entity", "North", 6)).toEqual({
    dimension: "Entity",
    limit: 100,
    afterTagId: "North",
    expectedMetadataRevision: 6,
  });
  expect(
    securityTagMutationBody(
      app,
      "metadata.security-tag.create",
      {
        dimensionId: "Entity",
        tagId: "NorthRead",
        displayName: "North read",
        shortDescription: "Read scope",
        semanticDescription: "Allows northern entity reads",
        expectedMetadataRevision: 6,
      },
      "tag-create-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "tag-create-1",
    program: {
      languageVersion: 2,
      function: "metadata.security-tag.create",
      arguments: {
        dimensionId: "Entity",
        tagId: "NorthRead",
        displayName: "North read",
        shortDescription: "Read scope",
        semanticDescription: "Allows northern entity reads",
        expectedMetadataRevision: 6,
      },
    },
  });
});

it("validates only the fixed tag ID envelope and leaves semantics to the core", () => {
  expect(validSecurityTagId("NorthRead")).toBe(true);
  expect(validSecurityTagId(" NorthRead")).toBe(false);
  expect(validSecurityTagId("North;Read")).toBe(false);
  expect(validSecurityTagId("x".repeat(21))).toBe(false);
});

it("reads the complete Security Tag catalogue beyond the former cap", async () => {
  let page = 0;
  const result = await collectSecurityTags("Entity", async (arguments_) => {
    expect(arguments_).toEqual(
      page === 0
        ? { dimension: "Entity", limit: 100 }
        : {
            dimension: "Entity",
            limit: 100,
            afterTagId: `cursor-${page}`,
            expectedMetadataRevision: 6,
          },
    );
    const current = page++;
    return {
      rows: Array.from({ length: 100 }, (_unused, row) => ({
        dimension_id: "Entity",
        tag_id: `${current}-${row}`,
        display_name: "Tag",
        short_description: "",
        semantic_description: "",
        status: "Active" as const,
      })),
      nextAfterTagId: current === 100 ? null : `cursor-${current + 1}`,
      metadataRevision: 6,
    };
  });
  expect(result.rows).toHaveLength(10100);
  expect(page).toBe(101);
});

it("rejects malformed and repeated Security Tag continuations", async () => {
  await expect(
    collectSecurityTags("Entity", async () => ({
      rows: [],
      nextAfterTagId: "" as never,
      metadataRevision: 6,
    })),
  ).rejects.toThrow("cursor is invalid");
  let page = 0;
  await expect(
    collectSecurityTags("Entity", async () => ({
      rows: [],
      nextAfterTagId: page++ < 1 ? "same" : "same",
      metadataRevision: 6,
    })),
  ).rejects.toThrow("cursor repeated");
});

it("renders the authoritative catalogue as an editable grid", async () => {
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
            rows: [
              {
                dimension_id: "Entity",
                tag_id: "NorthRead",
                display_name: "North read",
                short_description: "Read scope",
                semantic_description: "Allows northern entity reads",
                status: "Active",
              },
            ],
            nextAfterTagId: null,
            metadataRevision: 6,
          },
        }),
      );
    }),
  );
  render(
    <SecurityTagCatalog
      app={app}
      catalog={catalog}
      dimensionId="Entity"
      metadataRevision={6}
      onChanged={async () => undefined}
    />,
  );
  await waitFor(() =>
    expect(screen.getByText("NorthRead")).toBeInTheDocument(),
  );
  expect(screen.getByLabelText("NorthRead display name")).toHaveValue(
    "North read",
  );
  expect(screen.getByText("1 current rows")).toBeInTheDocument();
  expect(calls).toEqual([
    expect.objectContaining({
      program: {
        languageVersion: 2,
        function: "metadata.security-tag.list",
        arguments: { dimension: "Entity", limit: 100 },
      },
    }),
  ]);
});

it("invalidates create review whenever the exact row changes", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              rows: [],
              nextAfterTagId: null,
              metadataRevision: 6,
            },
          }),
        ),
    ),
  );
  render(
    <SecurityTagCatalog
      app={app}
      catalog={catalog}
      dimensionId="Entity"
      metadataRevision={6}
      onChanged={async () => undefined}
    />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText("New Security Tag stable ID")).toBeEnabled(),
  );
  fireEvent.change(screen.getByLabelText("New Security Tag stable ID"), {
    target: { value: "NorthRead" },
  });
  fireEvent.change(screen.getByLabelText("New Security Tag display name"), {
    target: { value: "North read" },
  });
  const review = screen.getByLabelText("Review");
  fireEvent.click(review);
  expect(review).toBeChecked();
  expect(screen.getByRole("button", { name: "Create" })).toBeEnabled();
  fireEvent.change(screen.getByLabelText("New Security Tag display name"), {
    target: { value: "Northern read" },
  });
  expect(review).not.toBeChecked();
  expect(screen.getByRole("button", { name: "Create" })).toBeDisabled();
});

it("keeps a tag active and explains a definite dependency refusal", async () => {
  const onChanged = vi.fn(async () => undefined);
  const paths: string[] = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      paths.push(path);
      if (path === "/api/operation-admission")
        return operationAdmissionResponse("a");
      if (path === "/api/metadata-action")
        return Response.json(
          {
            code: "SECURITY_TAG_IN_USE",
            message:
              "This tag is still assigned to a dimension, member, relationship, or access grant. Review those assignments before inactivating it.",
            retryable: false,
          },
          { status: 409 },
        );
      return Response.json({
        result: {
          rows: [
            {
              dimension_id: "Entity",
              tag_id: "NorthRead",
              display_name: "North read",
              short_description: "",
              semantic_description: "",
              status: "Active",
            },
          ],
          nextAfterTagId: null,
          metadataRevision: 6,
        },
      });
    }),
  );
  render(
    <SecurityTagCatalog
      app={app}
      catalog={catalog}
      dimensionId="Entity"
      metadataRevision={6}
      onChanged={onChanged}
    />,
  );
  fireEvent.click(await screen.findByRole("button", { name: "Inactivate" }));
  fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "This tag is still assigned to a dimension, member, relationship, or access grant.",
  );
  expect(
    screen.getByText("Active", { exact: true, selector: ".status-chip" }),
  ).toBeVisible();
  expect(
    screen.queryByText("The reviewed security-tag change was applied."),
  ).toBeNull();
  expect(onChanged).not.toHaveBeenCalled();
  expect(paths).toEqual([
    "/api/read",
    "/api/operation-admission",
    "/api/metadata-action",
  ]);
  expect(
    screen.queryByRole("button", {
      name: "Check original security tag receipt",
    }),
  ).toBeNull();
});

it("checks a lost acknowledgement in its original dimension and preserves another draft", async () => {
  const onChanged = vi.fn(async () => undefined);
  const clipboard = vi
    .fn<(value: string) => Promise<void>>()
    .mockResolvedValue(undefined);
  vi.stubGlobal("navigator", { clipboard: { writeText: clipboard } });
  const writes: unknown[] = [];
  const reads: Array<{
    workspaceId: string;
    applicationId: string;
    program: unknown;
  }> = [];
  let admissions = 0;
  let revision = 6;
  let operationId = "";
  let withholdCurrentCatalogue = false;
  vi.stubGlobal("confirm", () => true);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/operation-admission") {
        admissions++;
        return operationAdmissionResponse("b");
      }
      if (String(input) === "/api/metadata-action") {
        operationId = body.idempotencyKey;
        writes.push(body);
        revision = 7;
        throw new TypeError("The write acknowledgement was lost");
      }
      if (body.program.function === "application.operation.receipt.read") {
        reads.push(body);
        return Response.json({
          result: {
            operationId: body.program.arguments.operationId,
            actorId: catalog.applicationAccess.subjectId,
            commandDigest: "a".repeat(64),
            committedRevision: revision,
            committedAt: "2026-11-21T12:00:00Z",
            outcome: { changedCount: 1 },
          },
        });
      }
      const dimension = body.program.arguments.dimension;
      const originalCatalogue =
        body.applicationId === "app" && dimension === "Entity";
      return Response.json({
        result: {
          rows: originalCatalogue
            ? ["North", "South"].map((name) => ({
                dimension_id: dimension,
                tag_id: name,
                display_name:
                  name === "North" && revision === 7
                    ? "Northern entities"
                    : name,
                short_description: "",
                semantic_description: "",
                status: "Active",
              }))
            : [],
          nextAfterTagId: null,
          metadataRevision: withholdCurrentCatalogue ? 6 : revision,
        },
      });
    }),
  );
  const props = { app, catalog, metadataRevision: 6, onChanged };
  const { rerender } = render(
    <SecurityTagCatalog {...props} dimensionId="Entity" />,
  );
  const north = await screen.findByLabelText("North display name");
  fireEvent.change(screen.getByLabelText("South short description"), {
    target: { value: "Unsaved southern scope" },
  });
  fireEvent.change(north, { target: { value: "Northern entities" } });
  const row = within(north.closest("tr")!);
  fireEvent.click(row.getByLabelText("Review edit"));
  fireEvent.click(row.getByRole("button", { name: "Save" }));
  const pending = await screen.findByRole("region", {
    name: "Security tag change status",
  });
  const check = within(pending).getByRole("button", {
    name: "Check original security tag receipt",
  });
  await waitFor(() => expect(check).toBeEnabled());
  expect(within(pending).getByRole("heading")).toHaveFocus();
  expect(row.getByRole("button", { name: "Save" })).toBeDisabled();
  expect(screen.getByLabelText("New Security Tag stable ID")).toBeDisabled();
  expect(onChanged).not.toHaveBeenCalled();

  rerender(<SecurityTagCatalog {...props} dimensionId="Account" />);
  await waitFor(() =>
    expect(screen.getByLabelText("New Security Tag stable ID")).toBeEnabled(),
  );
  expect(
    screen.queryByRole("region", { name: "Security tag change status" }),
  ).toBeNull();
  expect(screen.queryByLabelText("North display name")).toBeNull();
  rerender(
    <SecurityTagCatalog
      {...props}
      app={{ ...app, applicationId: "sibling" }}
      dimensionId="Entity"
    />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText("New Security Tag stable ID")).toBeEnabled(),
  );
  expect(
    screen.queryByRole("region", { name: "Security tag change status" }),
  ).toBeNull();
  expect(screen.queryByLabelText("South short description")).toBeNull();
  const otherActor = {
    ...catalog,
    applicationAccess: {
      ...catalog.applicationAccess,
      subjectId: "other-admin",
    },
  };
  rerender(
    <SecurityTagCatalog {...props} catalog={otherActor} dimensionId="Entity" />,
  );
  expect(await screen.findByLabelText("South short description")).toHaveValue(
    "",
  );
  expect(
    screen.queryByRole("region", { name: "Security tag change status" }),
  ).toBeNull();
  rerender(<SecurityTagCatalog {...props} dimensionId="Entity" />);
  const restoredCheck = await screen.findByRole("button", {
    name: "Check original security tag receipt",
  });
  await waitFor(() => expect(restoredCheck).toBeEnabled());
  const receiptProgram = {
    languageVersion: 2,
    function: "application.operation.receipt.read",
    arguments: { operationId },
  };
  fireEvent.click(
    screen.getByRole("button", { name: "Copy receipt check for MCP" }),
  );
  expect(
    await screen.findByText("Receipt check copied for your MCP client."),
  ).toBeVisible();
  expect(JSON.parse(clipboard.mock.calls[0]![0])).toEqual({
    workspace_id: "ws",
    application_id: "app",
    program: receiptProgram,
  });
  withholdCurrentCatalogue = true;
  fireEvent.click(restoredCheck);
  const confirmed = await screen.findByText(
    "The original Security Tag change was recorded.",
  );
  expect(confirmed).toHaveFocus();
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Read the current Security Tag catalogue before editing.",
  );
  expect(
    screen
      .getAllByRole("button", { name: "Inactivate" })
      .every((button) => (button as HTMLButtonElement).disabled),
  ).toBe(true);
  withholdCurrentCatalogue = false;
  fireEvent.click(
    screen.getByRole("button", { name: "Read current Security Tags" }),
  );
  await waitFor(() =>
    expect(screen.getByLabelText("South short description")).toBeEnabled(),
  );
  expect(screen.getByLabelText("South short description")).toHaveValue(
    "Unsaved southern scope",
  );
  expect(screen.getByLabelText("North display name")).toHaveValue(
    "Northern entities",
  );
  expect(screen.getAllByLabelText("Review edit")).toHaveLength(1);
  expect(reads).toEqual([
    { workspaceId: "ws", applicationId: "app", program: receiptProgram },
  ]);
  expect(writes).toHaveLength(1);
  expect(admissions).toBe(1);
  expect(onChanged).toHaveBeenCalledOnce();
});

it("retries only the admitted Security Tag packet after an exact missing receipt", async () => {
  const writes: Array<{
    program: { function: string };
    idempotencyKey: string;
  }> = [];
  let admissions = 0;
  let receiptChecks = 0;
  let revision = 6;
  vi.stubGlobal("confirm", () => true);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/operation-admission") {
        admissions++;
        return operationAdmissionResponse("c");
      }
      if (String(input) === "/api/metadata-action") {
        writes.push(body);
        if (writes.length === 1) throw new TypeError("Reply unavailable");
        revision = 7;
        return Response.json({
          languageVersion: 2,
          function: body.program.function,
          result: {
            operationId: body.idempotencyKey,
            changedCount: 1,
            committedRevision: revision,
          },
        });
      }
      if (body.program.function === "application.operation.receipt.read") {
        receiptChecks++;
        return Response.json(
          {
            code:
              receiptChecks === 1
                ? "APPLICATION_GRANT_REQUIRED"
                : "OPERATION_RECEIPT_NOT_FOUND",
          },
          { status: receiptChecks === 1 ? 403 : 400 },
        );
      }
      return Response.json({
        result: { rows: [], nextAfterTagId: null, metadataRevision: revision },
      });
    }),
  );
  render(
    <SecurityTagCatalog
      app={app}
      catalog={catalog}
      dimensionId="Entity"
      metadataRevision={6}
      onChanged={async () => undefined}
    />,
  );
  const id = screen.getByLabelText("New Security Tag stable ID");
  await waitFor(() => expect(id).toBeEnabled());
  fireEvent.change(id, { target: { value: "NorthRead" } });
  fireEvent.change(screen.getByLabelText("New Security Tag display name"), {
    target: { value: "North" },
  });
  fireEvent.click(screen.getByLabelText("Review"));
  fireEvent.click(screen.getByRole("button", { name: "Create" }));
  const check = await screen.findByRole("button", {
    name: "Check original security tag receipt",
  });
  await waitFor(() => expect(check).toBeEnabled());
  fireEvent.click(check);
  expect(
    await screen.findByText(
      "The receipt check could not confirm the original security tag change.",
    ),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", {
      name: "Retry original security tag change",
    }),
  ).toBeNull();
  expect(id).toBeDisabled();
  fireEvent.click(check);
  const retry = await screen.findByRole("button", {
    name: "Retry original security tag change",
  });
  await waitFor(() => expect(retry).toBeEnabled());
  fireEvent.click(retry);
  expect(
    await screen.findByText("The reviewed security-tag change was applied."),
  ).toBeVisible();
  await waitFor(() => expect(id).toBeEnabled());
  expect(id).toHaveValue("");
  expect(writes).toHaveLength(2);
  expect(writes[1]).toEqual(writes[0]);
  expect(admissions).toBe(1);
});
