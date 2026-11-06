import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
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
  applicationAccess: { role: "Administrator", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "metadata.security-tag.list": {},
    "metadata.security-tag.create": {},
    "metadata.security-tag.update": {},
    "metadata.security-tag.status.set": {},
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
  expect(screen.getByText("1 rows · revision 6")).toBeInTheDocument();
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
    expect(screen.getByText("0 rows · revision 6")).toBeInTheDocument(),
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
