import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  MemberLists,
  collectMemberLists,
  memberListArguments,
  memberListMutationBody,
  parseMemberListJson,
} from "./MemberLists";
import { resetUnsavedWorkForTests, unsavedWorkSnapshot } from "./unsaved-work";

const app = {
  workspaceId: "ws",
  applicationId: "cube",
  name: "Cube",
  status: "Active",
};

const catalog = {
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "metadata.member_list.version.save": {},
    "metadata.member_list.version.list": {},
    "metadata.member_list.publish": {},
    "metadata.member_list.deactivate": {},
    "metadata.member_list.evaluate": {},
  },
  revisions: { metadata: 7, data: 1, policy: 3, security: 1, commit: 4 },
};

afterEach(() => {
  resetUnsavedWorkForTests();
  vi.unstubAllGlobals();
});

it("reads every member list beyond the former catalogue cap", async () => {
  expect(memberListArguments("list-a", 7, 3)).toEqual({
    limit: 100,
    afterListId: "list-a",
    expectedMetadataRevision: 7,
    expectedPolicyRevision: 3,
  });
  let page = 0;
  const result = await collectMemberLists(async (arguments_) => {
    const current = page++;
    if (current) {
      expect(arguments_.expectedMetadataRevision).toBe(7);
      expect(arguments_.expectedPolicyRevision).toBe(3);
    }
    return {
      memberLists: Array.from({ length: 100 }, (_unused, row) => ({
        listId: `list-${current}-${row}`,
        version: 1,
        dimensionId: "Product",
        name: "List",
        definition: {},
        canonicalDigest: "a".repeat(64),
        status: "Saved" as const,
        stateRevision: 1,
      })),
      nextAfterListId: current === 10 ? null : `cursor-${current + 1}`,
      metadataRevision: 7,
      policyRevision: 3,
    };
  });
  expect(result.rows).toHaveLength(1100);
});

it("rejects malformed, repeated, duplicate, and drifting member-list pages", async () => {
  await expect(
    collectMemberLists(async () => ({
      memberLists: [],
      nextAfterListId: "" as never,
      metadataRevision: 7,
      policyRevision: 3,
    })),
  ).rejects.toThrow("cursor is invalid");
  let page = 0;
  await expect(
    collectMemberLists(async () => ({
      memberLists: [],
      nextAfterListId: page++ < 1 ? "same" : "same",
      metadataRevision: 7,
      policyRevision: 3,
    })),
  ).rejects.toThrow("cursor repeated");
  let duplicatePage = 0;
  await expect(
    collectMemberLists(async () => ({
      memberLists: [
        {
          listId: "same",
          version: 1,
          dimensionId: "Product",
          name: "List",
          definition: {},
          canonicalDigest: "a".repeat(64),
          status: "Saved",
          stateRevision: 1,
        },
      ],
      nextAfterListId: duplicatePage++ < 1 ? "more" : null,
      metadataRevision: 7,
      policyRevision: 3,
    })),
  ).rejects.toThrow("repeated a row");
  let revisionPage = 0;
  await expect(
    collectMemberLists(async () => ({
      memberLists: [],
      nextAfterListId: revisionPage++ < 1 ? "more" : null,
      metadataRevision: revisionPage === 1 ? 7 : 8,
      policyRevision: 3,
    })),
  ).rejects.toThrow("changed while reading");
});

it("constructs only the existing confirmed metadata-action envelope", () => {
  expect(
    memberListMutationBody(
      app,
      "metadata.member_list.publish",
      { listId: "active", version: 2 },
      "member-list-123",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "cube",
    program: {
      languageVersion: 2,
      function: "metadata.member_list.publish",
      arguments: { listId: "active", version: 2 },
    },
    idempotencyKey: "member-list-123",
    confirmed: true,
  });
});

it("rejects malformed JSON before any governed request", () => {
  expect(() => parseMemberListJson("[]", "Expression", "object")).toThrow(
    "Expression must be a JSON object.",
  );
  expect(() => parseMemberListJson("{}", "Parameters", "array")).toThrow(
    "Parameters must be a JSON array.",
  );
});

it("reads and evaluates an immutable member list through existing V2 reads", async () => {
  const functions: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      functions.push(body.program.function);
      if (body.program.function === "metadata.member_list.version.list")
        return new Response(
          JSON.stringify({
            result: {
              memberLists: [
                {
                  listId: "active-products",
                  version: 2,
                  dimensionId: "Product",
                  name: "Active products",
                  definition: {
                    parameters: [],
                    expression: { kind: "explicit", memberIds: ["A", "B"] },
                  },
                  canonicalDigest: "a".repeat(64),
                  status: "Published",
                  stateRevision: 4,
                },
              ],
              nextAfterListId: null,
              metadataRevision: 7,
              policyRevision: 3,
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            listId: "active-products",
            version: 2,
            dimensionId: "Product",
            memberIds: ["A", "B"],
            memberCount: 2,
            canonicalDigest: "a".repeat(64),
            metadataRevision: 7,
            stateRevision: 4,
            status: "Published",
          },
        }),
      );
    }),
  );
  render(<MemberLists app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read member lists" }));
  await screen.findByRole("option", { name: /Active products/ });
  fireEvent.change(screen.getByLabelText("Existing member list"), {
    target: { value: "active-products" },
  });
  fireEvent.click(screen.getByRole("button", { name: /Evaluate against/ }));
  await screen.findByText("2 members");
  expect(screen.getByText("A, B")).toBeInTheDocument();
  expect(functions).toEqual([
    "metadata.member_list.version.list",
    "metadata.member_list.evaluate",
  ]);
});

it("saves reviewed JSON without evaluating it in the browser", async () => {
  const bodies: unknown[] = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal("crypto", { randomUUID: () => "member-list-request-1" });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      bodies.push(body);
      if (String(input) === "/api/metadata-action")
        return new Response(
          JSON.stringify({
            result: {
              listId: "active-products",
              version: 1,
              status: "Saved",
              canonicalDigest: "b".repeat(64),
              metadataRevision: 7,
              policyRevision: 3,
              committedRevision: 5,
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            memberLists: [],
            nextAfterListId: null,
            metadataRevision: 7,
            policyRevision: 3,
          },
        }),
      );
    }),
  );
  render(<MemberLists app={app} catalog={catalog} />);
  fireEvent.change(screen.getByLabelText("List ID"), {
    target: { value: "active-products" },
  });
  fireEvent.change(screen.getByLabelText("Dimension ID"), {
    target: { value: "Product" },
  });
  fireEvent.change(screen.getByLabelText("Name"), {
    target: { value: "Active products" },
  });
  fireEvent.change(screen.getByLabelText("Member-list expression"), {
    target: { value: '{"kind":"explicit","memberIds":["A","B"]}' },
  });
  expect(unsavedWorkSnapshot()).toEqual([
    expect.objectContaining({ label: "Unsaved member-list definition" }),
  ]);
  fireEvent.click(screen.getByLabelText(/I reviewed the exact definition/));
  fireEvent.click(
    screen.getByRole("button", { name: "Save immutable version" }),
  );
  await waitFor(() =>
    expect(
      screen.getByText("active-products v1 is Saved."),
    ).toBeInTheDocument(),
  );
  expect(bodies[0]).toEqual(
    expect.objectContaining({
      idempotencyKey: "member-list-ui-member-list-request-1",
      confirmed: true,
      program: {
        languageVersion: 2,
        function: "metadata.member_list.version.save",
        arguments: {
          definition: {
            format: "openepm-member-list-v1",
            listId: "active-products",
            version: 1,
            dimensionId: "Product",
            name: "Active products",
            parameters: [],
            expression: { kind: "explicit", memberIds: ["A", "B"] },
          },
          expectedMetadataRevision: 7,
          expectedPolicyRevision: 3,
        },
      },
    }),
  );
  await waitFor(() => expect(unsavedWorkSnapshot()).toEqual([]));
});
