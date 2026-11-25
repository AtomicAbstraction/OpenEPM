import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { CoordinateAccessExplanation } from "./CoordinateAccessExplanation";
import {
  ResourceAccessRoster,
  SavedViewAccessReview,
  resourceAccess,
} from "./ResourceAccessRoster";

const app = {
  workspaceId: "ops",
  applicationId: "capacity",
  name: "Capacity",
  status: "Active",
};
const resource = { action: "facts.read", coordinate: { Period: "Q1" } };
const source = {
  assignmentId: "plan-north",
  assignmentRevision: 2,
  groupId: "g-north",
  roleId: "planner",
  roleRevision: 1,
  scopeId: "north",
  scopeRevision: 3,
  action: "facts.read",
};
function page(extra: Record<string, unknown> = {}) {
  return {
    ...resource,
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    collection: "people",
    coverage: "complete_in_application",
    coverageReasons: [],
    businessState: "not_applicable",
    asOf: "2026-11-25T10:00:00Z",
    nextCursor: null,
    people: [],
    groups: [],
    origins: [],
    ...extra,
  };
}
function mockService(
  read: (fn: string, args: Record<string, unknown>) => unknown,
) {
  const fetch = vi.fn(async (_url: string, init: RequestInit) => {
    const { program } = JSON.parse(String(init.body));
    const result = read(program.function, program.arguments);
    return new Response(JSON.stringify({ result }), {
      headers: { "Content-Type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}
afterEach(() => vi.unstubAllGlobals());

it.each(["locked", "workflow_role_unbound", "per_assignment"])(
  "reviews the selected coordinate and its independent sources under %s",
  async (businessState) => {
    mockService((fn, args) => {
      if (fn === "metadata.dimension.list")
        return {
          rows: [
            {
              dimension_id: "Period",
              status: "Active",
              model_role: "Period",
              name: "Period",
            },
          ],
          metadataRevision: 7,
          nextAfterDimensionId: null,
        };
      if (fn === "metadata.member.list")
        return {
          rows: [{ member_id: "Q1", name: "First quarter", status: "Active" }],
          metadataRevision: 7,
          nextAfterMemberId: null,
        };
      expect(fn).toBe(resourceAccess);
      expect(args).toEqual({
        ...resource,
        action: "facts.write",
        collection: "people",
        expectedMetadataRevision: 7,
        limit: 25,
      });
      return page({
        action: "facts.write",
        businessState,
        people: [
          {
            subjectId: "user-a",
            displayName: "Alex",
            username: "alex",
            grantingGroupIds: ["g-north", "g-other"],
            entryGroupIds: ["g-entry"],
            ...(businessState === "per_assignment"
              ? { businessState: "open" }
              : {}),
          },
          ...(businessState === "per_assignment"
            ? [
                {
                  subjectId: "user-b",
                  displayName: "Sam",
                  username: "sam",
                  grantingGroupIds: ["g-other"],
                  entryGroupIds: ["g-entry"],
                  businessState: "workflow_role_unbound",
                },
              ]
            : []),
        ],
      });
    });
    render(
      <CoordinateAccessExplanation
        app={app}
        revision={7}
        people={[]}
        canReviewResource
        canExplainPerson={false}
      />,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Choose a coordinate" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Choose Period member" }),
    );
    fireEvent.change(await screen.findByLabelText("Member of Period"), {
      target: { value: "Q1" },
    });
    expect(screen.queryByLabelText("Person to inspect")).toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: "Show entitled people" }),
    );
    expect(await screen.findByText("Alex")).toBeTruthy();
    expect(
      screen.getByText("Resource grant from g-north, g-other"),
    ).toBeTruthy();
    expect(
      screen.getAllByText("Application entry from g-entry").length,
    ).toBeGreaterThan(0);
    expect(
      screen.getByText(
        businessState === "locked"
          ? /planning lock currently prevents/
          : businessState === "per_assignment"
            ? /depends on the planning duties/
            : /active planning policy requires a verified workflow role/,
      ),
    ).toBeTruthy();
    if (businessState === "per_assignment") {
      expect(
        screen.getByText("Planning allows Set").closest("li"),
      ).toHaveTextContent("Alex");
      expect(
        screen
          .getByText("No matching assignment supplies a planning duty")
          .closest("li"),
      ).toHaveTextContent("Sam");
    }
  },
);

it("distinguishes an empty granting group and pages its assignment sources within the selected resource", async () => {
  mockService((fn, args) => {
    expect(fn).toBe(resourceAccess);
    if (args.collection === "groups")
      return page({
        collection: "groups",
        coverage: "partial",
        coverageReasons: ["directory_identity_unresolved"],
        groups: [
          {
            groupId: "g-north",
            groupName: "North",
            hasActiveMembers: false,
            origins: [source],
            originsComplete: false,
          },
        ],
      });
    expect(args.groupId).toBe("g-north");
    return page({
      collection: "origins",
      groupId: "g-north",
      origins: [
        {
          ...source,
          assignmentId: args.cursor ? "later-grant" : "first-grant",
        },
      ],
      nextCursor: args.cursor ? null : "page-2",
    });
  });
  render(<ResourceAccessRoster app={app} revision={7} resource={resource} />);
  fireEvent.click(screen.getByRole("button", { name: "Show granting groups" }));
  expect(await screen.findByText("No active members recorded")).toBeTruthy();
  expect(screen.getByText(/Directory evidence is incomplete/)).toBeTruthy();
  fireEvent.click(
    screen.getByRole("button", { name: "All assignment sources for North" }),
  );
  expect(await screen.findByText("first-grant")).toBeTruthy();
  fireEvent.click(
    screen.getByRole("button", { name: "Next assignment sources" }),
  );
  expect(await screen.findByText("later-grant")).toBeTruthy();
});

it("uses the caller's visible saved view pages and rejects a result for a different object", async () => {
  mockService((fn, args) => {
    if (fn === "grid.definition.list") {
      if (args.afterGridId) {
        expect(args.expectedCollectionToken).toBe("b".repeat(64));
        return {
          grids: [{ gridId: "press", name: "Press capacity" }],
          nextAfterGridId: null,
          collectionToken: "b".repeat(64),
        };
      }
      return {
        grids: [{ gridId: "allocation", name: "Allocation" }],
        nextAfterGridId: "allocation",
        collectionToken: "b".repeat(64),
      };
    }
    expect(fn).toBe(resourceAccess);
    expect(args).toEqual({
      collection: "people",
      limit: 25,
      action: "views.read",
      savedViewId: "press",
      expectedMetadataRevision: 7,
    });
    return page({
      action: "views.read",
      coordinate: undefined,
      savedViewId: "wrong",
      people: [
        {
          subjectId: "hidden",
          username: null,
          displayName: "Outside object",
          grantingGroupIds: ["g-north"],
          entryGroupIds: ["g-north"],
        },
      ],
    });
  });
  render(<SavedViewAccessReview app={app} revision={7} />);
  fireEvent.click(screen.getByRole("button", { name: "Choose a saved view" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Next saved views" }),
  );
  await screen.findByRole("option", { name: "Press capacity · press" });
  fireEvent.change(screen.getByLabelText("Saved view"), {
    target: { value: "press" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Show entitled people" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "unavailable or has changed",
  );
  expect(screen.queryByText("Outside object")).toBeNull();
});
