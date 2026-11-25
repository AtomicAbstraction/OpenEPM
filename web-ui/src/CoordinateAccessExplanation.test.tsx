import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  CoordinateAccessExplanation,
  explainAccess,
} from "./CoordinateAccessExplanation";
const app = {
  workspaceId: "ops",
  applicationId: "capacity",
  name: "Capacity",
  status: "Active",
};
const people = [
  { subjectId: "planner-1", displayName: "Alex", username: "alex" },
];
function service(mismatch = false, unbound = false) {
  const calls = vi.fn(async (url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    let result;
    switch (body.program.function) {
      case "metadata.dimension.list":
        result = {
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
        break;
      case "metadata.member.list":
        expect(body.program.arguments).toMatchObject({
          dimension: "Period",
          expectedMetadataRevision: 7,
        });
        result = {
          rows: [{ member_id: "Q1", name: "First quarter", status: "Active" }],
          nextAfterMemberId: null,
          metadataRevision: 7,
        };
        break;
      case explainAccess:
        expect(url).toBe("/api/security");
        expect(body.program.arguments).toEqual({
          subjectId: "planner-1",
          action: "facts.write",
          coordinate: { Period: "Q1" },
          expectedMetadataRevision: 7,
        });
        result = {
          workspaceId: "ops",
          applicationId: "capacity",
          subjectId: mismatch ? "wrong-person" : "planner-1",
          coordinate: { Period: "Q1" },
          action: "facts.write",
          businessState: unbound ? "workflow_role_unbound" : "locked",
          operation: "blocked",
          entitlement: "granted",
          reason: unbound
            ? "workflow_role_binding_unavailable"
            : "intersection_locked",
          asOf: "2026-11-25T10:00:00Z",
          originsComplete: true,
          origins: [
            {
              assignmentId: "regional-team",
              scopeId: "first-quarter",
              roleId: "planner",
              action: "facts.write",
              groupId: "group-1",
              scopeRevision: 2,
              assignmentRevision: 3,
            },
          ],
        };
        break;
      default:
        throw new Error("Unexpected read");
    }
    return new Response(JSON.stringify({ result }), {
      headers: { "Content-Type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", calls);
  return calls;
}
afterEach(() => vi.unstubAllGlobals());
async function point() {
  fireEvent.click(screen.getByRole("button", { name: "Choose a coordinate" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Choose Period member" }),
  );
  fireEvent.change(await screen.findByLabelText("Member of Period"), {
    target: { value: "Q1" },
  });
}
it.each([false, true])(
  "shows the granting group and the planning constraint (missing workflow role %s)",
  async (unbound) => {
    service(false, unbound);
    render(
      <CoordinateAccessExplanation app={app} revision={7} people={people} />,
    );
    await point();
    expect(
      screen.getByRole("button", { name: "Inspect decision" }),
    ).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Person to inspect"), {
      target: { value: "planner-1" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect decision" }));
    expect(
      await screen.findByText(
        unbound
          ? "No matching assignment supplies a planning duty"
          : "Locked by the planning workflow",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("granted")).toBeInTheDocument();
    expect(screen.getByText("blocked")).toBeInTheDocument();
    expect(screen.getByText("regional-team")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Resource action"), {
      target: { value: "facts.read" },
    });
    expect(screen.queryByText("regional-team")).toBeNull();
  },
);
it("rejects an unexpected subject instead of displaying another person's explanation", async () => {
  service(true);
  render(
    <CoordinateAccessExplanation
      app={app}
      revision={7}
      people={people}
      activePerson="planner-1"
    />,
  );
  await point();
  fireEvent.click(screen.getByRole("button", { name: "Inspect decision" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("unavailable");
  expect(screen.queryByText("regional-team")).toBeNull();
});
