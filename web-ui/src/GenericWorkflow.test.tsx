import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import { GenericWorkflow, genericWorkflowActionBody } from "./GenericWorkflow";

afterEach(() => vi.unstubAllGlobals());

const app = {
  workspaceId: "ws",
  applicationId: "cube",
  name: "Cube",
  status: "Active",
};
const catalog = {
  applicationAccess: { role: "Reader", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "application.workflow.worklist": {},
    "application.workflow.occurrence.read": {},
    "application.workflow.activity.complete": {},
    "application.workflow.activity.return": {},
    "application.workflow.occurrence.cancel": {},
  },
  revisions: { metadata: 1, data: 2, policy: 3, security: 4, commit: 5 },
};

it("wraps exact generic workflow programs without evaluating them", () => {
  const program = {
    languageVersion: 2,
    function: "application.workflow.occurrence.cancel",
    arguments: { occurrenceId: "1".repeat(32), expectedOccurrenceVersion: 4 },
  };
  expect(
    genericWorkflowActionBody(
      { workspaceId: "ws", applicationId: "cube" },
      program,
      "workflow-action-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "cube",
    program,
    idempotencyKey: "workflow-action-1",
    confirmed: true,
  });
});

it("renders assigned generic work and submits server-owned evidence", async () => {
  const occurrence = "1".repeat(32);
  const openDestination = vi.fn(
    () =>
      "The configured function has no inspectable immutable artifact identity.",
  );
  vi.stubGlobal("crypto", { randomUUID: () => "workflow-complete-key" });
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  const calls: Array<{ url: string; body: any }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body));
      calls.push({ url, body });
      if (url === "/api/application-workflow-occurrence")
        return new Response(
          JSON.stringify({
            result: { operationId: "complete-receipt", status: "Completed" },
          }),
        );
      if (body.program.function === "application.workflow.worklist")
        return new Response(
          JSON.stringify({
            result: {
              items: body.program.arguments.afterOccurrenceId
                ? [
                    {
                      occurrenceId: occurrence,
                      occurrenceVersion: 1,
                      flowId: "generic-flow",
                      version: 1,
                      definitionDigest: "a".repeat(64),
                      activityId: "prepare",
                      activityVersion: 1,
                      name: "Prepare cube slice",
                      kind: "Action",
                      destination: {
                        kind: "Function",
                        function: "application.rule.run",
                        argumentsDigest: "d".repeat(64),
                      },
                      assignmentResolution: {
                        assignmentId: "owner",
                        kind: "Action",
                      },
                    },
                  ]
                : [
                    {
                      occurrenceId: "2".repeat(32),
                      occurrenceVersion: 1,
                      flowId: "generic-flow",
                      version: 1,
                      definitionDigest: "a".repeat(64),
                      activityId: "other",
                      activityVersion: 1,
                      name: "Earlier assigned work",
                      kind: "Action",
                      destination: {
                        kind: "Function",
                        function: "application.rule.run",
                        argumentsDigest: "e".repeat(64),
                      },
                      assignmentResolution: {
                        assignmentId: "owner",
                        kind: "Action",
                      },
                    },
                  ],
              nextCursor: body.program.arguments.afterOccurrenceId
                ? null
                : {
                    afterOccurrenceId: "2".repeat(32),
                    afterActivityId: "other",
                  },
            },
          }),
        );
      if (body.program.function === "application.workflow.occurrence.read")
        return new Response(
          JSON.stringify({
            result: {
              occurrenceId: occurrence,
              flowId: "generic-flow",
              version: 1,
              status: "Active",
              occurrenceVersion: 1,
              activities: [
                {
                  activityId: "prepare",
                  kind: "Action",
                  status: "Ready",
                  activityVersion: 1,
                },
              ],
              events: [
                {
                  ordinal: 1,
                  eventType: "OccurrenceStarted",
                  committedRevision: 9,
                  createdAt: "2026-11-02T10:00:00Z",
                },
              ],
            },
          }),
        );
      if (body.program.function === "application.workflow.read")
        return new Response(
          JSON.stringify({
            result: {
              definition: {
                activities: [
                  {
                    activityId: "prepare",
                    evidenceContract: {
                      kind: "ManualAttestation",
                      statement: "Prepared",
                    },
                  },
                ],
              },
            },
          }),
        );
      throw new Error(`Unexpected ${body.program.function}`);
    }),
  );

  const rendered = render(
    <GenericWorkflow
      app={app}
      catalog={catalog}
      targetOccurrenceId={occurrence}
      openDestination={openDestination}
    />,
  );
  expect((await screen.findAllByText("Prepare cube slice")).length).toBe(2);
  expect(await screen.findByText("Prepared")).toBeInTheDocument();
  expect(
    (
      await axe.run(rendered.container, {
        rules: { "color-contrast": { enabled: false } },
      })
    ).violations,
  ).toEqual([]);
  fireEvent.click(
    screen.getByRole("button", { name: "Open governed destination" }),
  );
  expect(openDestination).toHaveBeenCalledWith({
    kind: "Function",
    function: "application.rule.run",
    argumentsDigest: "d".repeat(64),
  });
  expect(screen.getByRole("alert")).toHaveTextContent(
    "no inspectable immutable artifact identity",
  );
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact activity, evidence requirement and current occurrence version.",
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Complete activity" }));
  await screen.findByText(/Recorded by operation complete-receipt/);
  const action = calls.find(
    (item) => item.url === "/api/application-workflow-occurrence",
  )!;
  expect(action.body).toEqual({
    workspaceId: "ws",
    applicationId: "cube",
    confirmed: true,
    idempotencyKey: "workflow-ui-workflow-complete-key",
    program: {
      languageVersion: 2,
      function: "application.workflow.activity.complete",
      arguments: {
        occurrenceId: occurrence,
        activityId: "prepare",
        expectedActivityVersion: 1,
        evidence: { kind: "ManualAttestation", confirmed: true },
      },
    },
  });
  await waitFor(() =>
    expect(
      calls.filter(
        (item) =>
          item.body.program?.function === "application.workflow.worklist",
      ).length,
    ).toBeGreaterThan(1),
  );
  expect(
    calls.filter(
      (item) =>
        item.body.program?.function === "application.workflow.worklist" &&
        item.body.program.arguments.afterOccurrenceId === "2".repeat(32),
    ).length,
  ).toBeGreaterThan(0);
});
