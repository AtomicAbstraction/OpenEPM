import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import { GenericWorkflow, genericWorkflowActionBody } from "./GenericWorkflow";
import { operationAdmissionResponse } from "./test-setup";

afterEach(() => vi.unstubAllGlobals());

const app = {
  workspaceId: "ws",
  applicationId: "cube",
  name: "Cube",
  status: "Active",
};
const occurrenceToken = "1".repeat(64);
const activityToken = "2".repeat(64);
const flowToken = "3".repeat(64);
const catalog = {
  applicationAccess: { role: "Reader", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "application.workflow.worklist": {},
    "application.workflow.occurrence.read": {},
    "application.workflow.activity.evidence.list": {},
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
    arguments: {
      occurrenceId: "1".repeat(32),
      expectedOccurrenceStateToken: occurrenceToken,
    },
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
      if (url === "/api/operation-admission")
        return operationAdmissionResponse("5");
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
                      occurrenceStateToken: occurrenceToken,
                      flowId: "generic-flow",
                      flowStateToken: flowToken,
                      definitionDigest: "a".repeat(64),
                      activityId: "prepare",
                      activityStateToken: activityToken,
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
                      occurrenceStateToken: occurrenceToken,
                      flowId: "generic-flow",
                      flowStateToken: flowToken,
                      definitionDigest: "a".repeat(64),
                      activityId: "other",
                      activityStateToken: activityToken,
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
              flowStateToken: flowToken,
              status: "Active",
              occurrenceStateToken: occurrenceToken,
              lastEventOrdinal: 1,
              activities: [
                {
                  activityId: "prepare",
                  kind: "Action",
                  status: "Ready",
                  activityStateToken: activityToken,
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
                name: "Monthly close",
                activities: [
                  {
                    activityId: "prepare",
                    name: "Prepare cube slice",
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
  expect((await screen.findAllByText("Prepare cube slice")).length).toBe(3);
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
  expect(openDestination).toHaveBeenCalledWith(
    {
      kind: "Function",
      function: "application.rule.run",
      argumentsDigest: "d".repeat(64),
    },
    { occurrenceId: occurrence, activityId: "prepare" },
  );
  expect(screen.getByRole("alert")).toHaveTextContent(
    "no inspectable immutable artifact identity",
  );
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact activity, evidence requirement and current occurrence state.",
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Complete activity" }));
  await screen.findByText("Activity completed.");
  expect(screen.queryByText("complete-receipt")).not.toBeInTheDocument();
  expect(screen.queryByText("generic-flow · prepare")).not.toBeInTheDocument();
  expect(screen.queryByText("owner")).not.toBeInTheDocument();
  expect(screen.queryByText("Event 1")).not.toBeInTheDocument();
  const action = calls.find(
    (item) => item.url === "/api/application-workflow-occurrence",
  )!;
  expect(action.body).toEqual({
    workspaceId: "ws",
    applicationId: "cube",
    confirmed: true,
    idempotencyKey: expect.stringMatching(/^oa1_/),
    program: {
      languageVersion: 2,
      function: "application.workflow.activity.complete",
      arguments: {
        occurrenceId: occurrence,
        activityId: "prepare",
        expectedActivityStateToken: activityToken,
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

it("keeps an edited activity intact until local selection is accepted", async () => {
  const activities = ["prepare", "review"].map((activityId) => ({
    occurrenceId: "1".repeat(32),
    occurrenceStateToken: occurrenceToken,
    flowId: "cycle",
    flowStateToken: flowToken,
    definitionDigest: "a".repeat(64),
    activityId,
    activityStateToken: activityToken,
    name: activityId === "prepare" ? "Prepare plan" : "Review plan",
    kind: "Action",
    destination: {
      kind: "Function",
      function: "application.rule.run",
      argumentsDigest: "b".repeat(64),
    },
    assignmentResolution: { assignmentId: "owner", kind: "Action" },
  }));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const { program } = JSON.parse(String(init?.body));
      const result =
        program.function === "application.workflow.worklist"
          ? { items: activities, nextCursor: null }
          : program.function === "application.workflow.occurrence.read"
            ? {
                occurrenceId: "1".repeat(32),
                flowId: "cycle",
                flowStateToken: flowToken,
                status: "Active",
                occurrenceStateToken: occurrenceToken,
                lastEventOrdinal: 1,
                activities: activities.map((item) => ({
                  ...item,
                  status: "Ready",
                })),
                events: [],
              }
            : program.function === "application.workflow.activity.evidence.list"
              ? {
                  items: [
                    {
                      selectionKey: "keep-this-evidence",
                      label: "Application rule run",
                      occurredAt: "2026-11-02T10:00:00Z",
                      outcome: "Committed",
                      current: true,
                    },
                  ],
                  nextBeforeCommittedRevision: null,
                }
              : {
                  definition: {
                    name: "Planning review",
                    activities: activities.map((item) => ({
                      activityId: item.activityId,
                      name: item.name,
                      evidenceContract: { kind: "OperationReceipt" },
                    })),
                  },
                };
      return new Response(JSON.stringify({ result }));
    }),
  );
  let accept: (() => void) | undefined;
  const openDestination = vi.fn(() => null);
  render(
    <GenericWorkflow
      app={app}
      catalog={catalog}
      openDestination={openDestination}
      onRequestTransition={(action) => {
        accept = action;
      }}
    />,
  );
  const receipt = await screen.findByLabelText("Completion evidence");
  await screen.findByRole("option", { name: /Application rule run/ });
  fireEvent.change(receipt, { target: { value: "keep-this-evidence" } });
  fireEvent.click(
    screen.getByRole("button", { name: "Open activity Review plan" }),
  );
  expect(receipt).toHaveValue("keep-this-evidence");
  expect(
    screen.getByRole("heading", { name: "Prepare plan" }),
  ).toBeInTheDocument();
  act(() => accept?.());
  await waitFor(() =>
    expect(screen.getByLabelText("Completion evidence")).toHaveValue(""),
  );
  expect(
    screen.getByRole("heading", { name: "Review plan" }),
  ).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Open governed destination" }),
  );
  expect(openDestination).toHaveBeenCalledWith(activities[1].destination, {
    occurrenceId: activities[1].occurrenceId,
    activityId: "review",
  });
});

it("ignores late errors from a cancelled application worklist read", async () => {
  let rejectOld: ((error: Error) => void) | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (body.applicationId === "cube")
        return new Promise<Response>((_resolve, reject) => {
          rejectOld = reject;
        });
      return Promise.resolve(
        new Response(
          JSON.stringify({ result: { items: [], nextCursor: null } }),
        ),
      );
    }),
  );
  const view = render(<GenericWorkflow app={app} catalog={catalog} />);
  view.rerender(
    <GenericWorkflow
      app={{ ...app, applicationId: "other" }}
      catalog={catalog}
    />,
  );
  await screen.findByText("No generic workflow activity is ready for you now.");
  await act(async () => rejectOld?.(new Error("Old application failure")));
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});
