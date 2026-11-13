import { discardUnsavedWork } from "./unsaved-work";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  BuildSchedules,
  exactApplicationSchedule,
  scheduleListBody,
  scheduleMutationBody,
  scheduleReadBody,
} from "./BuildSchedules";
import { operationAdmissionResponse } from "./test-setup";

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Application",
  status: "Active",
};
const catalog = {
  applicationAccess: { role: "Administrator", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: Object.fromEntries(
    ["save", "activate", "deactivate", "read", "list"].map((suffix) => [
      `schedule.${suffix}`,
      {},
    ]),
  ),
  revisions: {
    metadata: 7,
    data: 8,
    policy: 9,
    security: 10,
    commit: 11,
    schemaEpoch: 224,
  },
};

afterEach(() => vi.unstubAllGlobals());

it("preserves the exact browser schedule contracts", () => {
  expect(scheduleListBody({ workspaceId: "ws", applicationId: "app" })).toEqual(
    {
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "schedule.list",
        arguments: { limit: 100 },
      },
    },
  );
  expect(
    scheduleReadBody({ workspaceId: "ws", applicationId: "app" }, "nightly")
      .program.arguments,
  ).toEqual({ scheduleId: "nightly" });
  expect(
    scheduleMutationBody(
      app,
      catalog,
      "schedule.activate",
      {
        scheduleId: "nightly",
        expectedStateToken: "b".repeat(64),
      },
      "schedule-key-1",
    ),
  ).toMatchObject({
    confirmed: true,
    idempotencyKey: "schedule-key-1",
    program: {
      function: "schedule.activate",
      arguments: {
        scheduleId: "nightly",
        expectedStateToken: "b".repeat(64),
        expectedMetadataRevision: 7,
        expectedPolicyRevision: 9,
        expectedSchemaEpoch: 224,
      },
    },
  });
});

it("reads and opens authoritative current generic schedules", async () => {
  const definition = {
    format: "openepm-application-schedule-v1",
    scheduleId: "nightly",
  };
  const row = {
    scheduleId: "nightly",
    stateToken: "b".repeat(64),
    definition,
    definitionDigest: "a".repeat(64),
    status: "Active" as const,
    targetStatus: "Current" as const,
    effectiveStatus: "Active" as const,
    reasonCode: null,
    updatedAt: "2026-11-02T00:00:00Z",
  };
  const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      calls.push({ url, body });
      const fn = (body.program as { function: string }).function;
      return new Response(
        JSON.stringify(
          fn.endsWith(".list")
            ? { result: { schedules: [row], nextAfterScheduleId: null } }
            : { result: { defined: true, schedule: row } },
        ),
        { status: 200 },
      );
    }),
  );
  render(<BuildSchedules app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read schedules" }));
  await screen.findByText("nightly");
  fireEvent.click(screen.getByRole("button", { name: "Open" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Schedule definition JSON")).toHaveValue(
      JSON.stringify(definition, null, 2),
    ),
  );
  expect(calls.map((call) => call.url)).toEqual([
    "/api/application-schedule",
    "/api/application-schedule",
  ]);
  expect(
    screen.getByText(/Save validates the current definition/),
  ).toBeInTheDocument();
});

it("does not render when generic schedule discovery is absent", () => {
  const hidden = { ...catalog, functions: {} };
  const { container } = render(<BuildSchedules app={app} catalog={hidden} />);
  expect(container).toBeEmptyDOMElement();
});

it("binds a workflow target to the exact published schedule", async () => {
  const digest = "d".repeat(64);
  const definition = {
    format: "openepm-application-schedule-v1",
    scheduleId: "nightly",
  };
  const result = {
    defined: true,
    schedule: {
      scheduleId: "nightly",
      stateToken: "b".repeat(64),
      definition,
      definitionDigest: digest,
      status: "Active",
      targetStatus: "Current",
      effectiveStatus: "Active",
      reasonCode: null,
      updatedAt: "2026-11-02T00:00:00Z",
    },
  };
  expect(() =>
    exactApplicationSchedule(
      {
        ...result,
        schedule: { ...result.schedule, stateToken: "c".repeat(64) },
      },
      { scheduleId: "nightly", stateToken: "b".repeat(64), digest },
    ),
  ).toThrow("INVALID_APPLICATION_SCHEDULE_RESPONSE");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      expect(body.program.arguments).toEqual({ scheduleId: "nightly" });
      return new Response(JSON.stringify({ result }));
    }),
  );
  render(
    <BuildSchedules
      app={app}
      catalog={catalog}
      target={{ scheduleId: "nightly", stateToken: "b".repeat(64), digest }}
    />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Schedule definition JSON")).toHaveValue(
      JSON.stringify(definition, null, 2),
    ),
  );
});

const savedSchedule = {
  scheduleId: "draft",
  stateToken: "b".repeat(64),
  definition: {
    format: "openepm-application-schedule-v1",
    scheduleId: "draft",
  },
  definitionDigest: "a".repeat(64),
  status: "Saved" as const,
  targetStatus: "Current" as const,
  effectiveStatus: "Saved" as const,
  reasonCode: null,
  updatedAt: "2026-11-07T00:00:00Z",
};

const blockedSchedule = {
  ...savedSchedule,
  scheduleId: "blocked",
  definition: { ...savedSchedule.definition, scheduleId: "blocked" },
  status: "Active" as const,
  targetStatus: "Stale" as const,
  effectiveStatus: "Blocked" as const,
  reasonCode: "APPLICATION_SCHEDULE_TARGET_STALE" as const,
};

it("keeps Active workflow targets strict while allowing the server's Saved inspection contract", () => {
  const target = {
    scheduleId: "draft",
    stateToken: "b".repeat(64),
    digest: "a".repeat(64),
  };
  const response = { defined: true, schedule: savedSchedule };
  expect(() => exactApplicationSchedule(response, target)).toThrow(
    "INVALID_APPLICATION_SCHEDULE_RESPONSE",
  );
  expect(exactApplicationSchedule(response, target, false)).toEqual(
    savedSchedule,
  );
  expect(() =>
    exactApplicationSchedule(
      response,
      { ...target, stateToken: "c".repeat(64) },
      false,
    ),
  ).toThrow("INVALID_APPLICATION_SCHEDULE_RESPONSE");
});

it("opens a Saved schedule and prevents activation of a visibly changed definition", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      return new Response(
        JSON.stringify({
          result: body.program.function.endsWith(".list")
            ? { schedules: [savedSchedule], nextAfterScheduleId: null }
            : { defined: true, schedule: savedSchedule },
        }),
      );
    }),
  );
  render(<BuildSchedules app={app} catalog={catalog} />);
  expect(
    screen.queryByLabelText("Schedule definition JSON"),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Read schedules" }));
  fireEvent.click(await screen.findByRole("button", { name: "Open" }));
  expect(await screen.findByRole("button", { name: "Activate" })).toBeEnabled();
  fireEvent.change(screen.getByLabelText("Schedule definition JSON"), {
    target: {
      value: JSON.stringify({
        ...savedSchedule.definition,
        unexpectedChange: true,
      }),
    },
  });
  expect(screen.getByRole("button", { name: "Activate" })).toBeDisabled();
});

it("shows a stale target as blocked and refuses to activate or bind it", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      return new Response(
        JSON.stringify({
          result: body.program.function.endsWith(".list")
            ? { schedules: [blockedSchedule], nextAfterScheduleId: null }
            : { defined: true, schedule: blockedSchedule },
        }),
      );
    }),
  );
  const target = {
    scheduleId: blockedSchedule.scheduleId,
    stateToken: blockedSchedule.stateToken,
    digest: blockedSchedule.definitionDigest,
  };
  expect(() =>
    exactApplicationSchedule(
      { defined: true, schedule: blockedSchedule },
      target,
    ),
  ).toThrow("INVALID_APPLICATION_SCHEDULE_RESPONSE");
  render(<BuildSchedules app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read schedules" }));
  expect(await screen.findByText("Blocked")).toBeVisible();
  expect(screen.getByText(/Target changed; rebind/)).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Open" }));
  expect(await screen.findByText(/target rule changed/i)).toBeVisible();
  expect(screen.getByRole("button", { name: "Activate" })).toBeDisabled();
});

it("preserves a new schedule until its close transition is accepted", () => {
  let accept: (() => void) | undefined;
  const transition = vi.fn((action: () => void) => {
    accept = action;
  });
  render(
    <BuildSchedules
      app={app}
      catalog={catalog}
      onRequestTransition={transition}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
  fireEvent.change(screen.getByLabelText("Schedule definition JSON"), {
    target: { value: JSON.stringify(savedSchedule.definition) },
  });
  fireEvent.click(screen.getByRole("button", { name: "Close editor" }));
  expect(transition).toHaveBeenCalledOnce();
  expect(screen.getByLabelText("Schedule definition JSON")).toHaveValue(
    JSON.stringify(savedSchedule.definition),
  );
  act(() => {
    discardUnsavedWork();
    accept?.();
  });
  expect(
    screen.queryByLabelText("Schedule definition JSON"),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
  expect(screen.getByLabelText("Schedule definition JSON")).toHaveValue("{}");
});

it("uses one signed admission for an exact schedule retry", async () => {
  const submissions: Record<string, unknown>[] = [];
  let admissions = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: unknown, init?: RequestInit) => {
      if (String(url) === "/api/operation-admission") {
        admissions += 1;
        return operationAdmissionResponse("4");
      }
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "schedule.save") {
        submissions.push(body);
        if (submissions.length === 1) throw new TypeError("Response lost");
        return new Response(
          JSON.stringify({ result: { status: "Saved", operationId: "op" } }),
        );
      }
      return new Response(
        JSON.stringify({
          result: { schedules: [], nextAfterScheduleId: null },
        }),
      );
    }),
  );
  render(<BuildSchedules app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
  fireEvent.change(screen.getByLabelText("Schedule definition JSON"), {
    target: { value: JSON.stringify(savedSchedule.definition) },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Response lost");
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  expect(await screen.findByText("Schedule Saved recorded.")).toBeVisible();
  expect(admissions).toBe(1);
  expect(submissions).toHaveLength(2);
  expect(submissions[1]).toEqual(submissions[0]);
  expect(submissions[0].idempotencyKey).toMatch(/^oa1_/);
});

it("keeps the new exact schedule visible when a canceled earlier target returns late", async () => {
  const pending: Array<{
    arguments: { scheduleId: string };
    resolve: (response: Response) => void;
  }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(
      (_url: unknown, init?: RequestInit) =>
        new Promise<Response>((resolve) => {
          pending.push({
            arguments: JSON.parse(String(init?.body)).program.arguments,
            resolve,
          });
        }),
    ),
  );
  const target = {
    scheduleId: "first",
    stateToken: "b".repeat(64),
    digest: "a".repeat(64),
  };
  const { rerender } = render(
    <BuildSchedules app={app} catalog={catalog} target={target} />,
  );
  await waitFor(() => expect(pending).toHaveLength(1));
  rerender(
    <BuildSchedules
      app={app}
      catalog={catalog}
      target={{ ...target, scheduleId: "second" }}
    />,
  );
  await waitFor(() => expect(pending).toHaveLength(2));
  const response = (id: string) =>
    new Response(
      JSON.stringify({
        result: {
          defined: true,
          schedule: {
            ...savedSchedule,
            scheduleId: id,
            definition: { ...savedSchedule.definition, scheduleId: id },
            status: "Active",
            effectiveStatus: "Active",
          },
        },
      }),
    );
  await act(async () => pending[1].resolve(response("second")));
  expect(screen.getByLabelText("Schedule definition JSON")).toHaveValue(
    JSON.stringify(
      { ...savedSchedule.definition, scheduleId: "second" },
      null,
      2,
    ),
  );
  await act(async () => pending[0].resolve(response("first")));
  expect(screen.getByLabelText("Schedule definition JSON")).toHaveValue(
    JSON.stringify(
      { ...savedSchedule.definition, scheduleId: "second" },
      null,
      2,
    ),
  );
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});
