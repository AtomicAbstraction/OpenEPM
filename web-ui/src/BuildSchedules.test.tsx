import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  BuildSchedules,
  exactApplicationSchedule,
  scheduleListBody,
  scheduleMutationBody,
  scheduleReadBody,
} from "./BuildSchedules";

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
    ["save", "publish", "deactivate", "read", "list"].map((suffix) => [
      `schedule.version.${suffix}`,
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
        function: "schedule.version.list",
        arguments: { limit: 100 },
      },
    },
  );
  expect(
    scheduleReadBody({ workspaceId: "ws", applicationId: "app" }, "nightly", 2)
      .program.arguments,
  ).toEqual({ scheduleId: "nightly", version: 2 });
  expect(
    scheduleMutationBody(
      app,
      catalog,
      "schedule.version.publish",
      {
        scheduleId: "nightly",
        version: 2,
        expectedStateRevision: 3,
      },
      "schedule-key-1",
    ),
  ).toMatchObject({
    confirmed: true,
    idempotencyKey: "schedule-key-1",
    program: {
      function: "schedule.version.publish",
      arguments: {
        scheduleId: "nightly",
        version: 2,
        expectedStateRevision: 3,
        expectedMetadataRevision: 7,
        expectedPolicyRevision: 9,
        expectedSchemaEpoch: 224,
      },
    },
  });
});

it("reads and opens authoritative generic schedule versions", async () => {
  const definition = {
    format: "openepm-application-schedule-v1",
    scheduleId: "nightly",
    version: 1,
  };
  const row = {
    scheduleId: "nightly",
    version: 1,
    definition,
    definitionDigest: "a".repeat(64),
    status: "Published" as const,
    stateRevision: 4,
    createdRevision: 5,
    createdAt: "2026-11-02T00:00:00Z",
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
    screen.getByText(
      /Due-time calculation, execution and recovery remain fixed-core services/,
    ),
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
    version: 2,
  };
  const result = {
    defined: true,
    schedule: {
      scheduleId: "nightly",
      version: 2,
      definition,
      definitionDigest: digest,
      status: "Published",
      stateRevision: 4,
      createdRevision: 5,
      createdAt: "2026-11-02T00:00:00Z",
    },
  };
  expect(() =>
    exactApplicationSchedule(
      { ...result, schedule: { ...result.schedule, version: 3 } },
      { scheduleId: "nightly", version: 2, digest },
    ),
  ).toThrow("INVALID_APPLICATION_SCHEDULE_RESPONSE");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      expect(body.program.arguments).toEqual({
        scheduleId: "nightly",
        version: 2,
      });
      return new Response(JSON.stringify({ result }));
    }),
  );
  render(
    <BuildSchedules
      app={app}
      catalog={catalog}
      target={{ scheduleId: "nightly", version: 2, digest }}
    />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Schedule definition JSON")).toHaveValue(
      JSON.stringify(definition, null, 2),
    ),
  );
});
