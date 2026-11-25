import {
  discardUnsavedWork,
  usePreservedDraft,
  unsavedWorkSnapshot,
  setDraftIdentity,
} from "./unsaved-work";
import {
  act,
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  BuildSchedules,
  exactApplicationSchedule,
  exactScheduleAuthority,
  scheduleAuthorityStatus,
  exactScheduleOccurrences,
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
    [
      ...["save", "activate", "deactivate", "read", "list"].map(
        (suffix) => `schedule.${suffix}`,
      ),
      "application.rule.read",
      "execution.delegation.read",
    ].map((name) => [name, {}]),
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

const scheduleDefinition = (scheduleId: string) => ({
  format: "openepm-application-schedule-v1",
  scheduleId,
  target: {
    kind: "ApplicationRule",
    ruleId: "margin.calculate",
    stateToken: "c".repeat(64),
    programDigest: "d".repeat(64),
  },
  bindings: {},
  pov: [],
  recurrence: {
    kind: "FixedInterval",
    intervalSeconds: 86400,
    firstDueAt: "2026-12-01T09:00:00Z",
    catchUpPolicy: "latest",
    maxCatchUp: 1,
  },
  retryPolicy: {
    maxAttempts: 3,
    backoffSeconds: 60,
    needsInspectionAfter: true,
  },
  cancellationPolicy: "PreserveCommittedStopFuture",
  delegation: {
    delegationId: "schedule.authority",
    stateToken: "e".repeat(64),
  },
});

afterEach(() => {
  vi.unstubAllGlobals();
  discardUnsavedWork();
});

const authority = {
  delegation_id: "schedule.authority",
  state_token: "e".repeat(64),
  status: "Active" as const,
  issuer: "https://identity.example.test",
  subject_id: "scheduled-operator",
  operation_scope: ["application.rule.run"],
  valid_from: "2020-01-01T00:00:00Z",
  valid_until: "2099-01-01T00:00:00Z",
  schedule_id: null,
};

it.each([
  [{ status: "Revoked" as const }, "Revoked"],
  [{ valid_until: "2021-01-01T00:00:00Z" }, "Expired"],
  [{ valid_from: "2090-01-01T00:00:00Z" }, "Not yet valid"],
  [{ schedule_id: "another" }, "Bound to another schedule"],
  [{ operation_scope: [] }, "Rule execution is not permitted"],
  [{ state_token: "f".repeat(64) }, "Bound authority changed"],
] as const)(
  "explains the native bound-authority condition %j",
  (change, status) => {
    const current = exactScheduleAuthority(
      { defined: true, delegation: { ...authority, ...change } },
      authority.delegation_id,
    );
    expect(
      scheduleAuthorityStatus(
        current,
        "draft",
        authority.state_token,
        Date.parse("2026-11-17T00:00:00Z"),
      ),
    ).toBe(status);
  },
);

it("inspects the bound actor and changed pin without silently rebinding the schedule", async () => {
  const effects: unknown[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "execution.delegation.read")
        return new Response(
          JSON.stringify({
            result: {
              defined: true,
              delegation: { ...authority, state_token: "f".repeat(64) },
            },
          }),
        );
      if (!["schedule.list", "schedule.read"].includes(body.program.function))
        effects.push(body);
      return new Response(
        JSON.stringify({
          result:
            body.program.function === "schedule.list"
              ? { schedules: [savedSchedule], nextAfterScheduleId: null }
              : { defined: true, schedule: savedSchedule },
        }),
      );
    }),
  );
  render(<BuildSchedules app={app} catalog={catalog} />);
  fireEvent.click(await screen.findByRole("button", { name: "Open" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Inspect bound authority" }),
  );
  expect(await screen.findByText("Bound authority changed")).toBeVisible();
  expect(screen.getByText("scheduled-operator")).toBeVisible();
  expect(screen.getByText("https://identity.example.test")).toBeVisible();
  expect(screen.getByRole("button", { name: "Activate" })).toBeEnabled();
  // Inspection is not a browser authorization gate; the core validates the exact saved binding.
  expect(effects).toEqual([]);
});

it("withdraws a prior execution authority while checking again and keeps denial details out of the schedule", async () => {
  let reads = 0;
  let finishRead!: (response: Response) => void;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const { program } = JSON.parse(String(init?.body));
      if (program.function === "execution.delegation.read") {
        if (++reads > 1)
          return new Promise<Response>((resolve) => (finishRead = resolve));
        return new Response(
          JSON.stringify({ result: { defined: true, delegation: authority } }),
        );
      }
      return new Response(
        JSON.stringify({
          result:
            program.function === "schedule.list"
              ? { schedules: [savedSchedule], nextAfterScheduleId: null }
              : { defined: true, schedule: savedSchedule },
        }),
      );
    }),
  );
  render(<BuildSchedules app={app} catalog={catalog} />);
  fireEvent.click(await screen.findByRole("button", { name: "Open" }));
  const inspect = await screen.findByRole("button", {
    name: "Inspect bound authority",
  });
  fireEvent.click(inspect);
  expect(await screen.findByText("scheduled-operator")).toBeVisible();

  fireEvent.click(inspect);
  expect(screen.queryByText("scheduled-operator")).not.toBeInTheDocument();
  expect(inspect).toBeDisabled();
  await act(async () =>
    finishRead(
      new Response(
        JSON.stringify({
          code: "APPLICATION_GRANT_REQUIRED",
          message: "private identity directory response",
        }),
        { status: 403 },
      ),
    ),
  );
  expect(
    screen.getByText("The execution authority could not be verified."),
  ).toBeVisible();
  expect(screen.queryByText("scheduled-operator")).not.toBeInTheDocument();
  expect(
    screen.queryByText(/private identity directory response/),
  ).not.toBeInTheDocument();
  expect(inspect).toBeEnabled();
});

it("keeps a late inspection result hidden after the catalogue removes support", async () => {
  let finishRead!: (response: Response) => void;
  let signal: AbortSignal | undefined;
  const fetch = vi.fn(async (_url, init) => {
    const { program } = JSON.parse(String(init?.body));
    if (program.function === "execution.delegation.read") {
      signal = init?.signal as AbortSignal;
      return new Promise<Response>((resolve) => (finishRead = resolve));
    }
    return new Response(
      JSON.stringify({
        result:
          program.function === "schedule.list"
            ? { schedules: [savedSchedule], nextAfterScheduleId: null }
            : { defined: true, schedule: savedSchedule },
      }),
    );
  });
  vi.stubGlobal("fetch", fetch);
  const { rerender } = render(<BuildSchedules app={app} catalog={catalog} />);
  fireEvent.click(await screen.findByRole("button", { name: "Open" }));
  const inspect = await screen.findByRole("button", {
    name: "Inspect bound authority",
  });
  fireEvent.click(inspect);
  await waitFor(() => expect(signal).toBeDefined());
  const functions = { ...catalog.functions };
  delete functions["execution.delegation.read"];
  rerender(<BuildSchedules app={app} catalog={{ ...catalog, functions }} />);
  expect(signal?.aborted).toBe(true);
  expect(
    screen.getByText(
      /Authority inspection is unavailable through the current application catalogue/,
    ),
  ).toBeVisible();
  expect(inspect).toBeDisabled();
  await act(async () =>
    finishRead(
      new Response(
        JSON.stringify({ result: { defined: true, delegation: authority } }),
      ),
    ),
  );
  expect(screen.queryByText("scheduled-operator")).not.toBeInTheDocument();
  rerender(<BuildSchedules app={app} catalog={catalog} />);
  expect(inspect).toBeEnabled();
  expect(screen.queryByText("scheduled-operator")).not.toBeInTheDocument();
});

const occurrenceItem = (sequence: number) => ({
  occurrenceId: `occ-${sequence}`,
  taskId: `task-${sequence}`,
  sequence,
  dueAt: "2026-11-17T09:00:00Z",
  nativeStatus: "published",
  status: "Succeeded",
  scheduleStateToken: "b".repeat(64),
  currentPin: true,
  workflowId: null,
});

it("reads three native descending occurrence pages and exposes only exact task references", async () => {
  const cursors: unknown[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(String(init?.body));
      const query = body.program.arguments.occurrences;
      if (query) {
        cursors.push(query.afterSequence);
        expect(query.expectedStateToken).toBe(savedSchedule.stateToken);
        const sequence =
          query.afterSequence === undefined
            ? 90
            : query.afterSequence === 90
              ? 60
              : 30;
        return new Response(
          JSON.stringify({
            result: {
              defined: true,
              schedule: savedSchedule,
              occurrences: {
                scheduleStateToken: savedSchedule.stateToken,
                items: [
                  {
                    ...occurrenceItem(sequence),
                    ...(sequence === 30
                      ? {
                          scheduleStateToken: "c".repeat(64),
                          currentPin: false,
                        }
                      : {}),
                  },
                ],
                hasMore: sequence !== 30,
                nextAfterSequence: sequence === 30 ? null : sequence,
              },
            },
          }),
        );
      }
      return new Response(
        JSON.stringify({
          result:
            body.program.function === "schedule.list"
              ? { schedules: [savedSchedule], nextAfterScheduleId: null }
              : { defined: true, schedule: savedSchedule },
        }),
      );
    }),
  );
  render(<BuildSchedules app={app} catalog={catalog} />);
  fireEvent.click(await screen.findByRole("button", { name: "Open" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Inspect occurrences" }),
  );
  expect(await screen.findByText(/1 visible occurrences loaded/)).toBeVisible();
  fireEvent.click(
    screen.getByRole("button", { name: "Read older occurrences" }),
  );
  expect(await screen.findByText(/2 visible occurrences loaded/)).toBeVisible();
  fireEvent.click(
    screen.getByRole("button", { name: "Read older occurrences" }),
  );
  expect(
    await screen.findByText("3 visible occurrences loaded."),
  ).toBeVisible();
  expect(screen.getByText("Uses an earlier saved version")).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Read older occurrences" }),
  ).toBeNull();
  expect(cursors).toEqual([undefined, 90, 60]);
  expect(
    screen
      .getAllByRole("link", { name: "Inspect task" })[0]
      .getAttribute("href"),
  ).toContain("task-90");
});

it("rejects mixed schedule versions and non-descending or repeated occurrence references", () => {
  const page = {
    scheduleStateToken: savedSchedule.stateToken,
    items: [occurrenceItem(40)],
    hasMore: true,
    nextAfterSequence: 40,
  };
  expect(() =>
    exactScheduleOccurrences(
      { ...page, scheduleStateToken: "f".repeat(64) },
      savedSchedule.stateToken,
    ),
  ).toThrow("does not match");
  expect(() =>
    exactScheduleOccurrences(page, savedSchedule.stateToken, [], 30),
  ).toThrow("invalid or repeated");
  expect(() =>
    exactScheduleOccurrences(
      page,
      savedSchedule.stateToken,
      [occurrenceItem(40)],
      50,
    ),
  ).toThrow("invalid or repeated");
  expect(() =>
    exactScheduleOccurrences(
      { ...page, nextAfterSequence: 41 },
      savedSchedule.stateToken,
    ),
  ).toThrow("did not advance");
  expect(() =>
    exactScheduleOccurrences(
      { ...page, items: [{ ...occurrenceItem(40), currentPin: false }] },
      savedSchedule.stateToken,
    ),
  ).toThrow("invalid or repeated");
});

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
  const definition = scheduleDefinition("nightly");
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
  await screen.findByText("nightly");
  expect(screen.getByText("margin.calculate")).toBeInTheDocument();
  expect(screen.getByText("Every 1 day")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Open" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Schedule name")).toHaveValue("nightly"),
  );
  expect(screen.getByLabelText("Rule name")).toHaveValue("margin.calculate");
  expect(
    screen.queryByText(/stateToken|programDigest/),
  ).not.toBeInTheDocument();
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
  const definition = scheduleDefinition("nightly");
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
    expect(screen.getByLabelText("Schedule name")).toHaveValue("nightly"),
  );
});

const savedSchedule = {
  scheduleId: "draft",
  stateToken: "b".repeat(64),
  definition: scheduleDefinition("draft"),
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
  expect(screen.queryByLabelText("Schedule name")).not.toBeInTheDocument();
  fireEvent.click(await screen.findByRole("button", { name: "Open" }));
  expect(await screen.findByRole("button", { name: "Activate" })).toBeEnabled();
  fireEvent.change(screen.getByLabelText("Repeat every (minutes)"), {
    target: { value: "60" },
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
  expect(await screen.findByText("Blocked")).toBeVisible();
  expect(screen.getByText(/Target changed; rebind/)).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Open" }));
  expect(await screen.findByText(/target rule changed/i)).toBeVisible();
  expect(screen.getByRole("button", { name: "Activate" })).toBeDisabled();
});

it("preserves a new schedule until its close transition is accepted", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: { schedules: [], nextAfterScheduleId: null },
          }),
        ),
    ),
  );
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
  const newSchedule = screen.getByRole("button", { name: "New schedule" });
  await waitFor(() => expect(newSchedule).toBeEnabled());
  fireEvent.click(newSchedule);
  fireEvent.change(screen.getByLabelText("Schedule name"), {
    target: { value: "draft" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Close editor" }));
  expect(transition).toHaveBeenCalledOnce();
  expect(screen.getByLabelText("Schedule name")).toHaveValue("draft");
  act(() => {
    discardUnsavedWork();
    accept?.();
  });
  expect(screen.queryByLabelText("Schedule name")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
  expect(screen.getByLabelText("Schedule name")).toHaveValue("");
});

it("builds a governed schedule through business fields without exposing version keys", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(url) === "/api/read")
        return new Response(
          JSON.stringify({
            result: {
              defined: true,
              ruleId: "margin.calculate",
              stateToken: "c".repeat(64),
              programDigest: "d".repeat(64),
              status: "Active",
              program: {
                arguments: {
                  parameters: [
                    {
                      name: "Comment",
                      type: "String",
                    },
                    {
                      name: "Scenario",
                      type: "Member",
                      dimensionId: "Scenario",
                      required: false,
                    },
                  ],
                },
              },
            },
          }),
        );
      if (String(url) === "/api/execution-delegation")
        return new Response(
          JSON.stringify({
            result: {
              defined: true,
              delegation: {
                delegation_id: "schedule.authority",
                state_token: "e".repeat(64),
                status: "Active",
                issuer: "https://identity.example.test",
                subject_id: "scheduled-operator",
                operation_scope: ["application.rule.run"],
                valid_from: "2020-01-01T00:00:00Z",
                valid_until: "2099-01-01T00:00:00Z",
                schedule_id: null,
              },
            },
          }),
        );
      expect(body.program.function).toBe("schedule.list");
      return new Response(
        JSON.stringify({
          result: { schedules: [], nextAfterScheduleId: null },
        }),
      );
    }),
  );
  render(<BuildSchedules app={app} catalog={catalog} />);
  const create = screen.getByRole("button", { name: "New schedule" });
  await waitFor(() => expect(create).toBeEnabled());
  fireEvent.click(create);
  expect(
    screen.getByRole("region", { name: "Exact member scope" }),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Add POV member" }),
  ).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/POV 1 member/)).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Schedule name"), {
    target: { value: "nightly.margin" },
  });
  fireEvent.change(screen.getByLabelText("Rule name"), {
    target: { value: "margin.calculate" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Load current rule" }));
  const comment = await screen.findByLabelText("Comment");
  expect(screen.queryByLabelText("Scenario")).not.toBeInTheDocument();
  fireEvent.change(comment, { target: { value: "Nightly margin" } });
  fireEvent.change(screen.getByLabelText("First run (UTC)"), {
    target: { value: "2026-12-01T09:00" },
  });
  fireEvent.change(screen.getByLabelText("Authority name"), {
    target: { value: "schedule.authority" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Load current authority" }),
  );
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled(),
  );
  expect(screen.queryByText("c".repeat(64))).not.toBeInTheDocument();
  expect(screen.queryByText("d".repeat(64))).not.toBeInTheDocument();
  expect(screen.queryByText("e".repeat(64))).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Schedule definition JSON"),
  ).not.toBeInTheDocument();
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
          JSON.stringify({
            result: {
              status: "Saved",
              operationId: body.idempotencyKey,
              scheduleId: "draft",
            },
          }),
        );
      }
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
  const open = await screen.findByRole("button", { name: "Open" });
  await waitFor(() => expect(open).toBeEnabled());
  fireEvent.click(open);
  await screen.findByLabelText("Repeat every (minutes)");
  fireEvent.change(screen.getByLabelText("Repeat every (minutes)"), {
    target: { value: "60" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Response lost");
  expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  expect(screen.getByLabelText("Repeat every (minutes)")).toBeDisabled();
  const clock = vi
    .spyOn(Date, "now")
    .mockReturnValue(Date.now() + 60 * 60 * 1000);
  fireEvent.click(
    screen.getByRole("button", { name: "Reconcile original schedule action" }),
  );
  expect(await screen.findByText("Schedule Saved recorded.")).toBeVisible();
  clock.mockRestore();
  expect(admissions).toBe(1);
  expect(submissions).toHaveLength(2);
  expect(submissions[1]).toEqual(submissions[0]);
  expect(submissions[0].idempotencyKey).toMatch(/^oa1_/);
});

it("keeps an admitted schedule action across catalogue refresh and ignores its canceled acknowledgement", async () => {
  const submissions: Array<{
    body: { idempotencyKey: string };
    signal: AbortSignal | null | undefined;
  }> = [];
  let answerOriginal: ((response: Response) => void) | undefined;
  let admissions = 0;
  const confirmation = (operationId: string) =>
    new Response(
      JSON.stringify({
        result: { status: "Saved", operationId, scheduleId: "draft" },
      }),
    );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: unknown, init?: RequestInit) => {
      if (String(url) === "/api/operation-admission") {
        admissions += 1;
        return operationAdmissionResponse("6");
      }
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "schedule.save") {
        submissions.push({ body, signal: init?.signal });
        if (submissions.length === 1)
          return new Promise<Response>((resolve) => (answerOriginal = resolve));
        if (submissions.length === 2)
          return new Response(
            JSON.stringify({ error: "APPLICATION_SCHEDULE_STALE_CONTEXT" }),
            { status: 409 },
          );
        return confirmation(body.idempotencyKey);
      }
      return new Response(
        JSON.stringify({
          result:
            body.program.function === "schedule.list"
              ? { schedules: [savedSchedule], nextAfterScheduleId: null }
              : { defined: true, schedule: savedSchedule },
        }),
      );
    }),
  );
  const view = render(<BuildSchedules app={app} catalog={catalog} />);
  fireEvent.click(await screen.findByRole("button", { name: "Open" }));
  fireEvent.change(await screen.findByLabelText("Repeat every (minutes)"), {
    target: { value: "61" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(submissions).toHaveLength(1));
  const reader = {
    ...catalog,
    applicationAccess: { ...catalog.applicationAccess, role: "Reader" },
    functions: Object.fromEntries(
      Object.entries(catalog.functions).filter(
        ([name]) =>
          ![
            "schedule.save",
            "schedule.activate",
            "schedule.deactivate",
          ].includes(name),
      ),
    ),
    revisions: {
      ...catalog.revisions,
      security: catalog.revisions.security + 1,
    },
  };
  view.rerender(<BuildSchedules app={app} catalog={reader} />);
  expect(submissions[0].signal?.aborted).toBe(true);
  expect(
    screen.getByRole("button", { name: "Reconcile original schedule action" }),
  ).toBeDisabled();
  expect(
    screen.getByText(
      "Reconciliation is unavailable with the current schedule capabilities.",
    ),
  ).toBeVisible();
  await act(async () =>
    answerOriginal?.(confirmation(submissions[0].body.idempotencyKey)),
  );
  expect(
    screen.queryByText("Schedule Saved recorded."),
  ).not.toBeInTheDocument();
  expect(
    screen.getByRole("region", { name: "Original schedule action" }),
  ).toBeVisible();
  expect(screen.getByLabelText("Repeat every (minutes)")).toHaveValue(61);

  // When the projection is absent, no original schedule data is displayed.
  view.rerender(<BuildSchedules app={app} catalog={null} />);
  expect(
    screen.queryByRole("region", { name: "Original schedule action" }),
  ).not.toBeInTheDocument();
  view.unmount();
  const restored = render(<BuildSchedules app={app} catalog={null} />);
  await act(async () => {});
  restored.rerender(<BuildSchedules app={app} catalog={catalog} />);
  await screen.findByRole("region", { name: "Original schedule action" });
  restored.rerender(
    <BuildSchedules
      app={{ ...app, applicationId: "sibling" }}
      catalog={catalog}
    />,
  );
  await screen.findByRole("button", { name: "Open" });
  expect(
    screen.queryByRole("region", { name: "Original schedule action" }),
  ).not.toBeInTheDocument();
  restored.rerender(<BuildSchedules app={app} catalog={catalog} />);
  const reconcile = await screen.findByRole("button", {
    name: "Reconcile original schedule action",
  });
  await waitFor(() => expect(reconcile).toBeEnabled());
  fireEvent.click(reconcile);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "APPLICATION_SCHEDULE_STALE_CONTEXT",
  );
  expect(
    screen.queryByText("Schedule Saved recorded."),
  ).not.toBeInTheDocument();
  expect(screen.getByLabelText("Repeat every (minutes)")).toHaveValue(61);
  await waitFor(() => expect(reconcile).toBeEnabled());
  fireEvent.click(reconcile);
  expect(await screen.findByText("Schedule Saved recorded.")).toBeVisible();
  expect(admissions).toBe(1);
  expect(submissions.map(({ body }) => body)).toEqual([
    submissions[0].body,
    submissions[0].body,
    submissions[0].body,
  ]);
});

it("keeps the new exact schedule visible when a canceled earlier target returns late", async () => {
  const pending: Array<{
    arguments: { scheduleId: string };
    resolve: (response: Response) => void;
  }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((_url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "schedule.list")
        return Promise.resolve(
          new Response(
            JSON.stringify({
              result: { schedules: [], nextAfterScheduleId: null },
            }),
          ),
        );
      return new Promise<Response>((resolve) => {
        pending.push({
          arguments: body.program.arguments,
          resolve,
        });
      });
    }),
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
  expect(screen.getByLabelText("Schedule name")).toHaveValue("second");
  await act(async () => pending[0].resolve(response("first")));
  expect(screen.getByLabelText("Schedule name")).toHaveValue("second");
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it("refuses schedule save before dispatch when recovery capacity is fully pinned", async () => {
  const effects: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: unknown, init?: RequestInit) => {
      if (String(url) === "/api/operation-admission")
        return operationAdmissionResponse("5");
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "schedule.save")
        effects.push(body.idempotencyKey);
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
  const open = await screen.findByRole("button", { name: "Open" });
  await waitFor(() => expect(open).toBeEnabled());
  fireEvent.click(open);
  await screen.findByLabelText("Repeat every (minutes)");
  fireEvent.change(screen.getByLabelText("Repeat every (minutes)"), {
    target: { value: "60" },
  });
  for (let index = 0; index < 24; index += 1) {
    const pin = renderHook(() =>
      usePreservedDraft(
        "ws",
        "app",
        `pending-${index}`,
        "Unconfirmed operation",
        false,
        { packet: "" },
        () => undefined,
      ),
    );
    act(() => {
      pin.result.current.retain({ packet: `original-${index}` });
    });
    pin.unmount();
  }
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "cannot retain another recovery record",
  );
  expect(effects).toEqual([]);
  expect(
    unsavedWorkSnapshot().filter(
      (item) => item.label === "Unconfirmed operation",
    ),
  ).toHaveLength(24);
});

it("never stores the old actor's schedule proposal or packet under a replacement identity", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: unknown, init?: RequestInit) => {
      if (String(url) === "/api/operation-admission")
        return operationAdmissionResponse("6");
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "schedule.save")
        throw new TypeError("Response lost");
      return new Response(
        JSON.stringify({
          result: body.program.function.endsWith(".list")
            ? { schedules: [savedSchedule], nextAfterScheduleId: null }
            : { defined: true, schedule: savedSchedule },
        }),
      );
    }),
  );
  const forActor = (subjectId: string) => ({
    ...catalog,
    applicationAccess: {
      ...catalog.applicationAccess,
      issuer: "issuer",
      subjectId,
    },
  });
  setDraftIdentity("actor-one");
  const view = render(<BuildSchedules app={app} catalog={forActor("one")} />);
  const open = await screen.findByRole("button", { name: "Open" });
  await waitFor(() => expect(open).toBeEnabled());
  fireEvent.click(open);
  fireEvent.change(await screen.findByLabelText("Repeat every (minutes)"), {
    target: { value: "61" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await screen.findByText("Response lost");
  setDraftIdentity("actor-two");
  view.rerender(<BuildSchedules app={app} catalog={forActor("two")} />);
  await screen.findByRole("button", { name: "Open" });
  expect(
    screen.queryByRole("region", { name: "Original schedule action" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Repeat every (minutes)"),
  ).not.toBeInTheDocument();
  expect(
    unsavedWorkSnapshot().some((item) => item.id.startsWith("actor-two:")),
  ).toBe(false);
  view.unmount();
  const remount = render(
    <BuildSchedules app={app} catalog={forActor("two")} />,
  );
  await screen.findByRole("button", { name: "Open" });
  expect(
    screen.queryByRole("region", { name: "Original schedule action" }),
  ).not.toBeInTheDocument();
  remount.unmount();
  setDraftIdentity("actor-one");
  render(<BuildSchedules app={app} catalog={forActor("one")} />);
  await screen.findByRole("region", { name: "Original schedule action" });
  expect(screen.getByLabelText("Repeat every (minutes)")).toHaveValue(61);
});

it("describes a missing schedule read as unavailable without inventing a denial", () => {
  render(
    <BuildSchedules
      app={app}
      catalog={{ ...catalog, functions: {} }}
      target={{
        scheduleId: "draft",
        stateToken: "a".repeat(64),
        digest: "b".repeat(64),
      }}
    />,
  );
  expect(
    screen.getByText(
      "Schedule inspection is unavailable in the current application context.",
    ),
  ).toBeVisible();
  expect(screen.queryByText(/not authorized/)).not.toBeInTheDocument();
});
