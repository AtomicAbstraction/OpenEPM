import {
  act,
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { useEffect } from "react";
import { afterEach, expect, it, vi } from "vitest";
import {
  BuildRules,
  collectApplicationRules,
  ruleAvailabilityLabel,
  ruleListArguments,
  ruleReadArguments,
  ruleRunBody,
} from "./BuildRules";
import type { RuleSummary } from "./BuildRules";
import { operationAdmissionResponse } from "./test-setup";
import type { ApplicationCatalog } from "./types";
import { ruleValueDigest } from "./application-rule-run";
import {
  usePreservedDraft,
  unsavedWorkSnapshot,
  discardUnsavedWork,
  setDraftIdentity,
} from "./unsaved-work";
vi.mock("./PythonDefinitionEditor", () => ({
  PythonDefinitionEditor: ({
    kind,
    binding,
    onSourceCurrentness,
  }: {
    kind: string;
    binding?: { programId: string };
    onSourceCurrentness?: (state: "current" | "unavailable") => void;
  }) => {
    useEffect(
      () =>
        onSourceCurrentness?.(
          binding?.programId === "stale-source" ? "unavailable" : "current",
        ),
      [binding?.programId, onSourceCurrentness],
    );
    return (
      <div aria-label="Inline Python source">
        {kind}: {binding?.programId || "new"}
      </div>
    );
  },
}));
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "Active",
};
const catalog: ApplicationCatalog = {
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "application.rule.list": {},
    "application.rule.read": {},
    "application.rule.run": {},
    "application.rule.run.read": {},
    "python.program.save": {},
    "python.environment.list": {},
  },
  revisions: {
    metadata: 4,
    policy: 2,
    data: 1,
    security: 1,
    commit: 1,
    schemaEpoch: 1,
  },
};
const row = {
  defined: true,
  valid: true,
  active: true,
  sourceCurrent: true,
  ruleId: "forecast",
  stateToken: "d".repeat(64),
  programDigest: "a".repeat(64),
  metadataCurrent: true,
  status: "Active" as const,
  executable: true,
  reason: null,
} satisfies RuleSummary;
const detail = {
  ...row,
  defined: true,
  program: { function: "application.rule.definition" },
  source: {
    programId: "forecast-source",
    programSourceToken: "c".repeat(64),
    sourceDigest: "b".repeat(64),
    buildId: "build",
    active: true,
  },
};
async function nativeOutcome(
  body: ReturnType<typeof ruleRunBody>,
  changes: Record<string, unknown> = {},
) {
  const bindings = body.program.arguments.bindings;
  const value = {
    workflowId: "1".repeat(32),
    planDigest: "2".repeat(64),
    ruleId: body.program.arguments.ruleId,
    stateToken: body.program.arguments.expectedStateToken,
    status: "running",
    unitCount: 1,
    committedUnits: 0,
    remainingUnits: 1,
    checkpoints: [] as Array<{
      ordinal: number;
      jobId: string;
      committed: boolean;
      receiptId: string | null;
    }>,
    bindings,
    bindingDigest: await ruleValueDigest(bindings),
    argumentsDigest: await ruleValueDigest({
      ruleId: body.program.arguments.ruleId,
      bindings,
    }),
    ...changes,
  };
  if (value.status === "published" && changes.checkpoints === undefined) {
    value.checkpoints = [
      { ordinal: 1, jobId: "child-1", committed: true, receiptId: "child-1" },
    ];
    value.committedUnits = 1;
    value.remainingUnits = 0;
  }
  return value;
}
async function nativeLineage(
  body: ReturnType<typeof ruleRunBody>,
  changes: Record<string, unknown> = {},
) {
  const value = await nativeOutcome(body, changes);
  return {
    ...value,
    sealedPlanDigest: value.planDigest,
    publishedRule: {
      ruleId: value.ruleId,
      stateToken: value.stateToken,
      programDigest: body.program.arguments.expectedProgramDigest,
    },
    freshness: { current: false, staleReasons: ["publication"] },
    lineageComplete: value.status === "published",
    lineage: [
      {
        ordinal: 1,
        unitName: "unit",
        function: "facts.numeric.batch",
        jobId: value.checkpoints[0]?.jobId ?? null,
        jobStatus: value.status === "published" ? "published" : "not_admitted",
        committed: value.checkpoints[0]?.committed ?? false,
        receiptId: value.checkpoints[0]?.receiptId ?? null,
        receiptRevision: value.status === "published" ? 1 : null,
      },
    ],
    ...changes,
  };
}
const page = (rows: RuleSummary[] = [row], next: string | null = null) => ({
  rows,
  nextAfterRuleId: next,
  hasMore: next !== null,
  metadataRevision: 4,
  policyRevision: 2,
});
it("reads all application rules with revision-pinned pagination and rejects drifting or duplicate pages", async () => {
  const collected = await collectApplicationRules(async (args) => {
    const start = "afterRuleId" in args ? Number(args.afterRuleId) : 0;
    const rows = Array.from({ length: 100 }, (_, index) => ({
      ...row,
      ruleId: String(start + index + 1),
    }));
    return page(rows, start < 2500 ? String(start + 100) : null);
  });
  expect(collected.rows).toHaveLength(2600);
  for (const second of [
    page([{ ...row, stateToken: "c".repeat(64) }]),
    { ...page([{ ...row, ruleId: "other" }]), policyRevision: 3 },
    {
      ...page([{ ...row, ruleId: "other" }]),
      hasMore: false,
      nextAfterRuleId: "again",
    },
  ]) {
    let calls = 0;
    await expect(
      collectApplicationRules(async (args) => {
        if (++calls === 1) return page([row], "forecast");
        expect(args).toEqual({
          limit: 100,
          afterRuleId: "forecast",
          expectedMetadataRevision: 4,
          expectedPolicyRevision: 2,
        });
        return second;
      }),
    ).rejects.toThrow();
  }
});
it("rejects an unfinished page without a cursor bound to its last row", async () => {
  for (const first of [
    { ...page([row]), hasMore: true },
    page([], "forecast"),
    page([row], "different-rule"),
  ]) {
    const fetchPage = vi.fn(async () => first);
    await expect(collectApplicationRules(fetchPage)).rejects.toThrow(
      "Application rules continuation status is inconsistent.",
    );
    expect(fetchPage).toHaveBeenCalledTimes(1);
  }
  expect((await collectApplicationRules(async () => page([]))).rows).toEqual(
    [],
  );
});
it("continues an ordered-rule query with the exact collection token and rejects a changed cut", async () => {
  const collectionToken = "a".repeat(64);
  const secondRow = { ...row, ruleId: "second" };
  for (const secondToken of [collectionToken, "b".repeat(64), undefined]) {
    const fetchPage = vi
      .fn()
      .mockResolvedValueOnce({ ...page([row], row.ruleId), collectionToken })
      .mockResolvedValueOnce({
        ...page([secondRow]),
        collectionToken: secondToken,
      });
    const result = collectApplicationRules(fetchPage, "facts.numeric.sequence");
    if (secondToken === collectionToken) {
      expect((await result).rows).toEqual([row, secondRow]);
    } else {
      await expect(result).rejects.toThrow();
    }
    expect(fetchPage).toHaveBeenNthCalledWith(1, {
      limit: 100,
      containsOperation: "facts.numeric.sequence",
    });
    expect(fetchPage).toHaveBeenNthCalledWith(2, {
      limit: 100,
      containsOperation: "facts.numeric.sequence",
      afterRuleId: row.ruleId,
      expectedMetadataRevision: 4,
      expectedPolicyRevision: 2,
      collectionToken,
    });
  }
});
it("offers the ordered filter when advertised and reads the selected subset through the shared directory", async () => {
  const filteredCatalog = {
    ...catalog,
    functions: {
      ...catalog.functions,
      "application.rule.list": {
        programSchema: {
          properties: {
            arguments: {
              properties: { containsOperation: { type: "string" } },
            },
          },
        },
      },
    },
  };
  const fetchPage = vi.fn(async (_url, init) => {
    const body = JSON.parse(String(init?.body));
    expect(body.program.function).toBe("application.rule.list");
    return new Response(
      JSON.stringify({
        result: {
          ...page(body.program.arguments.containsOperation ? [] : [row]),
          collectionToken: "a".repeat(64),
        },
      }),
    );
  });
  vi.stubGlobal("fetch", fetchPage);
  render(<BuildRules app={app} catalog={filteredCatalog} />);
  await screen.findByRole("button", { name: row.ruleId });
  const selector = screen.getByRole("combobox", { name: "Rule operations" });
  fireEvent.change(selector, { target: { value: "ordered" } });
  await screen.findByText(
    "No current rules contain ordered numeric sequences.",
  );
  expect(screen.queryByRole("button", { name: row.ruleId })).toBeNull();
  expect(JSON.parse(fetchPage.mock.calls[1][1].body).program.arguments).toEqual(
    {
      limit: 100,
      containsOperation: "facts.numeric.sequence",
    },
  );
  fireEvent.change(selector, { target: { value: "all" } });
  await screen.findByRole("button", { name: row.ruleId });
  fireEvent.change(selector, { target: { value: "batch" } });
  await screen.findByText("No current rules contain numeric batches.");
  expect(
    JSON.parse(fetchPage.mock.calls.at(-1)![1].body).program.arguments,
  ).toEqual({
    limit: 100,
    containsOperation: "facts.numeric.batch",
  });
});
it.each([false, true])(
  "can open a known rule after a list request is interrupted (earlier page %s)",
  async (earlier) => {
    const calls: Record<string, unknown>[] = [];
    const earlierRule = { ...row, ruleId: "earlier-rule" };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url, init) => {
        const body = JSON.parse(init.body).program;
        calls.push(body);
        if (body.function === "application.rule.list") {
          if (earlier && !body.arguments.afterRuleId)
            return Response.json({
              result: page([earlierRule], earlierRule.ruleId),
            });
          return Response.json({ code: "PROCESSING_BUSY" }, { status: 503 });
        }
        expect(body).toEqual({
          languageVersion: 2,
          function: "application.rule.read",
          arguments: { ruleId: "forecast" },
        });
        return Response.json({ result: detail });
      }),
    );
    render(<BuildRules app={app} catalog={catalog} />);
    await screen.findByText(/The rule list could not be completed/);
    expect(
      Boolean(screen.queryByRole("button", { name: "earlier-rule" })),
    ).toBe(earlier);
    expect(screen.queryByText("No current application rules.")).toBeNull();
    fireEvent.change(screen.getByLabelText("Exact rule ID"), {
      target: { value: "forecast" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Open rule by ID" }));
    expect(
      await screen.findByLabelText("Application rule detail"),
    ).toBeVisible();
    expect(
      calls.filter(({ function: name }) => name === "application.rule.list"),
    ).toHaveLength(earlier ? 2 : 1);
    expect(
      screen.getByText(/The rule list could not be completed/),
    ).toBeVisible();
  },
);

it("shows only permitted group rules and continues using the last visible rule", async () => {
  const token = "a".repeat(64);
  const first = { ...row, ruleId: "press-replenishment" };
  const second = { ...row, ruleId: "year-end-forecast" };
  const requests: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const raw = JSON.parse(init.body).program;
      expect(raw.function).toBe("application.rule.list");
      requests.push(raw.arguments);
      const response = raw.arguments.afterRuleId
        ? page([second])
        : page([first], first.ruleId);
      return Response.json({ result: { ...response, collectionToken: token } });
    }),
  );
  render(
    <BuildRules
      app={app}
      catalog={{
        ...catalog,
        applicationAccess: {
          ...catalog.applicationAccess,
          authorizationModel: "group_assignments",
          role: "Assigned",
          roles: ["Planner"],
        },
      }}
    />,
  );
  expect(
    await screen.findByRole("button", { name: first.ruleId }),
  ).toBeVisible();
  expect(screen.getByRole("button", { name: second.ruleId })).toBeVisible();
  expect(screen.queryByText(/rule list could not be completed/)).toBeNull();
  expect(requests).toEqual([
    { limit: 100 },
    {
      limit: 100,
      afterRuleId: first.ruleId,
      expectedMetadataRevision: 4,
      expectedPolicyRevision: 2,
      collectionToken: token,
    },
  ]);
});

it("preserves an equivalent unavailable outcome for missing and restricted IDs without using list permission", async () => {
  const ids: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const raw = JSON.parse(init.body).program;
      expect(raw.function).toBe("application.rule.read");
      ids.push(raw.arguments.ruleId);
      return raw.arguments.ruleId === "restricted"
        ? Response.json(
            { code: "RULE_RUN_TARGET_UNAVAILABLE" },
            { status: 403 },
          )
        : Response.json({
            result: { ruleId: "missing", defined: false, stateToken: null },
          });
    }),
  );
  render(
    <BuildRules
      app={app}
      catalog={{ ...catalog, functions: { "application.rule.read": {} } }}
    />,
  );
  for (const id of ["missing", "restricted"]) {
    fireEvent.change(screen.getByLabelText("Exact rule ID"), {
      target: { value: id },
    });
    fireEvent.click(screen.getByRole("button", { name: "Open rule by ID" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The exact application rule is unavailable.",
    );
    expect(screen.queryByLabelText("Application rule detail")).toBeNull();
  }
  expect(ids).toEqual(["missing", "restricted"]);
});

it("ignores a late exact read when the user opens a different rule", async () => {
  let finish: (value: Response) => void = () => {};
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const id = JSON.parse(init.body).program.arguments.ruleId;
      if (id === "delayed")
        return new Promise<Response>((resolve) => {
          finish = resolve;
        });
      return Response.json({ result: { ...detail, ruleId: id } });
    }),
  );
  render(
    <BuildRules
      app={app}
      catalog={{ ...catalog, functions: { "application.rule.read": {} } }}
    />,
  );
  for (const id of ["delayed", "current"]) {
    fireEvent.change(screen.getByLabelText("Exact rule ID"), {
      target: { value: id },
    });
    fireEvent.click(screen.getByRole("button", { name: "Open rule by ID" }));
  }
  const current = await screen.findByLabelText("Application rule detail");
  expect(
    within(current).getByRole("heading", { name: "current" }),
  ).toBeVisible();
  await act(async () =>
    finish(Response.json({ result: { ...detail, ruleId: "delayed" } })),
  );
  expect(
    within(current).getByRole("heading", { name: "current" }),
  ).toBeVisible();
  expect(current).not.toHaveTextContent("delayed");
});

it.each([
  ["STALE_EXPRESSION_RULE_LIST_REVISION", 409],
  ["APPLICATION_GRANT_REQUIRED", 403],
] as const)(
  "removes the earlier page when the next page invalidates its access or revision (%s)",
  async (code, status) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url, init) => {
        const { arguments: args } = JSON.parse(init.body).program;
        return args.afterRuleId
          ? Response.json({ code }, { status })
          : Response.json({ result: page([row], row.ruleId) });
      }),
    );
    render(<BuildRules app={app} catalog={catalog} />);
    await screen.findByRole("alert");
    expect(screen.queryByText(/Earlier pages are available/)).toBeNull();
    expect(screen.queryByRole("button", { name: "forecast" })).toBeNull();
  },
);

it("rejects invalid revision pins before attempting a continuation", async () => {
  for (const first of [
    { ...page([row], "forecast"), metadataRevision: -1 },
    { ...page([row], "forecast"), policyRevision: Number.NaN },
  ]) {
    const fetchPage = vi.fn(async () => first);
    await expect(collectApplicationRules(fetchPage)).rejects.toThrow(
      "Application rules revisions are invalid.",
    );
    expect(fetchPage).toHaveBeenCalledTimes(1);
  }
});
it("fails closed instead of inventing a Saved label for malformed rule state", async () => {
  for (const status of [undefined, "Saved", "Unknown"]) {
    await expect(
      collectApplicationRules(async () => {
        const malformed = page([{ ...row }]);
        (malformed.rows[0] as unknown as { status?: string }).status = status;
        return malformed;
      }),
    ).rejects.toThrow("Application rule summary is invalid.");
  }
});
it("explains effective lifecycle state instead of presenting an ambiguous saved rule", async () => {
  const unavailable: RuleSummary = {
    ...row,
    ruleId: "legacy-rule.1",
    status: "Unavailable" as const,
    valid: false,
    active: false,
    sourceCurrent: false,
    executable: false,
    reason: "ownership_unresolved" as const,
  };
  const awaitingValidation: RuleSummary = {
    ...row,
    ruleId: "current-rule",
    status: "Inactive" as const,
    valid: false,
    active: false,
    executable: false,
    reason: "validation_required" as const,
  };
  expect(ruleAvailabilityLabel(unavailable)).toBe(
    "Output ownership unresolved",
  );
  expect(ruleAvailabilityLabel(awaitingValidation)).toBe(
    "Current definition validation required",
  );
  for (const malformed of [
    { ...unavailable, reason: null },
    { ...awaitingValidation, executable: true },
    { ...row, reason: "ownership_unresolved" as const },
  ]) {
    await expect(
      collectApplicationRules(async () =>
        page([malformed as unknown as RuleSummary]),
      ),
    ).rejects.toThrow("Application rule summary is invalid.");
  }
});

it.each([
  "metadata_stale",
  "schema_stale",
  "dependency_stale",
  "source_environment_stale",
  "compiler_unavailable",
] as const)(
  "keeps an Active %s owner inspectable without enabling execution",
  async (reason) => {
    const stale: RuleSummary = {
      ...row,
      valid: false,
      executable: false,
      reason,
    };
    expect(
      (await collectApplicationRules(async () => page([stale]))).rows,
    ).toEqual([stale]);
    const effects: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url, init) => {
        const body = JSON.parse(String(init?.body));
        if (body.program.function === "application.rule.list")
          return new Response(JSON.stringify({ result: page([stale]) }));
        if (body.program.function === "application.rule.read")
          return new Response(
            JSON.stringify({ result: { ...detail, ...stale } }),
          );
        effects.push(body);
        throw new Error("A stale owner must not be dispatched");
      }),
    );
    render(
      <BuildRules
        app={app}
        catalog={catalog}
        targetApplicationRule={{
          ruleId: row.ruleId,
          stateToken: row.stateToken,
          digest: row.programDigest,
        }}
      />,
    );
    expect(
      await screen.findByLabelText("Current rule availability"),
    ).toHaveTextContent(ruleAvailabilityLabel(stale));
    await screen.findByLabelText("Inline Python source");
    const run = screen.getByRole("button", { name: "Run rule" });
    expect(run).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(run);
    expect(effects).toEqual([]);
  },
);

it("opens the current inactive source without inventing a compiled payload after Save", async () => {
  const inactive: RuleSummary = {
    ...row,
    status: "Inactive",
    valid: false,
    active: false,
    executable: false,
    reason: "validation_required",
    programDigest: null,
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(String(init?.body));
      return new Response(
        JSON.stringify({
          result:
            body.program.function === "application.rule.list"
              ? page([inactive])
              : {
                  ...detail,
                  ...inactive,
                  program: null,
                  source: { ...detail.source, active: false, buildId: null },
                },
        }),
      );
    }),
  );
  render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  await screen.findByText(/No current compiled rule is available/);
  expect(screen.getByLabelText("Inline Python source")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Run rule" })).toHaveAttribute(
    "aria-disabled",
    "true",
  );
});
it("preserves exact read and governed compiled rule run contracts", () => {
  expect(ruleListArguments()).toEqual({ limit: 100 });
  expect(ruleReadArguments("forecast")).toEqual({
    ruleId: "forecast",
  });
  expect(
    ruleRunBody(
      app,
      "forecast",
      { ratio: "2" },
      "run-key",
      row.stateToken,
      row.programDigest,
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "run-key",
    program: {
      languageVersion: 2,
      function: "application.rule.run",
      arguments: {
        ruleId: "forecast",
        bindings: { ratio: "2" },
        expectedStateToken: row.stateToken,
        expectedProgramDigest: row.programDigest,
      },
    },
  });
});
it.each(["application.rule.list", "application.rule.read"])(
  "clears the rule list and source after changed authority on %s",
  async (interrupted) => {
    let changed = false;
    const calls: string[] = [];
    const message =
      "Rule access changed while loading. Choose Refresh rules to check current access.";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url, init) => {
        const { program } = JSON.parse(String(init?.body));
        calls.push(program.function);
        if (changed && program.function === interrupted)
          return Response.json(
            { code: "RULE_READ_AUTHORIZATION_STALE", message },
            { status: 409 },
          );
        return Response.json({
          result:
            program.function === "application.rule.list" ? page() : detail,
        });
      }),
    );
    render(<BuildRules app={app} catalog={catalog} />);
    const rule = await screen.findByRole("button", { name: "forecast" });
    if (interrupted === "application.rule.list") {
      fireEvent.click(rule);
      await screen.findByLabelText("Inline Python source");
      changed = true;
      fireEvent.click(screen.getByRole("button", { name: "Refresh rules" }));
    } else {
      changed = true;
      fireEvent.click(rule);
    }
    expect(await screen.findByRole("alert")).toHaveTextContent(message);
    expect(screen.queryByLabelText("Inline Python source")).toBeNull();
    expect(screen.queryByRole("button", { name: "forecast" })).toBeNull();

    changed = false;
    fireEvent.click(screen.getByRole("button", { name: "Refresh rules" }));
    fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
    expect(
      await screen.findByLabelText("Inline Python source"),
    ).toHaveTextContent("forecast-source");
    expect(new Set(calls)).toEqual(
      new Set(["application.rule.list", "application.rule.read"]),
    );
  },
);

it("loads rules automatically, opens exact source inline, and hides compiled internals", async () => {
  const calls: { program: { function: string; arguments: unknown } }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const body = JSON.parse(init.body);
      calls.push(body);
      return new Response(
        JSON.stringify({
          result: body.program.function.endsWith(".list") ? page() : detail,
        }),
      );
    }),
  );
  render(<BuildRules app={app} catalog={catalog} />);
  expect(await screen.findByText("Executable")).toBeVisible();
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  expect(
    await screen.findByLabelText("Inline Python source"),
  ).toHaveTextContent("ApplicationRule: forecast-source");
  expect(
    screen.queryByText("Compiled rule inspection"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Compiled application rule"),
  ).not.toBeInTheDocument();
  expect(calls[1].program).toEqual({
    languageVersion: 2,
    function: "application.rule.read",
    arguments: { ruleId: "forecast" },
  });
  expect(
    screen.queryByRole("button", { name: /Save immutable/ }),
  ).not.toBeInTheDocument();
});
it("requires the exact workflow artifact digest and guards source-editor transitions", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: { ...detail, programDigest: "c".repeat(64) },
          }),
        ),
    ),
  );
  const transition = vi.fn();
  render(
    <BuildRules
      app={app}
      catalog={catalog}
      targetApplicationRule={{
        ruleId: "forecast",
        stateToken: row.stateToken,
        digest: row.programDigest,
      }}
      onRequestTransition={transition}
    />,
  );
  await screen.findByText("The exact application rule is unavailable.");
  expect(
    screen.queryByLabelText("Inline Python source"),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "New rule" }));
  expect(transition).toHaveBeenCalledOnce();
  await act(async () => transition.mock.calls[0][0]());
  expect(screen.getByLabelText("Inline Python source")).toHaveTextContent(
    "ApplicationRule: new",
  );
});
it("preserves unrelated drafts only when New rule opens a blank local editor", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify({ result: page() }))),
  );
  const transition = vi.fn((action: () => void, _preserveDrafts?: boolean) =>
    action(),
  );
  render(
    <BuildRules app={app} catalog={catalog} onRequestTransition={transition} />,
  );
  const create = screen.getByRole("button", { name: "New rule" });
  await waitFor(() => expect(create).toBeEnabled());
  fireEvent.click(create);
  expect(transition.mock.calls[0][1]).toBe(true);
  fireEvent.click(create);
  expect(transition.mock.calls[1][1]).toBe(false);
  fireEvent.click(screen.getByRole("button", { name: "Close rule" }));
  expect(transition.mock.calls[2][1]).toBeUndefined();
});
it("guards New rule when replacing a selected rule or retained unsent parameters after remount", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(String(init?.body));
      return new Response(
        JSON.stringify({
          result: body.program.function.endsWith(".list") ? page() : detail,
        }),
      );
    }),
  );
  const transition = vi.fn((action: () => void, _preserveDrafts?: boolean) =>
    action(),
  );
  const first = render(
    <BuildRules app={app} catalog={catalog} onRequestTransition={transition} />,
  );
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  const parameters = await screen.findByLabelText(
    "Application rule parameters",
  );
  transition.mockImplementation(() => undefined);
  fireEvent.click(screen.getByRole("button", { name: "New rule" }));
  expect(transition.mock.calls.at(-1)?.[1]).toBe(false);
  fireEvent.change(parameters, { target: { value: '{"factor":"2"}' } });
  await waitFor(() => expect(unsavedWorkSnapshot()).toHaveLength(1));
  first.unmount();
  render(
    <BuildRules app={app} catalog={catalog} onRequestTransition={transition} />,
  );
  await screen.findByRole("button", { name: "forecast" });
  expect(
    screen.queryByLabelText("Application rule detail"),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "New rule" }));
  expect(transition.mock.calls.at(-1)?.[1]).toBe(false);
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});
it("does not present a stale bound source as a runnable active rule", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              ...detail,
              source: { ...detail.source, programId: "stale-source" },
            },
          }),
        ),
    ),
  );
  render(
    <BuildRules
      app={app}
      catalog={catalog}
      targetApplicationRule={{
        ruleId: row.ruleId,
        stateToken: row.stateToken,
        digest: row.programDigest,
      }}
    />,
  );
  expect(
    await screen.findByText(
      "The rule's bound source is unavailable or stale; refresh the exact current source before running.",
    ),
  ).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Run rule" })).toHaveAttribute(
    "aria-disabled",
    "true",
  );
});
it("ignores a superseded rule read when another application is opened", async () => {
  const finishes: ((value: Response) => void)[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          finishes.push(resolve);
        }),
    ),
  );
  const { rerender } = render(<BuildRules app={app} catalog={catalog} />);
  await waitFor(() => expect(finishes).toHaveLength(1));
  rerender(
    <BuildRules app={{ ...app, applicationId: "other" }} catalog={catalog} />,
  );
  await waitFor(() => expect(finishes).toHaveLength(2));
  await act(async () =>
    finishes[0](new Response(JSON.stringify({ result: page() }))),
  );
  await waitFor(() =>
    expect(
      screen.queryByRole("button", { name: "forecast" }),
    ).not.toBeInTheDocument(),
  );
});
it("removes already loaded rule and source state when the application changes", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const body = JSON.parse(init.body);
      return new Response(
        JSON.stringify({
          result: body.program.function.endsWith(".list") ? page() : detail,
        }),
      );
    }),
  );
  const view = render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  await screen.findByLabelText("Application rule detail");
  view.rerender(
    <BuildRules app={{ ...app, applicationId: "other" }} catalog={catalog} />,
  );
  expect(
    screen.queryByRole("button", { name: "forecast" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Application rule detail"),
  ).not.toBeInTheDocument();
});
it("runs an eligible publication and follows its owner lineage without requesting the Python source", async () => {
  const functions = Object.fromEntries(
    [
      "application.rule.list",
      "application.rule.read",
      "application.rule.run",
      "application.rule.run.read",
    ].map((name) => [name, {}]),
  );
  const calls: string[] = [];
  let original: ReturnType<typeof ruleRunBody>;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      const body = JSON.parse(init.body);
      if (url === "/api/operation-admission")
        return operationAdmissionResponse("1");
      const name = body.program.function;
      calls.push(name);
      let result;
      if (name === "application.rule.list") result = page();
      else if (name === "application.rule.read") result = detail;
      else if (name === "application.rule.run") {
        expect(url).toBe("/api/rule-action");
        original = body;
        result = await nativeOutcome(body);
      } else if (name === "application.rule.run.read") {
        expect(body.program.arguments).toEqual({ workflowId: "1".repeat(32) });
        result = await nativeLineage(original, { status: "published" });
      } else {
        throw new Error(`Runner requested an unavailable function: ${name}`);
      }
      return Response.json({ result });
    }),
  );
  render(
    <BuildRules
      app={app}
      catalog={{
        ...catalog,
        functions,
        applicationAccess: {
          role: "Assigned",
          authorizationModel: "group_assignments",
          workspaceAdministrator: false,
        },
      }}
    />,
  );
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  const run = await screen.findByRole("button", { name: "Run rule" });
  expect(run).not.toHaveAttribute("aria-disabled");
  expect(
    screen.queryByLabelText("Inline Python source"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "New rule" }),
  ).not.toBeInTheDocument();
  fireEvent.click(run);
  fireEvent.click(
    await screen.findByRole("button", { name: "Refresh original run status" }),
  );
  expect(await screen.findByText(/Rule run published/)).toHaveTextContent(
    "1 receipt-confirmed committed units",
  );
  expect(calls).toEqual(Object.keys(functions));
});

it("runs the exact compiled workflow through its supported route and preserves lost-response replay", async () => {
  const submissions: Record<string, unknown>[] = [];
  let admission = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      if (String(url) === "/api/operation-admission")
        return operationAdmissionResponse(String(++admission));
      const body = JSON.parse(init.body);
      if (body.program.function === "application.rule.run") {
        expect(url).toBe("/api/rule-action");
        submissions.push(body);
        if (submissions.length === 1) throw new TypeError("Response lost");
        return new Response(
          JSON.stringify({
            result: await nativeOutcome(body, { status: "published" }),
          }),
        );
      }
      if (body.program.function === "application.rule.run.read") {
        expect(body.program.arguments.originalRequest).toEqual({
          program: submissions[0].program,
          idempotencyKey: submissions[0].idempotencyKey,
        });
        return originalRuleUnavailable();
      }
      return new Response(
        JSON.stringify({
          result: body.program.function.endsWith(".list") ? page() : detail,
        }),
      );
    }),
  );
  render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  const run = await screen.findByRole("button", { name: "Run rule" });
  await waitFor(() => expect(run).not.toHaveAttribute("aria-disabled"));
  fireEvent.click(run);
  await screen.findByText("Response lost");
  fireEvent.click(
    screen.getByRole("button", { name: "Read original rule outcome" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Retry original rule request" }),
  );
  await screen.findByText(/Rule run published/);
  expect(screen.getByText(/Rule run published/)).toHaveTextContent(
    "1 receipt-confirmed committed units",
  );
  expect(
    screen.queryByText(/Cancellation reconciliation is still pending/),
  ).not.toBeInTheDocument();
  expect(screen.getByText("Every unit has a confirmed receipt.")).toBeVisible();
  expect(screen.queryByText(/unresolved work/)).not.toBeInTheDocument();
  expect(
    screen.queryByText(/These counts do not claim rollback/),
  ).not.toBeInTheDocument();
  expect(screen.queryByText(/^accepted$/)).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Application rule run result"),
  ).not.toBeInTheDocument();
  expect(submissions[1]).toEqual(submissions[0]);
  expect(submissions[0]).toMatchObject({
    program: {
      function: "application.rule.run",
      arguments: {
        expectedStateToken: row.stateToken,
        expectedProgramDigest: row.programDigest,
      },
    },
  });
  expect(screen.getByRole("button", { name: "Run rule" })).toHaveAttribute(
    "aria-disabled",
    "true",
  );
  fireEvent.click(screen.getByRole("button", { name: "Prepare another run" }));
  fireEvent.click(screen.getByRole("button", { name: "Run rule" }));
  await waitFor(() => expect(submissions).toHaveLength(3));
  expect(submissions[2].idempotencyKey).not.toEqual(
    submissions[1].idempotencyKey,
  );
});

it("shows the refresh failure without presenting a partial or previous list as current", async () => {
  const responses = [
    page([row]),
    { ...page([{ ...row, ruleId: "partial-rule" }]), hasMore: true },
    page([]),
  ];
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () => new Response(JSON.stringify({ result: responses.shift() })),
    ),
  );
  render(<BuildRules app={app} catalog={catalog} />);
  expect(await screen.findByRole("button", { name: "forecast" })).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Refresh rules" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Application rules continuation status is inconsistent.",
  );
  expect(screen.queryByRole("button", { name: "forecast" })).toBeNull();
  expect(screen.queryByRole("button", { name: "partial-rule" })).toBeNull();
  expect(screen.queryByText("No current application rules.")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Refresh rules" }));
  expect(
    await screen.findByText("No current application rules."),
  ).toBeVisible();
  expect(screen.queryByRole("alert")).toBeNull();
});

it.each(["identity", "grant", "capability"])(
  "fences pending rule reads when the %s context changes",
  async (kind) => {
    const pending: ((response: Response) => void)[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(() => new Promise<Response>((resolve) => pending.push(resolve))),
    );
    const view = render(<BuildRules app={app} catalog={catalog} />);
    await waitFor(() => expect(pending).toHaveLength(1));
    const changed: ApplicationCatalog = {
      ...catalog,
      applicationAccess:
        kind === "identity"
          ? { ...catalog.applicationAccess, subjectId: "another-user" }
          : catalog.applicationAccess,
      revisions:
        kind === "grant"
          ? { ...catalog.revisions, security: 2 }
          : catalog.revisions,
      functions: kind === "capability" ? {} : catalog.functions,
    };
    view.rerender(<BuildRules app={app} catalog={changed} />);
    await act(async () =>
      pending[0](new Response(JSON.stringify({ result: page() }))),
    );
    expect(
      screen.queryByRole("button", { name: "forecast" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(/No current application rules/),
    ).not.toBeInTheDocument();
    if (kind === "capability") {
      expect(
        screen.getByText(
          /Calculation rules are not available in the current application context/,
        ),
      ).toBeVisible();
      expect(pending).toHaveLength(1);
    } else {
      await waitFor(() => expect(pending).toHaveLength(2));
      await act(async () =>
        pending[1](new Response(JSON.stringify({ result: page([]) }))),
      );
      expect(
        await screen.findByText(/No current application rules/),
      ).toBeVisible();
    }
  },
);

it("hides loaded rule and source details immediately when access changes", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      return new Response(
        JSON.stringify({
          result: body.program.function.endsWith(".list") ? page() : detail,
        }),
      );
    }),
  );
  const view = render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  await screen.findByLabelText("Application rule detail");
  view.rerender(
    <BuildRules
      app={app}
      catalog={{
        ...catalog,
        functions: {},
        revisions: { ...catalog.revisions, security: 2 },
      }}
    />,
  );
  expect(
    screen.queryByRole("button", { name: "forecast" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Application rule detail"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Inline Python source"),
  ).not.toBeInTheDocument();
});

it.each(["success", "denial"])(
  "ignores a late rule run %s after identity changes",
  async (outcome) => {
    let finish: ((response: Response) => void) | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url, init) => {
        if (String(url) === "/api/operation-admission")
          return operationAdmissionResponse(`late-${outcome}`);
        const body = JSON.parse(init.body);
        if (body.program.function === "application.rule.run")
          return new Promise<Response>((resolve) => {
            finish = resolve;
          });
        return new Response(
          JSON.stringify({
            result: body.program.function.endsWith(".list") ? page() : detail,
          }),
        );
      }),
    );
    const view = render(<BuildRules app={app} catalog={catalog} />);
    fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
    const run = await screen.findByRole("button", { name: "Run rule" });
    await waitFor(() => expect(run).not.toHaveAttribute("aria-disabled"));
    fireEvent.click(run);
    await waitFor(() => expect(finish).toBeTypeOf("function"));
    view.rerender(
      <BuildRules
        app={app}
        catalog={{
          ...catalog,
          applicationAccess: {
            ...catalog.applicationAccess,
            subjectId: "different-user",
          },
          functions: {},
        }}
      />,
    );
    await act(async () =>
      finish!(
        outcome === "success"
          ? new Response(
              JSON.stringify({
                result: {
                  workflowId: "private-original-workflow",
                  status: "running",
                },
              }),
            )
          : new Response(JSON.stringify({ error: "private-original-denial" }), {
              status: 403,
            }),
      ),
    );
    expect(screen.queryByText(/Rule run accepted/)).not.toBeInTheDocument();
    expect(screen.queryByText(/private-original/)).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText("Application rule detail"),
    ).not.toBeInTheDocument();
  },
);

it("retains same-owner parameters after grant refresh but clears them for another identity", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      return new Response(
        JSON.stringify({
          result: body.program.function.endsWith(".list") ? page() : detail,
        }),
      );
    }),
  );
  const view = render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  const parameters = await screen.findByLabelText(
    "Application rule parameters",
  );
  fireEvent.change(parameters, { target: { value: '{"ratio":"1.25"}' } });
  const revised = {
    ...catalog,
    revisions: { ...catalog.revisions, security: 2 },
  };
  view.rerender(<BuildRules app={app} catalog={revised} />);
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  expect(
    await screen.findByLabelText("Application rule parameters"),
  ).toHaveValue('{"ratio":"1.25"}');
  view.rerender(
    <BuildRules
      app={app}
      catalog={{
        ...revised,
        applicationAccess: { ...catalog.applicationAccess, subjectId: "other" },
      }}
    />,
  );
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  expect(
    await screen.findByLabelText("Application rule parameters"),
  ).toHaveValue("{}");
});

function installRunFixture(
  handler: (
    body: ReturnType<typeof ruleRunBody>,
    call: number,
  ) => Promise<unknown>,
) {
  const writes: Array<ReturnType<typeof ruleRunBody>> = [];
  const reads: Array<Record<string, unknown>> = [];
  let admissions = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      if (String(url) === "/api/operation-admission")
        return operationAdmissionResponse((++admissions).toString(16));
      const body = JSON.parse(String(init?.body));
      const fn = body.program.function;
      if (fn === "application.rule.run") {
        writes.push(body);
        const value = await handler(body, writes.length);
        return value instanceof Response
          ? value
          : new Response(JSON.stringify({ result: value }));
      }
      if (fn === "application.rule.run.read") {
        reads.push(body);
        const value = await handler(body, -reads.length);
        return value instanceof Response
          ? value
          : new Response(JSON.stringify({ result: value }));
      }
      return new Response(
        JSON.stringify({ result: fn.endsWith(".list") ? page() : detail }),
      );
    }),
  );
  return { writes, reads, admissions: () => admissions };
}
function originalRuleUnavailable() {
  return new Response(
    JSON.stringify({ code: "APPLICATION_RULE_WORKFLOW_UNAVAILABLE" }),
    { status: 400 },
  );
}
async function startRunFixture() {
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  const run = await screen.findByRole("button", { name: "Run rule" });
  await waitFor(() => expect(run).not.toHaveAttribute("aria-disabled"));
  fireEvent.click(run);
}

it("reports the active submission and keeps the keyboard path through read-only recovery", async () => {
  let lose!: (error: Error) => void;
  let settle!: (value: unknown) => void;
  const calls = installRunFixture(async (_body, sequence) => {
    if (sequence > 0)
      return new Promise((_resolve, reject) => {
        lose = reject;
      });
    return new Promise((resolve) => {
      settle = resolve;
    });
  });
  render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  const run = await screen.findByRole("button", { name: "Run rule" });
  await waitFor(() => expect(run).not.toHaveAttribute("aria-disabled"));
  run.focus();
  fireEvent.click(run);
  await waitFor(() => expect(calls.writes).toHaveLength(1));
  expect(
    screen.getByText("Waiting for the rule run acknowledgement…"),
  ).toBeVisible();
  expect(
    screen.queryByText(/Rule run outcome unknown/),
  ).not.toBeInTheDocument();
  expect(run).toHaveFocus();
  expect(run).toHaveAttribute("aria-disabled", "true");
  expect(run).toHaveAttribute("tabindex", "-1");
  fireEvent.click(run);
  expect(calls.writes).toHaveLength(1);

  await act(async () => lose(new TypeError("Lost run acknowledgement")));
  const check = screen.getByRole("button", {
    name: "Read original rule outcome",
  });
  expect(check).toHaveFocus();
  expect(screen.getByText(/Rule run outcome unknown/)).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Retry original rule request" }),
  ).toBeNull();
  const original = await nativeLineage(calls.writes[0], {
    status: "published",
  });
  fireEvent.click(check);
  await waitFor(() => expect(calls.reads).toHaveLength(1));
  expect(screen.getByText("Checking the original run status…")).toBeVisible();
  expect(check).toHaveFocus();
  const find = screen.getByRole("textbox", { name: "Find calculation rule" });
  find.focus();
  await act(async () => settle(original));
  expect(await screen.findByText(/Rule run published/)).toBeVisible();
  expect(find).toHaveFocus();
  expect(calls.writes).toHaveLength(1);
  expect(calls.admissions()).toBe(1);
});

it("guards New rule while an original unknown run survives without a selected rule", async () => {
  const calls = installRunFixture(
    async () =>
      new Response(JSON.stringify({ error: "UNKNOWN_OUTCOME" }), {
        status: 400,
      }),
  );
  const first = render(<BuildRules app={app} catalog={catalog} />);
  await startRunFixture();
  await screen.findByRole("button", { name: "Read original rule outcome" });
  first.unmount();
  const transition = vi.fn();
  render(
    <BuildRules app={app} catalog={catalog} onRequestTransition={transition} />,
  );
  await screen.findByRole("button", { name: "forecast" });
  expect(
    screen.queryByLabelText("Application rule detail"),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "New rule" }));
  expect(transition.mock.calls[0][1]).toBe(false);
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  expect(calls.writes).toHaveLength(1);
  expect(calls.admissions()).toBe(1);
});

it("requires a current missing-outcome check before sending an exact retry", async () => {
  let refusal = "APPLICATION_GRANT_REQUIRED";
  const calls = installRunFixture(async (_body, count) => {
    if (count > 0) throw new Error("Lost response");
    return new Response(JSON.stringify({ code: refusal }), {
      status: refusal === "APPLICATION_GRANT_REQUIRED" ? 403 : 400,
    });
  });
  const view = render(<BuildRules app={app} catalog={catalog} />);
  await startRunFixture();
  await screen.findByText("Lost response");
  const check = screen.getByRole("button", {
    name: "Read original rule outcome",
  });
  const retry = () =>
    screen.queryByRole("button", { name: "Retry original rule request" });
  fireEvent.click(check);
  expect(await screen.findByText("APPLICATION_GRANT_REQUIRED")).toBeVisible();
  expect(retry()).toBeNull();
  refusal = "APPLICATION_RULE_WORKFLOW_UNAVAILABLE";
  fireEvent.click(check);
  await screen.findByText(/No recorded outcome could be confirmed/);
  expect(retry()).toBeEnabled();
  view.rerender(
    <BuildRules
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 3 } }}
    />,
  );
  expect(retry()).toBeNull();
  expect(calls.writes).toHaveLength(1);
  expect(calls.admissions()).toBe(1);
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});
it("retains default-parameter uncertainty across remount and expiry without another admission", async () => {
  let original!: ReturnType<typeof ruleRunBody>;
  const calls = installRunFixture(async (body, count) => {
    if (count === 1) {
      original = body;
      throw new TypeError("Lost native acknowledgement");
    }
    expect(count).toBeLessThan(0);
    expect(body.program.arguments).toEqual({
      originalRequest: {
        program: original.program,
        idempotencyKey: original.idempotencyKey,
      },
    });
    return nativeLineage(original, { status: "published" });
  });
  const first = render(<BuildRules app={app} catalog={catalog} />);
  await startRunFixture();
  await screen.findByText("Lost native acknowledgement");
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  expect(screen.getByLabelText("Application rule parameters")).toBeDisabled();
  expect(screen.getByRole("button", { name: "Run rule" })).toHaveAttribute(
    "aria-disabled",
    "true",
  );
  first.unmount();
  vi.spyOn(Date, "now").mockReturnValue(Date.now() + 7_200_000);
  const reopened = render(<BuildRules app={app} catalog={null} />);
  await act(async () => {});
  reopened.rerender(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Read original rule outcome" }),
  );
  await screen.findByText(/Rule run published/);
  expect(calls.writes).toHaveLength(1);
  expect(calls.reads).toHaveLength(1);
  expect(calls.admissions()).toBe(1);
  expect(unsavedWorkSnapshot()).toHaveLength(0);
});
it.each([400, 403])(
  "retains a first dispatched %s because native acceptance may precede the error",
  async (status) => {
    const calls = installRunFixture(
      async () =>
        new Response(JSON.stringify({ code: "NATIVE_ADVANCE_FAILED" }), {
          status,
        }),
    );
    render(<BuildRules app={app} catalog={catalog} />);
    await startRunFixture();
    await screen.findByText("NATIVE_ADVANCE_FAILED");
    expect(screen.getByRole("button", { name: "Run rule" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
    expect(
      screen.getByRole("button", { name: "Read original rule outcome" }),
    ).toBeEnabled();
    expect(
      screen.queryByRole("button", { name: "Retry original rule request" }),
    ).toBeNull();
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    expect(calls.admissions()).toBe(1);
  },
);
it("keeps expired rejected replay pinned through source and grant changes without a fresh admission", async () => {
  const calls = installRunFixture(async (_body, count) => {
    if (count === 1) throw new Error("Lost response");
    if (count < 0) return originalRuleUnavailable();
    return new Response(
      JSON.stringify({ code: "OPERATION_ADMISSION_EXPIRED" }),
      { status: 400 },
    );
  });
  const view = render(<BuildRules app={app} catalog={catalog} />);
  await startRunFixture();
  await screen.findByText("Lost response");
  const changed = {
    ...catalog,
    revisions: { ...catalog.revisions, metadata: 5, security: 2 },
    functions: {},
  };
  view.rerender(<BuildRules app={app} catalog={changed} />);
  expect(
    screen.getByLabelText("Original rule execution recovery"),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Retry original rule request" }),
  ).toBeNull();
  expect(
    screen.queryByLabelText("Application rule detail"),
  ).not.toBeInTheDocument();
  view.rerender(
    <BuildRules
      app={app}
      catalog={{
        ...changed,
        functions: {
          "application.rule.run": {},
          "application.rule.run.read": {},
        },
      }}
    />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Read original rule outcome" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Retry original rule request" }),
  );
  await screen.findByText(
    "The original admission expired. Check the original outcome again.",
  );
  view.unmount();
  render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Read original rule outcome" }),
  );
  expect(
    await screen.findByText(/No recorded outcome could be confirmed/),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Retry original rule request" }),
  ).toBeNull();
  expect(calls.writes).toHaveLength(2);
  expect(calls.reads).toHaveLength(2);
  expect(calls.writes[1]).toEqual(calls.writes[0]);
  expect(calls.admissions()).toBe(1);
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});
it("reads known original lineage under read-only access after source change without opening the replacement", async () => {
  let original!: ReturnType<typeof ruleRunBody>;
  const calls = installRunFixture(async (body, count) => {
    if (count > 0) {
      original = body;
      return nativeOutcome(body);
    }
    expect(body.program.arguments).toEqual({ workflowId: "1".repeat(32) });
    return nativeLineage(original, { status: "published" });
  });
  const first = render(<BuildRules app={app} catalog={catalog} />);
  await startRunFixture();
  await screen.findByText(/Rule run running/);
  first.rerender(
    <BuildRules
      app={app}
      catalog={{
        ...catalog,
        revisions: { ...catalog.revisions, security: 2 },
        functions: { "application.rule.run.read": {} },
      }}
    />,
  );
  expect(screen.queryByText(/Rule run running/)).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Refresh original run status" }),
  ).toBeEnabled();
  first.unmount();
  render(
    <BuildRules
      app={app}
      catalog={{
        ...catalog,
        functions: { "application.rule.run.read": {} },
        revisions: { ...catalog.revisions, metadata: 9 },
      }}
    />,
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Refresh original run status" }),
  );
  await screen.findByText(/Rule run published/);
  expect(
    screen.getByText(/source or dependencies are no longer current/),
  ).toBeVisible();
  expect(calls.writes).toHaveLength(1);
  expect(calls.reads).toHaveLength(1);
  expect(calls.admissions()).toBe(1);
  expect(
    screen.queryByLabelText("Application rule detail"),
  ).not.toBeInTheDocument();
  expect(unsavedWorkSnapshot()).toHaveLength(0);
});
it.each([
  ["cancel_requested", "cancellation requested"],
  ["published", "published"],
])(
  "clears %s receipt evidence on a refused refresh and checks the same workflow again",
  async (status, label) => {
    let original!: ReturnType<typeof ruleRunBody>;
    const calls = installRunFixture(async (body, count) => {
      if (count > 0) {
        original = body;
        return nativeOutcome(body, {
          status,
          committedUnits: 1,
          remainingUnits: 0,
          checkpoints: [
            {
              ordinal: 1,
              jobId: "child-1",
              committed: true,
              receiptId: "child-1",
            },
          ],
        });
      }
      expect(body.program.arguments).toEqual({ workflowId: "1".repeat(32) });
      if (count === -1)
        return new Response(
          JSON.stringify({
            code: "APPLICATION_RULE_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED",
          }),
          { status: 403 },
        );
      return nativeLineage(original, { status: "published" });
    });
    render(<BuildRules app={app} catalog={catalog} />);
    await startRunFixture();
    await screen.findByText(new RegExp(`Rule run ${label}`));
    fireEvent.click(screen.getByText("Workflow checkpoint evidence"));
    expect(screen.getByText("Committed with receipt")).toBeVisible();
    expect(unsavedWorkSnapshot()).toHaveLength(status === "published" ? 0 : 1);
    const refresh = screen.getByRole("button", {
      name: "Refresh original run status",
    });
    act(() => refresh.focus());
    fireEvent.click(refresh);
    await screen.findByText(
      /Current access could not confirm the original run/,
    );
    expect(refresh).toHaveFocus();
    expect(
      screen.queryByText("Workflow checkpoint evidence"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(/receipt-confirmed committed units/),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Retry original rule request" }),
    ).not.toBeInTheDocument();
    expect(unsavedWorkSnapshot()).toHaveLength(status === "published" ? 0 : 1);

    fireEvent.click(refresh);
    await screen.findByText(/Rule run published/);
    fireEvent.click(screen.getByText("Workflow checkpoint evidence"));
    expect(screen.getByText("Committed with receipt")).toBeVisible();
    expect(
      screen.getByText(/source or dependencies are no longer current/),
    ).toBeVisible();
    expect(unsavedWorkSnapshot()).toHaveLength(0);
    expect(calls.reads).toHaveLength(2);
    expect(calls.writes).toHaveLength(1);
    expect(calls.admissions()).toBe(1);
  },
);

it("refuses the business effect when all same-tab recovery slots are pinned", async () => {
  const calls = installRunFixture(async (body) => nativeOutcome(body));
  for (let i = 0; i < 24; i++) {
    const slot = renderHook(() =>
      usePreservedDraft(
        "ws",
        "app",
        `other-${i}`,
        "Other unresolved operation",
        false,
        { packet: "" },
        () => undefined,
      ),
    );
    act(() => {
      slot.result.current.retain({ packet: `other-packet-${i}` });
    });
    slot.unmount();
  }
  render(<BuildRules app={app} catalog={catalog} />);
  await startRunFixture();
  await screen.findByText(/cannot retain another recovery record/);
  expect(calls.writes).toHaveLength(0);
  expect(calls.admissions()).toBe(1);
  expect(
    unsavedWorkSnapshot().filter(
      (item) => item.label === "Other unresolved operation",
    ),
  ).toHaveLength(24);
});
it.each([
  { ruleId: "different" },
  { argumentsDigest: "f".repeat(64) },
  {
    status: "published",
    remainingUnits: 1,
    committedUnits: 0,
    checkpoints: [],
  },
])("cannot settle malformed or wrong native acceptance %#", async (change) => {
  const calls = installRunFixture(async (body) => nativeOutcome(body, change));
  render(<BuildRules app={app} catalog={catalog} />);
  await startRunFixture();
  await screen.findByRole("alert");
  expect(
    screen.getByRole("button", { name: "Read original rule outcome" }),
  ).toBeEnabled();
  expect(
    screen.queryByRole("button", { name: "Retry original rule request" }),
  ).toBeNull();
  expect(
    screen.queryByRole("button", { name: "Prepare another run" }),
  ).not.toBeInTheDocument();
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  expect(calls.writes).toHaveLength(1);
});
it("does not let an old mount's late terminal acknowledgement erase a newer unknown replay", async () => {
  let oldReply!: (value: unknown) => void;
  const calls = installRunFixture(async (body, count) => {
    if (count === 1)
      return new Promise((resolve) => {
        oldReply = resolve;
      });
    if (count === 2) throw new Error("New replay reply lost");
    if (count < 0) return originalRuleUnavailable();
    return nativeOutcome(body, { status: "published" });
  });
  const first = render(<BuildRules app={app} catalog={catalog} />);
  await startRunFixture();
  await waitFor(() => expect(calls.writes).toHaveLength(1));
  first.unmount();
  const second = render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Read original rule outcome" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Retry original rule request" }),
  );
  await screen.findByText("New replay reply lost");
  await act(async () =>
    oldReply(await nativeOutcome(calls.writes[0], { status: "published" })),
  );
  second.unmount();
  render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Read original rule outcome" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Retry original rule request" }),
  );
  await screen.findByText(/Rule run published/);
  expect(calls.writes).toHaveLength(3);
  expect(calls.writes[2]).toEqual(calls.writes[0]);
  expect(calls.admissions()).toBe(1);
});
it("does not let an old terminal status read overwrite a newer mount's running observation", async () => {
  let original!: ReturnType<typeof ruleRunBody>;
  let oldReply!: (value: unknown) => void;
  const calls = installRunFixture(async (body, count) => {
    if (count > 0) {
      original = body;
      return nativeOutcome(body);
    }
    if (count === -1)
      return new Promise((resolve) => {
        oldReply = resolve;
      });
    return nativeLineage(original, count === -2 ? {} : { status: "published" });
  });
  const first = render(<BuildRules app={app} catalog={catalog} />);
  await startRunFixture();
  await screen.findByText(/Rule run running/);
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh original run status" }),
  );
  await waitFor(() => expect(calls.reads).toHaveLength(1));
  first.unmount();
  const second = render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Refresh original run status" }),
  );
  await waitFor(() => expect(calls.reads).toHaveLength(2));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Refresh original run status" }),
    ).toBeEnabled(),
  );
  await act(async () =>
    oldReply(await nativeLineage(original, { status: "published" })),
  );
  second.unmount();
  render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Refresh original run status" }),
  );
  await screen.findByText(/Rule run published/);
  expect(calls.writes).toHaveLength(1);
  expect(calls.reads).toHaveLength(3);
  expect(calls.admissions()).toBe(1);
});
it("explicit identity abandonment fences late original acceptance and never restores another actor's packet", async () => {
  setDraftIdentity("actor-one");
  let finish!: (value: unknown) => void;
  const calls = installRunFixture(
    async () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const first = render(<BuildRules app={app} catalog={catalog} />);
  await startRunFixture();
  await waitFor(() => expect(calls.writes).toHaveLength(1));
  first.unmount();
  act(() => discardUnsavedWork({ abandonRecovery: true }));
  setDraftIdentity("actor-two");
  render(
    <BuildRules
      app={app}
      catalog={{
        ...catalog,
        applicationAccess: {
          ...catalog.applicationAccess,
          subjectId: "actor-two",
        },
        functions: {},
      }}
    />,
  );
  await act(async () =>
    finish(await nativeOutcome(calls.writes[0], { status: "published" })),
  );
  expect(
    screen.queryByLabelText("Original rule execution recovery"),
  ).not.toBeInTheDocument();
  expect(unsavedWorkSnapshot()).toHaveLength(0);
});

it.each(["running", "published"])(
  "rechecks %s evidence under current access after context changes during digest validation",
  async (status) => {
    const originalBody = ruleRunBody(
      app,
      row.ruleId,
      {},
      "fixture",
      row.stateToken,
      row.programDigest,
    );
    const result = await nativeOutcome(originalBody, { status });
    const expectedDigest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode('{"bindings":{},"ruleId":"forecast"}'),
    );
    let finish!: (value: ArrayBuffer) => void;
    vi.spyOn(crypto.subtle, "digest").mockImplementationOnce(
      () =>
        new Promise<ArrayBuffer>((resolve) => {
          finish = resolve;
        }),
    );
    let original!: ReturnType<typeof ruleRunBody>;
    const calls = installRunFixture(async (body, count) => {
      if (count > 0) {
        original = body;
        return result;
      }
      expect(body.program.arguments).toEqual({
        originalRequest: {
          program: original.program,
          idempotencyKey: original.idempotencyKey,
        },
      });
      return nativeLineage(original, { status });
    });
    const limited = {
      ...catalog,
      revisions: { ...catalog.revisions, metadata: 9, security: 3 },
      functions: { "application.rule.run.read": {} },
    };
    const workspace = (current: ApplicationCatalog, covered = false) => (
      <div inert={covered || undefined}>
        <BuildRules app={app} catalog={current} />
      </div>
    );
    const view = render(workspace(catalog));
    fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
    const run = await screen.findByRole("button", { name: "Run rule" });
    await waitFor(() => expect(run).not.toHaveAttribute("aria-disabled"));
    run.focus();
    fireEvent.click(run);
    await waitFor(() => expect(finish).toBeDefined());
    view.rerender(workspace(catalog, true));
    run.blur(); // Model the browser taking focus out of the inert workspace.
    view.rerender(workspace(limited, true));
    await act(async () => finish(expectedDigest));
    view.rerender(workspace(limited));
    expect(
      screen.queryByText(new RegExp(`Rule run ${status}`)),
    ).not.toBeInTheDocument();
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    const statusRead = screen.getByRole("button", {
      name: "Read original rule outcome",
    });
    expect(statusRead).toHaveFocus();
    fireEvent.click(statusRead);
    await screen.findByText(new RegExp(`Rule run ${status}`));
    expect(
      screen.queryByRole("button", { name: "Retry original rule request" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name:
          status === "published"
            ? "Prepare another run"
            : "Refresh original run status",
      }),
    ).toBeEnabled();
    expect(unsavedWorkSnapshot()).toHaveLength(status === "published" ? 0 : 1);
    expect(calls.writes).toHaveLength(1);
    expect(calls.reads).toHaveLength(1);
    expect(calls.admissions()).toBe(1);
  },
);

it("distinguishes confirmed child receipts from an unfinished workflow publication", async () => {
  const calls = installRunFixture(async (body) =>
    nativeOutcome(body, {
      status: "partially_published",
      committedUnits: 1,
      remainingUnits: 0,
      checkpoints: [
        { ordinal: 1, jobId: "child-1", committed: true, receiptId: "child-1" },
      ],
    }),
  );
  render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  const run = await screen.findByRole("button", { name: "Run rule" });
  await waitFor(() => expect(run).not.toHaveAttribute("aria-disabled"));
  fireEvent.click(run);
  expect(
    await screen.findByText(/every checkpoint committed/i),
  ).toHaveTextContent(
    "The workflow stopped before publishing its final receipt.",
  );
  expect(calls.writes).toHaveLength(1);
});

it("keeps cancellation pending and opens only the committed step receipt", async () => {
  const effects: unknown[] = [];
  const receiptReads: unknown[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      if (String(url) === "/api/operation-admission")
        return operationAdmissionResponse("7");
      const body = JSON.parse(init.body);
      if (body.program.function === "application.operation.receipt.read") {
        receiptReads.push(body);
        return new Response(
          JSON.stringify({
            result: {
              operationId: "child-1",
              commandDigest: "c".repeat(64),
              actorId: "fixture-runner",
              committedRevision: 2,
              committedAt: "2026-11-19T15:00:00+00:00",
              outcome: { function: "facts.numeric.batch", changedCount: 1 },
            },
          }),
        );
      }
      if (body.program.function === "application.rule.run") {
        effects.push(body);
        return new Response(
          JSON.stringify({
            result: await nativeOutcome(body, {
              status: "cancel_requested",
              unitCount: 3,
              committedUnits: 1,
              remainingUnits: 2,
              checkpoints: [
                {
                  ordinal: 1,
                  jobId: "child-1",
                  committed: true,
                  receiptId: "child-1",
                },
                {
                  ordinal: 2,
                  jobId: "child-2",
                  committed: false,
                  receiptId: null,
                },
              ],
            }),
          }),
        );
      }
      return new Response(
        JSON.stringify({
          result: body.program.function.endsWith(".list") ? page() : detail,
        }),
      );
    }),
  );
  render(
    <BuildRules
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "application.operation.receipt.read": {},
        },
      }}
    />,
  );
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  const run = await screen.findByRole("button", { name: "Run rule" });
  await waitFor(() => expect(run).not.toHaveAttribute("aria-disabled"));
  fireEvent.click(run);
  await screen.findByText(/Rule run cancellation requested/);
  expect(screen.getByText(/Rule run cancellation requested/)).toHaveTextContent(
    "1 receipt-confirmed committed units · 2 remaining units without a confirmed receipt",
  );
  expect(
    screen.getByText(/Cancellation reconciliation is still pending/),
  ).toHaveTextContent(
    "unstarted, cancelled or unresolved work, including any child whose effect may already have committed",
  );
  expect(effects).toHaveLength(1);
  expect(receiptReads).toHaveLength(0);
  fireEvent.click(screen.getByText("Workflow checkpoint evidence"));
  expect(screen.getByText("Committed with receipt")).toBeVisible();
  expect(
    screen.getByText("Checkpoint recorded without a confirmed receipt"),
  ).toBeVisible();
  expect(screen.getByText("No checkpoint recorded")).toBeVisible();
  const inspect = screen.getByRole("button", {
    name: "Inspect receipt for step 1",
  });
  expect(
    screen.getAllByRole("button", { name: /Inspect receipt for step/ }),
  ).toEqual([inspect]);
  act(() => inspect.focus());
  fireEvent.click(inspect);
  const receipt = screen.getByRole("region", { name: "Step 1 receipt" });
  expect(
    within(receipt).getByRole("heading", { name: "Step 1 receipt" }),
  ).toHaveFocus();
  await within(receipt).findByText("Activity outcome loaded.");
  expect(receiptReads).toEqual([
    {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
      program: {
        languageVersion: 2,
        function: "application.operation.receipt.read",
        arguments: { operationId: "child-1" },
      },
    },
  ]);
  expect(screen.queryByText("child-1")).toBeNull();
  fireEvent.click(within(receipt).getByRole("button", { name: "Close" }));
  expect(inspect).toHaveFocus();
  expect(run).toHaveAttribute("aria-disabled", "true");
  expect(
    screen.queryByRole("button", { name: "Prepare another run" }),
  ).not.toBeInTheDocument();
});

it.each([
  { committedUnits: undefined },
  { committedUnits: null },
  { committedUnits: false },
  { remainingUnits: undefined },
  { remainingUnits: null },
  { remainingUnits: false },
])(
  "refuses absent or malformed rule counts without inventing zero %j",
  async (invalid) => {
    const calls = installRunFixture(
      async (body) =>
        new Response(
          JSON.stringify({
            result: await nativeOutcome(body, {
              status: "cancel_requested",
              ...invalid,
            }),
          }),
        ),
    );
    render(<BuildRules app={app} catalog={catalog} />);
    await startRunFixture();
    await screen.findByText(/invalid.*workflow/i);
    expect(
      screen.queryByText(/receipt-confirmed committed units/),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Rule run outcome unknown/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run rule" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
    expect(calls.writes).toHaveLength(1);
    expect(calls.admissions()).toBe(1);
  },
);
