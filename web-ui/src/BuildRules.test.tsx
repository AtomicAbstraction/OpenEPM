import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
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
afterEach(() => vi.unstubAllGlobals());
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
const row: RuleSummary = {
  ruleId: "forecast",
  stateToken: "d".repeat(64),
  programDigest: "a".repeat(64),
  metadataCurrent: true,
  status: "Active" as const,
  executable: true,
  reason: null,
};
const detail = {
  ...row,
  defined: true,
  program: { function: "application.rule.definition" },
  source: {
    programId: "forecast-source",
    sourceToken: "c".repeat(64),
    sourceDigest: "b".repeat(64),
    buildId: "build",
    active: true,
  },
};
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
    page([row]),
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
    executable: false,
    reason: "ownership_unresolved" as const,
  };
  const awaitingValidation: RuleSummary = {
    ...row,
    ruleId: "current-rule",
    status: "Inactive" as const,
    executable: false,
    reason: "validation_required" as const,
  };
  expect(ruleAvailabilityLabel(unavailable)).toBe(
    "Source ownership unresolved",
  );
  expect(ruleAvailabilityLabel(awaitingValidation)).toBe("Validation required");
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
it("opens exact source-bound application rules inline and places compiled JSON in inspection", async () => {
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
  fireEvent.click(screen.getByRole("button", { name: "Read rules" }));
  expect(await screen.findByText("Executable")).toBeVisible();
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  expect(
    await screen.findByLabelText("Inline Python source"),
  ).toHaveTextContent("ApplicationRule: forecast-source");
  expect(
    screen.getByText("Compiled rule inspection").closest("details"),
  ).not.toHaveAttribute("open");
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
  expect(screen.getByRole("button", { name: "Run rule" })).toBeDisabled();
});
it("ignores a superseded rule read when another application is opened", async () => {
  let finish: (value: Response) => void = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          finish = resolve;
        }),
    ),
  );
  const { rerender } = render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read rules" }));
  rerender(
    <BuildRules app={{ ...app, applicationId: "other" }} catalog={catalog} />,
  );
  await act(async () =>
    finish(new Response(JSON.stringify({ result: page() }))),
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
  fireEvent.click(screen.getByRole("button", { name: "Read rules" }));
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
            result: { workflowId: "accepted", status: "running" },
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
  render(<BuildRules app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read rules" }));
  fireEvent.click(await screen.findByRole("button", { name: "forecast" }));
  const run = await screen.findByRole("button", { name: "Run rule" });
  await waitFor(() => expect(run).toBeEnabled());
  fireEvent.click(run);
  await screen.findByText("Response lost");
  fireEvent.click(screen.getByRole("button", { name: "Run rule" }));
  await screen.findByText(/Rule workflow accepted/);
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
  expect(screen.getByRole("button", { name: "Run rule" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Prepare another run" }));
  fireEvent.click(screen.getByRole("button", { name: "Run rule" }));
  await waitFor(() => expect(submissions).toHaveLength(3));
  expect(submissions[2].idempotencyKey).not.toEqual(
    submissions[1].idempotencyKey,
  );
});
