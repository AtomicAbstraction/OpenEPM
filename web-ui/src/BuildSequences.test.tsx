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
  BuildSequences,
  collectNumericSequences,
  exactApplicationSequence,
  sequenceListArguments,
  sequenceReadArguments,
  sequenceRunBody,
} from "./BuildSequences";
import { installOperationAdmissionFixture } from "./test-setup";

afterEach(() => vi.unstubAllGlobals());

it("reads every numeric sequence beyond the former catalogue cap", async () => {
  let page = 0;
  const result = await collectNumericSequences(async (arguments_) => {
    const current = page++;
    if (current) {
      expect(arguments_.expectedMetadataRevision).toBe(46);
      expect(arguments_.expectedPolicyRevision).toBe(37);
    }
    return {
      rows: Array.from({ length: 100 }, (_unused, row) => ({
        ruleId: `sequence-${current}-${row}`,
        stateToken: "b".repeat(64),
        programDigest: "a".repeat(64),
        statementCount: 1,
        parameterDeclarations: {},
        metadataCurrent: true,
      })),
      hasMore: current < 10,
      nextAfterRuleId: current < 10 ? `cursor-${current + 1}` : null,
      metadataRevision: 46,
      policyRevision: 37,
    };
  });
  expect(result.rows).toHaveLength(1100);
});

it("rejects inconsistent and duplicate numeric sequence continuations", async () => {
  await expect(
    collectNumericSequences(async () => ({
      rows: [],
      hasMore: false,
      nextAfterRuleId: "unexpected",
      metadataRevision: 46,
      policyRevision: 37,
    })),
  ).rejects.toThrow("status is inconsistent");
  let page = 0;
  await expect(
    collectNumericSequences(async () => ({
      rows: [
        {
          ruleId: "same",
          stateToken: "b".repeat(64),
          programDigest: "a".repeat(64),
          statementCount: 1,
          parameterDeclarations: {},
          metadataCurrent: true,
        },
      ],
      hasMore: page++ < 1,
      nextAfterRuleId: page === 1 ? "more" : null,
      metadataRevision: 46,
      policyRevision: 37,
    })),
  ).rejects.toThrow("repeated a row");
});

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "Active",
};

it("preserves the revision-pinned sequence read contracts", () => {
  expect(sequenceListArguments()).toEqual({ limit: 100 });
  expect(sequenceListArguments("plan.ordered", 46, 37)).toEqual({
    limit: 100,
    afterRuleId: "plan.ordered",
    expectedMetadataRevision: 46,
    expectedPolicyRevision: 37,
  });
  expect(sequenceReadArguments("plan.ordered")).toEqual({
    ruleId: "plan.ordered",
  });
});

it("preserves the exact durable sequence run contract", () => {
  expect(
    sequenceRunBody(app, "plan.ordered", { Seed: "100.00000001" }, "run-key"),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    program: {
      languageVersion: 2,
      function: "rules.numeric_sequence.run",
      arguments: {
        ruleId: "plan.ordered",
        bindings: { Seed: "100.00000001" },
      },
    },
    idempotencyKey: "run-key",
    dependsOnJobIds: [],
    confirmed: true,
  });
});

it("lists and opens sequences through unchanged V2 reads", async () => {
  const calls: Array<Record<string, unknown>> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      if (body.program.function === "rules.numeric_sequence.list")
        return new Response(
          JSON.stringify({
            result: {
              rows: [
                {
                  ruleId: "plan.ordered",
                  stateToken: "b".repeat(64),
                  programDigest: "a".repeat(64),
                  statementCount: 2,
                  parameterDeclarations: { Seed: "amount" },
                  metadataCurrent: true,
                },
              ],
              hasMore: false,
              nextAfterRuleId: null,
              metadataRevision: 46,
              policyRevision: 37,
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            defined: true,
            ruleId: "plan.ordered",
            stateToken: "b".repeat(64),
            status: "Active",
            programDigest: "a".repeat(64),
            program: {
              languageVersion: 2,
              function: "rules.numeric_sequence.template",
              arguments: {
                statements: [
                  {
                    coordinate: { Account: "Revenue" },
                    op: "clear",
                  },
                ],
              },
            },
            currentMetadataRevision: 46,
            policyRevision: 37,
          },
        }),
      );
    }),
  );
  render(
    <BuildSequences
      app={app}
      catalog={{
        applicationAccess: { role: "Editor", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {
          "rules.numeric_sequence.list": {},
          "rules.numeric_sequence.read": {},
        },
        revisions: {
          metadata: 46,
          data: 1,
          policy: 37,
          security: 1,
          commit: 1,
        },
      }}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read sequences" }));
  await waitFor(() =>
    expect(
      screen.getByText("plan.ordered", { selector: "th" }),
    ).toBeInTheDocument(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Sequence rule detail")).toHaveTextContent(
      "rules.numeric_sequence.template",
    ),
  );
  expect(calls).toEqual([
    expect.objectContaining({
      program: {
        languageVersion: 2,
        function: "rules.numeric_sequence.list",
        arguments: { limit: 100 },
      },
    }),
    expect.objectContaining({
      program: {
        languageVersion: 2,
        function: "rules.numeric_sequence.read",
        arguments: { ruleId: "plan.ordered" },
      },
    }),
  ]);
});

it("binds a workflow target to the exact published sequence", async () => {
  const digest = "d".repeat(64);
  const result = {
    defined: true,
    ruleId: "plan.ordered",
    stateToken: "b".repeat(64),
    status: "Active",
    programDigest: digest,
    program: {
      languageVersion: 2,
      function: "rules.numeric_sequence.template",
      arguments: { statements: [] },
    },
  };
  expect(() =>
    exactApplicationSequence(
      { ...result, programDigest: "e".repeat(64) },
      { ruleId: "plan.ordered", stateToken: "b".repeat(64), digest },
    ),
  ).toThrow("INVALID_APPLICATION_SEQUENCE_RESPONSE");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      expect(body.program.arguments).toEqual({
        ruleId: "plan.ordered",
      });
      return new Response(JSON.stringify({ result }));
    }),
  );
  render(
    <BuildSequences
      app={app}
      catalog={{
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: { "rules.numeric_sequence.read": {} },
        revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
      }}
      target={{ ruleId: "plan.ordered", stateToken: "b".repeat(64), digest }}
    />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Sequence rule detail")).toHaveTextContent(
      "rules.numeric_sequence.template",
    ),
  );
});

it("distinguishes an unread catalogue from an authoritative empty result", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              rows: [],
              hasMore: false,
              nextAfterRuleId: null,
              metadataRevision: 46,
              policyRevision: 37,
            },
          }),
        ),
    ),
  );
  render(
    <BuildSequences
      app={app}
      catalog={{
        applicationAccess: { role: "Editor", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {
          "rules.numeric_sequence.list": {},
          "rules.numeric_sequence.read": {},
        },
        revisions: {
          metadata: 46,
          data: 1,
          policy: 37,
          security: 1,
          commit: 1,
        },
      }}
    />,
  );
  expect(
    screen.getByText("No published-sequence catalogue read yet."),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Read sequences" }));
  await waitFor(() =>
    expect(
      screen.getByText(
        "No published calculation sequences are defined for this application.",
      ),
    ).toBeInTheDocument(),
  );
});

it("does not render when the authoritative catalogue omits sequence reads", () => {
  const { container } = render(
    <BuildSequences
      app={app}
      catalog={{
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {},
        revisions: {
          metadata: 1,
          data: 1,
          policy: 1,
          security: 1,
          commit: 1,
        },
      }}
    />,
  );
  expect(container).toBeEmptyDOMElement();
});

it("opens bindings only for a selected sequence and preserves them until close is accepted", async () => {
  const detail = {
    defined: true,
    ruleId: "sequence.one",
    stateToken: "b".repeat(64),
    status: "Active",
    programDigest: "a".repeat(64),
    program: {
      languageVersion: 2,
      function: "rules.numeric_sequence.template",
      arguments: {
        statements: [{ coordinate: { Account: "Revenue" }, op: "clear" }],
      },
    },
    currentMetadataRevision: 7,
    policyRevision: 4,
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify({ result: detail }))),
  );
  let accept: (() => void) | undefined;
  const transition = vi.fn((action: () => void) => {
    accept = action;
  });
  const catalog = {
    applicationAccess: { role: "Editor", workspaceAdministrator: false },
    enabledCapabilities: [],
    functions: {
      "rules.numeric_sequence.read": {},
      "rules.numeric_sequence.run": {},
    },
    revisions: { metadata: 7, data: 1, policy: 4, security: 1, commit: 1 },
  };
  const { rerender } = render(
    <BuildSequences
      app={app}
      catalog={catalog}
      onRequestTransition={transition}
    />,
  );
  expect(
    screen.queryByLabelText("Sequence parameter bindings"),
  ).not.toBeInTheDocument();
  rerender(
    <BuildSequences
      app={app}
      catalog={catalog}
      onRequestTransition={transition}
      target={{
        ruleId: "sequence.one",
        stateToken: "b".repeat(64),
        digest: "a".repeat(64),
      }}
    />,
  );
  const bindings = await screen.findByLabelText("Sequence parameter bindings");
  fireEvent.change(bindings, { target: { value: '{"Seed":"1.00000001"}' } });
  fireEvent.click(screen.getByRole("button", { name: "Close inspector" }));
  expect(transition).toHaveBeenCalledOnce();
  expect(bindings).toHaveValue('{"Seed":"1.00000001"}');
  act(() => {
    discardUnsavedWork();
    accept?.();
  });
  expect(
    screen.queryByLabelText("Sequence parameter bindings"),
  ).not.toBeInTheDocument();
});

it("runs exact typed sequence bindings with a server preview and retries the same intent without acknowledgement rituals", async () => {
  const pin = {
    ruleId: "sequence.one",
    stateToken: "b".repeat(64),
    programDigest: "a".repeat(64),
  };
  const detail = {
    defined: true,
    ...pin,
    status: "Active",
    program: {
      languageVersion: 2,
      function: "rules.numeric_sequence.template",
      arguments: {
        parameters: {
          Seed: "amount",
          Factor: "ratio",
          Region: {
            type: "member",
            dimensionId: "Entity",
            sampleMemberId: "Europe",
          },
        },
        statements: [],
      },
    },
    currentMetadataRevision: 7,
    policyRevision: 4,
  };
  const submits: any[] = [];
  let previewCount = 0;
  vi.stubGlobal("confirm", vi.fn());
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      const body = JSON.parse(init.body);
      if (url === "/api/preview")
        return new Response(
          JSON.stringify({
            previewToken: `sealed-preview-token-${++previewCount}`,
            savedProgram: pin,
          }),
        );
      if (url === "/api/submit") {
        submits.push(body);
        if (submits.length === 1) throw new Error("Lost response");
        return new Response(
          JSON.stringify({ jobId: "sequence-job", duplicate: true }),
        );
      }
      return new Response(JSON.stringify({ result: detail }));
    }),
  );
  installOperationAdmissionFixture("1");
  render(
    <BuildSequences
      app={app}
      catalog={{
        applicationAccess: { role: "Editor", workspaceAdministrator: false },
        functions: {
          "rules.numeric_sequence.read": {},
          "rules.numeric_sequence.run": {},
        },
        enabledCapabilities: [],
        revisions: { metadata: 7, policy: 4, data: 1, security: 1, commit: 1 },
      }}
      target={{
        ruleId: pin.ruleId,
        stateToken: pin.stateToken,
        digest: pin.programDigest,
      }}
    />,
  );
  await screen.findByLabelText("Seed");
  expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  const run = screen.getByRole("button", { name: "Run sequence" });
  expect(run).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Seed"), {
    target: { value: "99999999999999999999.12345678" },
  });
  fireEvent.change(screen.getByLabelText("Factor"), {
    target: { value: "1.123456789012" },
  });
  fireEvent.change(screen.getByLabelText("Region"), {
    target: { value: "Europe" },
  });
  fireEvent.click(run);
  await waitFor(() => expect(submits).toHaveLength(1));
  await waitFor(() => expect(run).toBeEnabled());
  fireEvent.click(run);
  await screen.findByLabelText("Calculation sequence result");
  expect(submits).toHaveLength(2);
  expect(submits[0].idempotencyKey).toBe(submits[1].idempotencyKey);
  expect(submits[0].previewToken).toBe("sealed-preview-token-1");
  expect(submits[1].previewToken).toBe("sealed-preview-token-2");
  expect(submits[1].program.arguments).toEqual({
    ruleId: pin.ruleId,
    bindings: {
      Seed: "99999999999999999999.12345678",
      Factor: "1.123456789012",
      Region: "Europe",
    },
  });
  expect(window.confirm).not.toHaveBeenCalled();
});
