import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  BuildSequences,
  collectNumericSequences,
  exactApplicationSequence,
  sequenceListArguments,
  sequenceReadArguments,
  sequenceRunBody,
} from "./BuildSequences";

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
        version: 1,
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
          version: 1,
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
  expect(sequenceReadArguments("plan.ordered", 2)).toEqual({
    ruleId: "plan.ordered",
    version: 2,
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
      if (body.program.function === "rules.numeric_sequence.version.list")
        return new Response(
          JSON.stringify({
            result: {
              rows: [
                {
                  ruleId: "plan.ordered",
                  version: 2,
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
            version: 2,
            status: "Published",
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
          "rules.numeric_sequence.version.list": {},
          "rules.numeric_sequence.version.read": {},
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
        function: "rules.numeric_sequence.version.list",
        arguments: { limit: 100 },
      },
    }),
    expect.objectContaining({
      program: {
        languageVersion: 2,
        function: "rules.numeric_sequence.version.read",
        arguments: { ruleId: "plan.ordered", version: 2 },
      },
    }),
  ]);
});

it("binds a workflow target to the exact published sequence", async () => {
  const digest = "d".repeat(64);
  const result = {
    defined: true,
    ruleId: "plan.ordered",
    version: 2,
    status: "Published",
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
      { ruleId: "plan.ordered", version: 2, digest },
    ),
  ).toThrow("INVALID_APPLICATION_SEQUENCE_RESPONSE");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      expect(body.program.arguments).toEqual({
        ruleId: "plan.ordered",
        version: 2,
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
        functions: { "rules.numeric_sequence.version.read": {} },
        revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
      }}
      target={{ ruleId: "plan.ordered", version: 2, digest }}
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
          "rules.numeric_sequence.version.list": {},
          "rules.numeric_sequence.version.read": {},
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
