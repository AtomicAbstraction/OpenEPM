import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  BuildRules,
  collectExpressionRules,
  ruleActionBody,
  ruleListArguments,
  ruleReadArguments,
  ruleRunBody,
  simpleRuleDefinition,
} from "./BuildRules";

afterEach(() => vi.unstubAllGlobals());

it("opens an exact immutable application-rule workflow artifact", async () => {
  const digest = "f".repeat(64);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      expect(body.program).toEqual({
        languageVersion: 2,
        function: "application.rule.version.read",
        arguments: { ruleId: "close.rule", version: 3 },
      });
      return new Response(
        JSON.stringify({
          result: {
            defined: true,
            ruleId: "close.rule",
            version: 3,
            status: "Published",
            programDigest: digest,
            program: {
              languageVersion: 2,
              function: "application.rule.plan",
              arguments: { format: "openepm-application-rule-v1" },
            },
          },
        }),
      );
    }),
  );
  render(
    <BuildRules
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: { "application.rule.version.read": {} },
        revisions: {
          metadata: 1,
          data: 1,
          policy: 1,
          security: 1,
          commit: 1,
        },
      }}
      targetApplicationRule={{
        ruleId: "close.rule",
        version: 3,
        digest,
      }}
    />,
  );
  expect(
    await screen.findByLabelText("Application rule artifact"),
  ).toHaveTextContent("application.rule.plan");
});

it("reads every expression rule beyond the former catalogue cap", async () => {
  let page = 0;
  const result = await collectExpressionRules(async (arguments_) => {
    const current = page++;
    if (current) {
      expect(arguments_.expectedMetadataRevision).toBe(46);
      expect(arguments_.expectedPolicyRevision).toBe(37);
    }
    return {
      rows: Array.from({ length: 100 }, (_unused, row) => ({
        ruleId: `rule-${current}-${row}`,
        version: 1,
        resultKey: "result.key",
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

it("rejects malformed, repeated, duplicate, and drifting rule continuations", async () => {
  await expect(
    collectExpressionRules(async () => ({
      rows: [],
      hasMore: true,
      nextAfterRuleId: "" as never,
      metadataRevision: 46,
      policyRevision: 37,
    })),
  ).rejects.toThrow("cursor is invalid");
  let page = 0;
  await expect(
    collectExpressionRules(async () => ({
      rows: [],
      hasMore: true,
      nextAfterRuleId: page++ < 1 ? "same" : "same",
      metadataRevision: 46,
      policyRevision: 37,
    })),
  ).rejects.toThrow("cursor repeated");
  let revisionPage = 0;
  await expect(
    collectExpressionRules(async () => ({
      rows: [
        {
          ruleId: `r-${revisionPage}`,
          version: 1,
          resultKey: "result.key",
          parameterDeclarations: {},
          metadataCurrent: true,
        },
      ],
      hasMore: revisionPage++ < 1,
      nextAfterRuleId: revisionPage === 1 ? "more" : null,
      metadataRevision: revisionPage === 1 ? 46 : 47,
      policyRevision: 37,
    })),
  ).rejects.toThrow("changed while reading");
  let duplicatePage = 0;
  await expect(
    collectExpressionRules(async () => ({
      rows: [
        {
          ruleId: "same",
          version: 1,
          resultKey: "result.key",
          parameterDeclarations: {},
          metadataCurrent: true,
        },
      ],
      hasMore: duplicatePage++ < 1,
      nextAfterRuleId: duplicatePage === 1 ? "more" : null,
      metadataRevision: 46,
      policyRevision: 37,
    })),
  ).rejects.toThrow("repeated a row");
});

it("preserves the revision-pinned rule list contract", () => {
  expect(ruleListArguments()).toEqual({ limit: 100 });
  expect(ruleListArguments("planning.driver", 46, 37)).toEqual({
    limit: 100,
    afterRuleId: "planning.driver",
    expectedMetadataRevision: 46,
    expectedPolicyRevision: 37,
  });
  expect(ruleReadArguments("planning.driver", 2)).toEqual({
    ruleId: "planning.driver",
    version: 2,
  });
});

it("preserves the reviewed rule mutation and durable run contracts", () => {
  const app = {
    workspaceId: "ws",
    applicationId: "app",
    name: "Plan",
    status: "Active",
  };
  expect(
    ruleActionBody(
      app,
      "rules.expression.version.save",
      {
        ruleId: "planning.driver",
        version: 3,
        calculation: {
          sourceMembers: { Scenario: "Actual" },
          expression: { op: "SourceAmount" },
          resultKey: "driver.output",
        },
        expectedMetadataRevision: 46,
        expectedPolicyRevision: 37,
      },
      "save-key",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "save-key",
    program: {
      languageVersion: 2,
      function: "rules.expression.version.save",
      arguments: {
        ruleId: "planning.driver",
        version: 3,
        calculation: {
          sourceMembers: { Scenario: "Actual" },
          expression: { op: "SourceAmount" },
          resultKey: "driver.output",
        },
        expectedMetadataRevision: 46,
        expectedPolicyRevision: 37,
      },
    },
  });
  expect(
    ruleRunBody(app, "planning.driver", { factor: "1.25" }, "run-key"),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    program: {
      languageVersion: 2,
      function: "rules.expression.run",
      arguments: {
        ruleId: "planning.driver",
        bindings: { factor: "1.25" },
      },
    },
    idempotencyKey: "run-key",
    dependsOnJobIds: [],
    confirmed: true,
  });
});

it("generates only the approved typed expression shape", () => {
  expect(
    simpleRuleDefinition(
      { Account: "DriverAmount" },
      { Account: "DriverOutput" },
      "multiply",
      "0.125",
      "planning.driver.output",
    ),
  ).toEqual({
    sourceMembers: { Account: "DriverAmount" },
    targetMembers: { Account: "DriverOutput" },
    expression: {
      op: "Multiply",
      left: { op: "SourceAmount" },
      right: { op: "RatioLiteral", decimal: "0.125" },
    },
    resultKey: "planning.driver.output",
  });
  expect(() =>
    simpleRuleDefinition({}, {}, "divide", "0.000", "planning.driver.output"),
  ).toThrow("Division ratio cannot be zero");
});

it("lists and inspects rules through unchanged V2 reads", async () => {
  const calls: Array<Record<string, unknown>> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      if (body.program.function === "rules.expression.version.list")
        return new Response(
          JSON.stringify({
            result: {
              rows: [
                {
                  ruleId: "planning.driver",
                  version: 2,
                  resultKey: "driver.output",
                  parameterDeclarations: {},
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
            ruleId: "planning.driver",
            version: 2,
            status: "Published",
            program: {
              languageVersion: 2,
              function: "facts.expression.calculate",
            },
            currentMetadataRevision: 46,
            policyRevision: 37,
          },
        }),
      );
    }),
  );
  render(
    <BuildRules
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Editor", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {
          "rules.expression.version.list": {},
          "rules.expression.version.read": {},
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
  fireEvent.click(screen.getByRole("button", { name: "Read rules" }));
  await waitFor(() =>
    expect(
      screen.getByText("planning.driver", { selector: "th" }),
    ).toBeInTheDocument(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Calculation rule detail")).toHaveTextContent(
      "facts.expression.calculate",
    ),
  );
  expect(calls).toEqual([
    expect.objectContaining({
      program: {
        languageVersion: 2,
        function: "rules.expression.version.list",
        arguments: { limit: 100 },
      },
    }),
    expect.objectContaining({
      program: {
        languageVersion: 2,
        function: "rules.expression.version.read",
        arguments: { ruleId: "planning.driver", version: 2 },
      },
    }),
  ]);
});
