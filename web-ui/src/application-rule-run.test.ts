import { expect, it } from "vitest";
import {
  exactRuleRunOutcome,
  ruleValueDigest,
  type RuleRunPacket,
} from "./application-rule-run";
import { exactWorkflowOutcome } from "./workflow-outcome";
const packet: RuleRunPacket = {
  path: "/api/rule-action",
  body: {
    workspaceId: "ws",
    applicationId: "app",
    idempotencyKey: "original",
    confirmed: true,
    program: {
      languageVersion: 2,
      function: "application.rule.run",
      arguments: {
        ruleId: "forecast",
        bindings: {},
        expectedStateToken: "d".repeat(64),
        expectedProgramDigest: "a".repeat(64),
      },
    },
  },
};
const outcome = {
  workflowId: "1".repeat(32),
  planDigest: "2".repeat(64),
  ruleId: "forecast",
  stateToken: "d".repeat(64),
  bindings: {},
  bindingDigest:
    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
  argumentsDigest:
    "a644b29c41bf8dca1fee5b0460ce2f7f67824b4c5a43c4d09b4919691f8c468b",
  status: "running",
  unitCount: 1,
  committedUnits: 0,
  remainingUnits: 1,
  checkpoints: [],
};
it("matches fixed Python hashlib/json oracles including Unicode code-point ordering", async () => {
  expect(await ruleValueDigest({})).toBe(outcome.bindingDigest);
  expect(await ruleValueDigest({ ruleId: "forecast", bindings: {} })).toBe(
    outcome.argumentsDigest,
  );
  expect(
    await ruleValueDigest({
      Amount: "1E+2",
      Text: "é",
      Map: { "𐀀": "a", "\ue000": "b" },
    }),
  ).toBe("1f95517c69db2c93df875b77a8b39290f0f8cab29dae4f75f7e5673260a04190");
  await expect(ruleValueDigest({ value: 0.1 })).rejects.toThrow("inexact");
});
it("binds normalized decimals separately from original typed request spelling", async () => {
  const original = structuredClone(packet);
  original.body.program.arguments.bindings = { Amount: "1E+2" };
  const value = {
    ...outcome,
    bindings: { Amount: "100" },
    bindingDigest: await ruleValueDigest({ Amount: "100" }),
    argumentsDigest:
      "396d4bb27d1a3cf93fd21bc48f6714f61688b2a075cdfea75d6fd008875db577",
  };
  expect(await exactRuleRunOutcome(value, original)).toEqual(value);
  await expect(
    exactRuleRunOutcome(
      {
        ...value,
        argumentsDigest: await ruleValueDigest({
          ruleId: "forecast",
          bindings: value.bindings,
        }),
      },
      original,
    ),
  ).rejects.toThrow("parameter identity");
});
it.each([
  { workflowId: "wrong" },
  { planDigest: "wrong" },
  { unitCount: 0, remainingUnits: 0 },
  { status: "published" },
  { status: "partially_published" },
  { status: "failed", committedUnits: 1, remainingUnits: 0 },
  {
    checkpoints: [
      { ordinal: 1, jobId: "child", committed: true, receiptId: null },
    ],
    committedUnits: 1,
    remainingUnits: 0,
  },
])("rejects native workflow contradictions %#", (change) => {
  expect(() => exactWorkflowOutcome({ ...outcome, ...change })).toThrow();
});
it.each([
  { ruleId: "different" },
  { stateToken: "b".repeat(64) },
  { bindingDigest: "b".repeat(64) },
  { argumentsDigest: "b".repeat(64) },
  { memberListPins: [{ parameter: "p" }] },
])("rejects wrong original owner or typed bindings %#", async (change) => {
  await expect(
    exactRuleRunOutcome({ ...outcome, ...change }, packet),
  ).rejects.toThrow();
});
it("does not confuse plan digest with program digest and permits historical stale-source lineage", async () => {
  const lineage = {
    ...outcome,
    sealedPlanDigest: outcome.planDigest,
    publishedRule: {
      ruleId: "forecast",
      stateToken: outcome.stateToken,
      programDigest: "a".repeat(64),
    },
    freshness: { current: false, staleReasons: ["publication"] },
    lineageComplete: false,
    lineage: [
      {
        ordinal: 1,
        unitName: "u",
        function: "facts.numeric.batch",
        jobId: null,
        jobStatus: "not_admitted",
        committed: false,
        receiptId: null,
        receiptRevision: null,
      },
    ],
  };
  expect(await exactRuleRunOutcome(lineage, packet, outcome, true)).toEqual(
    lineage,
  );
  await expect(
    exactRuleRunOutcome(
      {
        ...lineage,
        publishedRule: {
          ...lineage.publishedRule,
          programDigest: outcome.planDigest,
        },
      },
      packet,
      outcome,
      true,
    ),
  ).rejects.toThrow("lineage identity");
  await expect(
    exactRuleRunOutcome({ ...lineage, lineage: [] }, packet, outcome, true),
  ).rejects.toThrow("receipt lineage");
});
it("cannot regress a committed receipt or replace the sealed plan under one workflow", () => {
  const prior = {
    ...outcome,
    checkpoints: [
      { ordinal: 1, jobId: "child", committed: true, receiptId: "child" },
    ],
    status: "published",
    committedUnits: 1,
    remainingUnits: 0,
  };
  expect(() =>
    exactWorkflowOutcome({ ...prior, planDigest: "e".repeat(64) }, prior),
  ).toThrow();
  expect(() =>
    exactWorkflowOutcome(
      {
        ...prior,
        checkpoints: [{ ...prior.checkpoints[0], receiptId: "different" }],
      },
      prior,
    ),
  ).toThrow();
});
