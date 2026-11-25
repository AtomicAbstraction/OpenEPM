import type { AdmittedEffectPacket } from "./api";
import {
  canonicalProgramDigest as ruleValueDigest,
  canonicalProgramJson as canonical,
} from "./canonical-program-digest";
import { exactWorkflowOutcome, type WorkflowOutcome } from "./workflow-outcome";

export { ruleValueDigest };

export type RuleRunRequest = {
  workspaceId: string;
  applicationId: string;
  program: {
    languageVersion: number;
    function: string;
    arguments: {
      ruleId: string;
      bindings: Record<string, unknown>;
      expectedStateToken: string;
      expectedProgramDigest: string;
    };
  };
  idempotencyKey: string;
  confirmed: boolean;
};
export type RuleRunPacket = AdmittedEffectPacket & { body: RuleRunRequest };
export type RuleRunOutcome = WorkflowOutcome & {
  ruleId: string;
  stateToken: string;
  bindings: Record<string, unknown>;
  bindingDigest: string;
  argumentsDigest: string;
  memberListPins?: Array<Record<string, unknown>>;
  publishedRule?: { ruleId: string; stateToken: string; programDigest: string };
  sealedPlanDigest?: string;
  freshness?: { current: boolean; staleReasons: string[] };
  lineage?: Array<{ ordinal: number; unitName: string }>;
};

function object(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
const digest = (value: unknown): value is string =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const identifier = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(value);

/** Acknowledgement and lineage are distinct native projections. The sealed
 * plan digest is not the source's compiled program digest. Normalized returned
 * bindings can differ from the original Decimal spelling without changing it. */
export async function exactRuleRunOutcome(
  value: unknown,
  packet: RuleRunPacket,
  prior?: RuleRunOutcome,
  lineage = false,
): Promise<RuleRunOutcome> {
  const expected = packet.body.program.arguments;
  if (!object(value))
    throw new Error("The server returned an invalid rule workflow.");
  const run = exactWorkflowOutcome(value as RuleRunOutcome, prior);
  if (
    run.ruleId !== expected.ruleId ||
    run.stateToken !== expected.expectedStateToken ||
    !object(run.bindings) ||
    !digest(run.bindingDigest) ||
    !digest(run.argumentsDigest) ||
    run.argumentsDigest !==
      (await ruleValueDigest({
        ruleId: expected.ruleId,
        bindings: expected.bindings,
      })) ||
    run.bindingDigest !== (await ruleValueDigest(run.bindings)) ||
    (prior &&
      (run.argumentsDigest !== prior.argumentsDigest ||
        run.bindingDigest !== prior.bindingDigest))
  )
    throw new Error(
      "Run returned a different rule, definition or parameter identity.",
    );
  if (
    run.memberListPins !== undefined &&
    (!Array.isArray(run.memberListPins) ||
      run.memberListPins.some(
        (pin) =>
          !object(pin) ||
          !identifier(pin.parameter) ||
          !identifier(pin.dimensionId) ||
          !identifier(pin.listId) ||
          !digest(pin.stateToken) ||
          !digest(pin.canonicalDigest) ||
          !digest(pin.memberIdsDigest) ||
          !digest(pin.resolutionDigest) ||
          !object(pin.parameters) ||
          !Number.isSafeInteger(pin.metadataRevision) ||
          Number(pin.metadataRevision) < 0 ||
          !Number.isSafeInteger(pin.memberCount) ||
          Number(pin.memberCount) < 0,
      ))
  )
    throw new Error("Run returned invalid member-list resolution pins.");
  if (
    prior &&
    canonical(run.memberListPins ?? []) !==
      canonical(prior.memberListPins ?? [])
  )
    throw new Error("Run returned different member-list resolution pins.");
  if (
    lineage &&
    (run.publishedRule?.ruleId !== expected.ruleId ||
      run.publishedRule?.stateToken !== expected.expectedStateToken ||
      run.publishedRule?.programDigest !== expected.expectedProgramDigest ||
      run.sealedPlanDigest !== run.planDigest ||
      !object(run.freshness) ||
      typeof run.freshness.current !== "boolean" ||
      !Array.isArray(run.freshness.staleReasons) ||
      run.freshness.staleReasons.some((reason) => typeof reason !== "string"))
  )
    throw new Error(
      "Status returned a different original rule or invalid lineage identity.",
    );
  if (lineage) {
    const chain = value.lineage;
    if (
      !Array.isArray(chain) ||
      chain.length !== run.unitCount ||
      typeof value.lineageComplete !== "boolean" ||
      (run.status === "published" && value.lineageComplete !== true) ||
      chain.some((item, index) => {
        if (
          !object(item) ||
          item.ordinal !== index + 1 ||
          typeof item.unitName !== "string" ||
          typeof item.function !== "string" ||
          typeof item.jobStatus !== "string" ||
          typeof item.committed !== "boolean" ||
          (item.jobId !== null && !identifier(item.jobId)) ||
          (item.receiptRevision !== null &&
            (!Number.isSafeInteger(item.receiptRevision) ||
              Number(item.receiptRevision) < 1)) ||
          (item.receiptId !== null && !identifier(item.receiptId))
        )
          return true;
        const checkpoint = run.checkpoints[index];
        return (
          item.committed !== Boolean(checkpoint?.committed) ||
          (checkpoint && item.jobId !== checkpoint.jobId) ||
          (item.committed &&
            (item.receiptId !== checkpoint?.receiptId ||
              item.receiptId !== item.jobId ||
              item.receiptRevision === null ||
              item.jobStatus !== "published")) ||
          (run.status === "published" && !item.committed)
        );
      })
    )
      throw new Error(
        "Status returned incomplete or inconsistent workflow receipt lineage.",
      );
  }
  return lineage ? run : { ...run, lineage: undefined };
}
