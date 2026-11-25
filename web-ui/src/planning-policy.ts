import { ApiError, type AdmittedEffectPacket } from "./api";
import { canonicalProgramDigest } from "./canonical-program-digest";
import { receiptForActorAfterRevision } from "./ReceiptInspector";
import type { Scope } from "./types";

export const policyFunctions = {
  list: "cube.write.policy.list",
  read: "cube.write.policy.read",
  save: "cube.write.policy.save",
  activate: "cube.write.policy.activate",
  deactivate: "cube.write.policy.deactivate",
} as const;
export type PolicyAction = "save" | "activate" | "deactivate";
export const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
export const isId = (s: unknown): s is string =>
  typeof s === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}(?![\s\S])/.test(s);
const isToken = (s: unknown): s is string =>
  typeof s === "string" && /^[0-9a-f]{64}(?![\s\S])/.test(s);
const isDate = (value: unknown): value is string =>
  typeof value === "string" &&
  /^\d{4}-\d{2}-\d{2}$/.test(value) &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString().slice(0, 10) === value;

export type Rule = {
  ruleId: string;
  priority: number;
  effect: "Allow" | "Deny";
  actions: string[];
  workflowRoles: string[];
  memberSelectors: Record<string, string[]>;
  scenarioBound: { dimensionId: string; members: string[] } | null;
  periodBound: {
    dimensionId: string;
    orderedMembers: string[];
    startMemberId: string;
    endMemberId: string;
  } | null;
  levelSelector?: {
    dimensionId: string;
    rootMemberId: string;
    depth: number;
  } | null;
  effectiveFrom: string | null;
  effectiveTo: string | null;
};
export type Definition = Scope & {
  policyId: string;
  effectiveFrom: string;
  effectiveTo: string | null;
  format?: "openepm-planning-workflow-policy-v2";
  rules: Rule[];
};
export type Policy = {
  policyId: string;
  stateToken: string;
  canonicalDigest: string;
  status: "Saved" | "Active";
  actor: { issuer: string; subjectId: string };
  updatedAt: string;
  definition: Definition;
  pendingDraft?: Policy | null;
};
export type PolicyPage = {
  policies: Policy[];
  collectionToken: string;
  nextAfterPolicyId: string | null;
};
export function newRule(): Rule {
  return {
    ruleId: "",
    priority: 100,
    effect: "Allow",
    actions: ["Set"],
    workflowRoles: [],
    memberSelectors: {},
    scenarioBound: null,
    periodBound: null,
    effectiveFrom: null,
    effectiveTo: null,
  };
}
export function newDefinition(scope: Scope): Definition {
  return {
    workspaceId: scope.workspaceId,
    applicationId: scope.applicationId,
    policyId: "",
    effectiveFrom: "",
    effectiveTo: null,
    rules: [newRule()],
  };
}
const ids = (value: unknown, max = 100): value is string[] =>
  Array.isArray(value) &&
  value.length > 0 &&
  value.length <= max &&
  value.every(isId) &&
  new Set(value).size === value.length;
const dates = (start: unknown, end: unknown) =>
  (start === null || isDate(start)) &&
  (end === null || isDate(end)) &&
  (start === null || end === null || start <= end);
function validRule(rule: unknown, v2: boolean): rule is Rule {
  if (
    !isObject(rule) ||
    !isId(rule.ruleId) ||
    !Number.isInteger(rule.priority) ||
    Number(rule.priority) < 0 ||
    Number(rule.priority) > 10000 ||
    !["Allow", "Deny"].includes(String(rule.effect)) ||
    !ids(rule.actions) ||
    !ids(rule.workflowRoles) ||
    !dates(rule.effectiveFrom, rule.effectiveTo) ||
    !isObject(rule.memberSelectors) ||
    Object.keys(rule.memberSelectors).length > 32 ||
    !Object.entries(rule.memberSelectors).every(
      ([key, val]) => isId(key) && ids(val, 1000),
    )
  )
    return false;
  const dimensions = Object.keys(rule.memberSelectors);
  const scenario = rule.scenarioBound,
    period = rule.periodBound,
    level = rule.levelSelector;
  if (scenario !== null) {
    if (
      !isObject(scenario) ||
      !isId(scenario.dimensionId) ||
      !ids(scenario.members, 1000)
    )
      return false;
    dimensions.push(scenario.dimensionId);
  }
  if (period !== null) {
    if (
      !isObject(period) ||
      !isId(period.dimensionId) ||
      !ids(period.orderedMembers, 1000) ||
      !isId(period.startMemberId) ||
      !isId(period.endMemberId) ||
      !period.orderedMembers.includes(period.startMemberId) ||
      period.orderedMembers.indexOf(period.endMemberId) <
        period.orderedMembers.indexOf(period.startMemberId)
    )
      return false;
    dimensions.push(period.dimensionId);
  }
  if (v2 && level !== null) {
    if (
      !isObject(level) ||
      !isId(level.dimensionId) ||
      !isId(level.rootMemberId) ||
      !Number.isInteger(level.depth) ||
      Number(level.depth) < 0 ||
      Number(level.depth) > 1000
    )
      return false;
    dimensions.push(level.dimensionId);
  }
  return (
    (v2 || level === undefined) &&
    new Set(dimensions).size === dimensions.length
  );
}
export function validDefinition(
  data: unknown,
  scope: Scope,
): data is Definition {
  return (
    isObject(data) &&
    data.workspaceId === scope.workspaceId &&
    data.applicationId === scope.applicationId &&
    isId(data.policyId) &&
    isDate(data.effectiveFrom) &&
    dates(data.effectiveFrom, data.effectiveTo) &&
    (data.format === undefined ||
      data.format === "openepm-planning-workflow-policy-v2") &&
    Array.isArray(data.rules) &&
    data.rules.length > 0 &&
    data.rules.length <= 500 &&
    data.rules.every((rule) => validRule(rule, Boolean(data.format))) &&
    new Set(data.rules.map((rule) => rule.ruleId)).size === data.rules.length
  );
}
export function policyRecord(
  value: unknown,
  scope: Scope,
  id: unknown,
  nested = false,
): Policy {
  if (
    !isObject(value) ||
    value.policyId !== id ||
    !isToken(value.stateToken) ||
    !isToken(value.canonicalDigest) ||
    !["Active", "Saved"].includes(String(value.status)) ||
    value.active !== (value.status === "Active") ||
    !validDefinition(value.definition, scope) ||
    value.definition.policyId !== id ||
    !isObject(value.actor) ||
    typeof value.actor.issuer !== "string" ||
    typeof value.actor.subjectId !== "string" ||
    typeof value.updatedAt !== "string"
  )
    throw new Error("The policy reply could not be verified.");
  if (value.pendingDraft != null) {
    if (nested || value.status !== "Active")
      throw new Error("The pending draft could not be verified.");
    const pending = policyRecord(value.pendingDraft, scope, id, true);
    if (pending.status !== "Saved" || pending.stateToken === value.stateToken)
      throw new Error("The pending draft could not be verified.");
  }
  return value as unknown as Policy;
}
export function policyPage(
  value: unknown,
  scope: Scope,
  cursor?: PolicyPage,
): PolicyPage {
  if (
    !isObject(value) ||
    !Array.isArray(value.policies) ||
    value.policies.length > 25 ||
    !isToken(value.collectionToken) ||
    (cursor && value.collectionToken !== cursor.collectionToken)
  )
    throw new Error("The policy collection changed. Refresh the list.");
  const policies = value.policies.map((row) =>
    policyRecord(row, scope, row?.policyId),
  );
  // PostgreSQL owns the collection order, including its identifier collation.
  const seen = new Set(cursor?.policies.map((row) => row.policyId));
  for (const row of policies) {
    if (seen.has(row.policyId) || row.policyId === cursor?.nextAfterPolicyId)
      throw new Error("The policy page is inconsistent. Refresh the list.");
    seen.add(row.policyId);
  }
  if (
    value.nextAfterPolicyId !== null &&
    (!policies.length || value.nextAfterPolicyId !== policies.at(-1)?.policyId)
  )
    throw new Error("The policy page cursor is invalid. Refresh the list.");
  return {
    policies,
    collectionToken: value.collectionToken,
    nextAfterPolicyId: value.nextAfterPolicyId as string | null,
  };
}
// Level pins and the authored-intent digest belong to the server. Carry the original selector when revising a rule.
export function authoredDefinition(policy: Policy): Definition {
  const d = policy.definition;
  return {
    workspaceId: d.workspaceId,
    applicationId: d.applicationId,
    policyId: d.policyId,
    effectiveFrom: d.effectiveFrom,
    effectiveTo: d.effectiveTo,
    ...(d.format && { format: d.format }),
    rules: d.rules.map((rule) => {
      const copy = structuredClone(rule);
      if (copy.levelSelector) {
        const { dimensionId, rootMemberId, depth } = copy.levelSelector;
        copy.levelSelector = { dimensionId, rootMemberId, depth };
      }
      return copy;
    }),
  };
}
export type Review = {
  action: PolicyAction;
  policyId: string;
  args: Record<string, unknown>;
  previousCommit: number;
  issuer: string;
  actorId: string;
  groupAssigned: boolean;
};
type Attempt = { packet: AdmittedEffectPacket; details: Review };
const status = (action: PolicyAction) =>
  action === "activate" ? "Active" : "Saved";
const protocol = {
  path: "/api/planning-policy",
  tool: "execute_v2_cube_write_policy",
  editor: "planning-policy-operation",
  pendingLabel: "Planning policy change awaiting confirmation",
  subject: "planning policy change",
  functions: [
    policyFunctions.save,
    policyFunctions.activate,
    policyFunctions.deactivate,
  ],
  closePrompt:
    "Close this expired policy request and read the current policy again?",
  initialRefusal: (e: unknown) =>
    e instanceof ApiError &&
    (e.kind === "authorization" ||
      ([400, 404, 409, 413, 422].includes(e.status) &&
        e.code !== "PLANNING_POLICY_IDEMPOTENCY_CONFLICT" &&
        (e.code.startsWith("PLANNING_POLICY_") ||
          [
            "APPLICATION_NOT_WRITABLE",
            "OPERATION_ADMISSION_MISMATCH",
            "PROGRAM_VALIDATION_FAILED",
          ].includes(e.code)))),
  result: (v: unknown, { details }: Attempt) => {
    if (
      !isObject(v) ||
      v.languageVersion !== 2 ||
      v.function !== policyFunctions[details.action] ||
      !isObject(v.result)
    )
      return null;
    const r = v.result;
    return r.policyId === details.policyId &&
      r.status === status(details.action) &&
      isToken(r.stateToken) &&
      isToken(r.canonicalDigest) &&
      Number.isSafeInteger(r.policyRevision) &&
      Number(r.policyRevision) >= 0 &&
      (details.action !== "activate" ||
        details.args.canonicalDigest === r.canonicalDigest)
      ? status(details.action)
      : null;
  },
  receiptResult: async (v: unknown, { packet, details }: Attempt) => {
    const body = packet.body;
    const receipt = receiptForActorAfterRevision(
      v,
      body.idempotencyKey,
      details.actorId,
      details.previousCommit,
    );
    if (
      receipt?.outcome.status !== status(details.action) ||
      ((details.groupAssigned || receipt.outcome.function !== undefined) &&
        receipt.outcome.function !== policyFunctions[details.action])
    )
      return null;
    const digest = await canonicalProgramDigest(
      {
        scope: [body.workspaceId, body.applicationId],
        actor: [details.issuer, details.actorId],
        function: body.program.function,
        ...details.args,
        ...(details.action === "save" && {
          expectedStateToken: details.args.expectedStateToken ?? null,
        }),
        idempotencyKey: body.idempotencyKey,
      },
      true,
    );
    return receipt.commandDigest === digest ? status(details.action) : null;
  },
};
export default protocol;
