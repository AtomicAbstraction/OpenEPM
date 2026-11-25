import { ApiError, type AdmittedEffectPacket } from "./api";
import type { ApplicationCatalog, Scope } from "./types";
import {
  useGovernedEffectRecovery,
  type GovernedEffectBody,
} from "./governed-effect-recovery";

type DelegationChange = { delegationId: string; action: "create" | "revoke" };

type Receipt = {
  languageVersion?: unknown;
  function?: unknown;
  result?: {
    operationId?: unknown;
    delegationId?: unknown;
    status?: unknown;
    stateToken?: unknown;
    policyRevision?: unknown;
  };
};

function exactReceipt(
  value: unknown,
  original: { packet: AdmittedEffectPacket; details: DelegationChange },
) {
  const reply = value as Receipt;
  const {
    packet,
    details: { action, delegationId },
  } = original;
  const expectedRevision = (
    packet.body.program.arguments as Record<string, unknown>
  ).expectedPolicyRevision;
  return reply?.languageVersion === 2 &&
    reply.function === packet.body.program.function &&
    reply.result?.operationId === packet.body.idempotencyKey &&
    reply.result.delegationId === delegationId &&
    reply.result.status === (action === "create" ? "Active" : "Revoked") &&
    typeof reply.result.stateToken === "string" &&
    /^[a-f0-9]{64}$/.test(reply.result.stateToken) &&
    typeof expectedRevision === "number" &&
    Number.isSafeInteger(reply.result.policyRevision) &&
    reply.result.policyRevision === expectedRevision + 1
    ? reply
    : null;
}

function initialRefusal(reason: unknown) {
  return (
    reason instanceof ApiError &&
    [400, 403, 409, 422].includes(reason.status) &&
    (reason.code.startsWith("EXECUTION_DELEGATION_") ||
      reason.code.startsWith("OPERATION_ADMISSION_") ||
      reason.code === "APPLICATION_GRANT_REQUIRED" ||
      reason.code === "PROGRAM_VALIDATION_FAILED")
  );
}

const delegationProtocol = {
  path: "/api/execution-delegation",
  tool: "execute_v2_execution_delegation",
  editor: "execution-delegation-change",
  pendingLabel: "Execution authority change with an unconfirmed outcome",
  functions: ["execution.delegation.create", "execution.delegation.revoke"],
  subject: "authority change",
  closePrompt:
    "Close this unconfirmed request? Read the current authority before submitting another change.",
  initialRefusal,
  result: exactReceipt,
};

export function useExecutionDelegationChange(
  scope: Scope | undefined,
  catalog: ApplicationCatalog | null,
  context: string,
  onRecorded: (details: DelegationChange) => void,
) {
  const recovery = useGovernedEffectRecovery(
    scope,
    catalog,
    context,
    delegationProtocol,
    onRecorded,
  );
  return {
    ...recovery,
    submit: (
      body: GovernedEffectBody,
      delegationId: string,
      action: DelegationChange["action"],
    ) => recovery.submit(body, { delegationId, action }),
    closeRecovery: () => recovery.closeRecovery()?.delegationId ?? null,
  };
}
