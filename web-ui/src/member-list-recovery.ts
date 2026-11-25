import { ApiError, type AdmittedEffectPacket } from "./api";
import { canonicalProgramDigest } from "./canonical-program-digest";
import { useGovernedEffectRecovery } from "./governed-effect-recovery";
import { receiptForActorAfterRevision } from "./ReceiptInspector";
import type { ApplicationCatalog, Scope } from "./types";

const statuses = {
  "metadata.member_list.save": "Saved",
  "metadata.member_list.activate": "Published",
  "metadata.member_list.deactivate": "Inactive",
  "metadata.member_list.delete": "Deleted",
} as const;

export type MemberListEffect = keyof typeof statuses;
export type MemberListChange = {
  functionName: MemberListEffect;
  listId: string;
  issuer: string;
  actorId: string;
  previousCommit: number;
  metadataRevision: number;
  policyRevision: number;
};

export type MemberListRecorded = {
  status: (typeof statuses)[MemberListEffect];
  pins?: { metadata: number; policy: number };
};

type Attempt = { packet: AdmittedEffectPacket; details: MemberListChange };

function exactReply(
  value: unknown,
  { packet, details }: Attempt,
): MemberListRecorded | null {
  const reply = value as {
    languageVersion?: unknown;
    function?: unknown;
    result?: {
      operationId?: unknown;
      listId?: unknown;
      status?: unknown;
      stateToken?: unknown;
      metadataRevision?: unknown;
      policyRevision?: unknown;
    };
  } | null;
  const result = reply?.result;
  const status = statuses[details.functionName];
  if (
    reply?.languageVersion !== 2 ||
    reply.function !== details.functionName ||
    result?.operationId !== packet.body.idempotencyKey ||
    result.listId !== details.listId ||
    result.status !== status ||
    result.metadataRevision !== details.metadataRevision ||
    (result.policyRevision !== details.policyRevision + 1 &&
      !(status === "Saved" && result.policyRevision === details.policyRevision))
  )
    return null;
  const token = result.stateToken;
  if (
    status === "Deleted"
      ? token !== null
      : typeof token !== "string" || !/^[a-f0-9]{64}$/.test(token)
  )
    return null;
  return {
    status,
    pins: { metadata: details.metadataRevision, policy: result.policyRevision },
  };
}

async function exactReceipt(
  value: unknown,
  { packet, details }: Attempt,
): Promise<MemberListRecorded | null> {
  const body = packet.body;
  const receipt = receiptForActorAfterRevision(
    value,
    body.idempotencyKey,
    details.actorId,
    details.previousCommit,
  );
  const status = statuses[details.functionName];
  // The member-list owner seals the original program, exact app and issuer/subject.
  // This also identifies existing receipts that carry no function or list fields.
  if (
    receipt?.outcome.status !== status ||
    receipt.commandDigest !==
      (await canonicalProgramDigest({
        scope: [body.workspaceId, body.applicationId],
        identity: [details.issuer, details.actorId],
        program: body.program,
      }))
  )
    return null;
  return { status };
}

const definitiveCodes = new Set([
  "APPLICATION_CAPABILITY_DISABLED",
  "APPLICATION_GRANT_REQUIRED",
  "APPLICATION_NOT_WRITABLE",
  "APPLICATION_UNAVAILABLE",
  "WORKSPACE_NOT_WRITABLE",
  "WORKSPACE_UNAVAILABLE",
  "RULE_GRANT_REQUIRED",
  "DEFINITION_CURRENT_VALIDATION_REQUIRED",
  "DEFINITION_OWNERSHIP_UNRESOLVED",
  "DEFINITION_REFERENCES_BLOCK_REMOVAL",
  "DEFINITION_SOURCE_OR_RECONCILIATION_REQUIRED",
  "PYTHON_DEFINITION_SOURCE_ACTIVATION_REQUIRED",
  "PYTHON_DEFINITION_SOURCE_REQUIRED",
  "STALE_METADATA_REVISION",
  "STALE_POLICY_REVISION",
  "OPERATION_ADMISSION_EXPIRED",
  "OPERATION_ADMISSION_MISMATCH",
  "METADATA_ACTION_CONFIRMATION_REQUIRED",
  "PROGRAM_VALIDATION_FAILED",
]);

const protocol = {
  path: "/api/metadata-action",
  tool: "execute_v2_metadata_program",
  editor: "member-list-change",
  pendingLabel: "Member-list change with an unconfirmed outcome",
  subject: "member-list change",
  functions: Object.keys(statuses),
  closePrompt:
    "Close this unconfirmed request? Review the current member list before submitting another change.",
  initialRefusal: (reason: unknown) =>
    reason instanceof ApiError &&
    [400, 403, 404, 409, 422].includes(reason.status) &&
    (reason.code.startsWith("MEMBER_LIST_") ||
      definitiveCodes.has(reason.code)),
  result: exactReply,
  receiptResult: exactReceipt,
};

export function useMemberListRecovery(
  scope: Scope | undefined,
  catalog: ApplicationCatalog | null,
  context: string,
  onRecorded: (change: MemberListChange, recorded: MemberListRecorded) => void,
) {
  return useGovernedEffectRecovery(
    scope,
    catalog,
    context,
    protocol,
    onRecorded,
  );
}
