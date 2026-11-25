import { ApiError, type AdmittedEffectPacket } from "./api";
import { useGovernedEffectRecovery } from "./governed-effect-recovery";
import { receiptForActorAfterRevision } from "./ReceiptInspector";
import type { ApplicationCatalog, Scope } from "./types";

type MetadataAttempt = { actorId: string; metadataRevision: number };
type Original = { packet: AdmittedEffectPacket; details: MetadataAttempt };
export type MetadataMutationRecord = "reply" | "receipt";

type MetadataRecoveryPolicy = {
  editor: string;
  pendingLabel: string;
  functions: readonly string[];
  subject: string;
  closePrompt: string;
  refuses: (code: string) => boolean;
};

const refusalCodes = new Set([
  "APPLICATION_GRANT_REQUIRED",
  "APPLICATION_NOT_WRITABLE",
  "APPLICATION_PROGRAM_INVALID",
  "METADATA_ACTION_CONFIRMATION_REQUIRED",
  "OPERATION_ADMISSION_MISMATCH",
  "STALE_METADATA_REVISION",
]);

function exactMutationReply(
  value: unknown,
  { packet, details }: Original,
): MetadataMutationRecord | null {
  const reply = value as {
    languageVersion?: unknown;
    function?: unknown;
    result?: {
      operationId?: string;
      changedCount?: number;
      committedRevision?: number;
    };
  } | null;
  const result = reply?.result;
  return reply?.languageVersion === 2 &&
    reply.function === packet.body.program.function &&
    result?.operationId === packet.body.idempotencyKey &&
    result.changedCount === 1 &&
    Number.isSafeInteger(result.committedRevision) &&
    Number(result.committedRevision) > details.metadataRevision
    ? "reply"
    : null;
}

function exactMutationReceipt(
  value: unknown,
  { packet, details }: Original,
): MetadataMutationRecord | null {
  const receipt = receiptForActorAfterRevision(
    value,
    packet.body.idempotencyKey,
    details.actorId,
    details.metadataRevision,
  );
  return receipt?.outcome.changedCount === 1 ? "receipt" : null;
}

export function useMetadataMutationRecovery<Details extends MetadataAttempt>(
  scope: Scope | undefined,
  catalog: ApplicationCatalog | null,
  context: string,
  policy: MetadataRecoveryPolicy,
  onRecorded: (details: Details, source: MetadataMutationRecord) => void,
) {
  return useGovernedEffectRecovery<Details, MetadataMutationRecord>(
    scope,
    catalog,
    context,
    {
      ...policy,
      path: "/api/metadata-action",
      tool: "execute_v2_metadata_program",
      initialRefusal: (reason) =>
        reason instanceof ApiError &&
        [400, 403, 409, 422].includes(reason.status) &&
        (refusalCodes.has(reason.code) || policy.refuses(reason.code)),
      result: exactMutationReply,
      receiptResult: exactMutationReceipt,
    },
    onRecorded,
  );
}
