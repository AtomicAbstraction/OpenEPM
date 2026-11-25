import { ApiError, type AdmittedEffectPacket } from "./api";
import { useGovernedEffectRecovery } from "./governed-effect-recovery";
import { receiptForActorAfterRevision } from "./ReceiptInspector";
import type { ApplicationCatalog, Scope } from "./types";

export const hierarchyBuild = "metadata.hierarchy.build";
type BuildAttempt = {
  actorId: string;
  metadataRevision: number;
  hierarchyId?: string;
  stateToken: string | null;
};
type Original = { packet: AdmittedEffectPacket; details: BuildAttempt };
type BuildRecord = "reply" | "receipt";
const tokenPattern = /^[0-9a-f]{64}$/;
const buildRefusals = new Set([
  "ACTIVE_DIMENSION_REQUIRED",
  "APPLICATION_GRANT_REQUIRED",
  "APPLICATION_NOT_WRITABLE",
  "APPLICATION_PROGRAM_INVALID",
  "HIERARCHY_CYCLE",
  "HIERARCHY_EDGE_LIMIT",
  "HIERARCHY_INACTIVE_MEMBER",
  "HIERARCHY_MEMBER_LIMIT",
  "HIERARCHY_PATH_LIMIT",
  "HIERARCHY_UNAVAILABLE",
  "METADATA_ACTION_CONFIRMATION_REQUIRED",
  "OPERATION_ADMISSION_MISMATCH",
  "STALE_HIERARCHY_STATE_TOKEN",
  "STALE_METADATA_REVISION",
]);

function buildReply(
  value: unknown,
  { details, packet }: Original,
): BuildRecord | null {
  const reply = value as {
    languageVersion?: unknown;
    function?: unknown;
    result?: {
      operationId?: string;
      hierarchyId?: string;
      stateToken?: string;
      closureCount?: number;
      membershipSemantics?: string;
      committedRevision?: number;
    };
  } | null;
  const result = reply?.result;
  return reply?.languageVersion === 2 &&
    reply.function === hierarchyBuild &&
    result?.operationId === packet.body.idempotencyKey &&
    typeof result.hierarchyId === "string" &&
    Boolean(result.hierarchyId) &&
    (details.hierarchyId === undefined ||
      result.hierarchyId === details.hierarchyId) &&
    typeof result.stateToken === "string" &&
    tokenPattern.test(result.stateToken) &&
    result.stateToken !== details.stateToken &&
    Number.isSafeInteger(result.closureCount) &&
    Number(result.closureCount) >= 0 &&
    Number(result.closureCount) <= 100000 &&
    (result.membershipSemantics === "unique_member" ||
      result.membershipSemantics === "placement") &&
    Number.isSafeInteger(result.committedRevision) &&
    Number(result.committedRevision) > details.metadataRevision
    ? "reply"
    : null;
}

function buildReceipt(
  value: unknown,
  { packet, details }: Original,
): BuildRecord | null {
  const receipt = receiptForActorAfterRevision(
    value,
    packet.body.idempotencyKey,
    details.actorId,
    details.metadataRevision,
  );
  return receipt?.outcome.function === hierarchyBuild ? "receipt" : null;
}

export function useHierarchyBuildRecovery(
  scope: Scope | undefined,
  catalog: ApplicationCatalog | null,
  context: string,
  dimensionId: string,
  onRecorded: (details: BuildAttempt, source: BuildRecord) => void,
) {
  return useGovernedEffectRecovery(
    scope,
    catalog,
    context,
    {
      path: "/api/metadata-action",
      tool: "execute_v2_metadata_program",
      editor: `metadata-hierarchy-build:${dimensionId}`,
      pendingLabel: "Hierarchy build with an unconfirmed outcome",
      functions: [hierarchyBuild],
      subject: "hierarchy build",
      closePrompt:
        "Close this unconfirmed build? Read the current hierarchy before reviewing another build.",
      initialRefusal: (reason) =>
        reason instanceof ApiError &&
        [400, 403, 409, 422].includes(reason.status) &&
        buildRefusals.has(reason.code),
      result: buildReply,
      receiptResult: buildReceipt,
    },
    onRecorded,
  );
}
