import { ApiError, type AdmittedEffectPacket } from "./api";
import { useGovernedEffectRecovery } from "./governed-effect-recovery";
import { receiptForActorAfterRevision } from "./ReceiptInspector";
import type { ApplicationCatalog, Scope } from "./types";

export const placementApply = "metadata.hierarchy.relationships.apply";

export type PlacementDraftAction = "create" | "copy" | "move";

export type HierarchyPatchPreview = {
  previewToken: string;
  hierarchyId: string;
  graphDigest: string;
  closureDigest: string;
  memberCount: number;
  edgeCount: number;
  closureCount: number;
  affectedPathCount: number;
  affectedRelationshipIds: string[];
};

type PlacementAttempt = {
  action: PlacementDraftAction;
  actorId: string;
  preview: HierarchyPatchPreview;
  metadataRevision: number;
};

type PlacementRecord = "reply" | "receipt";
const hexDigest = /^[0-9a-f]{64}$/;

function exactPlacementReply(
  value: unknown,
  { details }: { details: PlacementAttempt },
): PlacementRecord | null {
  const reply = value as {
    languageVersion?: unknown;
    function?: unknown;
    result?: Partial<HierarchyPatchPreview> & {
      kind?: string;
      operation?: string;
      metadataRevision?: number;
      committedRevision?: number;
      stateToken?: string;
    };
  } | null;
  const { metadataRevision, preview } = details;
  const result = reply?.result;
  if (
    reply?.languageVersion !== 2 ||
    reply.function !== placementApply ||
    result?.kind !== "hierarchy.build" ||
    result.operation !== "relationship.patch" ||
    result.metadataRevision !== metadataRevision + 1 ||
    !Number.isSafeInteger(result.committedRevision) ||
    Number(result.committedRevision) < result.metadataRevision ||
    typeof result.stateToken !== "string" ||
    !hexDigest.test(result.stateToken) ||
    typeof result.graphDigest !== "string" ||
    !hexDigest.test(result.graphDigest) ||
    typeof result.closureDigest !== "string" ||
    !hexDigest.test(result.closureDigest) ||
    ![
      "hierarchyId",
      "graphDigest",
      "closureDigest",
      "memberCount",
      "edgeCount",
      "closureCount",
      "affectedPathCount",
    ].every(
      (key) =>
        result[key as keyof HierarchyPatchPreview] ===
        preview[key as keyof HierarchyPatchPreview],
    ) ||
    !Array.isArray(result.affectedRelationshipIds) ||
    !Array.isArray(preview.affectedRelationshipIds) ||
    result.affectedRelationshipIds.length !==
      preview.affectedRelationshipIds.length ||
    !result.affectedRelationshipIds.every(
      (id, index) => id === preview.affectedRelationshipIds[index],
    )
  )
    return null;
  return "reply";
}

function exactPlacementReceipt(
  value: unknown,
  {
    packet,
    details,
  }: { packet: AdmittedEffectPacket; details: PlacementAttempt },
): PlacementRecord | null {
  return receiptForActorAfterRevision(
    value,
    packet.body.idempotencyKey,
    details.actorId,
    details.metadataRevision,
  )
    ? "receipt"
    : null;
}

const placementProtocol = {
  path: "/api/metadata-action",
  tool: "execute_v2_metadata_program",
  editor: "hierarchy-placement-apply",
  pendingLabel: "Hierarchy placement change with an unconfirmed outcome",
  functions: [placementApply],
  subject: "placement change",
  closePrompt:
    "Close this unconfirmed placement change? Review the current hierarchy before applying another change.",
  initialRefusal: (reason: unknown) =>
    reason instanceof ApiError &&
    [400, 403, 409, 422].includes(reason.status) &&
    (reason.code.startsWith("HIERARCHY_PATCH_") ||
      [
        "APPLICATION_GRANT_REQUIRED",
        "APPLICATION_NOT_WRITABLE",
        "APPLICATION_PROGRAM_INVALID",
        "METADATA_ACTION_CONFIRMATION_REQUIRED",
        "OPERATION_ADMISSION_MISMATCH",
        "RELATIONSHIP_HAS_ACTIVE_OWNERSHIP",
        "SEMANTIC_REFERENCE_MEMBER_UNAVAILABLE",
        "STALE_METADATA_REVISION",
      ].includes(reason.code)),
  result: exactPlacementReply,
  receiptResult: exactPlacementReceipt,
};

export function useHierarchyPlacementRecovery(
  scope: Scope | undefined,
  catalog: ApplicationCatalog | null,
  context: string,
  onRecorded: (details: PlacementAttempt, source: PlacementRecord) => void,
) {
  return useGovernedEffectRecovery(
    scope,
    catalog,
    context,
    placementProtocol,
    onRecorded,
  );
}
