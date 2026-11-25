import {
  useMetadataMutationRecovery,
  type MetadataMutationRecord,
} from "./metadata-mutation-recovery";
import type { ApplicationCatalog, Scope } from "./types";

const actions = [
  "create",
  "rename",
  "members.set",
  "default.set",
  "status.set",
] as const;
export type NamedHierarchyAction = (typeof actions)[number];
export const namedHierarchyFunction = (action: NamedHierarchyAction) =>
  `metadata.hierarchy.${action}`;

type MembershipChange = { memberId: string; status: "Active" | "Inactive" };
export type NamedHierarchyChange =
  | {
      action: "create";
      hierarchyId: string;
      name: string;
      membershipMode: "explicit" | "all_active";
      isDefault: boolean;
    }
  | { action: "rename"; hierarchyId: string; name: string }
  | { action: "members.set"; hierarchyId: string; members: MembershipChange[] }
  | { action: "default.set"; hierarchyId: string }
  | {
      action: "status.set";
      hierarchyId: string;
      status: "Active" | "Inactive";
    };

type Attempt = {
  change: NamedHierarchyChange;
  actorId: string;
  dimensionId: string;
  metadataRevision: number;
  editorContext: string;
};
const namedHierarchyProtocol = {
  editor: "named-hierarchy-change",
  pendingLabel: "Named hierarchy change with an unconfirmed outcome",
  functions: actions.map(namedHierarchyFunction),
  subject: "hierarchy change",
  closePrompt:
    "Close this unconfirmed hierarchy change? Review the current hierarchy before submitting another change.",
  refuses: (code: string) =>
    code.startsWith("HIERARCHY_") ||
    [
      "ACTIVE_DIMENSION_REQUIRED",
      "ACTIVE_HIERARCHY_REQUIRED",
      "EXPLICIT_ACTIVE_HIERARCHY_REQUIRED",
    ].includes(code),
};

export function useNamedHierarchyRecovery(
  scope: Scope | undefined,
  catalog: ApplicationCatalog | null,
  context: string,
  onRecorded: (details: Attempt, source: MetadataMutationRecord) => void,
) {
  return useMetadataMutationRecovery(
    scope,
    catalog,
    context,
    namedHierarchyProtocol,
    onRecorded,
  );
}
