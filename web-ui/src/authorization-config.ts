export type Action = {
  action: string;
  scopeKinds: string[];
  canDelegate: boolean;
};
export type RoleTemplate = {
  templateId: string;
  version: number;
  name: string;
  actions: string[];
};
export type TemplateOrigin = {
  templateId: string;
  version: number;
  upstreamName: string;
  upstreamActions: string[];
  nameOverridden: boolean;
  addedActions: string[];
  removedActions: string[];
};
export type Role = {
  roleId: string;
  name: string;
  actions: string[];
  workflowDuties?: string[];
  templateOrigin?: TemplateOrigin | null;
};
export type ReviewedRoleTemplate = {
  roleId: string;
  name: string;
  priorVersion: number | null;
  origin: TemplateOrigin;
  actions: string[];
  addedActions: string[];
  removedActions: string[];
};
export type ResourceScope = {
  scopeId: string;
  name: string;
  scopeKind: string;
  selector: Record<string, unknown>;
};
export type Group = {
  groupId: string;
  groupName: string | null;
  displayName?: string | null;
};
export type Privilege = { action: string; scopeId: string };
export type Assignment = {
  assignmentId: string;
  groupId: string;
  roleId: string;
  privileges: Privilege[];
};
export const collectionKeys = {
  roles: "roleId",
  scopes: "scopeId",
  assignments: "assignmentId",
  eligibleGroups: "groupId",
} as const;
export type Collection = keyof typeof collectionKeys;
export type Configuration = {
  revision: number;
  authorizationMode: "legacy" | "group_assignments";
  complete: boolean;
  canManageRoles: boolean;
  canManageWorkflowDuties?: boolean;
  availableWorkflowDuties?: string[];
  workflowDutiesComplete?: boolean;
  canManageScopes: boolean;
  canManageAssignments: boolean;
  workspaceId: string;
  applicationId: string;
  actions: Action[];
  roles: Role[];
  roleTemplates?: RoleTemplate[];
  scopes: ResourceScope[];
  assignments: Assignment[];
  eligibleGroups: Group[];
  nextAfter: Record<Collection, string | null>;
  snapshotToken: string;
};
export type Change =
  | ({ op: "putAssignment" } & Assignment)
  | { op: "removeAssignment"; assignmentId: string }
  | ({ op: "putRole" } & Pick<
      Role,
      "roleId" | "name" | "actions" | "workflowDuties"
    >)
  | {
      op: "adoptRoleTemplate";
      roleId: string;
      templateId: string;
      templateVersion: number;
    }
  | { op: "removeRole"; roleId: string }
  | ({ op: "putScope" } & ResourceScope)
  | { op: "removeScope"; scopeId: string };
export type RequesterBenefitReason =
  | "new_grant_path"
  | "additional_grant_path"
  | "potential_scope_expansion"
  | "new_application_entry";
export type RequesterBenefit = {
  classification: "none" | RequesterBenefitReason;
  grantsComplete: boolean;
  applicationEntry?: "admitted" | "requires_entry";
  grants: {
    groupId: string;
    assignmentId: string;
    action: string;
    scopeId: string;
    roleId: string;
    scopeKind: "entire_application" | "dimension_tags" | "exact_object";
    selector: Record<string, unknown>;
    scopeRevision: number;
    reason: RequesterBenefitReason;
    expandedPrerequisite?: string;
    previousWorkflowDuties?: string[];
    reviewedWorkflowDuties?: string[];
  }[];
};
export type Preview = {
  applicationId: string;
  workspaceId: string;
  authorizationMode: Configuration["authorizationMode"];
  impact: {
    affectedAssignments: string[];
    requesterBenefit?: RequesterBenefit;
    reviewedRoleTemplates?: ReviewedRoleTemplate[];
    reviewedWorkflowDuties?: {
      roleId: string;
      addedDuties: string[];
      removedDuties: string[];
    }[];
    changed: Record<"roles" | "scopes" | "assignments", string[]>;
  };
  expectedRevision: number;
  reviewDigest: string;
  changes: Change[];
};

export function validWorkflowDuties(values: unknown): values is string[] {
  return (
    Array.isArray(values) &&
    values.length <= 100 &&
    values.every(
      (duty) =>
        typeof duty === "string" &&
        /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}(?![\s\S])/.test(duty),
    ) &&
    new Set(values).size === values.length
  );
}

export function scopeLabel(
  scope: Pick<ResourceScope, "selector" | "scopeKind">,
) {
  if (scope.scopeKind === "entire_application") return "Entire application";
  if (scope.scopeKind === "exact_object")
    return `${scope.selector.objectType} · ${scope.selector.objectId}`;
  if (scope.scopeKind === "dimension_tags") {
    return Object.entries(scope.selector)
      .map(
        ([id, tags]) =>
          `${id}: ${Array.isArray(tags) ? tags.join(", ") : "Unavailable"}`,
      )
      .join(" · ");
  }
  return scope.scopeKind;
}
