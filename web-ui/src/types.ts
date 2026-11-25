export type ApplicationSummary = {
  workspaceId: string;
  workspaceName?: string;
  applicationId: string;
  name: string;
  status: string;
  kind?: string;
};

export type SessionIdentity = {
  identityBinding: string;
  displayIdentity?: string;
  issuer?: string;
  subject: string;
  applicationMcpEndpoint?: string | null;
};

export type ApplicationCatalog = {
  accessContext?: string;
  ownedJobOperations?: ("read" | "events" | "cancel")[];
  workspaceFunctions?: string[];
  applicationAccess: {
    role: string;
    authorizationModel?: "legacy" | "group_assignments";
    roles?: string[];
    workspaceAdministrator: boolean;
    issuer?: string;
    subjectId?: string;
  };
  enabledCapabilities: string[];
  functions: Record<string, unknown>;
  operationContracts?: Record<string, unknown>;
  applicationBlueprint?: {
    version: number;
    dimensions: {
      dimensionId: string;
      name: string;
      modelRole: string;
      semanticRole: string;
      density: string;
      shortDescription: string;
      detailedDescription: string;
    }[];
  };
  revisions: {
    metadata: number;
    data: number;
    policy: number;
    security: number;
    commit: number;
    capability?: number;
    schemaEpoch?: number;
  };
};

export function applicationRoleLabel(catalog: ApplicationCatalog) {
  const access = catalog.applicationAccess;
  return access.authorizationModel === "group_assignments"
    ? access.roles?.join(", ") || "No assigned roles"
    : access.role;
}

export type Scope = { workspaceId: string; applicationId: string };

export type WorkItem = {
  id: string;
  title: string;
  state: string;
  owner?: string;
  due?: string;
  step?: string;
  source: "Workflow" | "Planning";
};
