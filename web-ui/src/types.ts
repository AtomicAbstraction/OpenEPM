export type ApplicationSummary = {
  workspaceId: string;
  workspaceName?: string;
  applicationId: string;
  name: string;
  status: string;
  kind?: string;
};

export type SessionIdentity = {
  displayIdentity?: string;
  subject: string;
  applicationMcpEndpoint?: string | null;
};

export type ApplicationCatalog = {
  applicationAccess: { role: string; workspaceAdministrator: boolean };
  enabledCapabilities: string[];
  functions: Record<string, unknown>;
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
