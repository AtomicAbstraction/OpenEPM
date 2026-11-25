import { request } from "./api";

export const workspacePeople = "security.workspace.people.list";
export const personApplications = "security.workspace.person-applications.list";
export const bootstrapGroups = "security.workspace.bootstrap-groups.list";

export type WorkspacePerson = {
  subjectId: string;
  displayName: string | null;
  username: string | null;
  directoryStatus: "Active" | "Inactive" | "Unresolved";
  workspaceAdministrator: boolean | null;
  originsComplete: boolean;
  origins: {
    kind: "workspace_direct" | "workspace_group";
    groupId: string | null;
    groupName: string | null;
  }[];
};
export type EntitledApplication = {
  applicationId: string;
  applicationName: string;
  authorizationMode: "legacy" | "group_assignments";
  applicationRole: string | null;
  roleNames: string[];
  rolesComplete: boolean;
  workspaceInherited: boolean;
};
export type BootstrapGroup = {
  groupId: string;
  groupName: string | null;
  displayName: string | null;
  actorMember: boolean;
};
type Rows = {
  [workspacePeople]: { people: WorkspacePerson[] };
  [personApplications]: { applications: EntitledApplication[] };
  [bootstrapGroups]: { groups: BootstrapGroup[] };
};
type Envelope = {
  workspaceId: string;
  coverage: "complete_in_workspace" | "partial";
  coverageReasons: string[];
  asOf: string;
  nextCursor: string | null;
};
const nullableString = (value: unknown) =>
  value === null || typeof value === "string";
const textList = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === "string");
function completeEnvelope(data: Envelope, workspaceId: string) {
  return (
    data &&
    data.workspaceId === workspaceId &&
    ["complete_in_workspace", "partial"].includes(data.coverage) &&
    textList(data.coverageReasons) &&
    typeof data.asOf === "string" &&
    Number.isFinite(Date.parse(data.asOf)) &&
    nullableString(data.nextCursor)
  );
}
function validPerson(row: WorkspacePerson) {
  return (
    row &&
    typeof row.subjectId === "string" &&
    Boolean(row.subjectId) &&
    nullableString(row.displayName) &&
    nullableString(row.username) &&
    ["Active", "Inactive", "Unresolved"].includes(row.directoryStatus) &&
    (row.workspaceAdministrator === null ||
      typeof row.workspaceAdministrator === "boolean") &&
    typeof row.originsComplete === "boolean" &&
    Array.isArray(row.origins) &&
    row.origins.every(
      (origin) =>
        origin &&
        ["workspace_direct", "workspace_group"].includes(origin.kind) &&
        nullableString(origin.groupId) &&
        nullableString(origin.groupName),
    )
  );
}
function validApplication(row: EntitledApplication) {
  return (
    row &&
    typeof row.applicationId === "string" &&
    Boolean(row.applicationId) &&
    typeof row.applicationName === "string" &&
    ["group_assignments", "legacy"].includes(row.authorizationMode) &&
    nullableString(row.applicationRole) &&
    textList(row.roleNames) &&
    typeof row.rolesComplete === "boolean" &&
    typeof row.workspaceInherited === "boolean"
  );
}

export async function workspaceAccessRead<F extends keyof Rows>(
  workspaceId: string,
  fn: F,
  args: Record<string, unknown>,
  signal: AbortSignal,
) {
  const response = await request<{
    function: string;
    languageVersion: number;
    result: Envelope & Rows[F];
  }>(
    "/api/workspace-access",
    {
      workspaceId,
      program: { languageVersion: 2, function: fn, arguments: args },
    },
    signal,
  );
  const data = response.result;
  if (
    response.languageVersion !== 2 ||
    response.function !== fn ||
    !completeEnvelope(data, workspaceId)
  )
    throw new Error("Invalid workspace access response");
  let valid = false;
  if (fn === workspacePeople && "people" in data && Array.isArray(data.people))
    valid = data.people.length <= 100 && data.people.every(validPerson);
  if (
    fn === personApplications &&
    "applications" in data &&
    Array.isArray(data.applications)
  )
    valid =
      data.applications.length <= 100 &&
      data.applications.every(validApplication);
  if (fn === bootstrapGroups && "groups" in data && Array.isArray(data.groups))
    valid =
      data.groups.length <= 100 &&
      data.groups.every(
        (row: BootstrapGroup) =>
          row &&
          typeof row.groupId === "string" &&
          row.groupId &&
          nullableString(row.groupName) &&
          nullableString(row.displayName) &&
          typeof row.actorMember === "boolean",
      );
  if (!valid || (args.cursor && data.nextCursor === args.cursor))
    throw new Error("Invalid workspace access page");
  return data;
}
