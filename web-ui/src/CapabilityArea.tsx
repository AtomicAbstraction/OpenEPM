import { useEffect, useMemo, useRef, useState } from "react";
import { readProgram, readSecurityProgram, request } from "./api";
import { BuildRules } from "./BuildRules";
import { BuildSequences } from "./BuildSequences";
import { BuildSchedules } from "./BuildSchedules";
import { CalculatedMembers } from "./CalculatedMembers";
import { AdministrationSecurity } from "./AdministrationSecurity";
import { DataLoad } from "./DataLoad";
import { DataExport } from "./DataExport";
import { MetadataCreate } from "./MetadataCreate";
import { MetadataRelationships } from "./MetadataRelationships";
import { MetadataMaintenance } from "./MetadataMaintenance";
import { MetadataSecurityStringEditor } from "./MetadataSecurityStringEditor";
import { MemberLists } from "./MemberLists";
import { SecurityTagCatalog } from "./SecurityTagCatalog";
import { AttributeCatalog } from "./AttributeCatalog";
import { SemanticAttributes } from "./SemanticAttributes";
import { SupportingDetail } from "./SupportingDetail";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";

type Area =
  | "data"
  | "metadata"
  | "lists"
  | "rules"
  | "security"
  | "administration";

type Journey = {
  title: string;
  description: string;
  prefixes: string[];
  nativeAnchor: string;
  nativeOverview?: boolean;
};

export type TaskSummary = {
  taskId: string;
  sourceFamily: string;
  function: string;
  status: string;
  updatedAt?: string;
  initiatorKind?: string;
  initiatedBy?: string;
};

type MetadataDimension = {
  dimension_id: string;
  name: string;
  model_role: string;
  status: string;
  short_description?: string;
  detailed_description?: string;
};

type MetadataMember = {
  member_id: string;
  name: string;
  status: string;
  short_description?: string;
  detailed_description?: string;
  numeric_value_kind?: "amount" | "ratio" | null;
  custom_values?: Record<string, unknown>;
};

type MemberSecurity = {
  dimensionId: string;
  memberId: string;
  readTags: string[];
  writeTags: string[];
  securityString: string;
  metadataRevision: number;
  securityRevision: number;
};

type PythonProgramSummary = {
  programId: string;
  version: number;
  status: string;
  entryPoint: string;
  environmentId: string;
  environmentVersion: number;
  sourceDigest: string;
};

type PythonProgramDetail = PythonProgramSummary & {
  defined: boolean;
  parameterSchema: unknown;
  sourceText: string;
};

type PythonProgramListResponse = {
  result: {
    programs: PythonProgramSummary[];
    nextAfterProgramId: string | null;
  };
};

type PythonEnvironment = {
  environment_id: string;
  version: number;
  status: string;
  image_digest: string;
};

type PythonEnvironmentListResponse = {
  result: {
    environments: PythonEnvironment[];
    nextAfterEnvironmentId: string | null;
  };
};

type ExecutionDelegation = {
  delegation_id: string;
  latest_version: number;
  active_version: number | null;
  operation_scope: string[];
  valid_from: string;
  valid_until: string;
  issuer: string;
  subject_id: string;
};

type PythonBuild = {
  buildId: string;
  status: string;
  planDigest?: string | null;
  errorCode?: string | null;
  claimGeneration?: number;
  attempts?: number;
};

type PythonRun = {
  workflowId: string;
  buildId: string;
  status: string;
  committedUnits?: number;
  receiptId?: string | null;
  [key: string]: unknown;
};

type PythonSchedule = {
  schedule_id: string;
  latest_version: number;
  active_version: number | null;
  state_revision: number;
  program_id: string;
  program_version: number;
  parameter_values: Record<string, unknown>;
  interval_seconds: number;
  first_due_at: string;
  catch_up_policy: "skip" | "latest" | "all";
  max_catch_up: number;
  delegation_id: string;
  delegation_version: number;
  last_due_at?: string | null;
};

type PythonOccurrence = {
  occurrence_id: string;
  schedule_id: string;
  schedule_version: number;
  status: string;
  due_at?: string;
  build_id?: string | null;
  workflow_id?: string | null;
};

export function dimensionListArguments(
  afterDimensionId?: string | null,
  expectedMetadataRevision?: number,
) {
  return afterDimensionId
    ? { limit: 100, afterDimensionId, expectedMetadataRevision }
    : { limit: 100 };
}

export function memberListArguments(
  dimension: string,
  afterMemberId?: string | null,
  expectedMetadataRevision?: number,
) {
  return afterMemberId
    ? { dimension, limit: 100, afterMemberId, expectedMetadataRevision }
    : { dimension, limit: 100 };
}

type DimensionPage = {
  rows: MetadataDimension[];
  nextAfterDimensionId: string | null;
  metadataRevision: number;
};

type MemberPage = {
  rows: MetadataMember[];
  nextAfterMemberId: string | null;
  metadataRevision: number;
};

export function collectCapabilityDimensions(
  readPage: (
    arguments_: ReturnType<typeof dimensionListArguments>,
  ) => Promise<DimensionPage>,
) {
  let revision: number | undefined;
  return collectAllContinuations<DimensionPage, MetadataDimension>({
    label: "Metadata dimensions",
    readPage: async (cursor) => {
      const page = await readPage(dimensionListArguments(cursor, revision));
      revision = page.metadataRevision;
      return page;
    },
    rows: (page) => page.rows,
    nextCursor: (page) => page.nextAfterDimensionId,
    rowIdentity: (row) => row.dimension_id,
    consistencyIdentity: (page) => page.metadataRevision,
  });
}

export function collectCapabilityMembers(
  dimension: string,
  readPage: (
    arguments_: ReturnType<typeof memberListArguments>,
  ) => Promise<MemberPage>,
) {
  let revision: number | undefined;
  return collectAllContinuations<MemberPage, MetadataMember>({
    label: "Metadata members",
    readPage: async (cursor) => {
      const page = await readPage(
        memberListArguments(dimension, cursor, revision),
      );
      revision = page.metadataRevision;
      return page;
    },
    rows: (page) => page.rows,
    nextCursor: (page) => page.nextAfterMemberId,
    rowIdentity: (row) => row.member_id,
    consistencyIdentity: (page) => page.metadataRevision,
  });
}

export function exactMemberTags(value: string, label: string) {
  const tags = value
    .split(";")
    .map((tag) => tag.trim())
    .filter(Boolean);
  if (tags.length > 100) throw new Error(`${label} supports at most 100 tags.`);
  if (tags.length !== new Set(tags).size)
    throw new Error(`${label} contains a duplicate tag.`);
  if (tags.some((tag) => tag.length > 20 || tag.includes(";")))
    throw new Error(`${label} tags must be 1-20 characters.`);
  return tags;
}

export function memberSecurityMutationBody(
  app: ApplicationSummary,
  dimensionId: string,
  memberId: string,
  readTags: string[],
  writeTags: string[],
  expectedMetadataRevision: number,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: "metadata.member.security-tags.set",
      arguments: {
        dimensionId,
        memberId,
        readTags,
        writeTags,
        expectedMetadataRevision,
      },
    },
  };
}

export function memberSecurityStringMutationBody(
  app: ApplicationSummary,
  dimensionId: string,
  memberId: string,
  securityString: string,
  expectedMetadataRevision: number,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: "metadata.member.security-string.set",
      arguments: {
        dimensionId,
        memberId,
        securityString,
        expectedMetadataRevision,
      },
    },
  };
}

export function pythonProgramListArguments(afterProgramId?: string | null) {
  return afterProgramId ? { limit: 100, afterProgramId } : { limit: 100 };
}

export function pythonProgramReadArguments(programId: string, version: number) {
  return { programId, version };
}

export function pythonProgramActionBody(
  app: ApplicationSummary,
  catalog: ApplicationCatalog,
  program: Pick<PythonProgramSummary, "programId" | "version">,
  action: "publish" | "deactivate",
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: `python.program.${action}`,
      arguments: {
        programId: program.programId,
        version: program.version,
        expectedMetadataRevision: catalog.revisions.metadata,
        expectedPolicyRevision: catalog.revisions.policy,
        expectedSchemaEpoch: catalog.revisions.schemaEpoch,
      },
    },
  };
}

export function pythonEnvironmentListArguments(
  afterEnvironmentId?: string | null,
) {
  return afterEnvironmentId ? { limit: 50, afterEnvironmentId } : { limit: 50 };
}

export function collectPythonPrograms(
  readPage: (
    arguments_: ReturnType<typeof pythonProgramListArguments>,
  ) => Promise<PythonProgramListResponse>,
) {
  return collectAllContinuations<
    PythonProgramListResponse,
    PythonProgramSummary
  >({
    label: "Python programs",
    readPage: (cursor) => readPage(pythonProgramListArguments(cursor)),
    rows: (page) => page.result.programs,
    nextCursor: (page) => page.result.nextAfterProgramId,
    rowIdentity: (row) => row.programId,
  });
}

export function collectPythonEnvironments(
  readPage: (
    arguments_: ReturnType<typeof pythonEnvironmentListArguments>,
  ) => Promise<PythonEnvironmentListResponse>,
) {
  return collectAllContinuations<
    PythonEnvironmentListResponse,
    PythonEnvironment
  >({
    label: "Python environments",
    readPage: (cursor) => readPage(pythonEnvironmentListArguments(cursor)),
    rows: (page) => page.result.environments,
    nextCursor: (page) => page.result.nextAfterEnvironmentId,
    rowIdentity: (row) => `${row.environment_id}\u0000${row.version}`,
  });
}

function pythonEnvironmentSelection(environment: PythonEnvironment) {
  return JSON.stringify([environment.environment_id, environment.version]);
}

export function pythonProgramSaveBody(
  app: ApplicationSummary,
  catalog: ApplicationCatalog,
  draft: {
    programId: string;
    version: number;
    entryPoint: string;
    environmentId: string;
    environmentVersion: number;
    parameterSchema: Record<string, unknown>;
    sourceText: string;
  },
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: "python.program.save",
      arguments: {
        ...draft,
        expectedMetadataRevision: catalog.revisions.metadata,
        expectedPolicyRevision: catalog.revisions.policy,
        expectedSchemaEpoch: catalog.revisions.schemaEpoch,
      },
    },
  };
}

export function executionDelegationReadBody(
  app: ApplicationSummary,
  delegationId: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    program: {
      languageVersion: 2,
      function: "execution.delegation.read",
      arguments: { delegationId },
    },
  };
}

export function executionDelegationListBody(
  app: ApplicationSummary,
  afterDelegationId?: string | null,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    program: {
      languageVersion: 2,
      function: "execution.delegation.list",
      arguments: {
        limit: 50,
        afterDelegationId: afterDelegationId || null,
      },
    },
  };
}

export function executionDelegationMutationBody(
  app: ApplicationSummary,
  catalog: ApplicationCatalog,
  action: "create" | "revoke",
  draft: {
    delegationId: string;
    version: number;
    issuer?: string;
    subjectId?: string;
    operationScope?: string[];
    validFrom?: string;
    validUntil?: string;
  },
  idempotencyKey: string,
) {
  const arguments_ = {
    delegationId: draft.delegationId,
    version: draft.version,
    expectedMetadataRevision: catalog.revisions.metadata,
    expectedPolicyRevision: catalog.revisions.policy,
    expectedSchemaEpoch: catalog.revisions.schemaEpoch,
    ...(action === "create"
      ? {
          issuer: draft.issuer,
          subjectId: draft.subjectId,
          operationScope: draft.operationScope,
          validFrom: draft.validFrom,
          validUntil: draft.validUntil,
          scheduleId: null,
          scheduleVersion: null,
        }
      : {}),
  };
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    idempotencyKey,
    confirmed: true,
    program: {
      languageVersion: 2,
      function: `execution.delegation.${action}`,
      arguments: arguments_,
    },
  };
}

export function pythonScheduleReadBody(
  app: ApplicationSummary,
  scheduleId: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    program: {
      languageVersion: 2,
      function: "python.schedule.read",
      arguments: { scheduleId },
    },
  };
}

export function pythonScheduleListBody(
  app: ApplicationSummary,
  afterScheduleId?: string | null,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    program: {
      languageVersion: 2,
      function: "python.schedule.list",
      arguments: { limit: 50, afterScheduleId: afterScheduleId || null },
    },
  };
}

export function pythonScheduleMutationBody(
  app: ApplicationSummary,
  catalog: ApplicationCatalog,
  action: "save" | "publish" | "deactivate" | "run",
  draft: {
    scheduleId: string;
    version: number;
    stateRevision: number;
    programId?: string;
    programVersion?: number;
    parameters?: Record<string, unknown>;
    intervalSeconds?: number;
    firstDueAt?: string;
    catchUpPolicy?: "skip" | "latest" | "all";
    maxCatchUp?: number;
    delegationId?: string;
    delegationVersion?: number;
  },
  idempotencyKey: string,
) {
  const arguments_ =
    action === "save"
      ? {
          scheduleId: draft.scheduleId,
          expectedVersion: draft.version,
          expectedStateRevision: draft.stateRevision,
          programId: draft.programId,
          programVersion: draft.programVersion,
          parameters: draft.parameters,
          intervalSeconds: draft.intervalSeconds,
          firstDueAt: draft.firstDueAt,
          catchUpPolicy: draft.catchUpPolicy,
          maxCatchUp: draft.maxCatchUp,
          delegationId: draft.delegationId,
          delegationVersion: draft.delegationVersion,
          expectedMetadataRevision: catalog.revisions.metadata,
          expectedPolicyRevision: catalog.revisions.policy,
          expectedSchemaEpoch: catalog.revisions.schemaEpoch,
        }
      : action === "run"
        ? { scheduleId: draft.scheduleId }
        : {
            scheduleId: draft.scheduleId,
            version: draft.version,
            expectedStateRevision: draft.stateRevision,
            expectedMetadataRevision: catalog.revisions.metadata,
            expectedPolicyRevision: catalog.revisions.policy,
            expectedSchemaEpoch: catalog.revisions.schemaEpoch,
          };
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    idempotencyKey,
    confirmed: true,
    program: {
      languageVersion: 2,
      function: `python.schedule.${action}`,
      arguments: arguments_,
    },
  };
}

export function pythonOccurrenceBody(
  app: ApplicationSummary,
  action: "read" | "cancel",
  occurrenceId: string,
  idempotencyKey?: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    ...(action === "cancel" ? { idempotencyKey, confirmed: true } : {}),
    program: {
      languageVersion: 2,
      function: `python.schedule.occurrence.${action}`,
      arguments: { occurrenceId },
    },
  };
}

export function pythonBuildRequestBody(
  app: ApplicationSummary,
  catalog: ApplicationCatalog,
  program: Pick<PythonProgramSummary, "programId" | "version">,
  parameters: Record<string, unknown>,
  delegationId: string,
  delegationVersion: number,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    action: "request",
    idempotencyKey,
    confirmed: true,
    program: {
      languageVersion: 2,
      function: "python.program.build",
      arguments: {
        programId: program.programId,
        programVersion: program.version,
        parameters,
        expectedMetadataRevision: catalog.revisions.metadata,
        expectedPolicyRevision: catalog.revisions.policy,
        expectedSchemaEpoch: catalog.revisions.schemaEpoch,
        delegationId,
        delegationVersion,
        scheduleId: null,
        scheduleVersion: null,
      },
    },
  };
}

export function pythonRunRequestBody(
  app: ApplicationSummary,
  buildId: string,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    action: "request",
    idempotencyKey,
    confirmed: true,
    program: {
      languageVersion: 2,
      function: "python.program.run",
      arguments: { buildId },
    },
  };
}

export function pythonBuildControlBody(
  app: ApplicationSummary,
  action: "read" | "cancel",
  buildId: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    action,
    buildId,
    ...(action === "cancel" ? { confirmed: true } : {}),
  };
}

export function pythonArtifactReadBody(
  app: ApplicationSummary,
  buildId: string,
  section: "Plan" | "SourceMap" | "BuildLog",
  cursor: string | null,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    action: "artifact",
    buildId,
    section,
    cursor,
  };
}

export function pythonRunControlBody(
  app: ApplicationSummary,
  action: "read" | "cancel",
  workflowId: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    action,
    workflowId,
    ...(action === "cancel" ? { confirmed: true } : {}),
  };
}

const definitions: Record<
  Area,
  { title: string; description: string; journeys: Journey[] }
> = {
  data: {
    title: "Data",
    description:
      "Load, validate, inspect and export governed application data.",
    journeys: [
      {
        title: "Load data",
        description:
          "Stage files, validate members and publish exact-scope changes.",
        prefixes: ["facts.transfer.import", "facts.source."],
        nativeAnchor: "data-load-heading",
      },
      {
        title: "Export snapshot",
        description:
          "Produce an authorized export tied to a stable application snapshot.",
        prefixes: ["facts.transfer.export"],
        nativeAnchor: "data-export-heading",
      },
      {
        title: "Supporting detail",
        description: "Review detail lines and their exact governed total.",
        prefixes: ["facts.line-detail."],
        nativeAnchor: "detail-heading",
      },
    ],
  },
  metadata: {
    title: "Metadata",
    description:
      "Define dimensions, members, hierarchies and typed attributes.",
    journeys: [
      {
        title: "Dimensions and members",
        description:
          "Inspect and manage the multidimensional model through governed metadata functions.",
        prefixes: [
          "metadata.dimension",
          "metadata.member",
          "metadata.hierarchy",
        ],
        nativeAnchor: "metadata-explorer-heading",
      },
    ],
  },
  lists: {
    title: "Member Lists",
    description:
      "Author and reuse immutable multidimensional selections without embedding business logic in the server.",
    journeys: [
      {
        title: "Reusable member lists",
        description:
          "Save, publish, evaluate and deactivate explicit, hierarchy and attribute-driven member sets.",
        prefixes: ["metadata.member_list."],
        nativeAnchor: "member-list-heading",
      },
    ],
  },
  rules: {
    title: "Rules",
    description:
      "Compose generic calculations, ordered sequences and schedules from governed primitives.",
    journeys: [
      {
        title: "Rules and calculations",
        description:
          "Work with typed expressions, saved rules and deterministic calculation plans.",
        prefixes: [
          "facts.expression",
          "facts.rule",
          "rules.expression",
          "application.program",
          "application.rule.",
        ],
        nativeAnchor: "rule-explorer-heading",
      },
      {
        title: "Python programs",
        description:
          "Manage approved Python builders and sealed execution plans without database access.",
        prefixes: ["python.program."],
        nativeAnchor: "python-program-explorer-heading",
      },
    ],
  },
  security: {
    title: "Users & Security",
    description:
      "Assign application users and roles, then govern rule permissions and dimensional read/write access.",
    journeys: [
      {
        title: "Application users and roles",
        description:
          "Grant or revoke application access and choose each user's fixed application role.",
        prefixes: ["security.application.access"],
        nativeAnchor: "application-security-heading",
      },
      {
        title: "Role and data security",
        description:
          "Set rule capabilities and governed dimensional read/write assignments.",
        prefixes: [
          "security.rule.",
          "security.application.dimension",
          "application.dimension.access",
        ],
        nativeAnchor: "role-data-security-heading",
      },
    ],
  },
  administration: {
    title: "Administration",
    description: "Inspect controlled application state and lifecycle context.",
    journeys: [
      {
        title: "Application lifecycle",
        description:
          "Inspect controlled application state and maintenance operations.",
        prefixes: [
          "application.lifecycle",
          "application.maintenance",
          "application.reset",
        ],
        nativeAnchor: "application-lifecycle-heading",
        nativeOverview: true,
      },
    ],
  },
};

export function matchingFunctions(
  functions: Record<string, unknown>,
  prefixes: string[],
) {
  return Object.keys(functions)
    .filter((name) => prefixes.some((prefix) => name.startsWith(prefix)))
    .sort();
}

export function scrollToJourney(anchor: string) {
  const target = document.getElementById(anchor);
  target?.scrollIntoView({
    behavior: "smooth",
    block: "start",
  });
  target?.focus({ preventScroll: true });
}

export function openMetadataEditor(anchor: string) {
  const target = document.getElementById(anchor);
  if (target instanceof HTMLDetailsElement) target.open = true;
  scrollToJourney(anchor);
}

export const capabilityTaskListBody = (
  workspaceId: string,
  applicationId: string,
) => ({ workspaceId, applicationId, afterSequence: 0, limit: 100 });

export function matchingJourney(
  task: Pick<TaskSummary, "function">,
  journeys: Journey[],
) {
  return journeys.find((journey) =>
    journey.prefixes.some((prefix) => task.function.startsWith(prefix)),
  );
}

function activityInitiator(task: TaskSummary) {
  const kind = (task.initiatorKind || "").toLowerCase();
  if (kind.includes("agent") || kind.includes("mcp")) return "MCP agent";
  if (kind.includes("schedule")) return "Schedule";
  if (kind.includes("recover")) return "Recovery";
  return task.initiatedBy
    ? `Human · ${task.initiatedBy}`
    : "Verified principal";
}

function activityTime(value?: string) {
  if (!value) return "Time unavailable";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

export function ApplicationLifecycleSummary({
  app,
  catalog,
  index,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  index: number;
}) {
  return (
    <section
      className="panel capability-activity"
      aria-labelledby="application-lifecycle-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>AUTHORITATIVE APPLICATION STATE</small>
          <h2 id="application-lifecycle-heading" tabIndex={-1}>
            Application lifecycle
          </h2>
          <p>
            Inspect the selected application and current authority. Creation is
            available from Applications; maintenance and reset remain governed
            by their established fixed-core workflows.
          </p>
        </div>
        <a className="secondary-link" href={`#/applications/${index}`}>
          Open Applications →
        </a>
      </div>
      {!app ? (
        <p className="muted-copy">No accessible application is selected.</p>
      ) : (
        <div className="metric-grid application-lifecycle-summary">
          <article>
            <span>Application</span>
            <strong>{app.name}</strong>
            <small>
              {app.workspaceId} / {app.applicationId}
            </small>
          </article>
          <article>
            <span>Lifecycle state</span>
            <strong>{app.status}</strong>
            <small>{app.kind || "Multidimensional EPM"}</small>
          </article>
          <article>
            <span>Current authority</span>
            <strong>{catalog?.applicationAccess.role || "Checking…"}</strong>
            <small>
              {catalog?.applicationAccess.workspaceAdministrator
                ? "Workspace Administrator"
                : "Application-scoped access"}
            </small>
          </article>
          <article>
            <span>Current revisions</span>
            <strong>
              {catalog
                ? `M${catalog.revisions.metadata} · D${catalog.revisions.data}`
                : "Checking…"}
            </strong>
            <small>
              {catalog
                ? `Policy ${catalog.revisions.policy} · Security ${catalog.revisions.security}`
                : "Server-authoritative catalogue pending"}
            </small>
          </article>
        </div>
      )}
      <p className="authority-note">
        This view does not change lifecycle state. Any consequential lifecycle
        action must continue through the existing reviewed core workflow and
        durable receipt.
      </p>
    </section>
  );
}

export function CapabilityArea({
  area,
  app,
  catalog,
  index,
  targetApplicationRule,
  targetCalculatedMember,
  targetApplicationSequence,
  targetApplicationSchedule,
}: {
  area: Area;
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  index: number;
  targetApplicationRule?: { ruleId: string; version: number; digest: string };
  targetCalculatedMember?: {
    definitionId: string;
    version: number;
    digest: string;
  };
  targetApplicationSequence?: {
    ruleId: string;
    version: number;
    digest: string;
  };
  targetApplicationSchedule?: {
    scheduleId: string;
    version: number;
    digest: string;
  };
}) {
  const mutationKey = useStableMutationIntentKey("capability-ui");
  const definition = definitions[area];
  const [tasks, setTasks] = useState<TaskSummary[]>([]);
  const [taskError, setTaskError] = useState("");
  const [dimensions, setDimensions] = useState<MetadataDimension[]>([]);
  const [selectedDimension, setSelectedDimension] = useState("");
  const [members, setMembers] = useState<MetadataMember[]>([]);
  const [selectedMetadataMember, setSelectedMetadataMember] = useState("");
  const [metadataRevision, setMetadataRevision] = useState<number | null>(null);
  const [metadataBusy, setMetadataBusy] = useState(false);
  const [metadataError, setMetadataError] = useState("");
  const [metadataDocumentationOpen, setMetadataDocumentationOpen] =
    useState(false);
  const [memberSecurity, setMemberSecurity] = useState<MemberSecurity | null>(
    null,
  );
  const [memberSecurityString, setMemberSecurityString] = useState("");
  const [memberSecurityReviewed, setMemberSecurityReviewed] = useState(false);
  const [memberSecurityResult, setMemberSecurityResult] = useState("");
  const [pythonPrograms, setPythonPrograms] = useState<PythonProgramSummary[]>(
    [],
  );
  const [selectedPythonProgram, setSelectedPythonProgram] =
    useState<PythonProgramDetail | null>(null);
  const [pythonProgramBusy, setPythonProgramBusy] = useState(false);
  const [pythonProgramError, setPythonProgramError] = useState("");
  const [pythonProgramReviewed, setPythonProgramReviewed] = useState(false);
  const [pythonProgramResult, setPythonProgramResult] = useState("");
  const [pythonEnvironments, setPythonEnvironments] = useState<
    PythonEnvironment[]
  >([]);
  const [pythonDraftId, setPythonDraftId] = useState("");
  const [pythonDraftVersion, setPythonDraftVersion] = useState("1");
  const [pythonDraftEntry, setPythonDraftEntry] = useState("build");
  const [pythonDraftEnvironment, setPythonDraftEnvironment] = useState("");
  const [pythonDraftParameters, setPythonDraftParameters] = useState(
    '{\n  "type": "object"\n}',
  );
  const [pythonDraftSource, setPythonDraftSource] = useState("");
  const [pythonDraftReviewed, setPythonDraftReviewed] = useState(false);
  const [pythonDelegationId, setPythonDelegationId] = useState("");
  const [pythonDelegationVersion, setPythonDelegationVersion] = useState("1");
  const [pythonDelegation, setPythonDelegation] =
    useState<ExecutionDelegation | null>(null);
  const [pythonDelegationReadVerified, setPythonDelegationReadVerified] =
    useState(false);
  const [executionDelegations, setExecutionDelegations] = useState<
    ExecutionDelegation[]
  >([]);
  const [executionDelegationAfter, setExecutionDelegationAfter] = useState<
    string | null
  >(null);
  const [pythonDelegationIssuer, setPythonDelegationIssuer] = useState("");
  const [pythonDelegationSubject, setPythonDelegationSubject] = useState("");
  const [pythonDelegationValidFrom, setPythonDelegationValidFrom] =
    useState("");
  const [pythonDelegationValidUntil, setPythonDelegationValidUntil] =
    useState("");
  const [pythonDelegationBuild, setPythonDelegationBuild] = useState(true);
  const [pythonDelegationRun, setPythonDelegationRun] = useState(true);
  const [pythonDelegationCreateReviewed, setPythonDelegationCreateReviewed] =
    useState(false);
  const [pythonDelegationRevokeReviewed, setPythonDelegationRevokeReviewed] =
    useState(false);
  const [pythonDelegationResult, setPythonDelegationResult] = useState("");
  const [pythonBuildParameters, setPythonBuildParameters] = useState("{}");
  const [pythonBuildReviewed, setPythonBuildReviewed] = useState(false);
  const [pythonBuild, setPythonBuild] = useState<PythonBuild | null>(null);
  const [pythonBuildId, setPythonBuildId] = useState("");
  const [pythonBuildReadVerified, setPythonBuildReadVerified] = useState(false);
  const [pythonBuildCancelReviewed, setPythonBuildCancelReviewed] =
    useState(false);
  const [pythonArtifactSection, setPythonArtifactSection] = useState<
    "Plan" | "SourceMap" | "BuildLog"
  >("Plan");
  const [pythonArtifactCursor, setPythonArtifactCursor] = useState<
    string | null
  >(null);
  const [pythonArtifactText, setPythonArtifactText] = useState("");
  const pythonArtifactDecoder = useRef<TextDecoder | null>(null);
  const [pythonRunReviewed, setPythonRunReviewed] = useState(false);
  const [pythonRun, setPythonRun] = useState<PythonRun | null>(null);
  const [pythonWorkflowId, setPythonWorkflowId] = useState("");
  const [pythonRunReadVerified, setPythonRunReadVerified] = useState(false);
  const [pythonRunCancelReviewed, setPythonRunCancelReviewed] = useState(false);
  const [pythonSchedules, setPythonSchedules] = useState<PythonSchedule[]>([]);
  const [pythonSchedulesRead, setPythonSchedulesRead] = useState(false);
  const [pythonScheduleAfter, setPythonScheduleAfter] = useState<string | null>(
    null,
  );
  const [pythonSchedule, setPythonSchedule] = useState<PythonSchedule | null>(
    null,
  );
  const [pythonScheduleReadVerified, setPythonScheduleReadVerified] =
    useState(false);
  const [pythonScheduleId, setPythonScheduleId] = useState("");
  const [pythonScheduleVersion, setPythonScheduleVersion] = useState("0");
  const [pythonScheduleStateRevision, setPythonScheduleStateRevision] =
    useState("0");
  const [pythonScheduleInterval, setPythonScheduleInterval] = useState("3600");
  const [pythonScheduleFirstDue, setPythonScheduleFirstDue] = useState("");
  const [pythonScheduleCatchUp, setPythonScheduleCatchUp] = useState<
    "skip" | "latest" | "all"
  >("latest");
  const [pythonScheduleMaxCatchUp, setPythonScheduleMaxCatchUp] = useState("1");
  const [pythonScheduleParameters, setPythonScheduleParameters] =
    useState("{}");
  const [pythonScheduleReviewedAction, setPythonScheduleReviewedAction] =
    useState<"save" | "publish" | "deactivate" | "run" | null>(null);
  const [pythonScheduleResult, setPythonScheduleResult] = useState("");
  const [pythonOccurrence, setPythonOccurrence] =
    useState<PythonOccurrence | null>(null);
  const [pythonOccurrenceId, setPythonOccurrenceId] = useState("");
  const [pythonOccurrenceReadVerified, setPythonOccurrenceReadVerified] =
    useState(false);
  const [pythonOccurrenceCancelReviewed, setPythonOccurrenceCancelReviewed] =
    useState(false);

  const memberSecurityDirty = Boolean(
    memberSecurity &&
      (memberSecurityString !== memberSecurity.securityString ||
        memberSecurityReviewed),
  );
  const pythonProgramDirty = Boolean(
    pythonDraftReviewed ||
      pythonDraftId ||
      pythonDraftSource ||
      pythonDraftVersion !== "1" ||
      pythonDraftEntry !== "build" ||
      pythonDraftEnvironment ||
      pythonDraftParameters !== '{\n  "type": "object"\n}',
  );
  const pythonDelegationDirty = Boolean(
    pythonDelegationCreateReviewed ||
      pythonDelegationRevokeReviewed ||
      (pythonDelegation
        ? pythonDelegationId !== pythonDelegation.delegation_id ||
          pythonDelegationVersion !==
            String(
              pythonDelegationReadVerified
                ? pythonDelegation.latest_version
                : pythonDelegation.latest_version + 1,
            ) ||
          pythonDelegationIssuer !== pythonDelegation.issuer ||
          pythonDelegationSubject !== pythonDelegation.subject_id ||
          pythonDelegationValidFrom !==
            new Date(pythonDelegation.valid_from).toISOString().slice(0, 16) ||
          pythonDelegationValidUntil !==
            new Date(pythonDelegation.valid_until).toISOString().slice(0, 16) ||
          pythonDelegationBuild !==
            pythonDelegation.operation_scope.includes("python.program.build") ||
          pythonDelegationRun !==
            pythonDelegation.operation_scope.includes("python.program.run")
        : pythonDelegationId ||
          pythonDelegationIssuer ||
          pythonDelegationSubject ||
          pythonDelegationValidFrom ||
          pythonDelegationValidUntil ||
          !pythonDelegationBuild ||
          !pythonDelegationRun),
  );
  const pythonExecutionDirty = Boolean(
    pythonBuildReviewed ||
      pythonRunReviewed ||
      pythonBuildCancelReviewed ||
      pythonRunCancelReviewed ||
      pythonBuildParameters !== "{}",
  );
  const pythonScheduleDirty = Boolean(
    pythonScheduleReviewedAction ||
      pythonOccurrenceCancelReviewed ||
      (pythonSchedule
        ? pythonScheduleId !== pythonSchedule.schedule_id ||
          pythonScheduleVersion !== String(pythonSchedule.latest_version) ||
          pythonScheduleStateRevision !==
            String(pythonSchedule.state_revision) ||
          pythonScheduleInterval !== String(pythonSchedule.interval_seconds) ||
          pythonScheduleFirstDue !==
            new Date(pythonSchedule.first_due_at).toISOString().slice(0, 16) ||
          pythonScheduleCatchUp !== pythonSchedule.catch_up_policy ||
          pythonScheduleMaxCatchUp !== String(pythonSchedule.max_catch_up) ||
          pythonScheduleParameters !==
            JSON.stringify(pythonSchedule.parameter_values || {}, null, 2)
        : pythonScheduleId ||
          pythonScheduleVersion !== "0" ||
          pythonScheduleStateRevision !== "0" ||
          pythonScheduleInterval !== "3600" ||
          pythonScheduleFirstDue ||
          pythonScheduleCatchUp !== "latest" ||
          pythonScheduleMaxCatchUp !== "1" ||
          pythonScheduleParameters !== "{}"),
  );
  useUnsavedWork(
    "capability-member-security",
    "Unpublished member security change",
    memberSecurityDirty,
  );
  useUnsavedWork(
    "capability-python-program",
    "Unsaved Python program version",
    pythonProgramDirty,
  );
  useUnsavedWork(
    "capability-python-delegation",
    "Unsubmitted Python execution delegation",
    pythonDelegationDirty,
  );
  useUnsavedWork(
    "capability-python-execution",
    "Unsubmitted Python build or run action",
    pythonExecutionDirty,
  );
  useUnsavedWork(
    "capability-python-schedule",
    "Unsubmitted Python schedule action",
    pythonScheduleDirty,
  );

  useEffect(() => {
    setTasks([]);
    setTaskError("");
    if (area !== "data" || !app) return;
    let active = true;
    void request<{ tasks: TaskSummary[] }>(
      "/api/tasks",
      capabilityTaskListBody(app.workspaceId, app.applicationId),
    )
      .then((result) => {
        if (active) setTasks(result.tasks || []);
      })
      .catch((reason) => {
        if (active)
          setTaskError(
            reason instanceof Error
              ? reason.message
              : "Unable to read recent data activity",
          );
      });
    return () => {
      active = false;
    };
  }, [area, app?.workspaceId, app?.applicationId]);

  const canReadMetadata = Boolean(
    catalog?.functions["metadata.dimension.list"] &&
      catalog?.functions["metadata.member.list"],
  );
  const canReadPythonPrograms = Boolean(
    catalog?.functions["python.program.list"] &&
      catalog?.functions["python.program.read"],
  );
  const canAuthorPythonPrograms = Boolean(
    catalog?.functions["python.environment.list"] &&
      catalog?.functions["python.program.save"] &&
      catalog.revisions.schemaEpoch !== undefined,
  );
  const canReadMemberSecurity = Boolean(
    catalog?.functions["security.application.member-tags.read"],
  );
  const canWriteMemberSecurity = Boolean(
    catalog?.functions["metadata.member.security-string.set"],
  );

  useEffect(() => {
    setDimensions([]);
    setSelectedDimension("");
    setMembers([]);
    setSelectedMetadataMember("");
    setMetadataRevision(null);
    setMetadataError("");
    setMemberSecurity(null);
    setMemberSecurityString("");
    setMemberSecurityReviewed(false);
    setMemberSecurityResult("");
    setPythonPrograms([]);
    setSelectedPythonProgram(null);
    setPythonProgramError("");
    setPythonProgramReviewed(false);
    setPythonProgramResult("");
    setPythonEnvironments([]);
    setPythonDraftEnvironment("");
    setPythonDraftReviewed(false);
    setPythonDelegation(null);
    setPythonDelegationReadVerified(false);
    setExecutionDelegations([]);
    setExecutionDelegationAfter(null);
    setPythonDelegationCreateReviewed(false);
    setPythonDelegationRevokeReviewed(false);
    setPythonDelegationResult("");
    setPythonSchedules([]);
    setPythonSchedulesRead(false);
    setPythonScheduleAfter(null);
    setPythonSchedule(null);
    setPythonScheduleReadVerified(false);
    setPythonScheduleReviewedAction(null);
    setPythonScheduleResult("");
    setPythonOccurrence(null);
    setPythonOccurrenceReadVerified(false);
    setPythonOccurrenceCancelReviewed(false);
    setPythonBuildReviewed(false);
    setPythonBuild(null);
    setPythonBuildId("");
    setPythonBuildReadVerified(false);
    setPythonBuildCancelReviewed(false);
    setPythonArtifactCursor(null);
    setPythonArtifactText("");
    pythonArtifactDecoder.current = null;
    setPythonRunReviewed(false);
    setPythonRun(null);
    setPythonWorkflowId("");
    setPythonRunReadVerified(false);
    setPythonRunCancelReviewed(false);
  }, [app?.workspaceId, app?.applicationId]);

  async function readDimensions() {
    if (!app || !canReadMetadata) return;
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    setMetadataBusy(true);
    setMetadataError("");
    try {
      const collected = await collectCapabilityDimensions((arguments_) =>
        readProgram(scope, "metadata.dimension.list", arguments_),
      );
      const found = collected.rows;
      setDimensions(found);
      setMetadataRevision(collected.finalPage.metadataRevision);
      setSelectedDimension((current) =>
        found.some((dimension) => dimension.dimension_id === current)
          ? current
          : found[0]?.dimension_id || "",
      );
      setMembers([]);
      setSelectedMetadataMember("");
      setMemberSecurity(null);
    } catch (reason) {
      setMetadataError(
        reason instanceof Error ? reason.message : "Unable to read dimensions",
      );
    } finally {
      setMetadataBusy(false);
    }
  }

  async function readMemberSecurity(member: MetadataMember) {
    if (!app || !selectedDimension || !canReadMemberSecurity) return;
    setMetadataBusy(true);
    setMetadataError("");
    setMemberSecurityResult("");
    try {
      const result = await readSecurityProgram<MemberSecurity>(
        {
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
        },
        "security.application.member-tags.read",
        { dimensionId: selectedDimension, memberId: member.member_id },
      );
      setMemberSecurity(result);
      setMemberSecurityString(result.securityString);
      setMemberSecurityReviewed(false);
    } catch (reason) {
      setMetadataError(
        reason instanceof Error
          ? reason.message
          : "Unable to read member security tags",
      );
    } finally {
      setMetadataBusy(false);
    }
  }

  function memberSecurityDraftValid() {
    return Boolean(
      memberSecurity &&
        memberSecurityString.length <= 10000 &&
        memberSecurityString === memberSecurityString.trim(),
    );
  }

  async function saveMemberSecurity() {
    if (
      !app ||
      !memberSecurity ||
      !canWriteMemberSecurity ||
      !memberSecurityReviewed ||
      !memberSecurityDraftValid()
    )
      return;
    if (!window.confirm("Compile and save this exact Security String?")) return;
    setMetadataBusy(true);
    setMetadataError("");
    setMemberSecurityResult("");
    try {
      await request(
        "/api/metadata-action",
        memberSecurityStringMutationBody(
          app,
          memberSecurity.dimensionId,
          memberSecurity.memberId,
          memberSecurityString,
          memberSecurity.metadataRevision,
          mutationKey({
            operation: "member-security-string",
            dimensionId: memberSecurity.dimensionId,
            memberId: memberSecurity.memberId,
            securityString: memberSecurityString,
            metadataRevision: memberSecurity.metadataRevision,
          }),
        ),
      );
      setMemberSecurityReviewed(false);
      await readMemberSecurity({
        member_id: memberSecurity.memberId,
        name: memberSecurity.memberId,
        status: "Active",
      });
      setMemberSecurityResult(
        "The fixed metadata service compiled and applied the reviewed Security String.",
      );
    } catch (reason) {
      setMetadataError(
        reason instanceof Error
          ? reason.message
          : "Unable to save member security tags",
      );
    } finally {
      setMetadataBusy(false);
    }
  }

  async function readMembers() {
    if (!app || !selectedDimension || !canReadMetadata) return;
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    setMetadataBusy(true);
    setMetadataError("");
    try {
      const collected = await collectCapabilityMembers(
        selectedDimension,
        (arguments_) => readProgram(scope, "metadata.member.list", arguments_),
      );
      setMembers(collected.rows);
      setMetadataRevision(collected.finalPage.metadataRevision);
    } catch (reason) {
      setMetadataError(
        reason instanceof Error ? reason.message : "Unable to read members",
      );
    } finally {
      setMetadataBusy(false);
    }
  }

  useEffect(() => {
    if (area === "metadata" && app && canReadMetadata) void readDimensions();
  }, [area, app?.workspaceId, app?.applicationId, canReadMetadata]);

  useEffect(() => {
    if (
      area === "metadata" &&
      app &&
      selectedDimension &&
      metadataRevision !== null &&
      canReadMetadata
    )
      void readMembers();
  }, [
    area,
    app?.workspaceId,
    app?.applicationId,
    selectedDimension,
    canReadMetadata,
  ]);

  async function readPythonPrograms() {
    if (!app || !canReadPythonPrograms) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const collected = await collectPythonPrograms((arguments_) =>
        request<PythonProgramListResponse>("/api/python-program", {
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          program: {
            languageVersion: 2,
            function: "python.program.list",
            arguments: arguments_,
          },
        }),
      );
      setPythonPrograms(collected.rows);
      setSelectedPythonProgram(null);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error
          ? reason.message
          : "Unable to read Python programs",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function readPythonEnvironments() {
    if (!app || !canAuthorPythonPrograms) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const collected = await collectPythonEnvironments((arguments_) =>
        request<PythonEnvironmentListResponse>("/api/python-environment", {
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          program: {
            languageVersion: 2,
            function: "python.environment.list",
            arguments: arguments_,
          },
        }),
      );
      const found = collected.rows;
      const active = found.filter(
        (environment) => environment.status === "Active",
      );
      setPythonEnvironments(active);
      setPythonDraftEnvironment((current) =>
        active.some(
          (environment) => pythonEnvironmentSelection(environment) === current,
        )
          ? current
          : active.length
            ? pythonEnvironmentSelection(active[0])
            : "",
      );
      setPythonDraftReviewed(false);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error
          ? reason.message
          : "Unable to read approved Python environments",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  function changePythonDraft(change: () => void) {
    change();
    setPythonDraftReviewed(false);
    setPythonProgramResult("");
  }

  function exactPythonDraft() {
    const programId = pythonDraftId.trim();
    const version = Number(pythonDraftVersion);
    const entryPoint = pythonDraftEntry.trim();
    let environmentSelection: unknown;
    try {
      environmentSelection = JSON.parse(pythonDraftEnvironment);
    } catch {
      environmentSelection = null;
    }
    const environmentId = Array.isArray(environmentSelection)
      ? environmentSelection[0]
      : null;
    const environmentVersion = Array.isArray(environmentSelection)
      ? environmentSelection[1]
      : null;
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(programId))
      throw new Error(
        "Program ID must be a stable 1-200 character identifier.",
      );
    if (!Number.isInteger(version) || version < 1)
      throw new Error("Program version must be a positive whole number.");
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,99}$/.test(entryPoint))
      throw new Error("Entry point must be a Python identifier.");
    if (
      !pythonEnvironments.some(
        (environment) =>
          environment.environment_id === environmentId &&
          environment.version === environmentVersion &&
          environment.status === "Active",
      )
    )
      throw new Error("Select an active approved Python environment.");
    const bytes = new TextEncoder().encode(pythonDraftSource).length;
    if (!bytes || bytes > 1048576 || pythonDraftSource.includes("\0"))
      throw new Error("Python source must contain 1 byte to 1 MiB of UTF-8.");
    let parameterSchema: unknown;
    try {
      parameterSchema = JSON.parse(pythonDraftParameters);
    } catch {
      throw new Error("Parameter schema must be valid JSON.");
    }
    if (
      !parameterSchema ||
      Array.isArray(parameterSchema) ||
      typeof parameterSchema !== "object"
    )
      throw new Error("Parameter schema must be a JSON object.");
    return {
      programId,
      version,
      entryPoint,
      environmentId,
      environmentVersion,
      parameterSchema: parameterSchema as Record<string, unknown>,
      sourceText: pythonDraftSource,
    };
  }

  function pythonDraftIsValid() {
    try {
      exactPythonDraft();
      return true;
    } catch {
      return false;
    }
  }

  async function savePythonProgram() {
    if (!app || !catalog || !canAuthorPythonPrograms || !pythonDraftReviewed)
      return;
    let draft;
    try {
      draft = exactPythonDraft();
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Invalid Python program",
      );
      return;
    }
    if (!window.confirm("Save this exact immutable Python program version?"))
      return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonProgramResult("");
    try {
      const response = await request<{
        result?: { status?: string; operationId?: string };
      }>(
        "/api/python-program",
        pythonProgramSaveBody(
          app,
          catalog,
          draft,
          mutationKey({ operation: "python-program-save", draft }),
        ),
      );
      setPythonProgramResult(
        `The fixed core recorded ${response.result?.status || "the immutable version"}${response.result?.operationId ? ` by receipt ${response.result.operationId}` : ""}.`,
      );
      setPythonDraftReviewed(false);
      setPythonDraftId("");
      setPythonDraftVersion("1");
      setPythonDraftEntry("build");
      setPythonDraftEnvironment("");
      setPythonDraftParameters('{\n  "type": "object"\n}');
      setPythonDraftSource("");
      await readPythonPrograms();
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error
          ? reason.message
          : "Unable to save Python program",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function readPythonProgram(program: PythonProgramSummary) {
    if (!app || !canReadPythonPrograms) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const detail = await request<{ result: PythonProgramDetail }>(
        "/api/python-program",
        {
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          program: {
            languageVersion: 2,
            function: "python.program.read",
            arguments: pythonProgramReadArguments(
              program.programId,
              program.version,
            ),
          },
        },
      );
      if (!detail.result.defined)
        throw new Error("That immutable program version is unavailable.");
      setSelectedPythonProgram(detail.result);
      setPythonProgramReviewed(false);
      setPythonProgramResult("");
      setPythonBuildReviewed(false);
      setPythonBuild(null);
      setPythonBuildId("");
      setPythonBuildReadVerified(false);
      setPythonBuildCancelReviewed(false);
      setPythonArtifactCursor(null);
      setPythonArtifactText("");
      pythonArtifactDecoder.current = null;
      setPythonRunReviewed(false);
      setPythonRun(null);
      setPythonWorkflowId("");
      setPythonRunReadVerified(false);
      setPythonRunCancelReviewed(false);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to read program",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function changePythonPublication(action: "publish" | "deactivate") {
    if (
      !app ||
      !catalog ||
      !selectedPythonProgram ||
      !pythonProgramReviewed ||
      pythonProgramBusy ||
      catalog.revisions.schemaEpoch === undefined ||
      !catalog.functions[`python.program.${action}`]
    )
      return;
    if (
      !window.confirm(
        `${action === "publish" ? "Publish" : "Deactivate"} this exact immutable Python program version?`,
      )
    )
      return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonProgramResult("");
    try {
      const response = await request<{
        result?: { status?: string; operationId?: string };
      }>(
        "/api/python-program",
        pythonProgramActionBody(
          app,
          catalog,
          selectedPythonProgram,
          action,
          mutationKey({
            operation: "python-program-publication",
            programId: selectedPythonProgram.programId,
            version: selectedPythonProgram.version,
            action,
            revisions: catalog.revisions,
          }),
        ),
      );
      setPythonProgramResult(
        `The fixed core recorded ${response.result?.status || action}${response.result?.operationId ? ` by receipt ${response.result.operationId}` : ""}.`,
      );
      setPythonProgramReviewed(false);
      await readPythonPrograms();
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error
          ? reason.message
          : "Unable to change Python program publication",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  function exactBuildParameters() {
    let parameters: unknown;
    try {
      parameters = JSON.parse(pythonBuildParameters);
    } catch {
      throw new Error("Build parameters must be valid JSON.");
    }
    if (
      !parameters ||
      Array.isArray(parameters) ||
      typeof parameters !== "object"
    )
      throw new Error("Build parameters must be a JSON object.");
    return parameters as Record<string, unknown>;
  }

  function exactActiveBuildDelegation() {
    const version = Number(pythonDelegationVersion);
    if (
      !pythonDelegation ||
      pythonDelegation.delegation_id !== pythonDelegationId.trim() ||
      pythonDelegation.active_version !== version ||
      !pythonDelegation.operation_scope.includes("python.program.build") ||
      Date.parse(pythonDelegation.valid_from) > Date.now() ||
      Date.parse(pythonDelegation.valid_until) <= Date.now()
    )
      throw new Error("Read an active build authority for this exact version.");
    return version;
  }

  function pythonBuildInputsValid() {
    try {
      exactBuildParameters();
      exactActiveBuildDelegation();
      return selectedPythonProgram?.status === "Published";
    } catch {
      return false;
    }
  }

  function openExecutionDelegation(
    delegation: ExecutionDelegation,
    verified: boolean,
  ) {
    setPythonDelegation(delegation);
    setPythonDelegationReadVerified(verified);
    setPythonDelegationId(delegation.delegation_id);
    setPythonDelegationVersion(
      String(
        verified ? delegation.latest_version : delegation.latest_version + 1,
      ),
    );
    setPythonDelegationIssuer(delegation.issuer);
    setPythonDelegationSubject(delegation.subject_id);
    setPythonDelegationValidFrom(
      new Date(delegation.valid_from).toISOString().slice(0, 16),
    );
    setPythonDelegationValidUntil(
      new Date(delegation.valid_until).toISOString().slice(0, 16),
    );
    setPythonDelegationBuild(
      delegation.operation_scope.includes("python.program.build"),
    );
    setPythonDelegationRun(
      delegation.operation_scope.includes("python.program.run"),
    );
    setPythonDelegationCreateReviewed(false);
    setPythonDelegationRevokeReviewed(false);
    setPythonBuildReviewed(false);
  }

  async function readExecutionDelegations(next: boolean) {
    if (!app) return;
    if (next && !executionDelegationAfter) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const response = await request<{
        result: {
          delegations: ExecutionDelegation[];
          nextAfterDelegationId: string | null;
        };
      }>(
        "/api/execution-delegation",
        executionDelegationListBody(
          app,
          next ? executionDelegationAfter : null,
        ),
      );
      setExecutionDelegations((current) =>
        next
          ? [...current, ...response.result.delegations]
          : response.result.delegations,
      );
      setExecutionDelegationAfter(response.result.nextAfterDelegationId);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to read authorities",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  function changeExecutionDelegationDraft(change: () => void) {
    change();
    setPythonDelegationReadVerified(false);
    setPythonDelegationCreateReviewed(false);
    setPythonDelegationRevokeReviewed(false);
    setPythonDelegationResult("");
    setPythonBuildReviewed(false);
  }

  function exactExecutionDelegationDraft() {
    const delegationId = pythonDelegationId.trim();
    const version = Number(pythonDelegationVersion);
    const issuer = pythonDelegationIssuer.trim();
    const subjectId = pythonDelegationSubject.trim();
    const validFrom = Date.parse(pythonDelegationValidFrom);
    const validUntil = Date.parse(pythonDelegationValidUntil);
    const operationScope = [
      ...(pythonDelegationBuild ? ["python.program.build"] : []),
      ...(pythonDelegationRun ? ["python.program.run"] : []),
    ];
    if (!/^[A-Za-z0-9._-]{1,200}$/.test(delegationId))
      throw new Error(
        "Authority ID must be a stable 1-200 character identifier.",
      );
    if (!Number.isInteger(version) || version < 1)
      throw new Error("Authority version must be a positive whole number.");
    if (!issuer || issuer.length > 300 || !subjectId || subjectId.length > 300)
      throw new Error(
        "Issuer and subject are required and limited to 300 characters.",
      );
    if (!operationScope.length)
      throw new Error("Select at least one permitted function.");
    if (
      !Number.isFinite(validFrom) ||
      !Number.isFinite(validUntil) ||
      validUntil <= validFrom
    )
      throw new Error("Enter an increasing valid UTC time window.");
    return {
      delegationId,
      version,
      issuer,
      subjectId,
      operationScope,
      validFrom: new Date(validFrom).toISOString(),
      validUntil: new Date(validUntil).toISOString(),
    };
  }

  function executionDelegationDraftValid() {
    try {
      exactExecutionDelegationDraft();
      return !pythonDelegationReadVerified;
    } catch {
      return false;
    }
  }

  async function readPythonDelegation() {
    if (!app || !pythonDelegationId.trim()) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonDelegation(null);
    setPythonDelegationReadVerified(false);
    setPythonBuildReviewed(false);
    try {
      const response = await request<{
        result: { defined: boolean; delegation: ExecutionDelegation };
      }>(
        "/api/execution-delegation",
        executionDelegationReadBody(app, pythonDelegationId.trim()),
      );
      if (!response.result.defined)
        throw new Error("That execution authority is unavailable.");
      openExecutionDelegation(response.result.delegation, true);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to read authority",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function mutateExecutionDelegation(action: "create" | "revoke") {
    if (!app || !catalog || catalog.revisions.schemaEpoch === undefined) return;
    let draft;
    try {
      draft = exactExecutionDelegationDraft();
      if (
        action === "create" &&
        (pythonDelegationReadVerified || !pythonDelegationCreateReviewed)
      )
        return;
      if (
        action === "revoke" &&
        (!pythonDelegationReadVerified ||
          !pythonDelegationRevokeReviewed ||
          pythonDelegation?.active_version !== draft.version)
      )
        return;
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error
          ? reason.message
          : "Invalid execution authority",
      );
      return;
    }
    const verb = action === "create" ? "Create" : "Revoke";
    if (!window.confirm(`${verb} this exact execution authority version?`))
      return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonDelegationResult("");
    try {
      const response = await request<{
        result?: { status?: string; operationId?: string };
      }>(
        "/api/execution-delegation",
        executionDelegationMutationBody(
          app,
          catalog,
          action,
          draft,
          mutationKey({
            operation: "execution-delegation",
            action,
            draft,
            revisions: catalog.revisions,
          }),
        ),
      );
      setPythonDelegationResult(
        `The fixed core recorded ${response.result?.status || action}${
          response.result?.operationId
            ? ` by receipt ${response.result.operationId}`
            : ""
        }.`,
      );
      setPythonDelegation(null);
      setPythonDelegationReadVerified(false);
      setPythonDelegationCreateReviewed(false);
      setPythonDelegationRevokeReviewed(false);
      await readExecutionDelegations(false);
      if (action === "create") {
        setPythonDelegationVersion(String(draft.version));
      }
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error
          ? reason.message
          : `Unable to ${action} authority`,
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  function invalidatePythonScheduleDraft(
    change: () => void,
    identityChanged = false,
  ) {
    change();
    if (identityChanged) setPythonScheduleReadVerified(false);
    setPythonScheduleReviewedAction(null);
    setPythonScheduleResult("");
  }

  function openPythonSchedule(schedule: PythonSchedule, verified: boolean) {
    setPythonSchedule(schedule);
    setPythonScheduleReadVerified(verified);
    setPythonScheduleId(schedule.schedule_id);
    setPythonScheduleVersion(String(schedule.latest_version));
    setPythonScheduleStateRevision(String(schedule.state_revision));
    setPythonScheduleInterval(String(schedule.interval_seconds));
    setPythonScheduleFirstDue(
      new Date(schedule.first_due_at).toISOString().slice(0, 16),
    );
    setPythonScheduleCatchUp(schedule.catch_up_policy);
    setPythonScheduleMaxCatchUp(String(schedule.max_catch_up));
    setPythonScheduleParameters(
      JSON.stringify(schedule.parameter_values || {}, null, 2),
    );
    setPythonScheduleReviewedAction(null);
    setPythonDelegationId(schedule.delegation_id);
    setPythonDelegationVersion(String(schedule.delegation_version));
  }

  async function readPythonSchedules(next: boolean) {
    if (!app || (next && !pythonScheduleAfter)) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const response = await request<{
        result: {
          schedules: PythonSchedule[];
          nextAfterScheduleId: string | null;
        };
      }>(
        "/api/python-schedule",
        pythonScheduleListBody(app, next ? pythonScheduleAfter : null),
      );
      setPythonSchedules((current) =>
        next
          ? [...current, ...response.result.schedules]
          : response.result.schedules,
      );
      setPythonSchedulesRead(true);
      setPythonScheduleAfter(response.result.nextAfterScheduleId);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to read schedules",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function readPythonSchedule() {
    if (!app || !pythonScheduleId.trim()) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonScheduleReadVerified(false);
    try {
      const response = await request<{
        result: { defined: boolean; schedule: PythonSchedule };
      }>(
        "/api/python-schedule",
        pythonScheduleReadBody(app, pythonScheduleId.trim()),
      );
      if (!response.result.defined)
        throw new Error("That Python schedule is unavailable.");
      openPythonSchedule(response.result.schedule, true);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to read schedule",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  function exactPythonScheduleDraft() {
    const scheduleId = pythonScheduleId.trim();
    const version = Number(pythonScheduleVersion);
    const stateRevision = Number(pythonScheduleStateRevision);
    const intervalSeconds = Number(pythonScheduleInterval);
    const maxCatchUp = Number(pythonScheduleMaxCatchUp);
    const firstDue = Date.parse(pythonScheduleFirstDue);
    let parameters: unknown;
    try {
      parameters = JSON.parse(pythonScheduleParameters);
    } catch {
      throw new Error("Schedule parameters must be valid JSON.");
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(scheduleId))
      throw new Error(
        "Schedule ID must be a stable 1-200 character identifier.",
      );
    if (!Number.isInteger(version) || version < 0)
      throw new Error("Schedule version must be a non-negative whole number.");
    if (!Number.isInteger(stateRevision) || stateRevision < 0)
      throw new Error("State revision must be a non-negative whole number.");
    if (
      !Number.isInteger(intervalSeconds) ||
      intervalSeconds < 60 ||
      intervalSeconds > 2678400
    )
      throw new Error("Interval must be between 60 and 2,678,400 seconds.");
    if (!Number.isInteger(maxCatchUp) || maxCatchUp < 1 || maxCatchUp > 36)
      throw new Error("Maximum catch-up must be between 1 and 36.");
    if (!Number.isFinite(firstDue))
      throw new Error("Enter the first due time.");
    if (
      !parameters ||
      Array.isArray(parameters) ||
      typeof parameters !== "object"
    )
      throw new Error("Schedule parameters must be a JSON object.");
    if (!selectedPythonProgram || selectedPythonProgram.status !== "Published")
      throw new Error("Open the exact published program version first.");
    const delegationVersion = exactActiveBuildDelegation();
    if (!pythonDelegation?.operation_scope.includes("python.program.run"))
      throw new Error("The exact authority must permit build and run.");
    return {
      scheduleId,
      version,
      stateRevision,
      programId: selectedPythonProgram.programId,
      programVersion: selectedPythonProgram.version,
      parameters: parameters as Record<string, unknown>,
      intervalSeconds,
      firstDueAt: new Date(firstDue).toISOString(),
      catchUpPolicy: pythonScheduleCatchUp,
      maxCatchUp,
      delegationId: pythonDelegationId.trim(),
      delegationVersion,
    };
  }

  function pythonScheduleActionAllowed(
    action: "save" | "publish" | "deactivate" | "run",
  ) {
    if (action === "save") {
      try {
        exactPythonScheduleDraft();
        return (
          (pythonScheduleReadVerified ||
            (Number(pythonScheduleVersion) === 0 &&
              Number(pythonScheduleStateRevision) === 0)) &&
          Boolean(catalog?.functions["python.schedule.save"])
        );
      } catch {
        return false;
      }
    }
    if (!pythonScheduleReadVerified || !pythonSchedule) return false;
    const version = Number(pythonScheduleVersion);
    const exact =
      pythonSchedule.schedule_id === pythonScheduleId.trim() &&
      pythonSchedule.latest_version === version &&
      pythonSchedule.state_revision === Number(pythonScheduleStateRevision);
    if (!exact) return false;
    if (action === "publish")
      return (
        pythonSchedule.active_version !== version &&
        Boolean(catalog?.functions["python.schedule.publish"])
      );
    if (action === "deactivate")
      return (
        pythonSchedule.active_version === version &&
        Boolean(catalog?.functions["python.schedule.deactivate"])
      );
    return (
      pythonSchedule.active_version !== null &&
      Boolean(catalog?.functions["python.schedule.run"])
    );
  }

  async function mutatePythonSchedule(
    action: "save" | "publish" | "deactivate" | "run",
  ) {
    if (
      !app ||
      !catalog ||
      !pythonScheduleActionAllowed(action) ||
      pythonScheduleReviewedAction !== action
    )
      return;
    if (
      !window.confirm(
        `${action[0].toUpperCase() + action.slice(1)} this exact Python schedule?`,
      )
    )
      return;
    let draft;
    try {
      draft =
        action === "save"
          ? exactPythonScheduleDraft()
          : {
              scheduleId: pythonScheduleId.trim(),
              version: Number(pythonScheduleVersion),
              stateRevision: Number(pythonScheduleStateRevision),
            };
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Invalid Python schedule",
      );
      return;
    }
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const response = await request<{
        result: {
          status?: string;
          operationId?: string;
          occurrenceId?: string;
        };
      }>(
        "/api/python-schedule",
        pythonScheduleMutationBody(
          app,
          catalog,
          action,
          draft,
          mutationKey({
            operation: "python-schedule",
            action,
            draft,
            revisions: catalog.revisions,
          }),
        ),
      );
      setPythonScheduleResult(
        `${response.result.status || action}${
          response.result.operationId
            ? ` · receipt ${response.result.operationId}`
            : ""
        }${response.result.occurrenceId ? ` · occurrence ${response.result.occurrenceId}` : ""}`,
      );
      if (response.result.occurrenceId)
        setPythonOccurrenceId(response.result.occurrenceId);
      setPythonScheduleReviewedAction(null);
      setPythonScheduleReadVerified(false);
      await readPythonSchedules(false);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error
          ? reason.message
          : `Unable to ${action} schedule`,
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function readPythonOccurrence() {
    if (!app || !pythonOccurrenceId.trim()) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonOccurrenceReadVerified(false);
    try {
      const response = await request<{
        result: { defined: boolean; occurrence: PythonOccurrence };
      }>(
        "/api/python-schedule",
        pythonOccurrenceBody(app, "read", pythonOccurrenceId.trim()),
      );
      if (!response.result.defined)
        throw new Error("That schedule occurrence is unavailable.");
      setPythonOccurrence(response.result.occurrence);
      setPythonOccurrenceReadVerified(true);
      setPythonOccurrenceCancelReviewed(false);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to read occurrence",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function cancelPythonOccurrence() {
    if (
      !app ||
      !pythonOccurrenceReadVerified ||
      !pythonOccurrenceCancelReviewed ||
      !pythonOccurrence ||
      ![
        "ready",
        "running",
        "building",
        "running_program",
        "cancel_requested",
      ].includes(pythonOccurrence.status) ||
      !catalog?.functions["python.schedule.occurrence.cancel"]
    )
      return;
    if (
      !window.confirm("Request cancellation of this exact schedule occurrence?")
    )
      return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const response = await request<{ result: PythonOccurrence }>(
        "/api/python-schedule",
        pythonOccurrenceBody(
          app,
          "cancel",
          pythonOccurrence.occurrence_id,
          mutationKey({
            operation: "python-occurrence-cancel",
            occurrenceId: pythonOccurrence.occurrence_id,
          }),
        ),
      );
      setPythonOccurrence(response.result);
      setPythonOccurrenceCancelReviewed(false);
      setPythonScheduleResult(`Occurrence ${response.result.status}.`);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error
          ? reason.message
          : "Unable to cancel occurrence",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function requestPythonBuild() {
    if (!app || !catalog || !selectedPythonProgram || !pythonBuildReviewed)
      return;
    let parameters: Record<string, unknown>;
    let delegationVersion: number;
    try {
      parameters = exactBuildParameters();
      delegationVersion = exactActiveBuildDelegation();
      if (selectedPythonProgram.status !== "Published")
        throw new Error("Read an exact published program version first.");
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Invalid build request",
      );
      return;
    }
    if (!window.confirm("Request this exact isolated Python plan build?"))
      return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const response = await request<{ result: PythonBuild }>(
        "/api/python-build",
        pythonBuildRequestBody(
          app,
          catalog,
          selectedPythonProgram,
          parameters,
          pythonDelegationId.trim(),
          delegationVersion,
          mutationKey({
            operation: "python-build",
            programId: selectedPythonProgram.programId,
            version: selectedPythonProgram.version,
            parameters,
            delegationId: pythonDelegationId.trim(),
            delegationVersion,
            revisions: catalog.revisions,
          }),
        ),
      );
      setPythonBuild(response.result);
      setPythonBuildId(response.result.buildId);
      setPythonBuildReadVerified(false);
      setPythonBuildCancelReviewed(false);
      setPythonArtifactCursor(null);
      setPythonArtifactText("");
      pythonArtifactDecoder.current = null;
      setPythonBuildReviewed(false);
      setPythonRunReviewed(false);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to request build",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function readPythonBuild() {
    if (!app || !pythonBuildId.trim()) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonRunReviewed(false);
    try {
      const response = await request<{ result: PythonBuild }>(
        "/api/python-build",
        pythonBuildControlBody(app, "read", pythonBuildId.trim()),
      );
      setPythonBuild(response.result);
      setPythonBuildReadVerified(true);
      setPythonBuildCancelReviewed(false);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to read build",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function cancelPythonBuild() {
    if (
      !app ||
      !pythonBuild ||
      !pythonBuildReadVerified ||
      !pythonBuildCancelReviewed ||
      !["accepted", "ready", "running", "cancel_requested"].includes(
        pythonBuild.status,
      )
    )
      return;
    if (!window.confirm("Request cancellation of this exact Python build?"))
      return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const response = await request<{ result: PythonBuild }>(
        "/api/python-build",
        pythonBuildControlBody(app, "cancel", pythonBuild.buildId),
      );
      setPythonBuild(response.result);
      setPythonBuildReadVerified(false);
      setPythonBuildCancelReviewed(false);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to cancel build",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function readPythonArtifact(next: boolean) {
    if (
      !app ||
      !pythonBuild ||
      pythonBuild.status !== "sealed" ||
      !/^[0-9a-f]{64}$/.test(pythonBuild.planDigest || "") ||
      (next && !pythonArtifactCursor)
    )
      return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const response = await request<{
        result: { chunkBase64: string; nextCursor: string | null };
      }>(
        "/api/python-build",
        pythonArtifactReadBody(
          app,
          pythonBuild.buildId,
          pythonArtifactSection,
          next ? pythonArtifactCursor : null,
        ),
      );
      const bytes = Uint8Array.from(
        atob(response.result.chunkBase64),
        (value) => value.charCodeAt(0),
      );
      if (!next)
        pythonArtifactDecoder.current = new TextDecoder("utf-8", {
          fatal: true,
        });
      const decoder =
        pythonArtifactDecoder.current ||
        new TextDecoder("utf-8", { fatal: true });
      pythonArtifactDecoder.current = decoder;
      const chunk = decoder.decode(bytes, {
        stream: response.result.nextCursor !== null,
      });
      setPythonArtifactText((current) => (next ? current + chunk : chunk));
      setPythonArtifactCursor(response.result.nextCursor);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to read artifact",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function requestPythonRun() {
    if (
      !app ||
      !pythonBuild ||
      pythonBuild.status !== "sealed" ||
      !/^[0-9a-f]{64}$/.test(pythonBuild.planDigest || "") ||
      !pythonRunReviewed
    )
      return;
    if (
      !window.confirm(
        "Execute this exact sealed plan as a checkpointed workflow?",
      )
    )
      return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const response = await request<{ result: PythonRun }>(
        "/api/python-run",
        pythonRunRequestBody(
          app,
          pythonBuild.buildId,
          mutationKey({
            operation: "python-run",
            buildId: pythonBuild.buildId,
          }),
        ),
      );
      setPythonRun(response.result);
      setPythonWorkflowId(response.result.workflowId);
      setPythonRunReadVerified(false);
      setPythonRunCancelReviewed(false);
      setPythonRunReviewed(false);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to request run",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function readPythonRun() {
    if (!app || !pythonWorkflowId.trim()) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const response = await request<{ result: PythonRun }>("/api/python-run", {
        ...pythonRunControlBody(app, "read", pythonWorkflowId.trim()),
      });
      setPythonRun(response.result);
      setPythonRunReadVerified(true);
      setPythonRunCancelReviewed(false);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to read workflow",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function cancelPythonRun() {
    if (
      !app ||
      !pythonRun ||
      !pythonRunReadVerified ||
      !pythonRunCancelReviewed ||
      !["accepted", "running", "cancel_requested"].includes(pythonRun.status)
    )
      return;
    if (!window.confirm("Request cancellation of this exact workflow?")) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const response = await request<{ result: PythonRun }>(
        "/api/python-run",
        pythonRunControlBody(app, "cancel", pythonRun.workflowId),
      );
      setPythonRun(response.result);
      setPythonRunReadVerified(false);
      setPythonRunCancelReviewed(false);
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to cancel workflow",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  const dataActivity = useMemo(
    () =>
      tasks
        .map((task) => ({
          task,
          journey: matchingJourney(task, definition.journeys),
        }))
        .filter((item): item is { task: TaskSummary; journey: Journey } =>
          Boolean(item.journey),
        )
        .slice(0, 6),
    [tasks, definition.journeys],
  );
  return (
    <div className="page capability-page">
      <div className="page-heading">
        <div>
          <small>{app?.name || "Application"}</small>
          <h1>{definition.title}</h1>
          <p>{definition.description}</p>
        </div>
        {area === "metadata" && (
          <button
            type="button"
            className="secondary-link"
            aria-expanded={metadataDocumentationOpen}
            onClick={() => setMetadataDocumentationOpen((current) => !current)}
          >
            MCP Documentation
          </button>
        )}
      </div>
      {area === "metadata" && metadataDocumentationOpen && (
        <aside className="panel metadata-documentation" role="dialog">
          <div className="section-heading-row">
            <div>
              <small>AUTHORIZED APPLICATION FUNCTIONS</small>
              <h2>Metadata MCP documentation</h2>
              <p>
                These are the metadata functions currently authorized for your
                verified identity and selected application.
              </p>
            </div>
            <button onClick={() => setMetadataDocumentationOpen(false)}>
              Close
            </button>
          </div>
          <ul>
            {matchingFunctions(catalog?.functions || {}, ["metadata."]).map(
              (name) => (
                <li key={name}>{name}</li>
              ),
            )}
          </ul>
        </aside>
      )}
      {area !== "metadata" && (
        <div className="capability-grid">
          {definition.journeys.map((journey) => {
            const available = matchingFunctions(
              catalog?.functions || {},
              journey.prefixes,
            );
            const cataloguePending = catalog === null;
            return (
              <article className="panel capability-card" key={journey.title}>
                <div className="capability-card-heading">
                  <span
                    className={available.length ? "available-dot" : "muted-dot"}
                  />
                  <div>
                    <h2>{journey.title}</h2>
                    <p>{journey.description}</p>
                  </div>
                </div>
                <div className="capability-count">
                  <strong>{cataloguePending ? "—" : available.length}</strong>
                  <span>{`authorized function${available.length === 1 ? "" : "s"}`}</span>
                </div>
                {cataloguePending ? (
                  <p className="muted-copy" role="status">
                    Checking current access…
                  </p>
                ) : available.length ? (
                  <details>
                    <summary>Show authorized functions</summary>
                    <ul>
                      {available.map((name) => (
                        <li key={name}>{name}</li>
                      ))}
                    </ul>
                  </details>
                ) : journey.nativeOverview ? (
                  <p className="muted-copy">
                    Native read-only overview. Consequential actions remain in
                    established governed workflows.
                  </p>
                ) : (
                  <p className="muted-copy">
                    This journey is not available to the current role or
                    application.
                  </p>
                )}
                <button
                  className="secondary-link"
                  type="button"
                  onClick={() => scrollToJourney(journey.nativeAnchor)}
                >
                  Open {journey.title.toLowerCase()} ↓
                </button>
              </article>
            );
          })}
        </div>
      )}
      {area === "metadata" && canReadMetadata && (
        <section
          className="panel capability-activity metadata-workbook"
          aria-labelledby="metadata-explorer-heading"
        >
          <div className="metadata-workbook-toolbar">
            <div>
              <label>
                Dimension
                <select
                  aria-label="Metadata dimension"
                  value={selectedDimension}
                  onChange={(event) => {
                    setSelectedDimension(event.target.value);
                    setMembers([]);
                    setSelectedMetadataMember("");
                    setMemberSecurity(null);
                  }}
                >
                  {dimensions.map((dimension) => (
                    <option
                      key={dimension.dimension_id}
                      value={dimension.dimension_id}
                    >
                      {dimension.name} · {dimension.model_role}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="metadata-toolbar-actions">
              <button
                onClick={() => scrollToJourney("attribute-catalog-heading")}
              >
                + Add attribute
              </button>
              <button
                onClick={() => scrollToJourney("metadata-dimension-editor")}
              >
                + Add new dimension
              </button>
            </div>
          </div>
          {metadataError && (
            <div className="inline-error" role="alert">
              {metadataError}
            </div>
          )}
          <div className="metadata-sheet-heading">
            <div>
              <small>DIMENSIONS</small>
              <h2 id="metadata-explorer-heading" tabIndex={-1}>
                Dimension catalogue
              </h2>
            </div>
            <span>
              {dimensions.length} rows · revision {metadataRevision ?? "—"}
            </span>
          </div>
          <div
            className="react-grid-scroll metadata-sheet"
            tabIndex={0}
            aria-label="Scrollable dimension catalogue"
          >
            <table className="react-cube-grid metadata-dimension-grid">
              <thead>
                <tr>
                  <th>Stable ID</th>
                  <th>Name</th>
                  <th>Model role</th>
                  <th>Status</th>
                  <th>Short description</th>
                </tr>
              </thead>
              <tbody>
                {dimensions.map((dimension) => (
                  <tr
                    key={dimension.dimension_id}
                    className={
                      dimension.dimension_id === selectedDimension
                        ? "selected-row"
                        : ""
                    }
                    onClick={() => setSelectedDimension(dimension.dimension_id)}
                  >
                    <th>{dimension.dimension_id}</th>
                    <td>{dimension.name}</td>
                    <td>{dimension.model_role}</td>
                    <td>{dimension.status}</td>
                    <td>{dimension.short_description || ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <MetadataSecurityStringEditor
            key={`Dimension:${selectedDimension}`}
            app={app}
            catalog={catalog}
            targetKind="Dimension"
            targetId={selectedDimension}
            onChanged={readDimensions}
          />
          <div id="metadata-dimension-editor">
            <MetadataCreate
              app={app}
              catalog={catalog}
              dimensions={dimensions}
              metadataRevision={metadataRevision}
              onCreated={readDimensions}
              mode="dimension"
            />
          </div>
          <AttributeCatalog
            app={app}
            catalog={catalog}
            dimensions={dimensions}
            dimensionId={selectedDimension}
            metadataRevision={metadataRevision}
            onChanged={readDimensions}
          />
          <SemanticAttributes
            app={app}
            catalog={catalog}
            dimensionId={selectedDimension}
            dimensions={dimensions}
            members={members}
            metadataRevision={metadataRevision}
            onChanged={readDimensions}
          />
          <SecurityTagCatalog
            app={app}
            catalog={catalog}
            dimensionId={selectedDimension}
            metadataRevision={metadataRevision}
            onChanged={readDimensions}
          />
          {!catalog?.functions["metadata.relationship.list"] &&
            members.length > 0 && (
              <div
                className="react-grid-scroll"
                tabIndex={0}
                aria-label="Scrollable member table"
              >
                <table className="react-cube-grid metadata-member-grid">
                  <thead>
                    <tr>
                      <th>Member</th>
                      <th>Name</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.map((member) => (
                      <tr key={member.member_id}>
                        <th>{member.member_id}</th>
                        <td>{member.name}</td>
                        <td>{member.status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          {memberSecurity && (
            <article className="program-inspector access-editor">
              <h3>Member Security String</h3>
              <p>
                {memberSecurity.dimensionId} / {memberSecurity.memberId} ·
                metadata revision {memberSecurity.metadataRevision} · security
                revision {memberSecurity.securityRevision}
              </p>
              <label>
                Canonical Security String
                <input
                  aria-label="Member Security String"
                  value={memberSecurityString}
                  onChange={(event) => {
                    setMemberSecurityString(event.target.value);
                    setMemberSecurityReviewed(false);
                    setMemberSecurityResult("");
                  }}
                  placeholder="read=NorthRead;write=NorthWrite"
                />
              </label>
              <p>
                Use <code>read=…;write=…</code> with active, case-sensitive
                catalogue IDs. The fixed core validates and canonicalizes it.
              </p>
              {canWriteMemberSecurity && (
                <div className="reviewed-inline-action">
                  <label className="review-check">
                    <input
                      type="checkbox"
                      checked={memberSecurityReviewed}
                      disabled={!memberSecurityDraftValid()}
                      onChange={(event) =>
                        setMemberSecurityReviewed(event.target.checked)
                      }
                    />
                    I reviewed this exact member, metadata revision and
                    canonical Security String.
                  </label>
                  <button
                    disabled={
                      metadataBusy ||
                      !memberSecurityReviewed ||
                      !memberSecurityDraftValid()
                    }
                    onClick={() => void saveMemberSecurity()}
                  >
                    Compile and save Security String
                  </button>
                </div>
              )}
              {memberSecurityResult && (
                <p role="status">{memberSecurityResult}</p>
              )}
            </article>
          )}
          <MetadataCreate
            app={app}
            catalog={catalog}
            dimensions={dimensions}
            metadataRevision={metadataRevision}
            onCreated={readDimensions}
            mode="member"
          />
          <MetadataRelationships
            app={app}
            catalog={catalog}
            dimensionId={selectedDimension}
            members={members}
            metadataRevision={metadataRevision}
            onChanged={readDimensions}
            selectedMemberId={selectedMetadataMember}
            onSelectedMemberIdChange={setSelectedMetadataMember}
            onEditMemberSecurityString={
              canReadMemberSecurity
                ? (member) => void readMemberSecurity(member)
                : undefined
            }
            securityBusy={metadataBusy}
          />
          <MetadataMaintenance
            app={app}
            catalog={catalog}
            dimension={dimensions.find(
              (dimension) => dimension.dimension_id === selectedDimension,
            )}
            members={members}
            metadataRevision={metadataRevision}
            onChanged={readDimensions}
            selectedMemberId={selectedMetadataMember}
            onSelectedMemberIdChange={setSelectedMetadataMember}
          />
          <footer className="grid-status" aria-live="polite">
            <span>
              {metadataRevision === null
                ? "No metadata snapshot read"
                : `${dimensions.length} dimensions · ${members.length} members · metadata revision ${metadataRevision}`}
            </span>
          </footer>
          <p className="authority-note">
            The fixed core remains authoritative for model reads and reviewed
            member-security changes.
          </p>
        </section>
      )}
      {area === "rules" && canReadPythonPrograms && (
        <section
          className="panel capability-activity"
          aria-labelledby="python-program-explorer-heading"
        >
          <div className="section-heading-row">
            <div>
              <small>SEALED BUILD INPUTS</small>
              <h2 id="python-program-explorer-heading" tabIndex={-1}>
                Python programs
              </h2>
              <p>
                Inspect authorized immutable builders without executing source
                in the browser.
              </p>
            </div>
            <button
              disabled={pythonProgramBusy}
              onClick={() => void readPythonPrograms()}
            >
              {pythonProgramBusy ? "Reading…" : "Read programs"}
            </button>
          </div>
          {pythonProgramError && (
            <div className="inline-error" role="alert">
              {pythonProgramError}
            </div>
          )}
          {pythonProgramResult && <p role="status">{pythonProgramResult}</p>}
          {canAuthorPythonPrograms && (
            <article
              className="program-inspector python-authoring"
              aria-label="New Python program version"
            >
              <div className="section-heading-row">
                <div>
                  <small>REVIEWED IMMUTABLE SOURCE</small>
                  <h3>Save a new program version</h3>
                  <p>
                    Source is stored as an immutable builder. Saving does not
                    execute it or publish business effects.
                  </p>
                </div>
                <button
                  disabled={pythonProgramBusy}
                  onClick={() => void readPythonEnvironments()}
                >
                  {pythonEnvironments.length
                    ? "Refresh environments"
                    : "Read environments"}
                </button>
              </div>
              <div className="python-authoring-fields">
                <label>
                  Program ID
                  <input
                    aria-label="Python program ID"
                    value={pythonDraftId}
                    onChange={(event) =>
                      changePythonDraft(() =>
                        setPythonDraftId(event.target.value),
                      )
                    }
                    placeholder="cube-calculation"
                  />
                </label>
                <label>
                  Version
                  <input
                    aria-label="Python program version"
                    inputMode="numeric"
                    value={pythonDraftVersion}
                    onChange={(event) =>
                      changePythonDraft(() =>
                        setPythonDraftVersion(event.target.value),
                      )
                    }
                  />
                </label>
                <label>
                  Entry point
                  <input
                    aria-label="Python program entry point"
                    value={pythonDraftEntry}
                    onChange={(event) =>
                      changePythonDraft(() =>
                        setPythonDraftEntry(event.target.value),
                      )
                    }
                  />
                </label>
                <label>
                  Approved environment
                  <select
                    aria-label="Python program environment"
                    value={pythonDraftEnvironment}
                    onChange={(event) =>
                      changePythonDraft(() =>
                        setPythonDraftEnvironment(event.target.value),
                      )
                    }
                    disabled={!pythonEnvironments.length}
                  >
                    {!pythonEnvironments.length && (
                      <option value="">Read environments first</option>
                    )}
                    {pythonEnvironments.map((environment) => (
                      <option
                        key={`${environment.environment_id}:${environment.version}`}
                        value={pythonEnvironmentSelection(environment)}
                      >
                        {environment.environment_id} v{environment.version}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <label>
                Parameter schema
                <textarea
                  aria-label="Python parameter schema"
                  rows={5}
                  value={pythonDraftParameters}
                  onChange={(event) =>
                    changePythonDraft(() =>
                      setPythonDraftParameters(event.target.value),
                    )
                  }
                />
              </label>
              <label>
                Python source
                <textarea
                  aria-label="Python program source"
                  className="python-source-editor"
                  rows={12}
                  value={pythonDraftSource}
                  onChange={(event) =>
                    changePythonDraft(() =>
                      setPythonDraftSource(event.target.value),
                    )
                  }
                  placeholder={
                    "def build(context, parameters):\n    return Program()"
                  }
                />
              </label>
              <div className="reviewed-inline-actions">
                <label className="review-check">
                  <input
                    type="checkbox"
                    checked={pythonDraftReviewed}
                    disabled={!pythonDraftIsValid()}
                    onChange={(event) =>
                      setPythonDraftReviewed(event.target.checked)
                    }
                  />
                  I reviewed this exact source, schema, environment and pinned
                  application context.
                </label>
                <button
                  disabled={
                    pythonProgramBusy ||
                    !pythonDraftReviewed ||
                    !pythonDraftIsValid()
                  }
                  onClick={() => void savePythonProgram()}
                >
                  Save immutable version
                </button>
              </div>
            </article>
          )}
          {Boolean(catalog?.functions["execution.delegation.list"]) &&
            Boolean(catalog?.functions["execution.delegation.read"]) && (
              <article
                className="program-inspector execution-authorities"
                aria-label="Execution authority management"
              >
                <div className="section-heading-row">
                  <div>
                    <small>REVIEWED EXECUTION AUTHORITY</small>
                    <h3>Execution authorities</h3>
                    <p>
                      Inspect and govern which principals may build, run or
                      advance an approved program. The fixed core applies the
                      current application pins and validity window.
                    </p>
                  </div>
                  <div className="reviewed-inline-actions">
                    <button
                      disabled={pythonProgramBusy}
                      onClick={() => void readExecutionDelegations(false)}
                    >
                      {executionDelegations.length
                        ? "Refresh authorities"
                        : "Read authorities"}
                    </button>
                    <button
                      disabled={pythonProgramBusy || !executionDelegationAfter}
                      onClick={() => void readExecutionDelegations(true)}
                    >
                      Next page
                    </button>
                  </div>
                </div>
                {executionDelegations.length ? (
                  <div className="react-grid-scroll">
                    <table className="react-cube-grid python-program-grid">
                      <thead>
                        <tr>
                          <th>Authority</th>
                          <th>Version</th>
                          <th>State</th>
                          <th>Principal</th>
                          <th>Scope</th>
                          <th>Valid until</th>
                          <th>Use</th>
                        </tr>
                      </thead>
                      <tbody>
                        {executionDelegations.map((delegation) => (
                          <tr key={delegation.delegation_id}>
                            <th>{delegation.delegation_id}</th>
                            <td>{delegation.latest_version}</td>
                            <td>
                              {delegation.active_version === null
                                ? "Revoked"
                                : `Active v${delegation.active_version}`}
                            </td>
                            <td>{delegation.subject_id}</td>
                            <td>{delegation.operation_scope.join(", ")}</td>
                            <td>
                              {new Date(
                                delegation.valid_until,
                              ).toLocaleString()}
                            </td>
                            <td>
                              <button
                                disabled={pythonProgramBusy}
                                onClick={() =>
                                  openExecutionDelegation(delegation, false)
                                }
                              >
                                Use as next version
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="muted-copy">No authority catalogue read yet.</p>
                )}
                <div className="python-authoring-fields">
                  <label>
                    Authority ID
                    <input
                      aria-label="Execution authority ID"
                      value={pythonDelegationId}
                      onChange={(event) =>
                        changeExecutionDelegationDraft(() =>
                          setPythonDelegationId(event.target.value),
                        )
                      }
                      placeholder="owner-builder"
                    />
                  </label>
                  <label>
                    Version
                    <input
                      aria-label="Execution authority version"
                      inputMode="numeric"
                      value={pythonDelegationVersion}
                      onChange={(event) =>
                        changeExecutionDelegationDraft(() =>
                          setPythonDelegationVersion(event.target.value),
                        )
                      }
                    />
                  </label>
                  <label>
                    Issuer
                    <input
                      aria-label="Execution authority issuer"
                      value={pythonDelegationIssuer}
                      onChange={(event) =>
                        changeExecutionDelegationDraft(() =>
                          setPythonDelegationIssuer(event.target.value),
                        )
                      }
                    />
                  </label>
                  <label>
                    Subject
                    <input
                      aria-label="Execution authority subject"
                      value={pythonDelegationSubject}
                      onChange={(event) =>
                        changeExecutionDelegationDraft(() =>
                          setPythonDelegationSubject(event.target.value),
                        )
                      }
                    />
                  </label>
                  <label>
                    Valid from
                    <input
                      aria-label="Execution authority valid from"
                      type="datetime-local"
                      value={pythonDelegationValidFrom}
                      onChange={(event) =>
                        changeExecutionDelegationDraft(() =>
                          setPythonDelegationValidFrom(event.target.value),
                        )
                      }
                    />
                  </label>
                  <label>
                    Valid until
                    <input
                      aria-label="Execution authority valid until"
                      type="datetime-local"
                      value={pythonDelegationValidUntil}
                      onChange={(event) =>
                        changeExecutionDelegationDraft(() =>
                          setPythonDelegationValidUntil(event.target.value),
                        )
                      }
                    />
                  </label>
                </div>
                <fieldset className="authority-scope">
                  <legend>Permitted functions</legend>
                  <label>
                    <input
                      type="checkbox"
                      checked={pythonDelegationBuild}
                      onChange={(event) =>
                        changeExecutionDelegationDraft(() =>
                          setPythonDelegationBuild(event.target.checked),
                        )
                      }
                    />
                    Build sealed plans
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={pythonDelegationRun}
                      onChange={(event) =>
                        changeExecutionDelegationDraft(() =>
                          setPythonDelegationRun(event.target.checked),
                        )
                      }
                    />
                    Run sealed plans
                  </label>
                </fieldset>
                <div className="reviewed-inline-actions">
                  <button
                    disabled={pythonProgramBusy || !pythonDelegationId.trim()}
                    onClick={() => void readPythonDelegation()}
                  >
                    Read exact authority
                  </button>
                  <label className="review-check">
                    <input
                      type="checkbox"
                      checked={pythonDelegationCreateReviewed}
                      disabled={!executionDelegationDraftValid()}
                      onChange={(event) =>
                        setPythonDelegationCreateReviewed(event.target.checked)
                      }
                    />
                    I reviewed this exact new version, principal, scope,
                    validity and application pins.
                  </label>
                  <button
                    disabled={
                      pythonProgramBusy ||
                      !pythonDelegationCreateReviewed ||
                      !executionDelegationDraftValid() ||
                      !catalog?.functions["execution.delegation.create"]
                    }
                    onClick={() => void mutateExecutionDelegation("create")}
                  >
                    Create immutable version
                  </button>
                </div>
                <div className="reviewed-inline-actions">
                  <label className="review-check">
                    <input
                      type="checkbox"
                      checked={pythonDelegationRevokeReviewed}
                      disabled={
                        !pythonDelegationReadVerified ||
                        pythonDelegation?.active_version !==
                          Number(pythonDelegationVersion)
                      }
                      onChange={(event) =>
                        setPythonDelegationRevokeReviewed(event.target.checked)
                      }
                    />
                    I freshly read and reviewed this exact active version for
                    revocation.
                  </label>
                  <button
                    disabled={
                      pythonProgramBusy ||
                      !pythonDelegationRevokeReviewed ||
                      !pythonDelegationReadVerified ||
                      pythonDelegation?.active_version !==
                        Number(pythonDelegationVersion) ||
                      !catalog?.functions["execution.delegation.revoke"]
                    }
                    onClick={() => void mutateExecutionDelegation("revoke")}
                  >
                    Revoke active version
                  </button>
                </div>
                {pythonDelegationReadVerified && pythonDelegation && (
                  <p className="authority-summary" role="status">
                    Exact v{pythonDelegation.latest_version} read · issued by{" "}
                    {pythonDelegation.issuer} to {pythonDelegation.subject_id}
                    {" · "}
                    {pythonDelegation.operation_scope.join(", ")}
                  </p>
                )}
                {pythonDelegationResult && (
                  <p role="status">{pythonDelegationResult}</p>
                )}
              </article>
            )}
          {pythonPrograms.length ? (
            <div className="react-grid-scroll">
              <table className="react-cube-grid python-program-grid">
                <thead>
                  <tr>
                    <th>Program</th>
                    <th>Version</th>
                    <th>Status</th>
                    <th>Entry point</th>
                    <th>Environment</th>
                    <th>Inspect</th>
                  </tr>
                </thead>
                <tbody>
                  {pythonPrograms.map((program) => (
                    <tr key={`${program.programId}-${program.version}`}>
                      <th>{program.programId}</th>
                      <td>{program.version}</td>
                      <td>{program.status}</td>
                      <td>
                        <code>{program.entryPoint}</code>
                      </td>
                      <td>
                        {program.environmentId} v{program.environmentVersion}
                      </td>
                      <td>
                        <button
                          disabled={pythonProgramBusy}
                          onClick={() => void readPythonProgram(program)}
                        >
                          Open
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="muted-copy">No program catalogue read yet.</p>
          )}
          {selectedPythonProgram && (
            <article
              className="program-inspector"
              aria-label="Python program detail"
            >
              <h3>
                {selectedPythonProgram.programId} v
                {selectedPythonProgram.version}
              </h3>
              <p>
                {selectedPythonProgram.status} ·{" "}
                {selectedPythonProgram.entryPoint}
                {" · "}
                {selectedPythonProgram.environmentId} v
                {selectedPythonProgram.environmentVersion}
              </p>
              <dl>
                <dt>Source digest</dt>
                <dd>
                  <code>{selectedPythonProgram.sourceDigest}</code>
                </dd>
                <dt>Parameter schema</dt>
                <dd>
                  <pre>
                    {JSON.stringify(
                      selectedPythonProgram.parameterSchema,
                      null,
                      2,
                    )}
                  </pre>
                </dd>
              </dl>
              <details>
                <summary>Show authorized immutable source</summary>
                <pre>{selectedPythonProgram.sourceText}</pre>
              </details>
              <div className="reviewed-inline-actions">
                <label className="review-check">
                  <input
                    type="checkbox"
                    checked={pythonProgramReviewed}
                    onChange={(event) =>
                      setPythonProgramReviewed(event.target.checked)
                    }
                  />
                  I reviewed this immutable version and current publication
                  state.
                </label>
                <button
                  disabled={
                    pythonProgramBusy ||
                    !pythonProgramReviewed ||
                    selectedPythonProgram.status === "Published" ||
                    catalog?.revisions.schemaEpoch === undefined ||
                    !catalog?.functions["python.program.publish"]
                  }
                  onClick={() => void changePythonPublication("publish")}
                >
                  Publish version
                </button>
                <button
                  disabled={
                    pythonProgramBusy ||
                    !pythonProgramReviewed ||
                    selectedPythonProgram.status !== "Published" ||
                    catalog?.revisions.schemaEpoch === undefined ||
                    !catalog?.functions["python.program.deactivate"]
                  }
                  onClick={() => void changePythonPublication("deactivate")}
                >
                  Deactivate version
                </button>
              </div>
            </article>
          )}
          {selectedPythonProgram?.status === "Published" &&
            Boolean(catalog?.functions["execution.delegation.read"]) &&
            Boolean(catalog?.functions["python.program.build"]) && (
              <article
                className="program-inspector python-execution"
                aria-label="Python build and run"
              >
                <div className="section-heading-row">
                  <div>
                    <small>ISOLATED BUILD → SEALED PLAN → GOVERNED RUN</small>
                    <h3>Build and execute</h3>
                    <p>
                      The isolated builder proposes a plan. The fixed core
                      validates and seals it before any business execution.
                    </p>
                  </div>
                </div>
                <div className="python-authoring-fields">
                  <label>
                    Execution authority ID
                    <input
                      aria-label="Python execution authority ID"
                      value={pythonDelegationId}
                      onChange={(event) => {
                        setPythonDelegationId(event.target.value);
                        setPythonDelegation(null);
                        setPythonBuildReviewed(false);
                      }}
                    />
                  </label>
                  <label>
                    Authority version
                    <input
                      aria-label="Python execution authority version"
                      inputMode="numeric"
                      value={pythonDelegationVersion}
                      onChange={(event) => {
                        setPythonDelegationVersion(event.target.value);
                        setPythonBuildReviewed(false);
                      }}
                    />
                  </label>
                  <button
                    disabled={pythonProgramBusy || !pythonDelegationId.trim()}
                    onClick={() => void readPythonDelegation()}
                  >
                    Read exact authority
                  </button>
                </div>
                {pythonDelegation && (
                  <p className="authority-summary" role="status">
                    {pythonDelegation.issuer} delegated to{" "}
                    {pythonDelegation.subject_id}
                    {" · "}valid until{" "}
                    {new Date(pythonDelegation.valid_until).toLocaleString()}
                    {" · "}
                    {pythonDelegation.operation_scope.join(", ")}
                  </p>
                )}
                <label>
                  Build parameters
                  <textarea
                    aria-label="Python build parameters"
                    rows={5}
                    value={pythonBuildParameters}
                    onChange={(event) => {
                      setPythonBuildParameters(event.target.value);
                      setPythonBuildReviewed(false);
                    }}
                  />
                </label>
                <div className="reviewed-inline-actions">
                  <label className="review-check">
                    <input
                      type="checkbox"
                      checked={pythonBuildReviewed}
                      disabled={!pythonBuildInputsValid()}
                      onChange={(event) =>
                        setPythonBuildReviewed(event.target.checked)
                      }
                    />
                    I reviewed this published version, exact active authority,
                    parameters and current application pins.
                  </label>
                  <button
                    disabled={
                      pythonProgramBusy ||
                      !pythonBuildReviewed ||
                      !pythonBuildInputsValid()
                    }
                    onClick={() => void requestPythonBuild()}
                  >
                    Request isolated build
                  </button>
                </div>
                <div className="python-authoring-fields execution-status-fields">
                  <label>
                    Build ID
                    <input
                      aria-label="Python build ID"
                      value={pythonBuildId}
                      onChange={(event) => {
                        setPythonBuildId(event.target.value);
                        setPythonBuild(null);
                        setPythonBuildReadVerified(false);
                        setPythonBuildCancelReviewed(false);
                        setPythonArtifactCursor(null);
                        setPythonArtifactText("");
                        pythonArtifactDecoder.current = null;
                        setPythonRunReviewed(false);
                      }}
                    />
                  </label>
                  <button
                    disabled={pythonProgramBusy || !pythonBuildId.trim()}
                    onClick={() => void readPythonBuild()}
                  >
                    Refresh build
                  </button>
                </div>
                {pythonBuild && (
                  <div
                    className="execution-status-card"
                    aria-label="Python build status"
                  >
                    <strong>Build {pythonBuild.status}</strong>
                    <span>{pythonBuild.buildId}</span>
                    {pythonBuild.planDigest && (
                      <code>{pythonBuild.planDigest}</code>
                    )}
                    {pythonBuild.errorCode && (
                      <span>Error: {pythonBuild.errorCode}</span>
                    )}
                  </div>
                )}
                {pythonBuildReadVerified &&
                  pythonBuild &&
                  ["accepted", "ready", "running", "cancel_requested"].includes(
                    pythonBuild.status,
                  ) && (
                    <div className="reviewed-inline-actions">
                      <label className="review-check">
                        <input
                          type="checkbox"
                          checked={pythonBuildCancelReviewed}
                          onChange={(event) =>
                            setPythonBuildCancelReviewed(event.target.checked)
                          }
                        />
                        I reviewed this freshly read build state and request
                        cancellation.
                      </label>
                      <button
                        disabled={
                          pythonProgramBusy || !pythonBuildCancelReviewed
                        }
                        onClick={() => void cancelPythonBuild()}
                      >
                        Cancel build
                      </button>
                    </div>
                  )}
                {pythonBuild?.status === "sealed" && (
                  <section
                    className="artifact-inspector"
                    aria-label="Sealed build artifact"
                  >
                    <div className="python-authoring-fields execution-status-fields">
                      <label>
                        Artifact section
                        <select
                          aria-label="Python artifact section"
                          value={pythonArtifactSection}
                          onChange={(event) => {
                            setPythonArtifactSection(
                              event.target.value as
                                | "Plan"
                                | "SourceMap"
                                | "BuildLog",
                            );
                            setPythonArtifactCursor(null);
                            setPythonArtifactText("");
                            pythonArtifactDecoder.current = null;
                          }}
                        >
                          <option>Plan</option>
                          <option>SourceMap</option>
                          <option>BuildLog</option>
                        </select>
                      </label>
                      <button
                        disabled={pythonProgramBusy}
                        onClick={() => void readPythonArtifact(false)}
                      >
                        Read artifact
                      </button>
                      <button
                        disabled={pythonProgramBusy || !pythonArtifactCursor}
                        onClick={() => void readPythonArtifact(true)}
                      >
                        Next artifact page
                      </button>
                    </div>
                    {pythonArtifactText && <pre>{pythonArtifactText}</pre>}
                  </section>
                )}
                {pythonBuild?.status === "sealed" &&
                  /^[0-9a-f]{64}$/.test(pythonBuild.planDigest || "") &&
                  Boolean(catalog?.functions["python.program.run"]) && (
                    <div className="reviewed-inline-actions sealed-run-action">
                      <label className="review-check">
                        <input
                          type="checkbox"
                          checked={pythonRunReviewed}
                          onChange={(event) =>
                            setPythonRunReviewed(event.target.checked)
                          }
                        />
                        I reviewed this sealed plan digest and authorize the
                        checkpointed core workflow.
                      </label>
                      <button
                        disabled={pythonProgramBusy || !pythonRunReviewed}
                        onClick={() => void requestPythonRun()}
                      >
                        Run sealed plan
                      </button>
                    </div>
                  )}
                <div className="python-authoring-fields execution-status-fields">
                  <label>
                    Workflow ID
                    <input
                      aria-label="Python workflow ID"
                      value={pythonWorkflowId}
                      onChange={(event) => {
                        setPythonWorkflowId(event.target.value);
                        setPythonRun(null);
                        setPythonRunReadVerified(false);
                        setPythonRunCancelReviewed(false);
                      }}
                    />
                  </label>
                  <button
                    disabled={pythonProgramBusy || !pythonWorkflowId.trim()}
                    onClick={() => void readPythonRun()}
                  >
                    Refresh workflow
                  </button>
                </div>
                {pythonRun && (
                  <div
                    className="execution-status-card"
                    aria-label="Python workflow status"
                  >
                    <strong>Workflow {pythonRun.status}</strong>
                    <span>{pythonRun.workflowId}</span>
                    <span>{pythonRun.committedUnits ?? 0} committed units</span>
                    {pythonRun.receiptId && (
                      <code>Receipt {pythonRun.receiptId}</code>
                    )}
                  </div>
                )}
                {pythonRunReadVerified &&
                  pythonRun &&
                  ["accepted", "running", "cancel_requested"].includes(
                    pythonRun.status,
                  ) && (
                    <div className="reviewed-inline-actions">
                      <label className="review-check">
                        <input
                          type="checkbox"
                          checked={pythonRunCancelReviewed}
                          onChange={(event) =>
                            setPythonRunCancelReviewed(event.target.checked)
                          }
                        />
                        I reviewed this freshly read workflow state and its
                        committed units before requesting cancellation.
                      </label>
                      <button
                        disabled={pythonProgramBusy || !pythonRunCancelReviewed}
                        onClick={() => void cancelPythonRun()}
                      >
                        Cancel workflow
                      </button>
                    </div>
                  )}
              </article>
            )}
          {Boolean(catalog?.functions["python.schedule.list"]) &&
            Boolean(catalog?.functions["python.schedule.read"]) && (
              <article
                className="program-inspector python-schedules"
                aria-label="Python schedule management"
              >
                <div className="section-heading-row">
                  <div>
                    <small>SERVER-OWNED RECURRENCE</small>
                    <h3>Program schedules</h3>
                    <p>
                      Govern immutable recurrence definitions and their durable
                      occurrences. The server owns due-time progression,
                      duplicate suppression and execution.
                    </p>
                  </div>
                  <div className="reviewed-inline-actions">
                    <button
                      disabled={pythonProgramBusy}
                      onClick={() => void readPythonSchedules(false)}
                    >
                      {pythonSchedules.length
                        ? "Refresh schedules"
                        : "Read schedules"}
                    </button>
                    <button
                      disabled={pythonProgramBusy || !pythonScheduleAfter}
                      onClick={() => void readPythonSchedules(true)}
                    >
                      Next page
                    </button>
                  </div>
                </div>
                {pythonSchedules.length ? (
                  <div className="react-grid-scroll">
                    <table className="react-cube-grid python-program-grid">
                      <thead>
                        <tr>
                          <th>Schedule</th>
                          <th>Latest</th>
                          <th>Active</th>
                          <th>Program</th>
                          <th>Interval</th>
                          <th>Last due</th>
                          <th>Use</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pythonSchedules.map((schedule) => (
                          <tr key={schedule.schedule_id}>
                            <th>{schedule.schedule_id}</th>
                            <td>v{schedule.latest_version}</td>
                            <td>
                              {schedule.active_version === null
                                ? "None"
                                : `v${schedule.active_version}`}
                            </td>
                            <td>
                              {schedule.program_id} v{schedule.program_version}
                            </td>
                            <td>{schedule.interval_seconds}s</td>
                            <td>
                              {schedule.last_due_at
                                ? new Date(
                                    schedule.last_due_at,
                                  ).toLocaleString()
                                : "Never"}
                            </td>
                            <td>
                              <button
                                disabled={pythonProgramBusy}
                                onClick={() =>
                                  openPythonSchedule(schedule, false)
                                }
                              >
                                Use
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="muted-copy">
                    {pythonSchedulesRead
                      ? "No Python schedules are defined for this application."
                      : "No schedule catalogue read yet."}
                  </p>
                )}
                <div className="python-authoring-fields">
                  <label>
                    Schedule ID
                    <input
                      aria-label="Python schedule ID"
                      value={pythonScheduleId}
                      onChange={(event) =>
                        invalidatePythonScheduleDraft(
                          () => setPythonScheduleId(event.target.value),
                          true,
                        )
                      }
                    />
                  </label>
                  <label>
                    Latest version
                    <input
                      aria-label="Python schedule version"
                      inputMode="numeric"
                      value={pythonScheduleVersion}
                      onChange={(event) =>
                        invalidatePythonScheduleDraft(
                          () => setPythonScheduleVersion(event.target.value),
                          true,
                        )
                      }
                    />
                  </label>
                  <label>
                    State revision
                    <input
                      aria-label="Python schedule state revision"
                      inputMode="numeric"
                      value={pythonScheduleStateRevision}
                      onChange={(event) =>
                        invalidatePythonScheduleDraft(
                          () =>
                            setPythonScheduleStateRevision(event.target.value),
                          true,
                        )
                      }
                    />
                  </label>
                  <button
                    disabled={pythonProgramBusy || !pythonScheduleId.trim()}
                    onClick={() => void readPythonSchedule()}
                  >
                    Read exact schedule
                  </button>
                  <label>
                    Interval seconds
                    <input
                      aria-label="Python schedule interval seconds"
                      inputMode="numeric"
                      value={pythonScheduleInterval}
                      onChange={(event) =>
                        invalidatePythonScheduleDraft(() =>
                          setPythonScheduleInterval(event.target.value),
                        )
                      }
                    />
                  </label>
                  <label>
                    First due
                    <input
                      aria-label="Python schedule first due"
                      type="datetime-local"
                      value={pythonScheduleFirstDue}
                      onChange={(event) =>
                        invalidatePythonScheduleDraft(() =>
                          setPythonScheduleFirstDue(event.target.value),
                        )
                      }
                    />
                  </label>
                  <label>
                    Catch-up policy
                    <select
                      aria-label="Python schedule catch-up policy"
                      value={pythonScheduleCatchUp}
                      onChange={(event) =>
                        invalidatePythonScheduleDraft(() =>
                          setPythonScheduleCatchUp(
                            event.target.value as "skip" | "latest" | "all",
                          ),
                        )
                      }
                    >
                      <option value="skip">Skip missed occurrences</option>
                      <option value="latest">
                        Run latest missed occurrence
                      </option>
                      <option value="all">
                        Run bounded missed occurrences
                      </option>
                    </select>
                  </label>
                  <label>
                    Maximum catch-up
                    <input
                      aria-label="Python schedule maximum catch-up"
                      inputMode="numeric"
                      value={pythonScheduleMaxCatchUp}
                      onChange={(event) =>
                        invalidatePythonScheduleDraft(() =>
                          setPythonScheduleMaxCatchUp(event.target.value),
                        )
                      }
                    />
                  </label>
                </div>
                <label>
                  Parameters
                  <textarea
                    aria-label="Python schedule parameters"
                    rows={5}
                    value={pythonScheduleParameters}
                    onChange={(event) =>
                      invalidatePythonScheduleDraft(() =>
                        setPythonScheduleParameters(event.target.value),
                      )
                    }
                  />
                </label>
                <p className="authority-summary">
                  Program:{" "}
                  {selectedPythonProgram?.programId ||
                    "open an exact published version"}
                  {selectedPythonProgram
                    ? ` v${selectedPythonProgram.version} (${selectedPythonProgram.status})`
                    : ""}
                  {" · "}Authority:{" "}
                  {pythonDelegationId || "read an exact active authority"}
                  {pythonDelegationId ? ` v${pythonDelegationVersion}` : ""}
                </p>
                <div className="reviewed-inline-actions">
                  {(["save", "publish", "deactivate", "run"] as const).map(
                    (action) => (
                      <label className="review-check" key={action}>
                        <input
                          type="radio"
                          name="python-schedule-action"
                          checked={pythonScheduleReviewedAction === action}
                          disabled={!pythonScheduleActionAllowed(action)}
                          onChange={() =>
                            setPythonScheduleReviewedAction(action)
                          }
                        />
                        Review {action}
                      </label>
                    ),
                  )}
                  <button
                    disabled={
                      pythonProgramBusy ||
                      !pythonScheduleReviewedAction ||
                      !pythonScheduleActionAllowed(
                        pythonScheduleReviewedAction || "save",
                      )
                    }
                    onClick={() =>
                      pythonScheduleReviewedAction &&
                      void mutatePythonSchedule(pythonScheduleReviewedAction)
                    }
                  >
                    Apply reviewed schedule action
                  </button>
                </div>
                {pythonScheduleReadVerified && pythonSchedule && (
                  <p role="status">
                    Exact latest v{pythonSchedule.latest_version} read · active{" "}
                    {pythonSchedule.active_version === null
                      ? "none"
                      : `v${pythonSchedule.active_version}`}
                    {" · state revision "}
                    {pythonSchedule.state_revision}
                  </p>
                )}
                <div className="python-authoring-fields execution-status-fields">
                  <label>
                    Occurrence ID
                    <input
                      aria-label="Python schedule occurrence ID"
                      value={pythonOccurrenceId}
                      onChange={(event) => {
                        setPythonOccurrenceId(event.target.value);
                        setPythonOccurrence(null);
                        setPythonOccurrenceReadVerified(false);
                        setPythonOccurrenceCancelReviewed(false);
                      }}
                    />
                  </label>
                  <button
                    disabled={pythonProgramBusy || !pythonOccurrenceId.trim()}
                    onClick={() => void readPythonOccurrence()}
                  >
                    Read occurrence
                  </button>
                </div>
                {pythonOccurrence && (
                  <div className="execution-status-card">
                    <strong>Occurrence {pythonOccurrence.status}</strong>
                    <span>{pythonOccurrence.occurrence_id}</span>
                    <span>
                      {pythonOccurrence.schedule_id} v
                      {pythonOccurrence.schedule_version}
                    </span>
                  </div>
                )}
                {pythonOccurrenceReadVerified &&
                  pythonOccurrence &&
                  [
                    "ready",
                    "running",
                    "building",
                    "running_program",
                    "cancel_requested",
                  ].includes(pythonOccurrence.status) && (
                    <div className="reviewed-inline-actions">
                      <label className="review-check">
                        <input
                          type="checkbox"
                          checked={pythonOccurrenceCancelReviewed}
                          onChange={(event) =>
                            setPythonOccurrenceCancelReviewed(
                              event.target.checked,
                            )
                          }
                        />
                        I reviewed this freshly read occurrence and request
                        cancellation.
                      </label>
                      <button
                        disabled={
                          pythonProgramBusy ||
                          !pythonOccurrenceCancelReviewed ||
                          !catalog?.functions[
                            "python.schedule.occurrence.cancel"
                          ]
                        }
                        onClick={() => void cancelPythonOccurrence()}
                      >
                        Cancel occurrence
                      </button>
                    </div>
                  )}
                {pythonScheduleResult && (
                  <p role="status">{pythonScheduleResult}</p>
                )}
              </article>
            )}
          <p className="authority-note">
            Reading source does not execute it. Builds, publication and
            permissions remain fixed-core governed actions.
          </p>
        </section>
      )}
      {area === "rules" && (
        <BuildRules
          app={app}
          catalog={catalog}
          targetApplicationRule={targetApplicationRule}
        />
      )}
      {area === "rules" && (
        <CalculatedMembers
          app={app}
          catalog={catalog}
          target={targetCalculatedMember}
        />
      )}
      {area === "rules" && (
        <BuildSequences
          app={app}
          catalog={catalog}
          target={targetApplicationSequence}
        />
      )}
      {area === "rules" && (
        <BuildSchedules
          app={app}
          catalog={catalog}
          target={targetApplicationSchedule}
        />
      )}
      {area === "lists" && <MemberLists app={app} catalog={catalog} />}
      {area === "administration" && (
        <ApplicationLifecycleSummary
          app={app}
          catalog={catalog}
          index={index}
        />
      )}
      {area === "security" && (
        <AdministrationSecurity app={app} catalog={catalog} />
      )}
      {area === "data" && <DataLoad app={app} catalog={catalog} />}
      {area === "data" && <DataExport app={app} catalog={catalog} />}
      {area === "data" && <SupportingDetail app={app} catalog={catalog} />}
      {area === "data" && (
        <section
          className="panel capability-activity"
          aria-labelledby="data-activity-heading"
        >
          <div className="section-heading-row">
            <div>
              <small>AUTHORITATIVE TASK HISTORY</small>
              <h2 id="data-activity-heading">Recent governed data activity</h2>
              <p>
                Loads, exports and supporting-detail work from the existing
                durable task record.
              </p>
            </div>
            <a className="secondary-link" href={`#/monitor/${index}`}>
              Open Monitor →
            </a>
          </div>
          {taskError && (
            <div className="inline-error" role="alert">
              {taskError}
            </div>
          )}
          {!taskError && !dataActivity.length ? (
            <p className="muted-copy">
              No recent governed data activity is visible.
            </p>
          ) : (
            <div className="capability-activity-list">
              {dataActivity.map(({ task, journey }) => (
                <article key={task.taskId}>
                  <div>
                    <strong>{journey.title}</strong>
                    <span>{task.function}</span>
                  </div>
                  <div>
                    <span className="task-state neutral">{task.status}</span>
                    <small>
                      {activityInitiator(task)} · {activityTime(task.updatedAt)}
                    </small>
                  </div>
                </article>
              ))}
            </div>
          )}
          <p className="authority-note">
            This is a read-only view. Completion is shown only from the
            server-owned durable task state.
          </p>
        </section>
      )}
      <p className="authority-note">
        Availability is derived from the current server-authorized function
        catalogue. This page does not grant access or implement business rules.
      </p>
    </div>
  );
}
