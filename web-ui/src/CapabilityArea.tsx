import { useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  readProgram,
  readSecurityProgram,
  request,
  requestAdmittedEffect,
} from "./api";
import { BuildRules } from "./BuildRules";
import { PythonRuleEditor } from "./PythonRuleEditor";
import {
  pythonProgramActionBody,
  pythonProgramSaveBody,
} from "./python-source-contract";
import { PythonProgramTest } from "./PythonProgramTest";
import { PythonProgramRun } from "./PythonProgramRun";
import {
  ParameterFields,
  parameterInputError,
  parameterObject,
} from "./ParameterFields";
import type { SealedPythonTest } from "./PythonProgramTest";
import type {
  PythonCompletionDescriptor,
  PythonDiagnostics,
} from "./PythonRuleEditor";
import {
  authoringCompletions,
  authoringContextKey,
  pythonDiagnostics,
} from "./python-authoring";
import type { PythonBuildStatus } from "./python-authoring";
import { usePythonBuildObserver } from "./usePythonBuildObserver";
import type { PythonBuildObservation } from "./usePythonBuildObserver";
import { BuildSequences } from "./BuildSequences";
import { BuildSchedules } from "./BuildSchedules";
import { CalculatedMembers } from "./CalculatedMembers";
import { AdministrationSecurity } from "./AdministrationSecurity";
import {
  collectSecuritySubjectOptions,
  type SecuritySubject,
} from "./security-directory";
import { DataLoad } from "./DataLoad";
import { DataExport } from "./DataExport";
import { MemberLists } from "./MemberLists";
import { SupportingDetail } from "./SupportingDetail";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft, useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";
import {
  resolveWorkspaceSection,
  workspaceSections,
} from "./workspace-navigation";
import type { WorkspaceArea } from "./workspace-navigation";
import "./focused-workspaces.css";

type Area = WorkspaceArea;

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

export type PythonProgramSummary = {
  programId: string;
  stateToken: string;
  sourceToken: string;
  status: "Inactive" | "Active";
  entryPoint: string;
  environmentId: string;
  environmentStateToken: string;
  sourceDigest: string;
  declaredOutput: Record<string, unknown> | null;
  defined?: boolean;
  valid?: boolean;
  active?: boolean;
  sourceCurrent?: boolean;
  executable?: boolean;
  reason?: "ownership_unresolved" | "validation_required" | null;
  validation?: PythonBuildStatus | null;
  latestImpactTest?: PythonBuildStatus | null;
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
  state_token: string;
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
  state_token: string;
  status: "Active" | "Revoked";
  operation_scope: string[];
  valid_from: string;
  valid_until: string;
  issuer: string;
  subject_id: string;
};

type PythonSchedule = {
  schedule_id: string;
  state_token: string;
  status: "Saved" | "Active";
  program_id: string;
  program_source_token: string;
  parameter_values: Record<string, unknown>;
  interval_seconds: number;
  first_due_at: string;
  catch_up_policy: "skip" | "latest" | "all";
  max_catch_up: number;
  delegation_id: string;
  delegation_state_token: string;
  last_due_at?: string | null;
};

type PythonOccurrence = {
  occurrence_id: string;
  schedule_id: string;
  schedule_state_token: string;
  status: string;
  due_at?: string;
  build_id?: string | null;
  workflow_id?: string | null;
};

export {
  dimensionListArguments,
  memberListArguments,
  collectCapabilityDimensions,
  collectCapabilityMembers,
  exactMemberTags,
  memberSecurityMutationBody,
  memberSecurityStringMutationBody,
} from "./metadata-data";

export function pythonProgramListArguments(afterProgramId?: string | null) {
  return afterProgramId ? { limit: 100, afterProgramId } : { limit: 100 };
}

export function pythonProgramReadArguments(programId: string) {
  return { programId };
}

export { pythonProgramActionBody } from "./python-source-contract";

export function pythonProgramAvailabilityLabel(program: PythonProgramSummary) {
  if (program.declaredOutput === null) return "Source only · no typed output";
  if (program.reason === "ownership_unresolved")
    return "Output ownership unresolved";
  if (program.reason === "validation_required") return "Validation required";
  if (program.active && program.executable) return "Executable";
  return "Inactive by design";
}

const PROGRAM_ACRONYMS = new Set([
  "aic",
  "bs",
  "cf",
  "csp",
  "gp",
  "is",
  "sbc",
  "smp",
  "wc",
  "yoy",
]);

export function pythonProgramDisplayName(program: PythonProgramSummary) {
  const definitionId = program.declaredOutput?.definitionId;
  const source =
    typeof definitionId === "string" && definitionId.trim()
      ? definitionId
      : program.programId.replace(/^source-rule-/, "");
  return source
    .split(/[._-]+/)
    .filter((part) => part && part !== "rule")
    .map((part) =>
      PROGRAM_ACRONYMS.has(part.toLowerCase())
        ? part.toUpperCase()
        : part.charAt(0).toUpperCase() + part.slice(1),
    )
    .join(" ");
}

function pythonProgramTypeLabel(program: PythonProgramSummary) {
  const kind = program.declaredOutput?.kind;
  if (kind === "ApplicationRule") return "Application rule";
  if (kind === "CalculatedMember") return "Calculated member";
  return typeof kind === "string" && kind ? kind : "Python program";
}

export function pythonProgramHasParameters(schema: unknown) {
  if (!schema || typeof schema !== "object" || Array.isArray(schema))
    return false;
  const value = schema as Record<string, unknown>;
  const properties = value.properties;
  return Boolean(
    properties &&
      typeof properties === "object" &&
      !Array.isArray(properties) &&
      Object.keys(properties).length,
  );
}

function validatedPythonProgram(program: PythonProgramSummary) {
  const output = program?.declaredOutput;
  if (
    !program ||
    typeof program.programId !== "string" ||
    !program.programId ||
    typeof program.stateToken !== "string" ||
    !/^[0-9a-f]{64}$/.test(program.stateToken) ||
    typeof program.sourceToken !== "string" ||
    !/^[0-9a-f]{64}$/.test(program.sourceToken) ||
    !["Inactive", "Active"].includes(program.status) ||
    typeof program.sourceDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(program.sourceDigest) ||
    !(output === null || (typeof output === "object" && !Array.isArray(output)))
  )
    throw new Error("Python program summary is invalid.");
  if (output === null) {
    if (
      program.defined !== undefined ||
      program.valid !== undefined ||
      program.active !== undefined ||
      program.sourceCurrent !== undefined ||
      program.executable !== undefined ||
      program.reason !== undefined
    )
      throw new Error("Python source-only lifecycle is invalid.");
    return program;
  }
  if (
    typeof program.defined !== "boolean" ||
    typeof program.valid !== "boolean" ||
    typeof program.active !== "boolean" ||
    typeof program.sourceCurrent !== "boolean" ||
    typeof program.executable !== "boolean" ||
    program.reason === undefined ||
    ![null, "ownership_unresolved", "validation_required"].includes(
      program.reason,
    ) ||
    (program.reason === "ownership_unresolved" &&
      (program.sourceCurrent || program.executable)) ||
    (program.reason === "validation_required" &&
      (!program.sourceCurrent || program.valid || program.executable)) ||
    (program.executable && (!program.valid || !program.active)) ||
    (program.status === "Active") !== program.active
  )
    throw new Error("Python program lifecycle is invalid.");
  return program;
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
    rows: (page) => page.result.programs.map(validatedPythonProgram),
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
    rowIdentity: (row) => `${row.environment_id}\u0000${row.state_token}`,
  });
}

function pythonEnvironmentSelection(environment: PythonEnvironment) {
  return JSON.stringify([environment.environment_id, environment.state_token]);
}

export { pythonProgramSaveBody } from "./python-source-contract";

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
    expectedStateToken?: string;
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
          ...(draft.expectedStateToken
            ? { expectedStateToken: draft.expectedStateToken }
            : {}),
        }
      : { expectedStateToken: draft.expectedStateToken }),
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
  action: "save" | "activate" | "deactivate" | "run",
  draft: {
    scheduleId: string;
    expectedStateToken?: string;
    programId?: string;
    programSourceToken?: string;
    parameters?: Record<string, unknown>;
    intervalSeconds?: number;
    firstDueAt?: string;
    catchUpPolicy?: "skip" | "latest" | "all";
    maxCatchUp?: number;
    delegationId?: string;
    delegationStateToken?: string;
  },
  idempotencyKey: string,
) {
  const arguments_ =
    action === "save"
      ? {
          scheduleId: draft.scheduleId,
          ...(draft.expectedStateToken
            ? { expectedStateToken: draft.expectedStateToken }
            : {}),
          programId: draft.programId,
          programSourceToken: draft.programSourceToken,
          parameters: draft.parameters,
          intervalSeconds: draft.intervalSeconds,
          firstDueAt: draft.firstDueAt,
          catchUpPolicy: draft.catchUpPolicy,
          maxCatchUp: draft.maxCatchUp,
          delegationId: draft.delegationId,
          delegationStateToken: draft.delegationStateToken,
          expectedMetadataRevision: catalog.revisions.metadata,
          expectedPolicyRevision: catalog.revisions.policy,
          expectedSchemaEpoch: catalog.revisions.schemaEpoch,
        }
      : action === "run"
        ? { scheduleId: draft.scheduleId }
        : {
            scheduleId: draft.scheduleId,
            expectedStateToken: draft.expectedStateToken,
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

export function pythonOccurrenceListBody(
  app: ApplicationSummary,
  afterOccurrenceId?: string | null,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    program: {
      languageVersion: 2,
      function: "python.schedule.occurrence.list",
      arguments: {
        limit: 100,
        ...(afterOccurrenceId ? { afterOccurrenceId } : {}),
      },
    },
  };
}

export {
  pythonBuildRequestBody,
  pythonRunRequestBody,
} from "./python-execution-contract";

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
  lists: {
    title: "Member Lists",
    description:
      "Create reusable selections of dimension members for your model.",
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
      "Manage reusable calculations, published sequences and scheduled work.",
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
  return task.initiatedBy ? `Human · ${task.initiatedBy}` : "Verified user";
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
            Inspect the selected application's status and access. Create a new
            model from Applications.
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
            <small>{app.kind || "Multidimensional EPM"}</small>
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
            <span>Model information</span>
            <strong>{catalog ? "Current" : "Checking…"}</strong>
            <small>
              {catalog
                ? "Latest authorized application catalogue loaded"
                : "Application catalogue pending"}
            </small>
          </article>
        </div>
      )}
      <p className="authority-note">
        Application status and access are shown for the selected model.
      </p>
    </section>
  );
}

type CapabilityAreaProps = {
  area: Area;
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  index: number;
  targetApplicationRule?: {
    ruleId: string;
    stateToken: string;
    digest: string;
  };
  targetCalculatedMember?: {
    definitionId: string;
    stateToken: string;
    digest: string;
  };
  targetApplicationSequence?: {
    ruleId: string;
    stateToken: string;
    digest: string;
  };
  targetApplicationSchedule?: {
    scheduleId: string;
    stateToken: string;
    digest: string;
  };
  section?: string;
  onNavigateSection?: (section: string) => void;
  onRequestTransition?: (action: () => void) => void;
  onRefreshCatalog?: () => Promise<ApplicationCatalog>;
};

export function CapabilityArea(props: CapabilityAreaProps) {
  const [localSection, setLocalSection] = useState<string>();
  const artifactKind = props.targetApplicationRule
    ? "ApplicationRule"
    : props.targetCalculatedMember
      ? "CalculatedMember"
      : props.targetApplicationSequence
        ? "ApplicationSequence"
        : props.targetApplicationSchedule
          ? "ApplicationSchedule"
          : undefined;
  const section = resolveWorkspaceSection(
    props.area,
    props.section ?? localSection,
    artifactKind,
  );
  const changeSection = (next: string) => {
    if (next === section) return;
    const change = () =>
      props.onNavigateSection
        ? props.onNavigateSection(next)
        : setLocalSection(next);
    if (props.onRequestTransition) props.onRequestTransition(change);
    else change();
  };
  return (
    <CapabilityWorkspace
      key={`${props.app?.workspaceId}:${props.app?.applicationId}:${props.area}:${section}`}
      {...props}
      section={section}
      onNavigateSection={changeSection}
    />
  );
}

function CapabilityWorkspace({
  area,
  app,
  catalog,
  index,
  targetApplicationRule,
  targetCalculatedMember,
  targetApplicationSequence,
  targetApplicationSchedule,
  section,
  onNavigateSection,
  onRequestTransition,
  onRefreshCatalog,
}: CapabilityAreaProps & {
  section: string;
  onNavigateSection: (section: string) => void;
}) {
  const mutationKey = useStableMutationIntentKey("capability-ui");
  const definition = definitions[area];
  const [tasks, setTasks] = useState<TaskSummary[]>([]);
  const [taskError, setTaskError] = useState("");
  const [pythonPrograms, setPythonPrograms] = useState<PythonProgramSummary[]>(
    [],
  );
  const [selectedPythonProgram, setSelectedPythonProgram] =
    useState<PythonProgramDetail | null>(null);
  const [pythonProgramBusy, setPythonProgramBusy] = useState(false);
  const [pythonProgramError, setPythonProgramError] = useState("");
  const [pythonSelectedContextKey, setPythonSelectedContextKey] = useState("");
  const [pythonSealedTest, setPythonSealedTest] =
    useState<SealedPythonTest | null>(null);
  const [pythonProgramResult, setPythonProgramResult] = useState("");
  const [pythonEnvironments, setPythonEnvironments] = useState<
    PythonEnvironment[]
  >([]);
  const [pythonDraftId, setPythonDraftId] = useState("");
  const [pythonDraftEntry, setPythonDraftEntry] = useState("build");
  const [pythonDraftEnvironment, setPythonDraftEnvironment] = useState("");
  const [pythonDraftParameters, setPythonDraftParameters] = useState(
    '{\n  "type": "object"\n}',
  );
  const [pythonDraftSource, setPythonDraftSource] = useState("");
  const [pythonDraftDeclaredOutput, setPythonDraftDeclaredOutput] =
    useState<Record<string, unknown> | null>(null);
  const [pythonDraftEdited, setPythonDraftEdited] = useState(false);
  const [pythonAuthoringOpen, setPythonAuthoringOpen] = useState(false);
  const pythonAuthoringRef = useRef<HTMLElement | null>(null);
  const pythonListGeneration = useRef(0);
  const [pythonValidation, setPythonValidation] = useState<{
    build: PythonBuildStatus;
    contextKey: string;
  } | null>(null);
  const [pythonSelectedValidation, setPythonSelectedValidation] =
    useState<PythonBuildObservation | null>(null);
  const [pythonSourceDiagnostics, setPythonSourceDiagnostics] = useState<{
    diagnostics: PythonDiagnostics;
    contextKey: string;
  } | null>(null);

  const [pythonMetadata, setPythonMetadata] = useState<{
    contextKey: string;
    completions: PythonCompletionDescriptor[];
  } | null>(null);
  const [pythonMetadataError, setPythonMetadataError] = useState("");
  const [pythonMetadataRefresh, setPythonMetadataRefresh] = useState(0);
  const authoringGeneration = useRef(0);
  useEffect(
    () => () => {
      authoringGeneration.current += 1;
    },
    [],
  );
  const pythonContextKey =
    app && catalog ? authoringContextKey(app, catalog) : "";
  const pythonContextKeyRef = useRef(pythonContextKey);
  pythonContextKeyRef.current = pythonContextKey;
  const selectedValidationObserver = usePythonBuildObserver(
    app,
    pythonContextKey,
    pythonSelectedValidation,
    "Validation",
    setPythonSelectedValidation,
  );
  const selectedValidation =
    pythonSelectedValidation?.build.buildId ===
    selectedPythonProgram?.validation?.buildId
      ? pythonSelectedValidation?.build
      : selectedPythonProgram?.validation;
  // This mirrors the server's two accepted semantic prerequisites. Neither
  // Validation nor ImpactTest grants runtime authority; activation still goes
  // through the exact-current-source server mutation and revision checks.
  const currentSealedTest =
    pythonSealedTest?.contextKey === pythonContextKey &&
    pythonSealedTest.programId === selectedPythonProgram?.programId &&
    pythonSealedTest.sourceToken === selectedPythonProgram?.sourceToken
      ? pythonSealedTest
      : null;
  const activationArtifact =
    currentSealedTest ??
    (pythonSelectedContextKey === pythonContextKey &&
    selectedValidationObserver.current &&
    selectedValidation?.status === "sealed"
      ? selectedValidation
      : null);
  const pythonActivationReady = Boolean(
    selectedPythonProgram && activationArtifact,
  );
  useEffect(() => {
    if (
      !app ||
      !selectedPythonProgram ||
      selectedValidation?.status !== "sealed" ||
      selectedPythonProgram.validation?.status === "sealed" ||
      !selectedValidationObserver.current
    )
      return;
    const controller = new AbortController();
    const selected = selectedPythonProgram;
    void request<{ result: PythonProgramDetail }>(
      "/api/python-program",
      {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        program: {
          languageVersion: 2,
          function: "python.program.read",
          arguments: { programId: selected.programId },
        },
      },
      controller.signal,
    )
      .then((response) => {
        if (controller.signal.aborted) return;
        if (
          !response.result.defined ||
          response.result.programId !== selected.programId ||
          response.result.sourceToken !== selected.sourceToken ||
          response.result.sourceDigest !== selected.sourceDigest ||
          response.result.validation?.buildId !== selectedValidation.buildId ||
          response.result.validation.purpose !== "Validation" ||
          response.result.validation.status !== "sealed" ||
          response.result.validation.current !== true
        )
          throw new Error("The exact saved validation is unavailable.");
        setSelectedPythonProgram(response.result);
        setPythonSelectedValidation({
          build: response.result.validation,
          contextKey: pythonContextKey,
        });
      })
      .catch((reason) => {
        if (!controller.signal.aborted)
          setPythonProgramError(
            reason instanceof Error
              ? reason.message
              : "Unable to refresh validated source.",
          );
      });
    return () => controller.abort();
  }, [
    pythonContextKey,
    selectedPythonProgram?.programId,
    selectedPythonProgram?.sourceToken,
    selectedValidation?.buildId,
    selectedValidation?.status,
    selectedValidationObserver.current,
  ]);
  const {
    current: pythonValidationCurrent,
    error: pythonValidationError,
    refresh: refreshPythonValidation,
  } = usePythonBuildObserver(
    app,
    pythonContextKey,
    pythonValidation,
    "Validation",
    setPythonValidation,
  );
  const pythonEditorDiagnostics =
    pythonSourceDiagnostics?.contextKey === pythonContextKey
      ? pythonSourceDiagnostics.diagnostics
      : pythonValidationCurrent
        ? pythonDiagnostics(pythonValidation?.build.diagnostics)
        : undefined;
  const [pythonDelegationId, setPythonDelegationId] = useState("");
  const [pythonDelegationStateToken, setPythonDelegationStateToken] =
    useState("");
  const [pythonDelegation, setPythonDelegation] =
    useState<ExecutionDelegation | null>(null);
  const [pythonDelegationReadVerified, setPythonDelegationReadVerified] =
    useState(false);
  const [executionDelegations, setExecutionDelegations] = useState<
    ExecutionDelegation[]
  >([]);
  const [executionSubjects, setExecutionSubjects] = useState<SecuritySubject[]>(
    [],
  );
  const [executionDelegationAfter, setExecutionDelegationAfter] = useState<
    string | null
  >(null);
  const executionDelegationListGeneration = useRef(0);
  const executionDelegationReadGeneration = useRef(0);
  const [executionDirectoryIssuer, setExecutionDirectoryIssuer] = useState("");
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
  const [pythonScheduleInterval, setPythonScheduleInterval] = useState("3600");
  const [pythonScheduleFirstDue, setPythonScheduleFirstDue] = useState("");
  const [pythonScheduleCatchUp, setPythonScheduleCatchUp] = useState<
    "skip" | "latest" | "all"
  >("latest");
  const [pythonScheduleMaxCatchUp, setPythonScheduleMaxCatchUp] = useState("1");
  const [pythonScheduleParameters, setPythonScheduleParameters] =
    useState("{}");
  const [pythonScheduleReviewedAction, setPythonScheduleReviewedAction] =
    useState<"save" | "activate" | "deactivate" | "run" | null>(null);
  const [pythonScheduleResult, setPythonScheduleResult] = useState("");
  const [pythonOccurrence, setPythonOccurrence] =
    useState<PythonOccurrence | null>(null);
  const [pythonOccurrences, setPythonOccurrences] = useState<
    PythonOccurrence[]
  >([]);
  const [pythonOccurrenceAfter, setPythonOccurrenceAfter] = useState<
    string | null
  >(null);
  const [pythonOccurrenceBusy, setPythonOccurrenceBusy] = useState(false);
  const pythonOccurrenceListGeneration = useRef(0);
  const [pythonOccurrenceId, setPythonOccurrenceId] = useState("");
  const [pythonOccurrenceReadVerified, setPythonOccurrenceReadVerified] =
    useState(false);
  const [pythonOccurrenceCancelReviewed, setPythonOccurrenceCancelReviewed] =
    useState(false);

  const pythonProgramDirty = pythonDraftEdited;
  const pythonDelegationDirty = Boolean(
    pythonDelegationCreateReviewed ||
      pythonDelegationRevokeReviewed ||
      (pythonDelegation
        ? pythonDelegationId !== pythonDelegation.delegation_id ||
          pythonDelegationStateToken !==
            (pythonDelegationReadVerified
              ? pythonDelegation.state_token
              : "") ||
          executionDirectoryIssuer !== pythonDelegation.issuer ||
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
          pythonDelegationSubject ||
          pythonDelegationValidFrom ||
          pythonDelegationValidUntil ||
          !pythonDelegationBuild ||
          !pythonDelegationRun),
  );
  const pythonScheduleDirty = Boolean(
    pythonScheduleReviewedAction ||
      pythonOccurrenceCancelReviewed ||
      (pythonSchedule
        ? pythonScheduleId !== pythonSchedule.schedule_id ||
          pythonScheduleInterval !== String(pythonSchedule.interval_seconds) ||
          pythonScheduleFirstDue !==
            new Date(pythonSchedule.first_due_at).toISOString().slice(0, 16) ||
          pythonScheduleCatchUp !== pythonSchedule.catch_up_policy ||
          pythonScheduleMaxCatchUp !== String(pythonSchedule.max_catch_up) ||
          pythonScheduleParameters !==
            JSON.stringify(pythonSchedule.parameter_values || {}, null, 2)
        : pythonScheduleId ||
          pythonScheduleInterval !== "3600" ||
          pythonScheduleFirstDue ||
          pythonScheduleCatchUp !== "latest" ||
          pythonScheduleMaxCatchUp !== "1" ||
          pythonScheduleParameters !== "{}"),
  );
  usePreservedDraft(
    app?.workspaceId || "",
    app?.applicationId || "",
    "capability-python-program",
    "Unsaved Python program",
    pythonProgramDirty,
    {
      programId: pythonDraftId,
      entry: pythonDraftEntry,
      environment: pythonDraftEnvironment,
      parameters: pythonDraftParameters,
      source: pythonDraftSource,
    },
    (draft) => {
      setPythonDraftId(draft.programId);
      setPythonDraftEntry(draft.entry);
      setPythonDraftEnvironment(draft.environment);
      setPythonDraftParameters(draft.parameters);
      setPythonDraftSource(draft.source);
      setPythonDraftEdited(true);
      setPythonAuthoringOpen(true);
      setPythonValidation(null);
      setPythonSourceDiagnostics(null);
    },
  );
  useUnsavedWork(
    "capability-python-delegation",
    "Unsubmitted Python execution delegation",
    pythonDelegationDirty,
  );
  useUnsavedWork(
    "capability-python-schedule",
    "Unsubmitted Python schedule action",
    pythonScheduleDirty,
  );

  useEffect(() => {
    setTasks([]);
    setTaskError("");
    if (area !== "data" || section !== "activity" || !app) return;
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
  }, [area, section, app?.workspaceId, app?.applicationId]);

  const canReadPythonPrograms = Boolean(
    catalog?.functions["python.program.list"] &&
      catalog?.functions["python.program.read"],
  );
  const canAuthorPythonPrograms = Boolean(
    catalog?.functions["python.environment.list"] &&
      catalog?.functions["python.program.save"] &&
      catalog.revisions.schemaEpoch !== undefined,
  );
  useEffect(() => {
    if (
      !app ||
      !canReadPythonPrograms ||
      area !== "rules" ||
      !["python", "python-schedules"].includes(section)
    )
      return;
    void readPythonPrograms();
  }, [
    app?.workspaceId,
    app?.applicationId,
    area,
    section,
    canReadPythonPrograms,
  ]);
  useEffect(() => {
    if (
      !app ||
      area !== "rules" ||
      !["python", "python-schedules", "authorities"].includes(section) ||
      !catalog?.functions["execution.delegation.list"] ||
      !catalog.functions["execution.delegation.read"]
    )
      return;
    void readExecutionDelegations(false);
  }, [
    app?.workspaceId,
    app?.applicationId,
    area,
    section,
    Boolean(catalog?.functions["execution.delegation.list"]),
    Boolean(catalog?.functions["execution.delegation.read"]),
  ]);
  useEffect(() => {
    if (
      !app ||
      !catalog ||
      area !== "rules" ||
      section !== "python" ||
      !catalog.functions["metadata.authoring.context"]
    )
      return;
    const controller = new AbortController();
    setPythonMetadataError("");
    void readProgram<unknown>(
      app,
      "metadata.authoring.context",
      {},
      controller.signal,
    )
      .then((context) => {
        if (!controller.signal.aborted)
          setPythonMetadata({
            contextKey: pythonContextKey,
            completions: authoringCompletions(context, app, catalog),
          });
      })
      .catch((reason) => {
        if (!controller.signal.aborted) {
          setPythonMetadata(null);
          setPythonMetadataError(
            reason instanceof Error
              ? reason.message
              : "Unable to read metadata suggestions.",
          );
        }
      });
    return () => controller.abort();
  }, [
    pythonContextKey,
    Boolean(catalog?.functions["metadata.authoring.context"]),
    area,
    section,
    pythonMetadataRefresh,
  ]);

  useEffect(() => {
    setPythonPrograms([]);
    setSelectedPythonProgram(null);
    setPythonProgramError("");

    setPythonProgramResult("");
    setPythonEnvironments([]);
    setPythonDraftEnvironment("");
    setPythonDraftId("");
    setPythonDraftEntry("build");
    setPythonDraftParameters('{"type":"object"}');
    setPythonDraftSource("");
    setPythonAuthoringOpen(false);
    setPythonDraftEdited(false);
    setPythonValidation(null);
    setPythonSourceDiagnostics(null);
    setPythonMetadata(null);
    setPythonDelegation(null);
    setPythonDelegationReadVerified(false);
    setPythonDelegationId("");
    setPythonDelegationStateToken("");
    setExecutionDirectoryIssuer("");
    setPythonDelegationSubject("");
    setPythonDelegationValidFrom("");
    setPythonDelegationValidUntil("");
    setPythonDelegationBuild(true);
    setPythonDelegationRun(true);
    setExecutionDelegations([]);
    setExecutionSubjects([]);
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
    setPythonOccurrences([]);
    setPythonOccurrenceAfter(null);
    setPythonOccurrenceId("");
    setPythonOccurrenceReadVerified(false);
    setPythonOccurrenceCancelReviewed(false);
  }, [app?.workspaceId, app?.applicationId]);

  useEffect(() => {
    if (
      !app ||
      !["authorities", "python-schedules"].includes(section) ||
      !catalog?.functions["security.application.subject.list"] ||
      !catalog?.functions["security.identity.current.read"]
    ) {
      setExecutionSubjects([]);
      setExecutionDirectoryIssuer("");
      return;
    }
    const controller = new AbortController();
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    void Promise.all([
      collectSecuritySubjectOptions((arguments_) =>
        readSecurityProgram(
          scope,
          "security.application.subject.list",
          arguments_,
          controller.signal,
        ),
      ),
      readProgram<{ issuer: string; subjectId: string }>(
        scope,
        "security.identity.current.read",
        {},
        controller.signal,
      ),
    ])
      .then(([directory, identity]) => {
        if (controller.signal.aborted) return;
        setExecutionSubjects(
          [...directory.rows].sort(
            (left, right) =>
              left.displayName.localeCompare(right.displayName, undefined, {
                sensitivity: "base",
              }) ||
              left.username.localeCompare(right.username, undefined, {
                sensitivity: "base",
              }),
          ),
        );
        setExecutionDirectoryIssuer(identity.issuer);
      })
      .catch((reason: Error) => {
        if (controller.signal.aborted) return;
        setExecutionSubjects([]);
        setExecutionDirectoryIssuer("");
        setPythonProgramError(
          reason.message || "Unable to read authorized execution users.",
        );
      });
    return () => controller.abort();
  }, [
    app?.workspaceId,
    app?.applicationId,
    section,
    Boolean(catalog?.functions["security.application.subject.list"]),
    Boolean(catalog?.functions["security.identity.current.read"]),
  ]);

  useEffect(() => {
    if (
      !app ||
      area !== "rules" ||
      section !== "python-schedules" ||
      !catalog?.functions["python.schedule.occurrence.list"]
    )
      return;
    void readPythonOccurrences(false);
  }, [
    app?.workspaceId,
    app?.applicationId,
    area,
    section,
    Boolean(catalog?.functions["python.schedule.occurrence.list"]),
  ]);

  async function readPythonPrograms() {
    if (!app || !canReadPythonPrograms) return;
    const generation = ++pythonListGeneration.current;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonScheduleReviewedAction(null);
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
      if (generation !== pythonListGeneration.current) return;
      setPythonPrograms(collected.rows);
      setSelectedPythonProgram(null);
      setPythonSelectedValidation(null);
    } catch (reason) {
      if (generation !== pythonListGeneration.current) return;
      setPythonProgramError(
        reason instanceof Error
          ? reason.message
          : "Unable to read Python programs",
      );
    } finally {
      if (generation === pythonListGeneration.current)
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

  function changePythonDraft(change: () => void, _explicitIdentity = false) {
    change();
    setPythonDraftEdited(true);
    setPythonSourceDiagnostics(null);
    setPythonProgramResult("");
  }

  function exactPythonDraft() {
    const programId = pythonDraftId.trim();
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
    const environmentStateToken = Array.isArray(environmentSelection)
      ? environmentSelection[1]
      : null;
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(programId))
      throw new Error(
        "Program ID must be a stable 1-200 character identifier.",
      );
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,99}$/.test(entryPoint))
      throw new Error("Entry point must be a Python identifier.");
    if (
      !pythonEnvironments.some(
        (environment) =>
          environment.environment_id === environmentId &&
          environment.state_token === environmentStateToken &&
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
      entryPoint,
      environmentId,
      environmentStateToken,
      parameterSchema: parameterSchema as Record<string, unknown>,
      sourceText: pythonDraftSource,
      ...(selectedPythonProgram?.programId === programId &&
      pythonDraftDeclaredOutput
        ? { declaredOutput: pythonDraftDeclaredOutput }
        : {}),
      ...(selectedPythonProgram?.programId === programId
        ? { expectedStateToken: selectedPythonProgram.stateToken }
        : {}),
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
    if (!app || !catalog || !canAuthorPythonPrograms || pythonProgramBusy)
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
    const generation = ++authoringGeneration.current;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonProgramResult("");
    setPythonSourceDiagnostics(null);
    setPythonValidation(null);
    try {
      const response = await requestAdmittedEffect<{
        result: {
          status?: string;
          operationId?: string;
          validation?: PythonBuildStatus;
        };
      }>(
        "/api/python-program",
        pythonProgramSaveBody(
          app,
          catalog,
          draft,
          mutationKey({
            operation: "python-program-save",
            draft,
            contextKey: pythonContextKey,
          }),
        ),
      );
      if (generation !== authoringGeneration.current) return;
      setPythonProgramResult(
        selectedPythonProgram?.programId === draft.programId
          ? `Saved ${pythonProgramDisplayName(selectedPythonProgram)}.`
          : "Saved the new Python program.",
      );
      setPythonDraftEdited(false);
      if (response.result.validation?.purpose === "Validation")
        setPythonValidation({
          build: response.result.validation,
          contextKey: pythonContextKey,
        });
      else
        setPythonProgramError(
          "The saved source has no validation task. Reopen it to check validation.",
        );
      await readPythonPrograms();
      await onRefreshCatalog?.();
    } catch (reason) {
      if (generation !== authoringGeneration.current) return;
      const diagnostics =
        reason instanceof ApiError
          ? pythonDiagnostics(reason.details)
          : undefined;
      if (diagnostics)
        setPythonSourceDiagnostics({
          diagnostics,
          contextKey: pythonContextKey,
        });
      setPythonProgramError(
        reason instanceof Error
          ? reason.message
          : "Unable to save Python program",
      );
    } finally {
      if (generation === authoringGeneration.current)
        setPythonProgramBusy(false);
    }
  }

  function editCurrentPythonProgram(program: PythonProgramDetail) {
    const edit = () => {
      setPythonDraftId(program.programId);
      setPythonDraftEntry(program.entryPoint);
      setPythonDraftEnvironment(
        JSON.stringify([program.environmentId, program.environmentStateToken]),
      );
      setPythonDraftParameters(
        JSON.stringify(program.parameterSchema, null, 2),
      );
      setPythonDraftSource(program.sourceText);
      setPythonDraftDeclaredOutput(program.declaredOutput);
      setPythonDraftEdited(false);
      setPythonValidation(null);
      setPythonSourceDiagnostics(null);
      setPythonAuthoringOpen(true);
      setPythonProgramResult("");
      void readPythonEnvironments();
      window.requestAnimationFrame(() => {
        pythonAuthoringRef.current?.scrollIntoView({ block: "start" });
        pythonAuthoringRef.current?.focus();
      });
    };
    if (pythonDraftEdited && onRequestTransition) onRequestTransition(edit);
    else edit();
  }

  async function readPythonProgram(
    program: PythonProgramSummary,
    currentCatalog?: ApplicationCatalog,
  ) {
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
            arguments: pythonProgramReadArguments(program.programId),
          },
        },
      );
      if (
        !detail.result.defined ||
        detail.result.programId !== program.programId ||
        detail.result.sourceToken !== program.sourceToken ||
        detail.result.sourceDigest !== program.sourceDigest
      )
        throw new Error("That current program source is unavailable.");
      if (
        selectedPythonProgram?.programId !== detail.result.programId ||
        selectedPythonProgram?.sourceToken !== detail.result.sourceToken
      )
        setPythonBuildParameters("{}");
      setSelectedPythonProgram(detail.result);
      const contextKey = currentCatalog
        ? authoringContextKey(app, currentCatalog)
        : pythonContextKey;
      setPythonSelectedContextKey(contextKey);
      setPythonSelectedValidation(
        detail.result.validation?.purpose === "Validation"
          ? { build: detail.result.validation, contextKey }
          : null,
      );

      setPythonProgramResult("");
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error ? reason.message : "Unable to read program",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  async function changePythonActivation(action: "activate" | "deactivate") {
    const validationBuildId =
      action === "activate" ? activationArtifact?.buildId : undefined;
    if (
      !app ||
      !catalog ||
      !selectedPythonProgram ||
      pythonProgramBusy ||
      (action === "activate" && !pythonActivationReady) ||
      catalog.revisions.schemaEpoch === undefined ||
      !catalog.functions[`python.program.${action}`]
    )
      return;
    if (
      action === "deactivate" &&
      !window.confirm("Deactivate this current Python program?")
    )
      return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonProgramResult("");
    try {
      const response = await requestAdmittedEffect<{
        result?: { status?: string; operationId?: string };
      }>(
        "/api/python-program",
        pythonProgramActionBody(
          app,
          catalog,
          selectedPythonProgram,
          action,
          mutationKey({
            operation: "python-program-activation",
            programId: selectedPythonProgram.programId,
            sourceToken: selectedPythonProgram.sourceToken,
            action,
            contextKey: pythonContextKey,
            validationBuildId,
          }),
          validationBuildId,
        ),
      );
      const refreshed = await onRefreshCatalog?.();
      await readPythonPrograms();
      await readPythonProgram(selectedPythonProgram, refreshed);
      setPythonProgramResult(
        `Program is ${response.result?.status || action}.`,
      );
    } catch (reason) {
      setPythonProgramError(
        reason instanceof Error
          ? reason.message
          : "Unable to change Python program activation",
      );
    } finally {
      setPythonProgramBusy(false);
    }
  }

  const pythonParameterSchema =
    selectedPythonProgram && pythonSelectedContextKey === pythonContextKey
      ? parameterObject(selectedPythonProgram.parameterSchema)
      : undefined;
  const pythonScheduleParameterSchema =
    !pythonSchedule ||
    (pythonSchedule.program_id === selectedPythonProgram?.programId &&
      pythonSchedule.program_source_token ===
        selectedPythonProgram?.sourceToken)
      ? pythonParameterSchema
      : undefined;

  function exactActiveBuildDelegation() {
    const stateToken = pythonDelegationStateToken;
    if (
      !pythonDelegation ||
      pythonDelegation.delegation_id !== pythonDelegationId.trim() ||
      pythonDelegation.status !== "Active" ||
      pythonDelegation.state_token !== stateToken ||
      !pythonDelegation.operation_scope.includes("python.program.build") ||
      Date.parse(pythonDelegation.valid_from) > Date.now() ||
      Date.parse(pythonDelegation.valid_until) <= Date.now()
    )
      throw new Error("Read the current active build authority.");
    return stateToken;
  }

  function openExecutionDelegation(
    delegation: ExecutionDelegation,
    verified: boolean,
  ) {
    setPythonDelegation(delegation);
    setPythonDelegationReadVerified(verified);
    setPythonDelegationId(delegation.delegation_id);
    setPythonDelegationStateToken(verified ? delegation.state_token : "");
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

    setPythonScheduleReviewedAction(null);
  }

  async function readExecutionDelegations(next: boolean) {
    if (!app) return;
    if (next && !executionDelegationAfter) return;
    const generation = ++executionDelegationListGeneration.current;
    const contextKey = pythonContextKey;
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
      if (
        generation !== executionDelegationListGeneration.current ||
        contextKey !== pythonContextKeyRef.current
      )
        return;
      setExecutionDelegations((current) =>
        next
          ? [...current, ...response.result.delegations]
          : response.result.delegations,
      );
      setExecutionDelegationAfter(response.result.nextAfterDelegationId);
    } catch (reason) {
      if (
        generation === executionDelegationListGeneration.current &&
        contextKey === pythonContextKeyRef.current
      )
        setPythonProgramError(
          reason instanceof Error
            ? reason.message
            : "Unable to read authorities",
        );
    } finally {
      if (
        generation === executionDelegationListGeneration.current &&
        contextKey === pythonContextKeyRef.current
      )
        setPythonProgramBusy(false);
    }
  }

  function changeExecutionDelegationDraft(change: () => void) {
    change();
    setPythonDelegationReadVerified(false);
    setPythonDelegationCreateReviewed(false);
    setPythonDelegationRevokeReviewed(false);
    setPythonDelegationResult("");
  }

  function executionSubject(subjectId: string) {
    return executionSubjects.find(
      (subject) => subject.selectionKey === subjectId,
    );
  }

  function executionSubjectLabel(subjectId: string) {
    const subject = executionSubject(subjectId);
    return subject
      ? `${subject.displayName} (${subject.username})`
      : "Directory identity unavailable";
  }

  function executionScopeLabel(operationScope: string[]) {
    if (!operationScope.length) return "No permitted functions";
    return operationScope
      .map((operation) =>
        operation === "python.program.build"
          ? "Build sealed plans"
          : operation === "python.program.run"
            ? "Run sealed plans"
            : "Unavailable operation",
      )
      .join(", ");
  }

  function exactExecutionDelegationDraft() {
    const delegationId = pythonDelegationId.trim();
    const issuer = executionDirectoryIssuer.trim();
    const subjectId = pythonDelegationSubject.trim();
    const validFrom = Date.parse(pythonDelegationValidFrom);
    const validUntil = Date.parse(pythonDelegationValidUntil);
    const operationScope = [
      ...(pythonDelegationBuild ? ["python.program.build"] : []),
      ...(pythonDelegationRun ? ["python.program.run"] : []),
    ];
    if (!/^[A-Za-z0-9._-]{1,200}$/.test(delegationId))
      throw new Error(
        "Authority code must use 1-200 letters, numbers, dots, underscores or hyphens.",
      );
    if (
      !issuer ||
      issuer.length > 300 ||
      !subjectId ||
      subjectId.length > 300 ||
      !executionSubject(subjectId)
    )
      throw new Error("Choose a current authorized user from the directory.");
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
      ...(pythonDelegationReadVerified && pythonDelegation
        ? { expectedStateToken: pythonDelegation.state_token }
        : {}),
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

  async function readPythonDelegation(
    authorityName = pythonDelegationId.trim(),
  ) {
    if (!app || !authorityName) return;
    const generation = ++executionDelegationReadGeneration.current;
    const contextKey = pythonContextKey;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonDelegation(null);
    setPythonDelegationReadVerified(false);

    setPythonScheduleReviewedAction(null);
    try {
      const response = await request<{
        result: { defined: boolean; delegation: ExecutionDelegation };
      }>(
        "/api/execution-delegation",
        executionDelegationReadBody(app, authorityName),
      );
      if (
        generation !== executionDelegationReadGeneration.current ||
        contextKey !== pythonContextKeyRef.current
      )
        return;
      if (!response.result.defined)
        throw new Error("That execution authority is unavailable.");
      openExecutionDelegation(response.result.delegation, true);
    } catch (reason) {
      if (
        generation === executionDelegationReadGeneration.current &&
        contextKey === pythonContextKeyRef.current
      )
        setPythonProgramError(
          reason instanceof Error ? reason.message : "Unable to read authority",
        );
    } finally {
      if (
        generation === executionDelegationReadGeneration.current &&
        contextKey === pythonContextKeyRef.current
      )
        setPythonProgramBusy(false);
    }
  }

  const currentExecutionDelegations = executionDelegations.filter(
    (delegation) =>
      delegation.status === "Active" &&
      Date.parse(delegation.valid_from) <= Date.now() &&
      Date.parse(delegation.valid_until) > Date.now(),
  );
  const buildExecutionDelegations = currentExecutionDelegations.filter(
    (delegation) => delegation.operation_scope.includes("python.program.build"),
  );
  const scheduleExecutionDelegations = buildExecutionDelegations.filter(
    (delegation) => delegation.operation_scope.includes("python.program.run"),
  );

  function chooseExecutionDelegation(authorityName: string) {
    executionDelegationReadGeneration.current += 1;
    setPythonDelegationId(authorityName);
    setPythonDelegation(null);
    setPythonDelegationReadVerified(false);
    setPythonScheduleReviewedAction(null);
    if (authorityName) void readPythonDelegation(authorityName);
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
          pythonDelegation?.status !== "Active" ||
          pythonDelegation?.state_token !== draft.expectedStateToken)
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
    if (!window.confirm(`${verb} this current execution authority?`)) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonDelegationResult("");
    try {
      const response = await requestAdmittedEffect<{
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
        `Authority ${response.result?.status || action} was recorded.`,
      );
      setPythonDelegation(null);
      setPythonDelegationReadVerified(false);
      setPythonDelegationCreateReviewed(false);
      setPythonDelegationRevokeReviewed(false);
      await onRefreshCatalog?.();
      await readExecutionDelegations(false);
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
    setPythonDelegationStateToken(schedule.delegation_state_token);
    void readPythonDelegation(schedule.delegation_id);
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
    const intervalSeconds = Number(pythonScheduleInterval);
    const maxCatchUp = Number(pythonScheduleMaxCatchUp);
    const firstDue = Date.parse(pythonScheduleFirstDue);
    const inputError = parameterInputError(
      pythonScheduleParameters,
      pythonScheduleParameterSchema,
    );
    if (inputError) throw new Error(inputError);
    let parameters: unknown;
    try {
      parameters = JSON.parse(pythonScheduleParameters);
    } catch {
      throw new Error("Schedule parameters must be valid JSON.");
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(scheduleId))
      throw new Error(
        "Schedule code must use 1-200 letters, numbers, dots, colons, underscores or hyphens.",
      );
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
    if (!selectedPythonProgram || selectedPythonProgram.status !== "Active")
      throw new Error("Open the active current program first.");
    const delegationStateToken = exactActiveBuildDelegation();
    if (!pythonDelegation?.operation_scope.includes("python.program.run"))
      throw new Error("The exact authority must permit build and run.");
    return {
      scheduleId,
      expectedStateToken:
        pythonScheduleReadVerified && pythonSchedule
          ? pythonSchedule.state_token
          : undefined,
      programId: selectedPythonProgram.programId,
      programSourceToken: selectedPythonProgram.sourceToken,
      parameters: parameters as Record<string, unknown>,
      intervalSeconds,
      firstDueAt: new Date(firstDue).toISOString(),
      catchUpPolicy: pythonScheduleCatchUp,
      maxCatchUp,
      delegationId: pythonDelegationId.trim(),
      delegationStateToken,
    };
  }

  function pythonScheduleActionAllowed(
    action: "save" | "activate" | "deactivate" | "run",
  ) {
    if (action === "save") {
      try {
        exactPythonScheduleDraft();
        return (
          (pythonScheduleReadVerified || !pythonSchedule) &&
          Boolean(catalog?.functions["python.schedule.save"])
        );
      } catch {
        return false;
      }
    }
    if (!pythonScheduleReadVerified || !pythonSchedule) return false;
    const exact =
      pythonSchedule.schedule_id === pythonScheduleId.trim() &&
      /^[0-9a-f]{64}$/.test(pythonSchedule.state_token);
    if (!exact) return false;
    if (action === "activate")
      return (
        pythonSchedule.status !== "Active" &&
        Boolean(catalog?.functions["python.schedule.activate"])
      );
    if (action === "deactivate")
      return (
        pythonSchedule.status === "Active" &&
        Boolean(catalog?.functions["python.schedule.deactivate"])
      );
    return (
      pythonSchedule.status === "Active" &&
      Boolean(catalog?.functions["python.schedule.run"])
    );
  }

  async function mutatePythonSchedule(
    action: "save" | "activate" | "deactivate" | "run",
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
              expectedStateToken: pythonSchedule?.state_token,
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
      const response = await requestAdmittedEffect<{
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
        `Schedule ${response.result.status || action} was recorded.`,
      );
      if (response.result.occurrenceId)
        setPythonOccurrenceId(response.result.occurrenceId);
      setPythonScheduleReviewedAction(null);
      setPythonScheduleReadVerified(false);
      await readPythonSchedules(false);
      if (catalog.functions["python.schedule.occurrence.list"])
        await readPythonOccurrences(false);
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

  async function readPythonOccurrences(next: boolean) {
    if (!app || (next && !pythonOccurrenceAfter)) return;
    const generation = ++pythonOccurrenceListGeneration.current;
    const contextKey = pythonContextKey;
    setPythonOccurrenceBusy(true);
    setPythonProgramError("");
    try {
      const response = await request<{
        result: {
          occurrences: PythonOccurrence[];
          nextAfterOccurrenceId: string | null;
        };
      }>(
        "/api/python-schedule",
        pythonOccurrenceListBody(app, next ? pythonOccurrenceAfter : null),
      );
      if (
        generation !== pythonOccurrenceListGeneration.current ||
        contextKey !== pythonContextKeyRef.current
      )
        return;
      setPythonOccurrences((current) =>
        next
          ? [...current, ...response.result.occurrences]
          : response.result.occurrences,
      );
      setPythonOccurrenceAfter(response.result.nextAfterOccurrenceId);
    } catch (reason) {
      if (
        generation === pythonOccurrenceListGeneration.current &&
        contextKey === pythonContextKeyRef.current
      )
        setPythonProgramError(
          reason instanceof Error
            ? reason.message
            : "Unable to read schedule runs",
        );
    } finally {
      if (
        generation === pythonOccurrenceListGeneration.current &&
        contextKey === pythonContextKeyRef.current
      )
        setPythonOccurrenceBusy(false);
    }
  }

  function choosePythonOccurrence(occurrenceId: string) {
    setPythonOccurrenceId(occurrenceId);
    setPythonOccurrence(null);
    setPythonOccurrenceReadVerified(false);
    setPythonOccurrenceCancelReviewed(false);
    if (occurrenceId) void readPythonOccurrence(occurrenceId);
  }

  function pythonOccurrenceStatusLabel(status: string) {
    return status
      .split("_")
      .map((part) => part[0]?.toUpperCase() + part.slice(1))
      .join(" ");
  }

  async function readPythonOccurrence(
    occurrenceId = pythonOccurrenceId.trim(),
  ) {
    if (!app || !occurrenceId) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    setPythonOccurrenceReadVerified(false);
    try {
      const response = await request<{
        result: { defined: boolean; occurrence: PythonOccurrence };
      }>(
        "/api/python-schedule",
        pythonOccurrenceBody(app, "read", occurrenceId),
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
    if (!window.confirm("Request cancellation of this schedule run?")) return;
    setPythonProgramBusy(true);
    setPythonProgramError("");
    try {
      const body = pythonOccurrenceBody(
        app,
        "cancel",
        pythonOccurrence.occurrence_id,
        mutationKey({
          operation: "python-occurrence-cancel",
          occurrenceId: pythonOccurrence.occurrence_id,
        }),
      );
      if (!body.idempotencyKey)
        throw new Error("Python occurrence cancellation identity is missing.");
      const response = await requestAdmittedEffect<{
        result: PythonOccurrence;
      }>("/api/python-schedule", {
        ...body,
        idempotencyKey: body.idempotencyKey,
      });
      setPythonOccurrence(response.result);
      setPythonOccurrenceCancelReviewed(false);
      setPythonScheduleResult(
        `Schedule run ${pythonOccurrenceStatusLabel(response.result.status)}.`,
      );
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
          <p>
            {workspaceSections[area].find((item) => item.id === section)
              ?.description || definition.description}
          </p>
        </div>
      </div>
      <nav
        className="workspace-section-nav"
        aria-label={`${definition.title} workspaces`}
      >
        {workspaceSections[area].map((item) => (
          <button
            key={item.id}
            type="button"
            aria-current={section === item.id ? "page" : undefined}
            onClick={() => onNavigateSection(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>
      {!catalog ? (
        <p className="workspace-pending" role="status">
          Checking current access…
        </p>
      ) : (
        <>
          {section !== "reference" &&
            !["activity", "lifecycle"].includes(section) &&
            !matchingFunctions(
              catalog.functions,
              workspaceSections[area].find((item) => item.id === section)!
                .prefixes,
            ).length && (
              <p className="workspace-unavailable" role="status">
                This workspace is not available to your current application
                role. Choose another workspace or inspect Function reference.
              </p>
            )}
          {section === "reference" && (
            <section
              className="panel workspace-function-reference"
              aria-labelledby="workspace-reference-heading"
            >
              <div className="section-heading-row">
                <div>
                  <small>CURRENT ROLE</small>
                  <h2 id="workspace-reference-heading">Function reference</h2>
                  <p>
                    Available functions for {definition.title.toLowerCase()}.
                    Opening this reference does not perform an operation.
                  </p>
                </div>
              </div>
              {!catalog ? (
                <p role="status">Checking current access…</p>
              ) : (
                (() => {
                  const names = matchingFunctions(
                    catalog.functions,
                    workspaceSections[area].find(
                      (item) => item.id === "reference",
                    )!.prefixes,
                  );
                  return names.length ? (
                    <ul>
                      {names.map((name) => (
                        <li key={name}>
                          <code>{name}</code>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="muted-copy">
                      No functions in this workspace are available to your
                      current role.
                    </p>
                  );
                })()
              )}
            </section>
          )}
          {area === "rules" &&
            ["python", "authorities", "python-schedules"].includes(section) && (
              <section
                className="panel capability-activity python-workspace"
                aria-labelledby="python-program-explorer-heading"
              >
                <div className="section-heading-row">
                  <div>
                    <small>
                      {section === "python"
                        ? "CURRENT PROGRAMS"
                        : section === "authorities"
                          ? "ACCESS CONTROL"
                          : "PROGRAM AUTOMATION"}
                    </small>
                    <h2 id="python-program-explorer-heading" tabIndex={-1}>
                      {section === "python"
                        ? "Python programs"
                        : section === "authorities"
                          ? "Execution authorities"
                          : "Program schedules"}
                    </h2>
                  </div>
                  {["python", "python-schedules"].includes(section) && (
                    <button
                      disabled={pythonProgramBusy || !canReadPythonPrograms}
                      onClick={() => void readPythonPrograms()}
                    >
                      {pythonProgramBusy ? "Loading…" : "Refresh programs"}
                    </button>
                  )}
                </div>
                {pythonProgramError && (
                  <div className="inline-error" role="alert">
                    {pythonProgramError}
                  </div>
                )}
                {pythonProgramResult && (
                  <p role="status">{pythonProgramResult}</p>
                )}
                {section === "python" && canAuthorPythonPrograms && (
                  <details
                    className="workspace-create-disclosure"
                    open={pythonAuthoringOpen}
                    onToggle={(event) =>
                      setPythonAuthoringOpen(event.currentTarget.open)
                    }
                  >
                    <summary>
                      {selectedPythonProgram &&
                      pythonDraftId === selectedPythonProgram.programId
                        ? `Edit ${pythonProgramDisplayName(selectedPythonProgram)}`
                        : "Create a program"}
                    </summary>
                    <article
                      ref={pythonAuthoringRef}
                      className="program-inspector python-authoring"
                      aria-label="New Python program"
                      tabIndex={-1}
                    >
                      <div className="section-heading-row">
                        <div>
                          <small>PYTHON SOURCE</small>
                          <h3>
                            {selectedPythonProgram &&
                            pythonDraftId === selectedPythonProgram.programId
                              ? `Edit ${pythonProgramDisplayName(selectedPythonProgram)}`
                              : "Save a Python program"}
                          </h3>
                          <p>
                            Save the current source and validate it in the
                            isolated builder. Test the saved source before
                            activating it.
                          </p>
                        </div>
                        {(!selectedPythonProgram ||
                          pythonDraftId !==
                            selectedPythonProgram.programId) && (
                          <button
                            disabled={pythonProgramBusy}
                            onClick={() => void readPythonEnvironments()}
                          >
                            {pythonEnvironments.length
                              ? "Refresh environments"
                              : "Read environments"}
                          </button>
                        )}
                      </div>
                      <fieldset
                        disabled={pythonProgramBusy}
                        className="python-authoring-form"
                      >
                        {(!selectedPythonProgram ||
                          pythonDraftId !==
                            selectedPythonProgram.programId) && (
                          <>
                            <div className="python-authoring-fields">
                              <label>
                                Rule key
                                <input
                                  aria-label="Python rule key"
                                  value={pythonDraftId}
                                  onChange={(event) =>
                                    changePythonDraft(
                                      () =>
                                        setPythonDraftId(event.target.value),
                                      true,
                                    )
                                  }
                                  placeholder="cube-calculation"
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
                                      setPythonDraftEnvironment(
                                        event.target.value,
                                      ),
                                    )
                                  }
                                  disabled={!pythonEnvironments.length}
                                >
                                  {!pythonEnvironments.length && (
                                    <option value="">
                                      Read environments first
                                    </option>
                                  )}
                                  {pythonEnvironments.map((environment) => (
                                    <option
                                      key={`${environment.environment_id}:${environment.state_token}`}
                                      value={pythonEnvironmentSelection(
                                        environment,
                                      )}
                                    >
                                      {environment.environment_id}
                                    </option>
                                  ))}
                                </select>
                              </label>
                            </div>
                            <label>
                              Input definition
                              <textarea
                                aria-label="Python input definition"
                                rows={5}
                                value={pythonDraftParameters}
                                onChange={(event) =>
                                  changePythonDraft(() =>
                                    setPythonDraftParameters(
                                      event.target.value,
                                    ),
                                  )
                                }
                              />
                            </label>
                          </>
                        )}
                        <label>
                          Python source
                          <PythonRuleEditor
                            ariaLabel="Python program source"
                            value={pythonDraftSource}
                            readOnly={pythonProgramBusy}
                            diagnostics={pythonEditorDiagnostics}
                            completions={
                              pythonMetadata?.contextKey === pythonContextKey
                                ? pythonMetadata.completions
                                : []
                            }
                            onChange={(value) =>
                              changePythonDraft(() =>
                                setPythonDraftSource(value),
                              )
                            }
                          />
                        </label>
                        <div className="reviewed-inline-actions">
                          <button
                            disabled={
                              pythonProgramBusy ||
                              !pythonDraftEdited ||
                              !pythonDraftIsValid()
                            }
                            onClick={() => void savePythonProgram()}
                          >
                            Save and validate
                          </button>
                        </div>
                      </fieldset>
                      {pythonMetadataError && (
                        <p role="status">
                          {pythonMetadataError}{" "}
                          <button
                            onClick={() =>
                              setPythonMetadataRefresh((value) => value + 1)
                            }
                          >
                            Refresh metadata suggestions
                          </button>
                        </p>
                      )}
                      {pythonValidation && (
                        <p role="status">
                          Validation: {pythonValidation.build.status}
                          {!pythonValidationCurrent
                            ? " · application context changed; save the program again to validate the current application"
                            : ""}
                          {pythonValidation.build.errorCode
                            ? ` · ${pythonValidation.build.errorCode}`
                            : ""}
                        </p>
                      )}
                      {pythonValidationError && (
                        <p role="alert">
                          {pythonValidationError}{" "}
                          <button
                            disabled={!pythonValidationCurrent}
                            onClick={refreshPythonValidation}
                          >
                            Refresh validation status
                          </button>
                        </p>
                      )}
                    </article>
                  </details>
                )}
                {section === "authorities" &&
                  Boolean(catalog?.functions["execution.delegation.list"]) &&
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
                            Choose who may build or run an approved program,
                            which operations they may use and when their
                            authority expires.
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
                            disabled={
                              pythonProgramBusy || !executionDelegationAfter
                            }
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
                                <th>State</th>
                                <th>User</th>
                                <th>Scope</th>
                                <th>Valid until</th>
                                <th>Use</th>
                              </tr>
                            </thead>
                            <tbody>
                              {executionDelegations.map((delegation) => (
                                <tr key={delegation.delegation_id}>
                                  <th>{delegation.delegation_id}</th>
                                  <td>{delegation.status}</td>
                                  <td>
                                    {executionSubjectLabel(
                                      delegation.subject_id,
                                    )}
                                  </td>
                                  <td>
                                    {executionScopeLabel(
                                      delegation.operation_scope,
                                    )}
                                  </td>
                                  <td>
                                    {new Date(
                                      delegation.valid_until,
                                    ).toLocaleString()}
                                  </td>
                                  <td>
                                    <button
                                      disabled={pythonProgramBusy}
                                      onClick={() =>
                                        openExecutionDelegation(
                                          delegation,
                                          false,
                                        )
                                      }
                                    >
                                      Use authority details
                                    </button>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <p className="muted-copy">
                          No authority catalogue read yet.
                        </p>
                      )}
                      <div className="python-authoring-fields">
                        <label>
                          Authority code
                          <input
                            aria-label="Execution authority code"
                            value={pythonDelegationId}
                            onChange={(event) =>
                              changeExecutionDelegationDraft(() =>
                                setPythonDelegationId(event.target.value),
                              )
                            }
                            placeholder="budget-planning-operator"
                          />
                        </label>
                        <label>
                          Authorized user
                          <select
                            aria-label="Execution authority user"
                            value={pythonDelegationSubject}
                            onChange={(event) =>
                              changeExecutionDelegationDraft(() =>
                                setPythonDelegationSubject(event.target.value),
                              )
                            }
                          >
                            <option value="">Choose a current user</option>
                            {pythonDelegationSubject &&
                              !executionSubject(pythonDelegationSubject) && (
                                <option
                                  value={pythonDelegationSubject}
                                  disabled
                                >
                                  Directory identity unavailable
                                </option>
                              )}
                            {executionSubjects.map((subject) => (
                              <option
                                key={subject.selectionKey}
                                value={subject.selectionKey}
                              >
                                {subject.displayName} ({subject.username})
                              </option>
                            ))}
                          </select>
                        </label>
                        <label>
                          Valid from
                          <input
                            aria-label="Execution authority valid from"
                            type="datetime-local"
                            value={pythonDelegationValidFrom}
                            onChange={(event) =>
                              changeExecutionDelegationDraft(() =>
                                setPythonDelegationValidFrom(
                                  event.target.value,
                                ),
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
                                setPythonDelegationValidUntil(
                                  event.target.value,
                                ),
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
                          disabled={
                            pythonProgramBusy || !pythonDelegationId.trim()
                          }
                          onClick={() => void readPythonDelegation()}
                        >
                          Open authority
                        </button>
                        <label className="review-check">
                          <input
                            type="checkbox"
                            checked={pythonDelegationCreateReviewed}
                            disabled={!executionDelegationDraftValid()}
                            onChange={(event) =>
                              setPythonDelegationCreateReviewed(
                                event.target.checked,
                              )
                            }
                          />
                          I reviewed this authority, authorized user, permitted
                          functions, validity period and current application.
                        </label>
                        <button
                          disabled={
                            pythonProgramBusy ||
                            !pythonDelegationCreateReviewed ||
                            !executionDelegationDraftValid() ||
                            !catalog?.functions["execution.delegation.create"]
                          }
                          onClick={() =>
                            void mutateExecutionDelegation("create")
                          }
                        >
                          Create authority
                        </button>
                      </div>
                      <div className="reviewed-inline-actions">
                        <label className="review-check">
                          <input
                            type="checkbox"
                            checked={pythonDelegationRevokeReviewed}
                            disabled={
                              !pythonDelegationReadVerified ||
                              pythonDelegation?.status !== "Active" ||
                              pythonDelegation?.state_token !==
                                pythonDelegationStateToken
                            }
                            onChange={(event) =>
                              setPythonDelegationRevokeReviewed(
                                event.target.checked,
                              )
                            }
                          />
                          I freshly read and reviewed this current active
                          authority for revocation.
                        </label>
                        <button
                          disabled={
                            pythonProgramBusy ||
                            !pythonDelegationRevokeReviewed ||
                            !pythonDelegationReadVerified ||
                            pythonDelegation?.status !== "Active" ||
                            pythonDelegation?.state_token !==
                              pythonDelegationStateToken ||
                            !catalog?.functions["execution.delegation.revoke"]
                          }
                          onClick={() =>
                            void mutateExecutionDelegation("revoke")
                          }
                        >
                          Revoke authority
                        </button>
                      </div>
                      {pythonDelegationReadVerified && pythonDelegation && (
                        <p className="authority-summary" role="status">
                          Current {pythonDelegation.status.toLowerCase()}{" "}
                          authority for{" "}
                          {executionSubjectLabel(pythonDelegation.subject_id)}
                          {" · "}
                          {executionScopeLabel(
                            pythonDelegation.operation_scope,
                          )}
                        </p>
                      )}
                      {pythonDelegationResult && (
                        <p role="status">{pythonDelegationResult}</p>
                      )}
                    </article>
                  )}
                {["python", "python-schedules"].includes(section) &&
                  (pythonPrograms.length ? (
                    <div className="react-grid-scroll">
                      <table className="react-cube-grid python-program-grid">
                        <thead>
                          <tr>
                            <th>Rule</th>
                            <th>Status</th>
                            <th>Availability</th>
                            <th>Type</th>
                            <th>Inspect</th>
                          </tr>
                        </thead>
                        <tbody>
                          {pythonPrograms.map((program) => (
                            <tr key={program.programId}>
                              <th>{pythonProgramDisplayName(program)}</th>
                              <td>{program.status}</td>
                              <td>{pythonProgramAvailabilityLabel(program)}</td>
                              <td>{pythonProgramTypeLabel(program)}</td>
                              <td>
                                <button
                                  disabled={pythonProgramBusy}
                                  onClick={() => {
                                    setPythonScheduleReviewedAction(null);
                                    void readPythonProgram(program);
                                  }}
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
                    <p className="muted-copy">
                      {canReadPythonPrograms
                        ? pythonProgramBusy
                          ? "Loading permitted programs…"
                          : "No Python programs are available in this application."
                        : "Your current role cannot read Python programs."}
                    </p>
                  ))}
                {section === "python" && selectedPythonProgram && (
                  <article
                    className="program-inspector python-program-detail"
                    aria-label="Python program detail"
                  >
                    <h3>{pythonProgramDisplayName(selectedPythonProgram)}</h3>
                    <p>
                      {selectedPythonProgram.status} ·{" "}
                      {pythonProgramTypeLabel(selectedPythonProgram)}
                    </p>
                    <h4>Current source</h4>
                    <PythonRuleEditor
                      ariaLabel="Authorized Python source"
                      value={selectedPythonProgram.sourceText}
                      onChange={() => undefined}
                      readOnly
                      diagnostics={
                        pythonSelectedContextKey === pythonContextKey &&
                        selectedValidationObserver.current
                          ? pythonDiagnostics(selectedValidation?.diagnostics)
                          : undefined
                      }
                    />
                    {pythonProgramHasParameters(
                      selectedPythonProgram.parameterSchema,
                    ) ? (
                      <details>
                        <summary>Parameters</summary>
                        <pre
                          className="program-code"
                          role="region"
                          aria-label="Python parameter schema"
                          tabIndex={0}
                        >
                          {JSON.stringify(
                            selectedPythonProgram.parameterSchema,
                            null,
                            2,
                          )}
                        </pre>
                      </details>
                    ) : (
                      <p className="muted-copy">
                        This program does not require parameters.
                      </p>
                    )}
                    {canAuthorPythonPrograms && (
                      <button
                        disabled={pythonProgramBusy}
                        onClick={() =>
                          editCurrentPythonProgram(selectedPythonProgram)
                        }
                      >
                        Edit current source
                      </button>
                    )}
                    {app &&
                      catalog &&
                      Boolean(catalog.functions["python.program.test"]) && (
                        <PythonProgramTest
                          key={`${selectedPythonProgram.programId}:${selectedPythonProgram.sourceToken}:${selectedPythonProgram.latestImpactTest?.buildId}:${selectedPythonProgram.latestImpactTest?.status}:${selectedPythonProgram.latestImpactTest?.current}`}
                          app={app}
                          catalog={catalog}
                          program={{
                            ...selectedPythonProgram,
                            validation:
                              pythonSelectedContextKey === pythonContextKey &&
                              selectedValidationObserver.current &&
                              selectedValidation?.buildId ===
                                selectedPythonProgram.validation?.buildId
                                ? selectedValidation
                                : null,
                          }}
                          parameters={pythonBuildParameters}
                          onParametersChange={setPythonBuildParameters}
                          definitionContextKey={
                            pythonSelectedContextKey === pythonContextKey
                              ? pythonSelectedContextKey
                              : undefined
                          }
                          onSealedTest={setPythonSealedTest}
                        />
                      )}
                    {app &&
                      catalog &&
                      Boolean(catalog.functions["python.program.build"]) &&
                      Boolean(catalog.functions["python.program.run"]) &&
                      !selectedPythonProgram.validation?.definition &&
                      !selectedPythonProgram.latestImpactTest?.definition && (
                        <PythonProgramRun
                          app={app}
                          catalog={catalog}
                          program={selectedPythonProgram}
                          parameters={pythonBuildParameters}
                          suspended={pythonProgramBusy}
                          authority={
                            pythonDelegationReadVerified &&
                            pythonDelegation?.delegation_id ===
                              pythonDelegationId.trim() &&
                            pythonDelegation.status === "Active" &&
                            pythonDelegation.state_token ===
                              pythonDelegationStateToken
                              ? pythonDelegation
                              : null
                          }
                          onSetupAuthority={() =>
                            onNavigateSection("authorities")
                          }
                        />
                      )}
                    {selectedValidation && (
                      <p>
                        Validation: {selectedValidation.status}
                        {!selectedValidationObserver.current
                          ? " · stale application context"
                          : ""}
                      </p>
                    )}
                    {selectedValidationObserver.error && (
                      <p role="alert">
                        {selectedValidationObserver.error}{" "}
                        <button onClick={selectedValidationObserver.refresh}>
                          Refresh saved validation
                        </button>
                      </p>
                    )}
                    {activationArtifact?.definition && (
                      <p>
                        Ready to activate as a validated{" "}
                        {pythonProgramTypeLabel(
                          selectedPythonProgram,
                        ).toLowerCase()}
                        .
                      </p>
                    )}
                    <div className="reviewed-inline-actions">
                      <button
                        disabled={
                          pythonProgramBusy ||
                          selectedPythonProgram.status === "Active" ||
                          !pythonActivationReady ||
                          catalog?.revisions.schemaEpoch === undefined ||
                          !catalog?.functions["python.program.activate"]
                        }
                        onClick={() => void changePythonActivation("activate")}
                      >
                        Activate source
                      </button>
                      <button
                        disabled={
                          pythonProgramBusy ||
                          selectedPythonProgram.status !== "Active" ||
                          catalog?.revisions.schemaEpoch === undefined ||
                          !catalog?.functions["python.program.deactivate"]
                        }
                        onClick={() =>
                          void changePythonActivation("deactivate")
                        }
                      >
                        Deactivate source
                      </button>
                    </div>
                  </article>
                )}
                {section === "python-schedules" &&
                  Boolean(catalog?.functions["python.schedule.list"]) &&
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
                            Choose an active program and execution authority,
                            then define its recurrence. Open an existing
                            schedule to inspect or control it.
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
                                <th>Status</th>
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
                                  <td>{schedule.status}</td>
                                  <td>{schedule.program_id}</td>
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
                          Schedule code
                          <input
                            aria-label="Python schedule code"
                            value={pythonScheduleId}
                            onChange={(event) =>
                              invalidatePythonScheduleDraft(
                                () => setPythonScheduleId(event.target.value),
                                true,
                              )
                            }
                          />
                        </label>
                        <button
                          disabled={
                            pythonProgramBusy || !pythonScheduleId.trim()
                          }
                          onClick={() => void readPythonSchedule()}
                        >
                          Open schedule
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
                                  event.target.value as
                                    | "skip"
                                    | "latest"
                                    | "all",
                                ),
                              )
                            }
                          >
                            <option value="skip">
                              Skip missed occurrences
                            </option>
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
                      <ParameterFields
                        label="Schedule parameters"
                        advancedLabel="Python schedule parameters"
                        value={pythonScheduleParameters}
                        schema={pythonScheduleParameterSchema}
                        disabled={pythonProgramBusy}
                        onChange={(value) =>
                          invalidatePythonScheduleDraft(() =>
                            setPythonScheduleParameters(value),
                          )
                        }
                      />
                      {!pythonScheduleParameterSchema && (
                        <p>
                          Open the schedule's current source in the current
                          application context to use declared fields. The
                          advanced object remains available.
                        </p>
                      )}
                      <p className="authority-summary">
                        Program:{" "}
                        {selectedPythonProgram?.programId ||
                          "open an active current source"}
                        {selectedPythonProgram
                          ? ` (${selectedPythonProgram.status})`
                          : ""}
                        {" · "}Authority:{" "}
                        {pythonDelegation
                          ? `${executionSubjectLabel(pythonDelegation.subject_id)} (current)`
                          : "choose an active authority"}
                      </p>
                      <div className="python-authoring-fields">
                        <label>
                          Execution authority
                          <select
                            aria-label="Schedule execution authority"
                            value={pythonDelegationId}
                            disabled={pythonProgramBusy}
                            onChange={(event) => {
                              invalidatePythonScheduleDraft(() =>
                                chooseExecutionDelegation(event.target.value),
                              );
                            }}
                          >
                            <option value="">Choose an authority</option>
                            {scheduleExecutionDelegations.map((delegation) => (
                              <option
                                key={delegation.delegation_id}
                                value={delegation.delegation_id}
                              >
                                {executionSubjectLabel(delegation.subject_id)} ·{" "}
                                {delegation.operation_scope
                                  .map((scope) =>
                                    scope === "python.program.build"
                                      ? "Build"
                                      : "Run",
                                  )
                                  .join(" and ")}{" "}
                                · until{" "}
                                {new Date(
                                  delegation.valid_until,
                                ).toLocaleString()}
                              </option>
                            ))}
                          </select>
                        </label>
                      </div>
                      {pythonDelegation && (
                        <p className="authority-summary">
                          Authorized user:{" "}
                          {executionSubjectLabel(pythonDelegation.subject_id)}
                          {" · "}
                          {executionScopeLabel(
                            pythonDelegation.operation_scope,
                          )}
                          {" · Expires "}
                          {new Date(
                            pythonDelegation.valid_until,
                          ).toLocaleString()}
                        </p>
                      )}
                      <div className="reviewed-inline-actions">
                        {(
                          ["save", "activate", "deactivate", "run"] as const
                        ).map((action) => (
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
                        ))}
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
                            void mutatePythonSchedule(
                              pythonScheduleReviewedAction,
                            )
                          }
                        >
                          Apply reviewed schedule action
                        </button>
                      </div>
                      {pythonScheduleReadVerified && pythonSchedule && (
                        <p role="status">
                          Current schedule · {pythonSchedule.status}
                        </p>
                      )}
                      <div className="python-authoring-fields execution-status-fields">
                        <label>
                          Schedule run
                          <select
                            aria-label="Python schedule run"
                            value={pythonOccurrenceId}
                            disabled={pythonProgramBusy || pythonOccurrenceBusy}
                            onChange={(event) =>
                              choosePythonOccurrence(event.target.value)
                            }
                          >
                            <option value="">Choose a schedule run</option>
                            {pythonOccurrences.map((occurrence) => (
                              <option
                                key={occurrence.occurrence_id}
                                value={occurrence.occurrence_id}
                              >
                                {occurrence.schedule_id} ·{" "}
                                {pythonOccurrenceStatusLabel(occurrence.status)}
                                {occurrence.due_at
                                  ? ` · due ${new Date(
                                      occurrence.due_at,
                                    ).toLocaleString()}`
                                  : ""}
                              </option>
                            ))}
                          </select>
                        </label>
                        <button
                          disabled={
                            pythonProgramBusy ||
                            pythonOccurrenceBusy ||
                            !pythonOccurrenceAfter
                          }
                          onClick={() => void readPythonOccurrences(true)}
                        >
                          More schedule runs
                        </button>
                      </div>
                      {!pythonProgramBusy &&
                        !pythonOccurrenceBusy &&
                        !pythonOccurrences.length && (
                          <p className="muted-copy">
                            No schedule runs are available.
                          </p>
                        )}
                      {pythonOccurrence && (
                        <div className="execution-status-card">
                          <strong>
                            Run{" "}
                            {pythonOccurrenceStatusLabel(
                              pythonOccurrence.status,
                            )}
                          </strong>
                          <span>Schedule {pythonOccurrence.schedule_id}</span>
                          {pythonOccurrence.due_at && (
                            <span>
                              Due{" "}
                              {new Date(
                                pythonOccurrence.due_at,
                              ).toLocaleString()}
                            </span>
                          )}
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
                              I reviewed this freshly read occurrence and
                              request cancellation.
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
              </section>
            )}
          {area === "rules" && section === "rules" && (
            <BuildRules
              onRefreshCatalog={onRefreshCatalog}
              onRequestTransition={onRequestTransition}
              app={app}
              catalog={catalog}
              targetApplicationRule={targetApplicationRule}
            />
          )}
          {area === "rules" && section === "calculations" && (
            <CalculatedMembers
              onRefreshCatalog={onRefreshCatalog}
              onRequestTransition={onRequestTransition}
              app={app}
              catalog={catalog}
              target={targetCalculatedMember}
            />
          )}
          {area === "rules" && section === "sequences" && (
            <BuildSequences
              onRequestTransition={onRequestTransition}
              app={app}
              catalog={catalog}
              target={targetApplicationSequence}
            />
          )}
          {area === "rules" && section === "schedules" && (
            <BuildSchedules
              onRequestTransition={onRequestTransition}
              app={app}
              catalog={catalog}
              target={targetApplicationSchedule}
            />
          )}
          {area === "lists" && section === "lists" && (
            <MemberLists
              onRefreshCatalog={onRefreshCatalog}
              app={app}
              catalog={catalog}
              onRequestTransition={onRequestTransition}
            />
          )}
          {area === "administration" && section === "lifecycle" && (
            <ApplicationLifecycleSummary
              app={app}
              catalog={catalog}
              index={index}
            />
          )}
          {area === "security" &&
            ["security", "policy", "audit"].includes(section) && (
              <AdministrationSecurity
                app={app}
                catalog={catalog}
                view={
                  section === "policy" || section === "audit"
                    ? section
                    : "access"
                }
                onRequestTransition={onRequestTransition}
              />
            )}
          {area === "data" && section === "import" && (
            <DataLoad app={app} catalog={catalog} />
          )}
          {area === "data" && section === "export" && (
            <DataExport app={app} catalog={catalog} />
          )}
          {area === "data" && section === "detail" && (
            <SupportingDetail
              app={app}
              catalog={catalog}
              onRequestTransition={onRequestTransition}
            />
          )}
          {area === "data" && section === "activity" && (
            <section
              className="panel capability-activity"
              aria-labelledby="data-activity-heading"
            >
              <div className="section-heading-row">
                <div>
                  <small>AUTHORITATIVE TASK HISTORY</small>
                  <h2 id="data-activity-heading">
                    Recent governed data activity
                  </h2>
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
                        <span className="task-state neutral">
                          {task.status}
                        </span>
                        <small>
                          {activityInitiator(task)} ·{" "}
                          {activityTime(task.updatedAt)}
                        </small>
                      </div>
                    </article>
                  ))}
                </div>
              )}
              <p className="authority-note">
                Open Monitor to inspect a task's progress and result.
              </p>
            </section>
          )}
        </>
      )}
    </div>
  );
}
