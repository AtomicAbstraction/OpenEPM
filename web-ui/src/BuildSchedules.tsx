import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  readProgram,
  request,
  prepareAdmittedProgramEffect,
  replayAdmittedEffect,
  type AdmittedEffectPacket,
} from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import { usePreservedDraft, type DraftRecoveryLease } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { authoringContextKey } from "./python-authoring";
import { referenceHandoffHash } from "./reference-handoff";
import { outcomeAuthorityKey, ReceiptInspector } from "./ReceiptInspector";
import {
  ParameterFields,
  definitionParameterSchema,
  parameterInputError,
  parameterObject,
} from "./ParameterFields";
import { ExactScopeSelector } from "./ExactScopeSelector";
import "./rule-workspaces.css";

type ScheduleSummary = {
  scheduleId: string;
  stateToken: string;
  definition: Record<string, unknown>;
  definitionDigest: string;
  status: "Saved" | "Active";
  targetStatus: "Current" | "Stale";
  effectiveStatus: "Saved" | "Active" | "Blocked";
  reasonCode: null | "APPLICATION_SCHEDULE_TARGET_STALE";
  updatedAt: string;
};
type ScheduleTarget = {
  scheduleId: string;
  stateToken: string;
  digest: string;
};
type RuleParameterDefinition = {
  name: string;
  type: string;
  required?: boolean;
  dimensionId?: string;
};
type ScheduleOccurrence = {
  occurrenceId: string;
  taskId: string;
  sequence: number;
  dueAt: string;
  nativeStatus: string;
  status: string;
  scheduleStateToken: string;
  currentPin: boolean;
  workflowId: string | null;
};
type ScheduleOccurrencePage = {
  scheduleStateToken: string;
  items: ScheduleOccurrence[];
  nextAfterSequence: number | null;
  hasMore: boolean;
};
type ScheduleAttempt = {
  identity: string;
  action: "save" | "activate" | "deactivate";
  scheduleId: string;
  packet: AdmittedEffectPacket;
};
const SCHEDULE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const DIGEST = /^[0-9a-f]{64}$/;

type ExecutionAuthority = {
  delegation_id: string;
  state_token: string;
  status: "Active" | "Revoked";
  issuer: string;
  subject_id: string;
  operation_scope: string[];
  valid_from: string;
  valid_until: string;
  schedule_id: string | null;
};

export function exactScheduleAuthority(
  value: unknown,
  delegationId: string,
): ExecutionAuthority {
  const envelope = parameterObject(value);
  const current = parameterObject(envelope?.delegation);
  if (
    envelope?.defined !== true ||
    !current ||
    current.delegation_id !== delegationId ||
    typeof current.state_token !== "string" ||
    !DIGEST.test(current.state_token) ||
    !["Active", "Revoked"].includes(String(current.status)) ||
    typeof current.issuer !== "string" ||
    !current.issuer ||
    typeof current.subject_id !== "string" ||
    !current.subject_id ||
    !Array.isArray(current.operation_scope) ||
    !current.operation_scope.every((entry) => typeof entry === "string") ||
    typeof current.valid_from !== "string" ||
    !Number.isFinite(Date.parse(current.valid_from)) ||
    typeof current.valid_until !== "string" ||
    !Number.isFinite(Date.parse(current.valid_until)) ||
    Date.parse(current.valid_until) <= Date.parse(current.valid_from) ||
    (current.schedule_id !== null && typeof current.schedule_id !== "string")
  )
    throw new Error("The execution authority could not be verified.");
  return current as ExecutionAuthority;
}

export function scheduleAuthorityStatus(
  current: ExecutionAuthority,
  scheduleId: string,
  stateToken: string,
  now = Date.now(),
) {
  if (current.status === "Revoked") return "Revoked";
  if (Date.parse(current.valid_until) <= now) return "Expired";
  if (Date.parse(current.valid_from) > now) return "Not yet valid";
  if (current.schedule_id !== null && current.schedule_id !== scheduleId)
    return "Bound to another schedule";
  if (!current.operation_scope.includes("application.rule.run"))
    return "Rule execution is not permitted";
  if (current.state_token !== stateToken) return "Bound authority changed";
  return "Bound version matches the inspected active authority";
}

export function exactScheduleOccurrences(
  value: unknown,
  stateToken: string,
  previous: ScheduleOccurrence[] = [],
  afterSequence?: number,
): ScheduleOccurrencePage {
  const page = parameterObject(value);
  if (
    !page ||
    page.scheduleStateToken !== stateToken ||
    !Array.isArray(page.items) ||
    page.items.length > 100 ||
    typeof page.hasMore !== "boolean"
  )
    throw new Error(
      "The occurrence page does not match this schedule version. Reopen the current schedule.",
    );
  const ids = new Set(previous.map((item) => item.occurrenceId));
  const taskIds = new Set(previous.map((item) => item.taskId));
  let sequence = afterSequence ?? Number.POSITIVE_INFINITY;
  for (const value of page.items) {
    const item = parameterObject(value);
    if (
      !item ||
      typeof item.occurrenceId !== "string" ||
      !item.occurrenceId ||
      ids.has(item.occurrenceId) ||
      typeof item.taskId !== "string" ||
      !item.taskId ||
      taskIds.has(item.taskId) ||
      !Number.isSafeInteger(item.sequence) ||
      Number(item.sequence) <= 0 ||
      Number(item.sequence) >= sequence ||
      typeof item.dueAt !== "string" ||
      !Number.isFinite(Date.parse(item.dueAt)) ||
      typeof item.status !== "string" ||
      !item.status ||
      typeof item.nativeStatus !== "string" ||
      !item.nativeStatus ||
      typeof item.scheduleStateToken !== "string" ||
      !DIGEST.test(item.scheduleStateToken) ||
      typeof item.currentPin !== "boolean" ||
      item.currentPin !== (item.scheduleStateToken === stateToken) ||
      (item.workflowId !== null &&
        (typeof item.workflowId !== "string" || !item.workflowId))
    )
      throw new Error(
        "The occurrence page contains an invalid or repeated native reference.",
      );
    sequence = Number(item.sequence);
    ids.add(item.occurrenceId);
    taskIds.add(item.taskId);
  }
  if (
    page.hasMore
      ? page.items.length === 0 ||
        page.nextAfterSequence !== sequence ||
        sequence >= (afterSequence ?? Number.POSITIVE_INFINITY)
      : page.nextAfterSequence !== null
  )
    throw new Error("The occurrence continuation did not advance safely.");
  return {
    ...(page as ScheduleOccurrencePage),
    items: [...previous, ...(page.items as ScheduleOccurrence[])],
  };
}

export function exactApplicationSchedule(
  value: unknown,
  target: ScheduleTarget,
  requirePublished = true,
): ScheduleSummary {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("INVALID_APPLICATION_SCHEDULE_RESPONSE");
  const envelope = value as Record<string, unknown>;
  const schedule = envelope.schedule as Record<string, unknown> | null;
  const definition = schedule?.definition as
    | Record<string, unknown>
    | undefined;
  if (
    envelope.defined !== true ||
    !schedule ||
    schedule.scheduleId !== target.scheduleId ||
    schedule.stateToken !== target.stateToken ||
    schedule.definitionDigest !== target.digest ||
    !["Current", "Stale"].includes(String(schedule.targetStatus)) ||
    !["Saved", "Active", "Blocked"].includes(
      String(schedule.effectiveStatus),
    ) ||
    (schedule.targetStatus === "Current"
      ? schedule.reasonCode !== null ||
        schedule.effectiveStatus !== schedule.status
      : schedule.reasonCode !== "APPLICATION_SCHEDULE_TARGET_STALE" ||
        schedule.effectiveStatus !== "Blocked") ||
    (requirePublished
      ? schedule.status !== "Active" || schedule.effectiveStatus !== "Active"
      : !["Saved", "Active"].includes(String(schedule.status))) ||
    !SCHEDULE_ID.test(target.scheduleId) ||
    !DIGEST.test(target.digest) ||
    !definition ||
    definition.format !== "openepm-application-schedule-v1" ||
    definition.scheduleId !== target.scheduleId ||
    !DIGEST.test(String(schedule.stateToken)) ||
    typeof schedule.updatedAt !== "string" ||
    !Number.isFinite(Date.parse(schedule.updatedAt))
  )
    throw new Error("INVALID_APPLICATION_SCHEDULE_RESPONSE");
  return schedule as ScheduleSummary;
}

export const scheduleReadBody = (scope: Scope, scheduleId: string) => ({
  ...scope,
  program: {
    languageVersion: 2,
    function: "schedule.read",
    arguments: { scheduleId },
  },
});

export const scheduleListBody = (scope: Scope, afterScheduleId?: string) => ({
  ...scope,
  program: {
    languageVersion: 2,
    function: "schedule.list",
    arguments: { limit: 100, ...(afterScheduleId ? { afterScheduleId } : {}) },
  },
});

export const scheduleMutationBody = (
  app: ApplicationSummary,
  catalog: ApplicationCatalog,
  functionName: "schedule.save" | "schedule.activate" | "schedule.deactivate",
  argumentsValue: Record<string, unknown>,
  idempotencyKey: string,
) => ({
  workspaceId: app.workspaceId,
  applicationId: app.applicationId,
  confirmed: true,
  idempotencyKey,
  program: {
    languageVersion: 2,
    function: functionName,
    arguments: {
      ...argumentsValue,
      expectedMetadataRevision: catalog.revisions.metadata,
      expectedPolicyRevision: catalog.revisions.policy,
      expectedSchemaEpoch: catalog.revisions.schemaEpoch,
    },
  },
});

function parseDefinition(value: string) {
  const parsed: unknown = JSON.parse(value);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new Error("Schedule definition must be one JSON object.");
  return parsed as Record<string, unknown>;
}

function newScheduleDefinition(): Record<string, unknown> {
  return {
    format: "openepm-application-schedule-v1",
    scheduleId: "",
    target: {
      kind: "ApplicationRule",
      ruleId: "",
      stateToken: "",
      programDigest: "",
    },
    bindings: {},
    pov: [],
    recurrence: {
      kind: "FixedInterval",
      intervalSeconds: 86400,
      firstDueAt: "",
      catchUpPolicy: "latest",
      maxCatchUp: 1,
    },
    retryPolicy: {
      maxAttempts: 3,
      backoffSeconds: 60,
      needsInspectionAfter: true,
    },
    cancellationPolicy: "PreserveCommittedStopFuture",
    delegation: { delegationId: "", stateToken: "" },
  };
}

function scheduleDefinitionError(value: Record<string, unknown> | null) {
  if (!value) return "The schedule fields are incomplete.";
  const target = parameterObject(value.target);
  const recurrence = parameterObject(value.recurrence);
  const retry = parameterObject(value.retryPolicy);
  const delegation = parameterObject(value.delegation);
  if (
    value.format !== "openepm-application-schedule-v1" ||
    typeof value.scheduleId !== "string" ||
    !SCHEDULE_ID.test(value.scheduleId)
  )
    return "Enter a valid schedule name.";
  if (
    target?.kind !== "ApplicationRule" ||
    typeof target.ruleId !== "string" ||
    !SCHEDULE_ID.test(target.ruleId) ||
    typeof target.stateToken !== "string" ||
    !DIGEST.test(target.stateToken) ||
    typeof target.programDigest !== "string" ||
    !DIGEST.test(target.programDigest)
  )
    return "Choose a current published rule.";
  const bindings = parameterObject(value.bindings);
  if (!bindings) return "Rule parameters are invalid.";
  if (!Array.isArray(value.pov)) return "The point of view is invalid.";
  const povDimensions = new Set<string>();
  const povParameters = new Set<string>();
  for (const entry of value.pov) {
    const row = parameterObject(entry);
    if (
      !row ||
      typeof row.dimensionId !== "string" ||
      !SCHEDULE_ID.test(row.dimensionId) ||
      typeof row.parameter !== "string" ||
      !SCHEDULE_ID.test(row.parameter) ||
      typeof row.memberId !== "string" ||
      !SCHEDULE_ID.test(row.memberId) ||
      povDimensions.has(row.dimensionId) ||
      povParameters.has(row.parameter) ||
      Object.hasOwn(bindings, row.parameter)
    )
      return "Complete each point-of-view row with a unique dimension and rule parameter.";
    povDimensions.add(row.dimensionId);
    povParameters.add(row.parameter);
  }
  if (
    recurrence?.kind !== "FixedInterval" ||
    typeof recurrence.intervalSeconds !== "number" ||
    !Number.isInteger(recurrence.intervalSeconds) ||
    recurrence.intervalSeconds < 60 ||
    recurrence.intervalSeconds > 2678400 ||
    typeof recurrence.firstDueAt !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00Z$/.test(recurrence.firstDueAt) ||
    !["skip", "latest", "all"].includes(String(recurrence.catchUpPolicy)) ||
    typeof recurrence.maxCatchUp !== "number" ||
    !Number.isInteger(recurrence.maxCatchUp) ||
    recurrence.maxCatchUp < 1 ||
    recurrence.maxCatchUp > 36
  )
    return "Enter a valid UTC start time and recurrence.";
  if (
    typeof retry?.maxAttempts !== "number" ||
    !Number.isInteger(retry.maxAttempts) ||
    retry.maxAttempts < 1 ||
    retry.maxAttempts > 10 ||
    typeof retry.backoffSeconds !== "number" ||
    !Number.isInteger(retry.backoffSeconds) ||
    retry.backoffSeconds < 0 ||
    retry.backoffSeconds > 86400 ||
    retry.needsInspectionAfter !== true
  )
    return "Enter a valid retry policy.";
  if (
    typeof delegation?.delegationId !== "string" ||
    !SCHEDULE_ID.test(delegation.delegationId) ||
    typeof delegation.stateToken !== "string" ||
    !DIGEST.test(delegation.stateToken)
  )
    return "Choose a current execution authority.";
  if (value.cancellationPolicy !== "PreserveCommittedStopFuture")
    return "The schedule cancellation policy is invalid.";
  return null;
}

function scheduleRuleName(definition: Record<string, unknown>) {
  const target = definition.target;
  return target &&
    typeof target === "object" &&
    !Array.isArray(target) &&
    typeof (target as Record<string, unknown>).ruleId === "string"
    ? String((target as Record<string, unknown>).ruleId)
    : "Unavailable";
}

function scheduleFrequency(definition: Record<string, unknown>) {
  const recurrence = definition.recurrence;
  if (
    !recurrence ||
    typeof recurrence !== "object" ||
    Array.isArray(recurrence)
  )
    return "Unavailable";
  const seconds = (recurrence as Record<string, unknown>).intervalSeconds;
  if (typeof seconds !== "number" || !Number.isInteger(seconds) || seconds < 60)
    return "Unavailable";
  if (seconds % 86400 === 0)
    return `Every ${seconds / 86400} ${seconds === 86400 ? "day" : "days"}`;
  if (seconds % 3600 === 0)
    return `Every ${seconds / 3600} ${seconds === 3600 ? "hour" : "hours"}`;
  return `Every ${seconds / 60} minutes`;
}

export function BuildSchedules({
  app,
  catalog,
  target,
  onRequestTransition = (action) => action(),
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  target?: ScheduleTarget;
  onRequestTransition?: (action: () => void) => void;
}) {
  const activeRead = useRef<AbortController | null>(null);
  useEffect(
    () => () => activeRead.current?.abort(),
    [app?.workspaceId, app?.applicationId],
  );
  function beginRead() {
    activeRead.current?.abort();
    const controller = new AbortController();
    activeRead.current = controller;
    return controller;
  }
  const mutationIntentKey = useStableMutationIntentKey("schedule-ui");
  const functions = catalog?.functions || {};
  const available = Boolean(
    functions["schedule.list"] && functions["schedule.read"],
  );
  const canRead = Boolean(functions["schedule.read"]);
  const canSave = Boolean(functions["schedule.save"]);
  const canActivate = Boolean(functions["schedule.activate"]);
  const canDeactivate = Boolean(functions["schedule.deactivate"]);
  const canInspectAuthority = Boolean(functions["execution.delegation.read"]);
  const [schedules, setSchedules] = useState<ScheduleSummary[]>([]);
  const [catalogueRead, setCatalogueRead] = useState(false);
  const [listReadError, setListReadError] = useState(false);
  const [editorOpen, setEditorOpen] = useState(false);
  const editorHeading = useRef<HTMLHeadingElement>(null);
  const editorTrigger = useRef<HTMLElement | null>(null);
  const [storedSelected, setSelected] = useState<ScheduleSummary | null>(null);
  const [after, setAfter] = useState<string | null>(null);
  const [storedDefinition, setDefinition] = useState("{}");
  const [definitionTouched, setDefinitionTouched] = useState(false);
  const [parameterSchema, setParameterSchema] = useState<
    Record<string, unknown> | undefined
  >();
  const [ruleParameters, setRuleParameters] = useState<
    RuleParameterDefinition[]
  >([]);
  const [working, setWorking] = useState(false);
  const [settling, setSettling] = useState(false);
  const settlementRequest = useRef<AbortController | null>(null);
  const busy = working || settling;
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const [authorityInspection, setAuthorityInspection] = useState<{
    context: string;
    value: ExecutionAuthority;
  } | null>(null);
  const authorityRead = useRef<AbortController | null>(null);
  const [occurrencePage, setOccurrencePage] = useState<{
    context: string;
    page: ScheduleOccurrencePage;
  } | null>(null);
  const [occurrenceError, setOccurrenceError] = useState("");
  const [attempt, setAttempt] = useState<ScheduleAttempt | null>(null);
  const [inspectReceipt, setInspectReceipt] = useState(false);
  const scope = app
    ? { workspaceId: app.workspaceId, applicationId: app.applicationId }
    : null;
  const authorityKey =
    app && catalog
      ? JSON.stringify([
          authoringContextKey(app, catalog),
          outcomeAuthorityKey(app, catalog),
          canRead,
          canSave,
          canActivate,
          canDeactivate,
        ])
      : "unavailable";
  const identityKey =
    app && catalog
      ? JSON.stringify([
          app.workspaceId,
          app.applicationId,
          catalog.applicationAccess.issuer,
          catalog.applicationAccess.subjectId,
        ])
      : null;
  const currentIdentity = useRef(identityKey);
  currentIdentity.current = identityKey;
  const currentAttempt = attempt?.identity === identityKey ? attempt : null;
  const draftIdentity = useRef(identityKey);
  const ownDraft =
    identityKey !== null && draftIdentity.current === identityKey;
  const definition = ownDraft ? storedDefinition : "{}";
  const selected = ownDraft ? storedSelected : null;
  useEffect(() => {
    if (identityKey === null || draftIdentity.current === identityKey) return;
    draftIdentity.current = identityKey;
    setAttempt(null);
    setInspectReceipt(false);
    setDefinition("{}");
    setSelected(null);
    setDefinitionTouched(false);
  }, [identityKey]);
  useEffect(() => {
    if (editorOpen) editorHeading.current?.focus();
  }, [editorOpen, selected?.scheduleId, selected?.stateToken]);

  const proposalLocked = busy || Boolean(currentAttempt);
  const canReconcile = Boolean(
    canRead && currentAttempt && functions[`schedule.${currentAttempt.action}`],
  );
  const editorContext = JSON.stringify([
    authorityKey,
    editorOpen,
    selected?.scheduleId,
    selected?.stateToken,
    definition,
  ]);
  const currentEditorContext = useRef(editorContext);
  currentEditorContext.current = editorContext;
  const requestGeneration = useRef(0);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      requestGeneration.current += 1;
    };
  }, []);
  const beginEditorRequest = () => {
    const generation = ++requestGeneration.current;
    const context = editorContext;
    return () =>
      mounted.current &&
      requestGeneration.current === generation &&
      currentEditorContext.current === context;
  };
  const parsed = useMemo(() => {
    try {
      return parseDefinition(definition);
    } catch {
      return null;
    }
  }, [definition]);
  const exactSelected = Boolean(
    selected &&
      parsed?.scheduleId === selected.scheduleId &&
      JSON.stringify(parsed) === JSON.stringify(selected.definition),
  );
  const definitionError = scheduleDefinitionError(parsed);
  const targetDefinition = parameterObject(parsed?.target) ?? {};
  const recurrenceDefinition = parameterObject(parsed?.recurrence) ?? {};
  const retryDefinition = parameterObject(parsed?.retryPolicy) ?? {};
  const delegationDefinition = parameterObject(parsed?.delegation) ?? {};
  const authorityInspectionContext = JSON.stringify([
    authorityKey,
    parsed?.scheduleId,
    delegationDefinition.delegationId,
    delegationDefinition.stateToken,
  ]);
  const inspectedAuthority =
    canInspectAuthority &&
    authorityInspection?.context === authorityInspectionContext
      ? authorityInspection.value
      : null;
  useLayoutEffect(() => {
    if (!canInspectAuthority) setAuthorityInspection(null);
    return () => authorityRead.current?.abort();
  }, [canInspectAuthority, authorityInspectionContext]);
  const occurrenceContext = JSON.stringify([
    authorityKey,
    selected?.scheduleId,
    selected?.stateToken,
    exactSelected,
  ]);
  const currentOccurrences =
    occurrencePage?.context === occurrenceContext ? occurrencePage.page : null;
  const bindingDefinition = parameterObject(parsed?.bindings) ?? {};
  const povDefinition = Array.isArray(parsed?.pov) ? parsed.pov : [];
  const povScope = Object.fromEntries(
    povDefinition.flatMap((entry) => {
      const row = parameterObject(entry);
      return typeof row?.dimensionId === "string" &&
        typeof row.memberId === "string"
        ? [[row.dimensionId, row.memberId]]
        : [];
    }),
  );
  const memberParameters = ruleParameters.filter(
    (parameter) => parameter.type === "Member",
  );
  const memberParameterNames = new Set(
    memberParameters.map((parameter) => parameter.name),
  );
  const bindingParameterSchema = parameterSchema
    ? {
        ...parameterSchema,
        properties: Object.fromEntries(
          Object.entries(
            parameterObject(parameterSchema.properties) ?? {},
          ).filter(([name]) => !memberParameterNames.has(name)),
        ),
        required: Array.isArray(parameterSchema.required)
          ? parameterSchema.required.filter(
              (name) =>
                typeof name === "string" && !memberParameterNames.has(name),
            )
          : [],
      }
    : undefined;
  const parameterError = bindingParameterSchema
    ? parameterInputError(
        JSON.stringify(bindingDefinition),
        bindingParameterSchema,
      )
    : null;
  const povParameterError = parameterSchema
    ? memberParameters.some(
        (parameter) =>
          parameter.required !== false &&
          !povDefinition.some(
            (entry) => parameterObject(entry)?.parameter === parameter.name,
          ),
      )
      ? "Choose a point-of-view member for every required member parameter."
      : null
    : null;
  // Restore a scoped packet only once the catalogue identifies its owner.
  // Loading the catalogue must not consume an earlier mount's saved packet.
  const recoveryScope = identityKey === null ? null : scope;
  const recovery = usePreservedDraft(
    recoveryScope?.workspaceId || "",
    recoveryScope?.applicationId || "",
    "build-schedule",
    currentAttempt
      ? "Schedule action with an unconfirmed outcome"
      : "Unsaved schedule definition",
    ownDraft && (definitionTouched || Boolean(currentAttempt)),
    { identity: identityKey, definition, selected, attempt: currentAttempt },
    (saved) => {
      if (saved.identity !== identityKey) return;
      draftIdentity.current = identityKey;
      setDefinition(saved.definition);
      setSelected(saved.selected);
      setAttempt(saved.attempt);
      setDefinitionTouched(true);
      setEditorOpen(true);
    },
  );

  useLayoutEffect(() => {
    setSettling(false);
    return () => {
      // Cancel the browser wait. The admitted packet stays available for
      // reconciliation under current authority.
      settlementRequest.current?.abort();
      settlementRequest.current = null;
    };
  }, [authorityKey]);

  useEffect(() => {
    activeRead.current?.abort();
    requestGeneration.current += 1;
    setWorking(false);
    setSchedules([]);
    setCatalogueRead(false);
    setListReadError(false);
    setAfter(null);
    if (identityKey !== null && !currentAttempt) {
      setEditorOpen(false);
      setSelected(null);
      setDefinition("{}");
      setDefinitionTouched(false);
      setParameterSchema(undefined);
      setRuleParameters([]);
    }
    setError("");
    setResult("");
    setAuthorityInspection(null);
    setOccurrencePage(null);
    setOccurrenceError("");
  }, [authorityKey]);

  function changeContext(action: () => void) {
    if (proposalLocked) return;
    const trigger = document.activeElement;
    if (
      trigger instanceof HTMLElement &&
      !trigger.closest(".rule-editor-frame")
    )
      editorTrigger.current = trigger;
    const change = () => {
      setSelected(null);
      setDefinition("{}");
      setDefinitionTouched(false);
      setParameterSchema(undefined);
      setRuleParameters([]);
      setEditorOpen(false);
      setResult("");
      setError("");
      setOccurrenceError("");
      setOccurrencePage(null);
      action();
    };
    if (definitionTouched) onRequestTransition(change);
    else change();
  }

  function reviseDefinition(
    revision: (draft: Record<string, unknown>) => void,
  ) {
    const draft = JSON.parse(
      JSON.stringify(parsed ?? newScheduleDefinition()),
    ) as Record<string, unknown>;
    revision(draft);
    setDefinition(JSON.stringify(draft));
    setDefinitionTouched(true);
    setError("");
    setResult("");
  }

  async function loadCurrentRule() {
    if (!app || !parsed) return;
    const target = parameterObject(parsed.target);
    const ruleId = typeof target?.ruleId === "string" ? target.ruleId : "";
    if (!SCHEDULE_ID.test(ruleId)) {
      setError("Enter a rule name first.");
      return;
    }
    setWorking(true);
    setError("");
    const relevant = beginEditorRequest();
    try {
      const rule = await readProgram<{
        defined: boolean;
        ruleId: string;
        stateToken: string;
        programDigest: string;
        status: string;
        program?: { arguments?: Record<string, unknown> };
      }>(app, "application.rule.read", { ruleId });
      if (!relevant()) return;
      if (
        !rule.defined ||
        rule.ruleId !== ruleId ||
        rule.status !== "Active" ||
        !DIGEST.test(rule.stateToken) ||
        !DIGEST.test(rule.programDigest)
      )
        throw new Error("The current published rule is unavailable.");
      const declarations = rule.program?.arguments?.parameters;
      const schema = definitionParameterSchema(declarations);
      if (!schema || !Array.isArray(declarations))
        throw new Error(
          "The current rule does not expose valid named parameters.",
        );
      const parameters = declarations.map((declaration) => {
        const item = parameterObject(declaration)!;
        return {
          name: String(item.name),
          type: String(item.type),
          ...(typeof item.required === "boolean"
            ? { required: item.required }
            : {}),
          ...(typeof item.dimensionId === "string"
            ? { dimensionId: item.dimensionId }
            : {}),
        };
      });
      reviseDefinition((draft) => {
        draft.target = {
          kind: "ApplicationRule",
          ruleId,
          stateToken: rule.stateToken,
          programDigest: rule.programDigest,
        };
        const nextBindings = parameterObject(draft.bindings) ?? {};
        draft.bindings = Object.fromEntries(
          Object.entries(nextBindings).filter(
            ([name]) =>
              !parameters.some(
                (parameter) =>
                  parameter.type === "Member" && parameter.name === name,
              ),
          ),
        );
      });
      setParameterSchema(schema);
      setRuleParameters(parameters);
    } catch (reason) {
      if (!relevant()) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to load rule",
      );
    } finally {
      if (relevant()) setWorking(false);
    }
  }

  async function loadCurrentAuthority(rebind = true) {
    if (!app || !parsed || !canInspectAuthority) return;
    const authority = parameterObject(parsed.delegation);
    const delegationId =
      typeof authority?.delegationId === "string" ? authority.delegationId : "";
    if (!SCHEDULE_ID.test(delegationId)) {
      setError("Enter an execution authority name first.");
      return;
    }
    setWorking(true);
    setError("");
    setAuthorityInspection(null);
    authorityRead.current?.abort();
    const controller = new AbortController();
    authorityRead.current = controller;
    const relevant = beginEditorRequest();
    try {
      const response = await request<{
        result: unknown;
      }>(
        "/api/execution-delegation",
        {
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          program: {
            languageVersion: 2,
            function: "execution.delegation.read",
            arguments: { delegationId },
          },
        },
        controller.signal,
      );
      if (controller.signal.aborted || !relevant()) return;
      const current = exactScheduleAuthority(response.result, delegationId);
      const scheduleId = String(parsed.scheduleId ?? "");
      setAuthorityInspection({
        context: authorityInspectionContext,
        value: current,
      });
      if (rebind) {
        const status = scheduleAuthorityStatus(
          current,
          scheduleId,
          current.state_token,
        );
        if (status !== "Bound version matches the inspected active authority")
          throw new Error(
            `The current execution authority is unavailable: ${status}.`,
          );
        reviseDefinition((draft) => {
          draft.delegation = { delegationId, stateToken: current.state_token };
        });
        setAuthorityInspection({
          context: JSON.stringify([
            authorityKey,
            parsed.scheduleId,
            delegationId,
            current.state_token,
          ]),
          value: current,
        });
      }
    } catch (reason) {
      if (controller.signal.aborted || !relevant()) return;
      setError(
        reason instanceof ApiError && reason.kind === "authorization"
          ? "The execution authority could not be verified."
          : reason instanceof Error
            ? reason.message
            : "Unable to load authority",
      );
    } finally {
      if (authorityRead.current === controller) authorityRead.current = null;
      if (relevant()) setWorking(false);
    }
  }

  async function inspectOccurrences(append = false) {
    if (!scope || !selected || !exactSelected || !canRead) return;
    const relevant = beginEditorRequest();
    const afterSequence = append
      ? (currentOccurrences?.nextAfterSequence ?? undefined)
      : undefined;
    if (append && afterSequence === undefined) return;
    setWorking(true);
    setOccurrenceError("");
    if (!append) setOccurrencePage(null);
    try {
      const response = await request<{
        result: {
          defined: boolean;
          schedule: ScheduleSummary | null;
          occurrences?: unknown;
        };
      }>("/api/application-schedule", {
        ...scheduleReadBody(scope, selected.scheduleId),
        program: {
          languageVersion: 2,
          function: "schedule.read",
          arguments: {
            scheduleId: selected.scheduleId,
            occurrences: {
              expectedStateToken: selected.stateToken,
              limit: 25,
              ...(afterSequence === undefined ? {} : { afterSequence }),
            },
          },
        },
      });
      if (!relevant()) return;
      exactApplicationSchedule(
        response.result,
        {
          scheduleId: selected.scheduleId,
          stateToken: selected.stateToken,
          digest: selected.definitionDigest,
        },
        false,
      );
      const page = exactScheduleOccurrences(
        response.result.occurrences,
        selected.stateToken,
        append ? currentOccurrences?.items : [],
        afterSequence,
      );
      setOccurrencePage({ context: occurrenceContext, page });
    } catch (reason) {
      if (!relevant()) return;
      setOccurrenceError(
        reason instanceof Error
          ? reason.message
          : "Unable to inspect schedule occurrences.",
      );
    } finally {
      if (relevant()) setWorking(false);
    }
  }

  async function load(append = false) {
    if (!scope || !available) return;
    const controller = beginRead();
    setWorking(true);
    setError("");
    setListReadError(false);
    if (!append) setCatalogueRead(false);
    try {
      const response = await request<{
        result: {
          schedules: ScheduleSummary[];
          nextAfterScheduleId: string | null;
        };
      }>(
        "/api/application-schedule",
        scheduleListBody(scope, append ? after || undefined : undefined),
        controller.signal,
      );
      if (controller.signal.aborted) return;
      setSchedules((current) =>
        append
          ? [...current, ...response.result.schedules]
          : response.result.schedules,
      );
      setAfter(response.result.nextAfterScheduleId);
      setCatalogueRead(true);
    } catch (reason) {
      if (controller.signal.aborted) return;
      setListReadError(true);
      setError(
        reason instanceof Error ? reason.message : "Unable to read schedules",
      );
    } finally {
      if (!controller.signal.aborted) setWorking(false);
    }
  }

  useEffect(() => {
    if (scope && available) void load(false);
  }, [authorityKey, available]);

  async function open(
    row: Pick<
      ScheduleSummary,
      "scheduleId" | "stateToken" | "definitionDigest"
    >,
    requirePublished = false,
  ) {
    if (!scope || !canRead || currentAttempt) return;
    const controller = beginRead();
    setWorking(true);
    setError("");
    try {
      const response = await request<{
        result: { defined: boolean; schedule: ScheduleSummary | null };
      }>(
        "/api/application-schedule",
        scheduleReadBody(scope, row.scheduleId),
        controller.signal,
      );
      if (controller.signal.aborted) return;
      const exact = exactApplicationSchedule(
        response.result,
        {
          scheduleId: row.scheduleId,
          stateToken: row.stateToken,
          digest: row.definitionDigest,
        },
        requirePublished,
      );
      setEditorOpen(true);
      setSelected(exact);
      setDefinition(JSON.stringify(exact.definition, null, 2));
      setDefinitionTouched(false);
      setParameterSchema(undefined);
      setRuleParameters([]);
      setResult("");
    } catch (reason) {
      if (controller.signal.aborted) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to read schedule",
      );
    } finally {
      if (!controller.signal.aborted) setWorking(false);
    }
  }

  useEffect(() => {
    if (target)
      void open(
        {
          scheduleId: target.scheduleId,
          stateToken: target.stateToken,
          definitionDigest: target.digest,
        },
        true,
      );
  }, [
    app?.workspaceId,
    app?.applicationId,
    target?.scheduleId,
    target?.stateToken,
    target?.digest,
    canRead,
    authorityKey,
  ]);

  async function mutate(action: "save" | "activate" | "deactivate") {
    if (
      !app ||
      !catalog ||
      identityKey === null ||
      !functions[`schedule.${action}`] ||
      catalog.revisions.schemaEpoch === undefined ||
      proposalLocked
    )
      return;
    let body;
    try {
      if (action === "save") {
        if (!parsed || definitionError)
          throw new Error(definitionError || "Complete the schedule fields.");
        const bindings = parameterObject(parsed.bindings) ?? {};
        const parameterError = bindingParameterSchema
          ? parameterInputError(
              JSON.stringify(bindings),
              bindingParameterSchema,
            )
          : null;
        if (parameterError) throw new Error(parameterError);
        if (povParameterError) throw new Error(povParameterError);
        body = scheduleMutationBody(
          app,
          catalog,
          "schedule.save",
          {
            definition: parsed,
            ...(selected ? { expectedStateToken: selected.stateToken } : {}),
          },
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            action,
            definition: parsed,
            expectedStateToken: selected?.stateToken,
          }),
        );
      } else {
        if (!selected || !exactSelected)
          throw new Error("Open the exact current schedule first.");
        body = scheduleMutationBody(
          app,
          catalog,
          `schedule.${action}`,
          {
            scheduleId: selected.scheduleId,
            expectedStateToken: selected.stateToken,
          },
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            action,
            scheduleId: selected.scheduleId,
            stateToken: selected.stateToken,
          }),
        );
      }
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Invalid schedule intent",
      );
      return;
    }
    setWorking(true);
    setError("");
    const relevant = beginEditorRequest();
    try {
      const packet = await prepareAdmittedProgramEffect(
        "/api/application-schedule",
        body,
        body.idempotencyKey,
      );
      if (!relevant()) return;
      const captured = {
        identity: identityKey,
        action,
        scheduleId: String(parsed?.scheduleId),
        packet,
      };
      const lease = recovery.retain({
        identity: identityKey,
        definition,
        selected,
        attempt: captured,
      });
      setAttempt(captured);
      await sendOriginalAttempt(captured, lease, false);
    } catch (reason) {
      if (!relevant()) return;
      setError(
        reason instanceof Error
          ? reason.message
          : `Unable to ${action} schedule`,
      );
    } finally {
      if (relevant()) setWorking(false);
    }
  }

  async function sendOriginalAttempt(
    captured: ScheduleAttempt,
    lease: DraftRecoveryLease | null,
    wasUncertain = true,
  ) {
    if (
      captured.identity !== identityKey ||
      !mounted.current ||
      !canRead ||
      !functions[`schedule.${captured.action}`] ||
      settlementRequest.current
    )
      return;
    const controller = new AbortController();
    settlementRequest.current = controller;
    const settlementIsCurrent = () =>
      !controller.signal.aborted &&
      mounted.current &&
      currentIdentity.current === captured.identity;
    setSettling(true);
    setError("");
    try {
      if (!lease)
        throw new Error(
          "The original schedule recovery record is unavailable. No new request was sent.",
        );
      lease = recovery.retain(
        { identity: identityKey, definition, selected, attempt: captured },
        lease,
      );
      const response = await replayAdmittedEffect<{
        result: { status: string; operationId: string; scheduleId: string };
      }>(captured.packet, controller.signal);
      if (!settlementIsCurrent()) return;
      if (
        !response.result ||
        response.result.operationId !== captured.packet.body.idempotencyKey ||
        response.result.scheduleId !== captured.scheduleId ||
        response.result.status !==
          (captured.action === "activate" ? "Active" : "Saved")
      )
        throw new Error(
          "The schedule response did not confirm the original action. Its outcome remains unknown.",
        );
      recovery.release(lease, {
        identity: identityKey,
        definition,
        selected: null,
        attempt: null,
      });
      setAttempt(null);
      setInspectReceipt(false);
      setResult(`Schedule ${response.result.status} recorded.`);
      setDefinitionTouched(false);
      setSelected(null);
      await load(false);
    } catch (reason) {
      if (!settlementIsCurrent()) return;
      if (
        !wasUncertain &&
        reason instanceof ApiError &&
        [400, 401, 403, 409, 412, 422].includes(reason.status)
      ) {
        try {
          if (lease)
            recovery.release(
              lease,
              { identity: identityKey, definition, selected, attempt: null },
              definitionTouched,
            );
          setAttempt(null);
        } catch (changed) {
          setError(
            changed instanceof Error ? changed.message : String(changed),
          );
          return; // A newer recovery record retains its own outcome and intent.
        }
      }
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      if (settlementRequest.current === controller) {
        settlementRequest.current = null;
        setSettling(false);
      }
    }
  }

  if (!canRead)
    return target ? (
      <p role="alert">
        Schedule inspection is unavailable in the current application context.
      </p>
    ) : null;
  return (
    <section
      className="panel capability-activity"
      aria-labelledby="generic-schedule-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>GENERIC AUTOMATION</small>
          <h2 id="generic-schedule-heading" tabIndex={-1}>
            Rule schedules
          </h2>
          <p>
            Schedule a published rule with a defined recurrence and retry
            policy. Save validates the current definition before activation.
          </p>
        </div>
        <div className="rule-workspace-actions">
          <button
            disabled={proposalLocked || !available}
            onClick={() => changeContext(() => void load(false))}
          >
            {busy ? "Working…" : "Refresh schedules"}
          </button>
          {canSave && (
            <button
              className="primary"
              disabled={proposalLocked}
              aria-controls="rule-schedule-editor"
              aria-expanded={editorOpen}
              onClick={() =>
                changeContext(() => {
                  setDefinition(JSON.stringify(newScheduleDefinition()));
                  setParameterSchema(undefined);
                  setRuleParameters([]);
                  setEditorOpen(true);
                })
              }
            >
              New schedule
            </button>
          )}
        </div>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {currentAttempt && (
        <section className="panel" aria-label="Original schedule action">
          <h3>
            {settling
              ? "Submitting original schedule action"
              : "Schedule outcome unknown"}
          </h3>
          <p>
            The original {currentAttempt.action} of {currentAttempt.scheduleId}{" "}
            and its admitted identity are retained in this tab. Reconcile before
            changing this proposal.
          </p>
          <button
            disabled={busy || !canReconcile}
            onClick={() =>
              void sendOriginalAttempt(currentAttempt, recovery.lease)
            }
          >
            Reconcile original schedule action
          </button>
          {!canReconcile && (
            <p>
              Reconciliation is unavailable with the current schedule
              capabilities.
            </p>
          )}
          <button
            disabled={
              busy || !catalog?.functions["application.operation.receipt.read"]
            }
            onClick={() => setInspectReceipt(true)}
          >
            Inspect original schedule receipt
          </button>
          <p>
            Reconciliation never renews admission. An expired or denied retry
            does not prove that the original action had no effect. Receipt
            inspection is independent evidence; it does not rebuild this
            proposal.
          </p>
        </section>
      )}
      {inspectReceipt && currentAttempt && scope && (
        <ReceiptInspector
          scope={scope}
          catalog={catalog}
          operationId={currentAttempt.packet.body.idempotencyKey}
          close={() => setInspectReceipt(false)}
        />
      )}
      {result && <p role="status">{result}</p>}
      {catalogueRead && schedules.length ? (
        <div className="react-grid-scroll">
          <table className="react-cube-grid">
            <thead>
              <tr>
                <th>Schedule</th>
                <th>Rule</th>
                <th>Frequency</th>
                <th>Status</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {schedules.map((row) => (
                <tr key={row.scheduleId}>
                  <th>{row.scheduleId}</th>
                  <td>{scheduleRuleName(row.definition)}</td>
                  <td>{scheduleFrequency(row.definition)}</td>
                  <td>
                    {row.effectiveStatus}
                    {row.targetStatus === "Stale" && (
                      <small className="authority-note">
                        Target changed; rebind this schedule to the current
                        rule.
                      </small>
                    )}
                  </td>
                  <td>
                    <button
                      disabled={proposalLocked}
                      onClick={() => changeContext(() => void open(row))}
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
        <div className="rule-workspace-empty" role="status">
          <strong>
            {listReadError
              ? "Schedule list unavailable"
              : !available
                ? "Schedule listing is unavailable in the current application context"
                : busy
                  ? "Reading rule schedules…"
                  : catalogueRead
                    ? "No rule schedules yet"
                    : "Loading rule schedules…"}
          </strong>
          <p>
            {listReadError
              ? "Refresh schedules to retry. An unavailable read is not a confirmed empty list."
              : !available
                ? "You can inspect only an explicitly authorized schedule reference."
                : catalogueRead
                  ? "Create a schedule to run a published rule on a defined recurrence."
                  : "Current schedules will appear here automatically."}
          </p>
        </div>
      )}
      {after && (
        <button disabled={proposalLocked} onClick={() => void load(true)}>
          Read next schedules
        </button>
      )}
      {editorOpen && (
        <fieldset
          id="rule-schedule-editor"
          className="rule-editor-frame rule-editor-single"
          disabled={proposalLocked}
          aria-labelledby="schedule-editor-title"
        >
          <div className="rule-editor-heading">
            <div>
              <small>
                {selected ? "CURRENT DEFINITION" : "NEW DEFINITION"}
              </small>
              <h3 id="schedule-editor-title" ref={editorHeading} tabIndex={-1}>
                {selected ? selected.scheduleId : "Create a rule schedule"}
              </h3>
            </div>
            <button
              type="button"
              onClick={() =>
                changeContext(() => {
                  queueMicrotask(() =>
                    (
                      editorTrigger.current ||
                      document.getElementById("generic-schedule-heading")
                    )?.focus(),
                  );
                })
              }
            >
              Close editor
            </button>
          </div>
          <div className="governed-action-grid">
            <article className="governed-action-card">
              <small>BUSINESS SCHEDULE</small>
              <h4>What should run, and when</h4>
              <div className="parameter-field">
                <label htmlFor="schedule-name">Schedule name</label>
                <input
                  id="schedule-name"
                  readOnly={!canSave || Boolean(selected)}
                  value={
                    typeof parsed?.scheduleId === "string"
                      ? parsed.scheduleId
                      : ""
                  }
                  onChange={(event) =>
                    reviseDefinition((draft) => {
                      draft.scheduleId = event.target.value;
                    })
                  }
                />
                <small>
                  A stable business name used to identify this schedule.
                </small>
              </div>
              <fieldset className="parameter-fields">
                <legend>Published rule</legend>
                <div className="parameter-field">
                  <label htmlFor="schedule-rule">Rule name</label>
                  <input
                    id="schedule-rule"
                    readOnly={!canSave}
                    value={
                      typeof targetDefinition.ruleId === "string"
                        ? targetDefinition.ruleId
                        : ""
                    }
                    onChange={(event) => {
                      setParameterSchema(undefined);
                      setRuleParameters([]);
                      reviseDefinition((draft) => {
                        draft.target = {
                          kind: "ApplicationRule",
                          ruleId: event.target.value,
                          stateToken: "",
                          programDigest: "",
                        };
                        draft.bindings = {};
                        draft.pov = [];
                      });
                    }}
                  />
                </div>
                <button
                  type="button"
                  disabled={
                    !canSave ||
                    !catalog?.functions["application.rule.read"] ||
                    busy
                  }
                  onClick={() => void loadCurrentRule()}
                >
                  Load current rule
                </button>
                <p className="authority-note">
                  This verifies the published rule and privately binds its exact
                  current version to the schedule.
                </p>
              </fieldset>
              {parameterSchema ? (
                <ParameterFields
                  label="Rule parameters"
                  advancedLabel="Rule parameters"
                  value={JSON.stringify(bindingDefinition)}
                  schema={bindingParameterSchema}
                  disabled={!canSave || busy}
                  onChange={(value) => {
                    const next = JSON.parse(value) as Record<string, unknown>;
                    reviseDefinition((draft) => {
                      draft.bindings = next;
                    });
                  }}
                />
              ) : (
                <fieldset className="parameter-fields">
                  <legend>Rule parameters</legend>
                  <p>
                    Load the current rule to display its named business
                    parameters.
                  </p>
                  {Object.keys(bindingDefinition).length > 0 && (
                    <small>
                      {Object.keys(bindingDefinition).length} saved parameter
                      {Object.keys(bindingDefinition).length === 1 ? "" : "s"}
                      {" retained."}
                    </small>
                  )}
                </fieldset>
              )}
              <fieldset className="parameter-fields">
                <legend>Point of view</legend>
                <p>
                  Choose each member from the authorized hierarchy and bind it
                  to a named rule parameter. Each dimension and parameter can
                  appear once.
                </p>
                {app && catalog ? (
                  <ExactScopeSelector
                    app={app}
                    catalog={catalog}
                    value={povScope}
                    disabled={!canSave || busy}
                    onChange={(scope) =>
                      reviseDefinition((draft) => {
                        const existing = new Map(
                          povDefinition.flatMap((entry) => {
                            const row = parameterObject(entry);
                            return typeof row?.dimensionId === "string"
                              ? [[row.dimensionId, row] as const]
                              : [];
                          }),
                        );
                        draft.pov = Object.entries(scope).map(
                          ([dimensionId, memberId]) => {
                            const choices = memberParameters
                              .filter(
                                (parameter) =>
                                  parameter.dimensionId === dimensionId,
                              )
                              .map((parameter) => parameter.name);
                            const current = String(
                              existing.get(dimensionId)?.parameter ?? "",
                            );
                            return {
                              dimensionId,
                              memberId,
                              parameter: choices.includes(current)
                                ? current
                                : choices.length === 1
                                  ? choices[0]
                                  : "",
                            };
                          },
                        );
                      })
                    }
                  />
                ) : (
                  <p>Choose an application before selecting members.</p>
                )}
                {povDefinition.length === 0 ? (
                  <p>No separate point-of-view members are required.</p>
                ) : (
                  <div className="react-grid-scroll">
                    <table className="react-cube-grid">
                      <thead>
                        <tr>
                          <th>Dimension</th>
                          <th>Rule parameter</th>
                        </tr>
                      </thead>
                      <tbody>
                        {povDefinition.map((entry, index) => {
                          const row = parameterObject(entry) ?? {};
                          return (
                            <tr key={String(row.dimensionId ?? index)}>
                              <th>
                                {String(row.dimensionId ?? "Unavailable")}
                              </th>
                              <td>
                                {parameterSchema ? (
                                  <select
                                    aria-label={`Rule parameter for ${String(
                                      row.dimensionId ?? `POV ${index + 1}`,
                                    )}`}
                                    disabled={!canSave}
                                    value={String(row.parameter ?? "")}
                                    onChange={(event) =>
                                      reviseDefinition((draft) => {
                                        const next = Array.isArray(draft.pov)
                                          ? [...draft.pov]
                                          : [];
                                        next[index] = {
                                          ...row,
                                          parameter: event.target.value,
                                        };
                                        draft.pov = next;
                                      })
                                    }
                                  >
                                    <option value="">
                                      Choose rule parameter
                                    </option>
                                    {memberParameters
                                      .filter(
                                        (parameter) =>
                                          parameter.dimensionId ===
                                            row.dimensionId &&
                                          (!povDefinition.some(
                                            (candidate, candidateIndex) =>
                                              candidateIndex !== index &&
                                              parameterObject(candidate)
                                                ?.parameter === parameter.name,
                                          ) ||
                                            row.parameter === parameter.name),
                                      )
                                      .map((parameter) => (
                                        <option
                                          key={parameter.name}
                                          value={parameter.name}
                                        >
                                          {parameter.name}
                                        </option>
                                      ))}
                                  </select>
                                ) : (
                                  <span>
                                    {String(row.parameter ?? "Unavailable")}
                                  </span>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </fieldset>
              <fieldset className="parameter-fields">
                <legend>Recurrence</legend>
                <p className="authority-note">
                  All due times use UTC, independent of this browser’s time
                  zone. The start time and interval define eligibility; they do
                  not promise an exact dispatch time.
                </p>
                <div className="parameter-field">
                  <label htmlFor="schedule-first-run">First run (UTC)</label>
                  <input
                    id="schedule-first-run"
                    type="datetime-local"
                    readOnly={!canSave}
                    value={
                      typeof recurrenceDefinition.firstDueAt === "string"
                        ? recurrenceDefinition.firstDueAt.replace(/:00Z$/, "")
                        : ""
                    }
                    onChange={(event) =>
                      reviseDefinition((draft) => {
                        draft.recurrence = {
                          ...recurrenceDefinition,
                          kind: "FixedInterval",
                          firstDueAt: event.target.value
                            ? `${event.target.value}:00Z`
                            : "",
                        };
                      })
                    }
                  />
                </div>
                <div className="parameter-field">
                  <label htmlFor="schedule-interval">
                    Repeat every (minutes)
                  </label>
                  <input
                    id="schedule-interval"
                    type="number"
                    min={1}
                    max={44640}
                    step={1}
                    readOnly={!canSave}
                    value={
                      typeof recurrenceDefinition.intervalSeconds === "number"
                        ? recurrenceDefinition.intervalSeconds / 60
                        : ""
                    }
                    onChange={(event) =>
                      reviseDefinition((draft) => {
                        draft.recurrence = {
                          ...recurrenceDefinition,
                          kind: "FixedInterval",
                          intervalSeconds: Number(event.target.value) * 60,
                        };
                      })
                    }
                  />
                </div>
                <div className="parameter-field">
                  <label htmlFor="schedule-catch-up">Missed runs</label>
                  <select
                    id="schedule-catch-up"
                    disabled={!canSave}
                    value={String(recurrenceDefinition.catchUpPolicy ?? "")}
                    onChange={(event) =>
                      reviseDefinition((draft) => {
                        draft.recurrence = {
                          ...recurrenceDefinition,
                          kind: "FixedInterval",
                          catchUpPolicy: event.target.value,
                        };
                      })
                    }
                  >
                    <option value="skip">Skip missed runs</option>
                    <option value="latest">
                      Run the latest missed occurrence
                    </option>
                    <option value="all">
                      Run each bounded missed occurrence
                    </option>
                  </select>
                </div>
                <div className="parameter-field">
                  <label htmlFor="schedule-max-catch-up">
                    Maximum catch-up runs
                  </label>
                  <input
                    id="schedule-max-catch-up"
                    type="number"
                    min={1}
                    max={36}
                    step={1}
                    readOnly={!canSave}
                    value={String(recurrenceDefinition.maxCatchUp ?? "")}
                    onChange={(event) =>
                      reviseDefinition((draft) => {
                        draft.recurrence = {
                          ...recurrenceDefinition,
                          kind: "FixedInterval",
                          maxCatchUp: Number(event.target.value),
                        };
                      })
                    }
                  />
                </div>
              </fieldset>
              <fieldset className="parameter-fields">
                <legend>Failure handling</legend>
                <div className="parameter-field">
                  <label htmlFor="schedule-attempts">Maximum attempts</label>
                  <input
                    id="schedule-attempts"
                    type="number"
                    min={1}
                    max={10}
                    step={1}
                    readOnly={!canSave}
                    value={String(retryDefinition.maxAttempts ?? "")}
                    onChange={(event) =>
                      reviseDefinition((draft) => {
                        draft.retryPolicy = {
                          ...retryDefinition,
                          maxAttempts: Number(event.target.value),
                          needsInspectionAfter: true,
                        };
                      })
                    }
                  />
                </div>
                <div className="parameter-field">
                  <label htmlFor="schedule-retry-delay">
                    Delay between attempts (seconds)
                  </label>
                  <input
                    id="schedule-retry-delay"
                    type="number"
                    min={0}
                    max={86400}
                    step={1}
                    readOnly={!canSave}
                    value={String(retryDefinition.backoffSeconds ?? "")}
                    onChange={(event) =>
                      reviseDefinition((draft) => {
                        draft.retryPolicy = {
                          ...retryDefinition,
                          backoffSeconds: Number(event.target.value),
                          needsInspectionAfter: true,
                        };
                      })
                    }
                  />
                </div>
                <p className="authority-note">
                  A failed final attempt is held for inspection. Deactivation
                  stops future dispatch; committed work remains. Inspect each
                  occurrence before deciding whether more work is needed.
                </p>
              </fieldset>
              <fieldset className="parameter-fields">
                <legend>Execution authority</legend>
                <div className="parameter-field">
                  <label htmlFor="schedule-authority">Authority name</label>
                  <input
                    id="schedule-authority"
                    readOnly={!canSave}
                    value={String(delegationDefinition.delegationId ?? "")}
                    onChange={(event) =>
                      reviseDefinition((draft) => {
                        draft.delegation = {
                          delegationId: event.target.value,
                          stateToken: "",
                        };
                      })
                    }
                  />
                </div>
                <button
                  type="button"
                  disabled={!canSave || !canInspectAuthority || busy}
                  onClick={() => void loadCurrentAuthority()}
                >
                  Load current authority
                </button>
                <button
                  type="button"
                  disabled={
                    !canInspectAuthority ||
                    busy ||
                    !DIGEST.test(String(delegationDefinition.stateToken ?? ""))
                  }
                  onClick={() => void loadCurrentAuthority(false)}
                >
                  Inspect bound authority
                </button>
                <p className="authority-note">
                  Load current authority changes this draft’s binding. Inspect
                  bound authority reads its current actor and validity without
                  rebinding or saving. The core rechecks authority at dispatch
                  and at protected effects.
                </p>
                {!canInspectAuthority && (
                  <p>
                    Authority inspection is unavailable through the current
                    application catalogue.
                  </p>
                )}
                {inspectedAuthority && (
                  <div role="region" aria-label="Inspected execution authority">
                    <p>
                      <strong>
                        {scheduleAuthorityStatus(
                          inspectedAuthority,
                          String(parsed?.scheduleId ?? ""),
                          String(delegationDefinition.stateToken ?? ""),
                        )}
                      </strong>
                    </p>
                    <dl>
                      <dt>Execution actor</dt>
                      <dd>{inspectedAuthority.subject_id}</dd>
                      <dt>Identity issuer</dt>
                      <dd>{inspectedAuthority.issuer}</dd>
                      <dt>Valid from (UTC)</dt>
                      <dd>
                        {new Date(inspectedAuthority.valid_from).toISOString()}
                      </dd>
                      <dt>Valid until (UTC)</dt>
                      <dd>
                        {new Date(inspectedAuthority.valid_until).toISOString()}
                      </dd>
                      <dt>Schedule scope</dt>
                      <dd>
                        {inspectedAuthority.schedule_id ??
                          "Any schedule within the delegated application scope"}
                      </dd>
                    </dl>
                    <p>
                      This inspection does not grant access or certify a future
                      run. Current grants and the saved binding remain decisive.
                    </p>
                  </div>
                )}
              </fieldset>
              <p className="authority-note">
                Technical version keys are intentionally kept out of this
                workspace. They are checked automatically when the schedule is
                loaded and saved.
              </p>
              {selected && (
                <section aria-label="Schedule occurrences">
                  <h4>Actual occurrences</h4>
                  <p>
                    Read native occurrence and task states for this saved
                    schedule, newest first. Only tasks visible to your current
                    identity appear; these are not a total of all executions.
                  </p>
                  <button
                    type="button"
                    disabled={busy || !exactSelected}
                    onClick={() => void inspectOccurrences()}
                  >
                    {currentOccurrences
                      ? "Refresh occurrences"
                      : "Inspect occurrences"}
                  </button>
                  {!exactSelected && (
                    <p>
                      Occurrence inspection uses the saved definition. Reopen it
                      or save your reviewed changes first.
                    </p>
                  )}
                  {occurrenceError && (
                    <p role="alert">
                      Occurrence inspection unavailable: {occurrenceError}
                    </p>
                  )}
                  {currentOccurrences && (
                    <>
                      <p>
                        {currentOccurrences.items.length} visible occurrences
                        loaded
                        {currentOccurrences.hasMore
                          ? "; more visible occurrences are available."
                          : "."}
                      </p>
                      {!currentOccurrences.items.length && (
                        <p>
                          No visible occurrence was returned for this schedule.
                        </p>
                      )}
                      {!!currentOccurrences.items.length && (
                        <div className="react-grid-scroll">
                          <table className="react-cube-grid">
                            <thead>
                              <tr>
                                <th>Due (UTC)</th>
                                <th>Task status</th>
                                <th>Native occurrence status</th>
                                <th>Schedule version</th>
                                <th>Inspect</th>
                              </tr>
                            </thead>
                            <tbody>
                              {currentOccurrences.items.map((item) => {
                                const href = referenceHandoffHash({
                                  format: "openepm.reference-handoff/v1",
                                  scope: scope!,
                                  origin: {
                                    kind: "definition",
                                    artifactKind: "ApplicationSchedule",
                                    artifactId: selected.scheduleId,
                                  },
                                  target: { kind: "task", taskId: item.taskId },
                                  returnTo: null,
                                  observed: {},
                                  pendingOperation: null,
                                });
                                return (
                                  <tr key={item.occurrenceId}>
                                    <td>
                                      {new Date(item.dueAt).toISOString()}
                                    </td>
                                    <td>{item.status}</td>
                                    <td>{item.nativeStatus}</td>
                                    <td>
                                      {item.currentPin
                                        ? "Uses current saved version"
                                        : "Uses an earlier saved version"}
                                    </td>
                                    <td>
                                      <a
                                        href={href}
                                        onClick={(event) => {
                                          event.preventDefault();
                                          onRequestTransition(() => {
                                            window.location.hash = href;
                                          });
                                        }}
                                      >
                                        Inspect task
                                      </a>
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      )}
                      {currentOccurrences.hasMore && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void inspectOccurrences(true)}
                        >
                          Read older occurrences
                        </button>
                      )}
                      <p>
                        A version match does not establish execution
                        eligibility. Task inspection rechecks access; an earlier
                        occurrence does not prove the current rule’s outcome.
                      </p>
                    </>
                  )}
                </section>
              )}
              {definitionError && (
                <p className="inline-error">{definitionError}</p>
              )}
              {parameterError && (
                <p className="inline-error">{parameterError}</p>
              )}
              {povParameterError && (
                <p className="inline-error">{povParameterError}</p>
              )}
              {selected?.targetStatus === "Stale" && (
                <p className="inline-error" role="alert">
                  This schedule is blocked because its target rule changed.
                  Review the current rule and save the schedule again to rebind
                  it.
                </p>
              )}
              {(["save", "activate", "deactivate"] as const).map((action) => {
                if (action !== "save" && !selected) return null;
                const allowed =
                  action === "save"
                    ? canSave &&
                      !definitionError &&
                      !parameterError &&
                      !povParameterError
                    : action === "activate"
                      ? canActivate &&
                        exactSelected &&
                        selected?.status !== "Active" &&
                        selected?.targetStatus === "Current"
                      : canDeactivate &&
                        exactSelected &&
                        selected?.status === "Active";
                return (
                  <div key={action} className="review-row">
                    <button
                      disabled={!allowed || busy}
                      onClick={() => void mutate(action)}
                    >
                      {action[0].toUpperCase() + action.slice(1)}
                    </button>
                  </div>
                );
              })}
            </article>
          </div>
        </fieldset>
      )}
    </section>
  );
}
