import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  readProgram,
  prepareAdmittedProgramEffect,
  replayAdmittedEffect,
} from "./api";
import {
  collectAllContinuations,
  ContinuationConsistencyError,
} from "./continuation";
import { usePreservedDraft, type DraftRecoveryLease } from "./unsaved-work";
import { parseParameterJson } from "./exact-parameters";
import {
  exactRuleRunOutcome,
  type RuleRunPacket,
  type RuleRunOutcome,
} from "./application-rule-run";
import {
  terminalWorkflowOutcome,
  workflowUnitCounts,
  workflowCountGuidance,
  workflowStatusLabel,
} from "./workflow-outcome";
import { transferAction } from "./data-transfer-action";
import { WorkflowCheckpointEvidence } from "./WorkflowCheckpointEvidence";
import { useStableMutationIntentKey } from "./mutation-intent";
import { authoringContextKey } from "./python-authoring";
import {
  ParameterFields,
  definitionParameterSchema,
  parameterInputError,
  parameterObject,
} from "./ParameterFields";
import { PythonDefinitionEditor } from "./PythonDefinitionEditor";
import type { PythonSourceBinding } from "./PythonDefinitionEditor";
import { pythonDefinitionTemplates } from "./python-definition-templates";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import "./rule-workspaces.css";
import {
  definitionAvailabilityLabel,
  isDefinitionLifecycle,
  isDefinitionSourceBinding,
  type DefinitionLifecycle,
} from "./definition-lifecycle";

export type RuleSummary = DefinitionLifecycle & {
  ruleId: string;
  stateToken: string;
  programDigest: string | null;
  metadataCurrent: boolean;
};
type RuleDetail = RuleSummary & {
  defined: boolean;
  program: Record<string, unknown> | null;
  source?: PythonSourceBinding | null;
};
type RuleListPage = {
  rows: RuleSummary[];
  hasMore: boolean;
  nextAfterRuleId: string | null;
  metadataRevision: number;
  policyRevision: number;
  collectionToken?: string;
};
const ruleIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const unavailableRule = "The exact application rule is unavailable.";
const ruleOperations = {
  all: undefined,
  ordered: "facts.numeric.sequence",
  batch: "facts.numeric.batch",
} as const;
export function ruleListArguments(
  afterRuleId?: string | null,
  expectedMetadataRevision?: number,
  expectedPolicyRevision?: number,
  collectionToken?: string,
  containsOperation?: string,
) {
  return {
    limit: 100,
    ...(containsOperation ? { containsOperation } : {}),
    ...(afterRuleId
      ? {
          afterRuleId,
          expectedMetadataRevision,
          expectedPolicyRevision,
          ...(collectionToken ? { collectionToken } : {}),
        }
      : {}),
  };
}
export function ruleReadArguments(ruleId: string) {
  return { ruleId };
}
export function ruleAvailabilityLabel(rule: RuleSummary) {
  return definitionAvailabilityLabel(rule);
}

function validRuleOwner(row: RuleSummary) {
  return (
    isDefinitionLifecycle(row) &&
    typeof row.ruleId === "string" &&
    Boolean(row.ruleId) &&
    typeof row.stateToken === "string" &&
    /^[0-9a-f]{64}$/.test(row.stateToken) &&
    (row.programDigest === null
      ? !row.valid &&
        !row.executable &&
        (row.reason === "validation_required" ||
          row.reason === "ownership_unresolved")
      : typeof row.programDigest === "string" &&
        /^[0-9a-f]{64}$/.test(row.programDigest))
  );
}
export function collectApplicationRules(
  readPage: (
    arguments_: ReturnType<typeof ruleListArguments>,
  ) => Promise<RuleListPage>,
  containsOperation?: string,
  onVerifiedPage?: (rows: RuleSummary[]) => void,
) {
  let metadata: number | undefined, policy: number | undefined;
  let collectionToken: string | undefined;
  return collectAllContinuations<RuleListPage, RuleSummary>({
    label: "Application rules",
    onVerifiedPage,
    readPage: async (cursor) => {
      const page = await readPage(
        ruleListArguments(
          cursor,
          metadata,
          policy,
          collectionToken,
          containsOperation,
        ),
      );
      if (
        !Number.isSafeInteger(page.metadataRevision) ||
        page.metadataRevision < 0 ||
        !Number.isSafeInteger(page.policyRevision) ||
        page.policyRevision < 0 ||
        (page.collectionToken === undefined
          ? Boolean(containsOperation)
          : typeof page.collectionToken !== "string" ||
            !/^[0-9a-f]{64}$/.test(page.collectionToken))
      )
        throw new Error("Application rules revisions are invalid.");
      metadata = page.metadataRevision;
      policy = page.policyRevision;
      collectionToken = page.collectionToken;
      return page;
    },
    rows: (page) =>
      page.rows.map((row) => {
        if (!validRuleOwner(row) || typeof row.metadataCurrent !== "boolean")
          throw new Error("Application rule summary is invalid.");
        return row;
      }),
    nextCursor: (page) => {
      if (
        typeof page.hasMore !== "boolean" ||
        (page.hasMore
          ? typeof page.nextAfterRuleId !== "string" ||
            page.nextAfterRuleId !== page.rows.at(-1)?.ruleId
          : page.nextAfterRuleId !== null)
      )
        throw new Error(
          "Application rules continuation status is inconsistent.",
        );
      return page.hasMore ? page.nextAfterRuleId : null;
    },
    rowIdentity: (row) => row.ruleId,
    consistencyIdentity: (page) =>
      `${page.metadataRevision}:${page.policyRevision}:${page.collectionToken ?? ""}`,
  });
}
export function ruleRunBody(
  app: ApplicationSummary,
  ruleId: string,
  bindings: Record<string, unknown>,
  idempotencyKey: string,
  expectedStateToken: string,
  expectedProgramDigest: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    program: {
      languageVersion: 2,
      function: "application.rule.run",
      arguments: {
        ruleId,
        bindings,
        expectedStateToken,
        expectedProgramDigest,
      },
    },
    idempotencyKey,
    confirmed: true,
  };
}
type RuleRunAttempt = {
  ownerKey: string;
  packet: RuleRunPacket;
  outcome: RuleRunOutcome | null;
  outcomeContextKey: string | null;
  admissionExpired?: true;
};
type RuleDraft = {
  ownerKey: string;
  bindingTarget: string;
  bindings: string;
  attempt: RuleRunAttempt | null;
};
const ruleRunProgress = {
  prepare: "Preparing rule run…",
  submit: "Waiting for the rule run acknowledgement…",
  inspect: "Checking the original run status…",
  replay: "Retrying the exact original rule request…",
};

export function BuildRules({
  app,
  catalog,
  targetApplicationRule,
  onRequestTransition = (action) => action(),
  onRefreshCatalog,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  targetApplicationRule?: {
    ruleId: string;
    stateToken: string;
    digest: string;
  };
  onRequestTransition?: (action: () => void, preserveDrafts?: boolean) => void;
  onRefreshCatalog?: () => Promise<ApplicationCatalog>;
}) {
  const contextKey = JSON.stringify([
    app && catalog ? authoringContextKey(app, catalog) : null,
    app?.workspaceId,
    app?.applicationId,
    catalog?.applicationAccess,
    catalog?.revisions.capability,
    Object.keys(catalog?.functions || {}).sort(),
  ]);
  const ownerKey =
    app && catalog
      ? JSON.stringify([
          app.workspaceId,
          app.applicationId,
          catalog.applicationAccess.issuer,
          catalog.applicationAccess.subjectId,
        ])
      : "";
  const currentContext = useRef(contextKey);
  currentContext.current = contextKey;
  const previousOwner = useRef(ownerKey);
  const bindingTarget = useRef("");
  const [stateContext, setStateContext] = useState(contextKey);
  const currentState = stateContext === contextKey;
  const [rows, setRows] = useState<RuleSummary[]>([]),
    [read, setRead] = useState(false),
    [page, setPage] = useState(0),
    [query, setQuery] = useState("");
  const [ruleFilter, setRuleFilter] = useState<{
    owner: string;
    key: keyof typeof ruleOperations;
  } | null>(null);
  const [exactRuleId, setExactRuleId] = useState("");
  const [directoryIncomplete, setDirectoryIncomplete] = useState(false);
  const [selected, setSelected] = useState<RuleDetail | null>(null),
    [creating, setCreating] = useState(false);
  const parameterSchema = definitionParameterSchema(
    parameterObject(selected?.program?.arguments)?.parameters,
  );
  const [bindings, setBindings] = useState("{}"),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const [attempt, setAttempt] = useState<RuleRunAttempt | null>(null);
  const [unconfirmedLookup, setUnconfirmedLookup] = useState<{
    contextKey: string;
    operationId: string;
  } | null>(null);
  const ownAttempt = attempt?.ownerKey === ownerKey ? attempt : null;
  const result = ownAttempt?.outcome ?? null;
  const visibleOutcome =
    ownAttempt?.outcomeContextKey === contextKey ? result : null;
  const unresolved = Boolean(
    ownAttempt && (!result || !terminalWorkflowOutcome(result)),
  );
  const canRetryOriginal = Boolean(
    ownAttempt &&
      !result &&
      !ownAttempt.admissionExpired &&
      unconfirmedLookup?.contextKey === contextKey &&
      unconfirmedLookup.operationId === ownAttempt.packet.body.idempotencyKey &&
      catalog?.functions["application.rule.run"],
  );
  const [runStage, setRunStage] = useState<keyof typeof ruleRunProgress | null>(
    null,
  );
  const runBusy = runStage !== null;
  const [runError, setRunError] = useState<{
    ownerKey: string;
    message: string;
  } | null>(null);
  const mounted = useRef(true);
  const currentOwner = useRef(ownerKey);
  currentOwner.current = ownerKey;
  const runSequence = useRef(0);
  const runController = useRef<AbortController | null>(null);
  const runFocus = useRef<{
    ownerKey: string;
    origin: HTMLElement;
    restart: boolean;
    covered: boolean;
  } | null>(null);
  const rulesPanel = useRef<HTMLElement>(null);
  const runStatus = useRef<HTMLDivElement>(null);
  const readOriginalButton = useRef<HTMLButtonElement>(null);
  const runButton = useRef<HTMLButtonElement>(null);
  const ruleSearch = useRef<HTMLInputElement>(null);
  useEffect(() => {
    mounted.current = true;
    function releaseRunFocus(event: FocusEvent) {
      const focus = runFocus.current;
      if (
        focus &&
        event.target !== focus.origin &&
        !rulesPanel.current?.closest("[inert]")
      )
        runFocus.current = null;
    }
    document.addEventListener("focusin", releaseRunFocus);
    return () => {
      mounted.current = false;
      runController.current?.abort();
      document.removeEventListener("focusin", releaseRunFocus);
    };
  }, []);
  useLayoutEffect(() => {
    runSequence.current++;
    runController.current?.abort();
    runController.current = null;
    setRunStage(null);
    setRunError(null);
    setUnconfirmedLookup(null);
  }, [contextKey]);
  function retainRunFocus(origin: HTMLElement, restart = false) {
    runFocus.current =
      document.activeElement === origin
        ? { ownerKey, origin, restart, covered: false }
        : null;
  }
  useLayoutEffect(() => {
    const focus = runFocus.current;
    if (!focus) return;
    if (focus.ownerKey !== ownerKey) {
      runFocus.current = null;
      return;
    }
    // Session revalidation can temporarily take the entire workspace out of
    // the focus order while the original request and its owner still exist.
    if (rulesPanel.current?.closest("[inert]")) {
      focus.covered = true;
      return;
    }
    const active = document.activeElement;
    const removed = !focus.origin.isConnected;
    if (
      active !== focus.origin &&
      (active !== document.body || (!removed && !focus.covered))
    ) {
      runFocus.current = null;
      return;
    }
    focus.covered = false;
    if (runBusy) {
      if (active !== focus.origin) {
        const target = removed ? runStatus.current : focus.origin;
        if (target) {
          focus.origin = target;
          target.focus();
        }
      }
      return;
    }
    runFocus.current = null;
    if (focus.restart) {
      const target = runButton.current;
      (target && target.getAttribute("aria-disabled") !== "true"
        ? target
        : ruleSearch.current
      )?.focus();
    } else if (ownAttempt) {
      const target = readOriginalButton.current;
      (target && target.getAttribute("aria-disabled") !== "true"
        ? target
        : runStatus.current
      )?.focus();
    } else if (removed) {
      ruleSearch.current?.focus();
    }
  });
  function finishRun(controller: AbortController) {
    if (runController.current !== controller) return;
    runController.current = null;
    setRunStage(null);
  }
  const [sourceCurrentness, setSourceCurrentness] = useState<
    "checking" | "current" | "unavailable"
  >("unavailable");
  const [runIntent, setRunIntent] = useState(0);
  const activeRead = useRef<AbortController | null>(null);
  const isCurrent = (controller: AbortController) =>
    !controller.signal.aborted && currentContext.current === contextKey;
  const draftValue: RuleDraft = {
    ownerKey,
    bindingTarget:
      previousOwner.current === ownerKey ? bindingTarget.current : "",
    bindings: previousOwner.current === ownerKey ? bindings : "{}",
    attempt: ownAttempt,
  };
  const recovery = usePreservedDraft(
    ownerKey ? app?.workspaceId || "none" : "none",
    ownerKey ? app?.applicationId || "none" : "none",
    "application-rule-run",
    unresolved
      ? "Original application rule execution recovery"
      : "Unsubmitted rule parameters",
    unresolved || (draftValue.bindings !== "{}" && !ownAttempt),
    draftValue,
    (saved) => {
      if (saved.ownerKey !== ownerKey) return;
      bindingTarget.current = saved.bindingTarget;
      setBindings(saved.bindings);
      setAttempt(saved.attempt?.ownerKey === ownerKey ? saved.attempt : null);
    },
  );
  const mutationKey = useStableMutationIntentKey("application-rule-ui");
  const canRead = Boolean(
    catalog?.functions["application.rule.list"] &&
      catalog.functions["application.rule.read"],
  );
  const canInspectSource = Boolean(
    catalog &&
      (catalog.applicationAccess.authorizationModel !== "group_assignments" ||
        catalog.functions["python.program.read"]),
  );
  const listSpec = parameterObject(catalog?.functions["application.rule.list"]);
  const listSchema = parameterObject(listSpec?.programSchema);
  const listArgumentSchema = parameterObject(
    parameterObject(listSchema?.properties)?.arguments,
  );
  const hasOperationFilter = Boolean(
    parameterObject(listArgumentSchema?.properties)?.containsOperation,
  );
  const selectedFilter =
    hasOperationFilter && ruleFilter?.owner === ownerKey
      ? ruleFilter.key
      : "all";
  const canCreate = Boolean(
    catalog?.functions["python.program.save"] &&
      catalog.functions["python.environment.list"],
  );
  const filtered = useMemo(
    () =>
      rows.filter((row) =>
        row.ruleId.toLowerCase().includes(query.toLowerCase()),
      ),
    [rows, query],
  );
  const start = Math.min(
    page * 50,
    Math.max(0, Math.floor((filtered.length - 1) / 50) * 50),
  );
  function begin() {
    activeRead.current?.abort();
    const controller = new AbortController();
    activeRead.current = controller;
    setBusy(true);
    setError("");
    return controller;
  }
  useEffect(() => {
    activeRead.current?.abort();
    setStateContext(contextKey);
    setRows([]);
    setRead(false);
    setDirectoryIncomplete(false);
    setExactRuleId("");
    setSelected(null);
    setCreating(false);
    if (ownerKey && previousOwner.current !== ownerKey) {
      setBindings("{}");
      bindingTarget.current = "";
      setQuery("");
      setRunIntent(0);
      setAttempt(null);
      previousOwner.current = ownerKey;
    }
    setError("");
    setBusy(false);
    setSourceCurrentness("unavailable");
    return () => activeRead.current?.abort();
  }, [contextKey]);
  async function loadRules(filter = selectedFilter) {
    if (!app || !canRead || currentContext.current !== contextKey) return;
    const controller = begin();
    const verified: RuleSummary[] = [];
    try {
      const result = await collectApplicationRules(
        (args) =>
          readProgram<RuleListPage>(
            app,
            "application.rule.list",
            args,
            controller.signal,
          ),
        ruleOperations[filter],
        (pageRows) => {
          verified.push(...pageRows);
        },
      );
      if (isCurrent(controller)) {
        setRows(result.rows);
        setDirectoryIncomplete(false);
        setRead(true);
        setPage(0);
        return result.rows;
      }
    } catch (reason) {
      if (isCurrent(controller)) {
        const cutChanged =
          (reason instanceof ApiError &&
            reason.code === "STALE_EXPRESSION_RULE_LIST_REVISION") ||
          reason instanceof ContinuationConsistencyError;
        const invalidated = cutChanged || ruleReadAccessChanged(reason);
        setRows(invalidated ? [] : verified);
        setRead(!invalidated && verified.length > 0);
        setPage(0);
        setDirectoryIncomplete(!invalidated);
        if (invalidated) {
          setSelected(null);
          setSourceCurrentness("unavailable");
        }
        setError(
          cutChanged
            ? "The application changed while reading the rule list. Choose Refresh rules to start again."
            : reason instanceof ApiError &&
                reason.code === "RULE_RUN_DISCOVERY_SCAN_LIMIT"
              ? ""
              : reason instanceof Error
                ? reason.message
                : "Unable to read rules.",
        );
      }
    } finally {
      if (isCurrent(controller)) setBusy(false);
    }
  }
  useEffect(() => {
    if (app && canRead) void loadRules();
  }, [contextKey, canRead]);
  async function open(
    target:
      | string
      | {
          ruleId: string;
          stateToken: string;
          digest: string | null;
        },
  ) {
    if (
      !app ||
      !catalog?.functions["application.rule.read"] ||
      currentContext.current !== contextKey
    )
      return;
    const controller = begin();
    const ruleId = typeof target === "string" ? target : target.ruleId;
    setSelected(null);
    setSourceCurrentness("checking");
    setCreating(false);
    try {
      const detail = await readProgram<RuleDetail>(
        app,
        "application.rule.read",
        ruleReadArguments(ruleId),
        controller.signal,
      );
      if (!isCurrent(controller)) return;
      if (
        !validRuleOwner(detail) ||
        detail.ruleId !== ruleId ||
        (typeof target !== "string" &&
          (detail.stateToken !== target.stateToken ||
            detail.programDigest !== target.digest)) ||
        (detail.programDigest === null
          ? detail.program !== null
          : !detail.program ||
            typeof detail.program !== "object" ||
            Array.isArray(detail.program)) ||
        (detail.source != null &&
          (!detail.sourceCurrent ||
            !isDefinitionSourceBinding(detail.source) ||
            detail.source.active !== detail.active))
      )
        throw new Error(unavailableRule);
      setSelected(detail);
      if (detail.source && canInspectSource) {
        setSourceCurrentness("checking");
      } else {
        // A runner can verify the active publication without reading the author's Python.
        setSourceCurrentness(
          detail.source?.active && detail.sourceCurrent && detail.executable
            ? "current"
            : "unavailable",
        );
      }
      const exactTarget = JSON.stringify([
        ownerKey,
        detail.ruleId,
        detail.stateToken,
        detail.programDigest,
      ]);
      if (bindingTarget.current !== exactTarget) setBindings("{}");
      bindingTarget.current = exactTarget;
    } catch (reason) {
      if (isCurrent(controller)) {
        setSourceCurrentness("unavailable");
        const targetUnavailable =
          reason instanceof ApiError
            ? reason.code === "RULE_RUN_TARGET_UNAVAILABLE"
            : reason instanceof Error && reason.message === unavailableRule;
        if (targetUnavailable) {
          if (typeof target === "string") {
            setRows((current) =>
              current.filter((row) => row.ruleId !== ruleId),
            );
          }
        } else if (ruleReadAccessChanged(reason)) {
          setRows([]);
          setRead(false);
          setDirectoryIncomplete(false);
        }
        setError(
          targetUnavailable
            ? unavailableRule
            : reason instanceof Error
              ? reason.message
              : "Unable to open rule.",
        );
      }
    } finally {
      if (isCurrent(controller)) setBusy(false);
    }
  }
  useEffect(() => {
    if (targetApplicationRule) void open(targetApplicationRule);
  }, [
    contextKey,
    targetApplicationRule?.ruleId,
    targetApplicationRule?.stateToken,
    targetApplicationRule?.digest,
  ]);
  function recoveredDraft(work: RuleRunAttempt): RuleDraft {
    return {
      ownerKey: work.ownerKey,
      bindingTarget: "",
      bindings: "{}",
      attempt: work,
    };
  }
  async function sendOriginal(
    work: RuleRunAttempt,
    lease: DraftRecoveryLease | null,
    controller: AbortController,
    sequence: number,
    inspect: boolean,
  ) {
    const show = () =>
      !controller.signal.aborted &&
      mounted.current &&
      currentOwner.current === work.ownerKey &&
      currentContext.current === contextKey &&
      runSequence.current === sequence;
    try {
      const response = inspect
        ? await readProgram<unknown>(
            work.packet.body,
            "application.rule.run.read",
            work.outcome
              ? { workflowId: work.outcome.workflowId }
              : {
                  originalRequest: {
                    program: work.packet.body.program,
                    idempotencyKey: work.packet.body.idempotencyKey,
                  },
                },
            controller.signal,
          )
        : (
            await replayAdmittedEffect<{ result: unknown }>(
              work.packet,
              controller.signal,
            )
          ).result;
      const outcome = await exactRuleRunOutcome(
        response,
        work.packet,
        work.outcome ?? undefined,
        inspect,
      );
      // The catalogue can change while the outcome digest is being verified.
      // Keep the admitted request for a fresh authorized observation.
      if (!show()) return;
      const next = { ...work, outcome, outcomeContextKey: contextKey };
      if (lease) {
        if (terminalWorkflowOutcome(outcome))
          recovery.release(lease, recoveredDraft(next));
        else recovery.retain(recoveredDraft(next), lease);
      }
      setAttempt(next);
    } catch (reason) {
      // Acceptance may commit before eager advance throws, including 400/403.
      // Never discard a dispatched packet or borrow a newer lease in cleanup.
      if (!show()) return;
      if (inspect && work.outcome && ruleOutcomeUnavailable(reason)) {
        const next = { ...work, outcomeContextKey: null };
        setAttempt(next);
        setRunError({
          ownerKey: work.ownerKey,
          message:
            "Current access could not confirm the original run. Check its status again to see the recorded outcome.",
        });
        if (lease) recovery.retain(recoveredDraft(next), lease);
        return;
      }
      if (
        inspect &&
        !work.outcome &&
        reason instanceof ApiError &&
        reason.code === "APPLICATION_RULE_WORKFLOW_UNAVAILABLE"
      ) {
        setUnconfirmedLookup({
          contextKey,
          operationId: work.packet.body.idempotencyKey,
        });
        setRunError({
          ownerKey: work.ownerKey,
          message:
            "No recorded outcome could be confirmed. The original run remains unresolved.",
        });
      } else if (
        !inspect &&
        reason instanceof ApiError &&
        reason.code === "OPERATION_ADMISSION_EXPIRED"
      ) {
        const next = { ...work, admissionExpired: true } as const;
        recovery.retain(recoveredDraft(next), lease);
        setAttempt(next);
        setRunError({
          ownerKey: work.ownerKey,
          message:
            "The original admission expired. Check the original outcome again.",
        });
      } else {
        setRunError({
          ownerKey: work.ownerKey,
          message:
            reason instanceof Error
              ? reason.message
              : "Unable to confirm the original rule run.",
        });
      }
    } finally {
      if (show()) finishRun(controller);
    }
  }
  async function recover(inspect: boolean, origin: HTMLButtonElement) {
    if (
      !ownAttempt ||
      runController.current ||
      (unresolved && !recovery.lease) ||
      (!inspect && !canRetryOriginal) ||
      !catalog?.functions[
        inspect ? "application.rule.run.read" : "application.rule.run"
      ]
    )
      return;
    const work = structuredClone(ownAttempt);
    const sequence = ++runSequence.current;
    const controller = new AbortController();
    runController.current = controller;
    retainRunFocus(origin);
    setRunStage(inspect ? "inspect" : "replay");
    setRunError(null);
    setUnconfirmedLookup(null);
    try {
      // Reserve a new observation before await so older mounts cannot settle it.
      const lease = unresolved
        ? recovery.retain(recoveredDraft(work), recovery.lease)
        : null;
      await sendOriginal(work, lease, controller, sequence, inspect);
    } catch (reason) {
      if (
        mounted.current &&
        currentOwner.current === work.ownerKey &&
        runSequence.current === sequence
      ) {
        setRunError({
          ownerKey: work.ownerKey,
          message:
            reason instanceof Error
              ? reason.message
              : "Original run recovery is unavailable.",
        });
        finishRun(controller);
      }
    }
  }
  async function run(origin: HTMLButtonElement) {
    if (
      !app ||
      !currentState ||
      currentContext.current !== contextKey ||
      !catalog?.functions["application.rule.run"] ||
      !selected ||
      selected.status !== "Active" ||
      !selected.executable ||
      !selected.programDigest ||
      selected.source?.active === false ||
      sourceCurrentness !== "current" ||
      ownAttempt ||
      busy ||
      runController.current
    )
      return;
    const sequence = ++runSequence.current;
    const controller = new AbortController();
    runController.current = controller;
    retainRunFocus(origin);
    setRunStage("prepare");
    setRunError(null);
    try {
      const inputError = parameterInputError(bindings, parameterSchema);
      if (inputError) throw new Error(inputError);
      const values = parseParameterJson(bindings);
      if (!values || typeof values !== "object" || Array.isArray(values))
        throw new Error("Rule parameters must be a JSON object.");
      const body = ruleRunBody(
        app,
        selected.ruleId,
        values as Record<string, unknown>,
        mutationKey({
          ownerKey,
          ruleId: selected.ruleId,
          stateToken: selected.stateToken,
          programDigest: selected.programDigest,
          bindings: values,
          runIntent,
        }),
        selected.stateToken,
        selected.programDigest,
      );
      const packet = (await prepareAdmittedProgramEffect(
        "/api/rule-action",
        body,
        body.idempotencyKey,
        controller.signal,
      )) as RuleRunPacket;
      if (
        !mounted.current ||
        currentContext.current !== contextKey ||
        runSequence.current !== sequence
      )
        return;
      const work: RuleRunAttempt = {
        ownerKey,
        packet,
        outcome: null,
        outcomeContextKey: null,
      };
      const lease = recovery.retain(recoveredDraft(work));
      setAttempt(work);
      setRunStage("submit");
      await sendOriginal(work, lease, controller, sequence, false);
    } catch (reason) {
      if (
        mounted.current &&
        currentContext.current === contextKey &&
        runSequence.current === sequence
      )
        setRunError({
          ownerKey,
          message:
            reason instanceof Error
              ? reason.message
              : "Unable to prepare the rule run.",
        });
    } finally {
      if (
        mounted.current &&
        currentContext.current === contextKey &&
        runSequence.current === sequence
      )
        finishRun(controller);
    }
  }
  if (!app || !catalog) return null;
  return (
    <section
      ref={rulesPanel}
      className="panel capability-activity"
      aria-label="Calculation rules"
    >
      <div className="section-heading-row">
        <div>
          <h2>Calculation rules</h2>
          <p>
            Open a rule to view or edit its Python source, then run the current
            active definition.
          </p>
        </div>
        <div>
          <button
            disabled={busy || !canRead}
            onClick={() => onRequestTransition(() => void loadRules())}
          >
            Refresh rules
          </button>
          {canCreate && (
            <button
              disabled={busy}
              onClick={() =>
                onRequestTransition(
                  () => {
                    if (currentContext.current !== contextKey) return;
                    bindingTarget.current = "";
                    setBindings("{}");
                    setSelected(null);
                    setCreating(true);
                  },
                  // Opening the blank editor (including after a section remount)
                  // restores its own draft and replaces no local rule/run state.
                  currentState &&
                    !selected &&
                    !creating &&
                    bindings === "{}" &&
                    bindingTarget.current === "" &&
                    !ownAttempt,
                )
              }
            >
              New rule
            </button>
          )}
        </div>
      </div>
      {!catalog.functions["application.rule.read"] && (
        <p>
          Calculation rules are not available in the current application
          context.
        </p>
      )}
      {currentState && error && <p role="alert">{error}</p>}
      {currentState && directoryIncomplete && (
        <p role="status">
          The rule list could not be completed.{" "}
          {rows.length ? "Earlier pages are available below. " : ""}
          Refresh rules to try again, or open a rule by its exact ID.
        </p>
      )}
      {currentState && Boolean(catalog.functions["application.rule.read"]) && (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const id = exactRuleId.trim();
            if (ruleIdPattern.test(id))
              onRequestTransition(() => void open(id));
          }}
        >
          <label>
            Exact rule ID{" "}
            <input
              type="text"
              value={exactRuleId}
              maxLength={200}
              onChange={(event) => setExactRuleId(event.target.value)}
            />
          </label>
          <button
            type="submit"
            disabled={!ruleIdPattern.test(exactRuleId.trim())}
          >
            Open rule by ID
          </button>
        </form>
      )}
      {currentState && busy && <p role="status">Working…</p>}
      {runError?.ownerKey === ownerKey && (
        <p role="alert">{runError.message}</p>
      )}
      <section
        aria-label={
          ownAttempt || runBusy ? "Original rule execution recovery" : undefined
        }
      >
        {ownAttempt && (
          <h3>
            Original rule run: {ownAttempt.packet.body.program.arguments.ruleId}
          </h3>
        )}
        <div role="status" ref={runStatus} tabIndex={-1}>
          {runStage
            ? ruleRunProgress[runStage]
            : visibleOutcome
              ? `Rule run ${workflowStatusLabel(visibleOutcome.status)} · ${workflowUnitCounts(visibleOutcome)}`
              : result
                ? "The original run was recorded earlier. Current access or rule context changed."
                : ownAttempt
                  ? "Rule run outcome unknown. Check the original outcome before retrying."
                  : ""}
        </div>
        {ownAttempt && (
          <>
            {visibleOutcome && (
              <>
                <p>
                  {visibleOutcome.status === "partially_published" &&
                  visibleOutcome.remainingUnits === 0
                    ? "Every checkpoint committed. The workflow stopped before publishing its final receipt."
                    : workflowCountGuidance(visibleOutcome.status)}
                </p>
                <WorkflowCheckpointEvidence
                  key={JSON.stringify([contextKey, visibleOutcome.workflowId])}
                  workflow={visibleOutcome}
                  scope={app}
                  catalog={catalog}
                  unitNames={visibleOutcome.lineage}
                />
              </>
            )}
            <p>
              The original definition and typed parameters are retained in this
              tab. Recovery never admits a new intent or runs the currently
              selected replacement source.
            </p>
            <details>
              <summary>Inspect original definition and parameters</summary>
              <pre>
                {JSON.stringify(
                  ownAttempt.packet.body.program.arguments,
                  null,
                  2,
                )}
              </pre>
            </details>
            {visibleOutcome?.freshness?.current === false && (
              <p>
                Original execution evidence is retained; its source or
                dependencies are no longer current.
              </p>
            )}
            {unresolved && (
              <>
                {canRetryOriginal && (
                  <button
                    {...transferAction(runBusy || !recovery.lease, (origin) =>
                      recover(false, origin),
                    )}
                  >
                    Retry original rule request
                  </button>
                )}
                {ownAttempt.admissionExpired &&
                  catalog.functions["application.rule.run.read"] && (
                    <p>
                      The original admission has expired. You can still check
                      its recorded outcome.
                    </p>
                  )}
              </>
            )}
            {(result || catalog.functions["application.rule.run.read"]) && (
              <button
                ref={readOriginalButton}
                {...transferAction(
                  runBusy ||
                    (unresolved && !recovery.lease) ||
                    !catalog.functions["application.rule.run.read"],
                  (origin) => recover(true, origin),
                )}
              >
                {result
                  ? "Refresh original run status"
                  : "Read original rule outcome"}
              </button>
            )}
            {!catalog.functions["application.rule.run.read"] && (
              <p>
                Original run status is unavailable in this application context.
              </p>
            )}
            {result && terminalWorkflowOutcome(result) && (
              <button
                {...transferAction(runBusy, (origin) => {
                  retainRunFocus(origin, true);
                  setAttempt(null);
                  setRunError(null);
                  setRunIntent((value) => value + 1);
                })}
              >
                Prepare another run
              </button>
            )}
          </>
        )}
      </section>
      {currentState && canRead && hasOperationFilter && (
        <label>
          Rule operations
          <select
            value={selectedFilter}
            onChange={(event) => {
              const next = event.target.value as keyof typeof ruleOperations;
              if (
                !Object.hasOwn(ruleOperations, next) ||
                next === selectedFilter
              )
                return;
              onRequestTransition(() => {
                if (currentContext.current !== contextKey) return;
                setRuleFilter({ owner: ownerKey, key: next });
                setRows([]);
                setRead(false);
                setDirectoryIncomplete(false);
                setSelected(null);
                void loadRules(next);
              });
            }}
          >
            <option value="all">All operations</option>
            <option value="ordered">Ordered numeric sequences</option>
            <option value="batch">Numeric batches</option>
          </select>
        </label>
      )}
      {currentState && canRead && read && (
        <>
          <label>
            Find rule
            <input
              ref={ruleSearch}
              aria-label="Find calculation rule"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(0);
              }}
            />
          </label>
          <table className="react-cube-grid">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Status</th>
                <th>Availability</th>
                <th>Metadata</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(start, start + 50).map((row) => (
                <tr key={row.ruleId}>
                  <th>
                    <button
                      onClick={() =>
                        onRequestTransition(
                          () =>
                            void open({
                              ruleId: row.ruleId,
                              stateToken: row.stateToken,
                              digest: row.programDigest,
                            }),
                        )
                      }
                    >
                      {row.ruleId}
                    </button>
                  </th>
                  <td>{row.status}</td>
                  <td>{ruleAvailabilityLabel(row)}</td>
                  <td>{row.metadataCurrent ? "Current" : "Stale"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && !directoryIncomplete && (
            <p>
              {selectedFilter === "ordered"
                ? "No current rules contain ordered numeric sequences."
                : selectedFilter === "batch"
                  ? "No current rules contain numeric batches."
                  : "No current application rules."}
            </p>
          )}
          <button
            disabled={start === 0}
            onClick={() => setPage(start / 50 - 1)}
          >
            Previous rules
          </button>
          <button
            disabled={start + 50 >= filtered.length}
            onClick={() => setPage(start / 50 + 1)}
          >
            Next rules
          </button>
        </>
      )}
      {currentState && (creating || selected) && (
        <article
          className="program-inspector"
          aria-label="Application rule detail"
        >
          <h3>{selected ? selected.ruleId : "New rule"}</h3>
          {selected && (
            <p aria-label="Current rule availability">
              {selected.status} · {ruleAvailabilityLabel(selected)}
            </p>
          )}
          <button
            onClick={() =>
              onRequestTransition(() => {
                if (currentContext.current !== contextKey) return;
                bindingTarget.current = "";
                setBindings("{}");
                setSelected(null);
                setCreating(false);
              })
            }
          >
            Close rule
          </button>
          {creating || (selected?.source && canInspectSource) ? (
            <PythonDefinitionEditor
              key={
                selected ? `${selected.ruleId}:${selected.stateToken}` : "new"
              }
              app={app}
              catalog={catalog}
              kind="ApplicationRule"
              binding={selected?.source}
              definitionId={selected?.ruleId}
              template={pythonDefinitionTemplates.ApplicationRule}
              onRefreshCatalog={onRefreshCatalog}
              onSourceCurrentness={(state) => {
                if (currentContext.current === contextKey)
                  setSourceCurrentness(state);
              }}
              onChanged={async (definition) => {
                const rows = await loadRules();
                const row = rows?.find(
                  (row) =>
                    row.ruleId ===
                    (definition?.definitionId ?? selected?.ruleId),
                );
                if (row)
                  await open({
                    ruleId: row.ruleId,
                    stateToken: row.stateToken,
                    digest: row.programDigest,
                  });
              }}
            />
          ) : !selected?.source ? (
            <p>This rule has no bound Python source.</p>
          ) : null}
          {selected?.program === null && (
            <p>
              No current compiled rule is available. Inspect and validate the
              current source before execution.
            </p>
          )}
          {selected && (
            <>
              {Boolean(catalog.functions["application.rule.run"]) && (
                <section aria-label="Run rule">
                  <ParameterFields
                    label="Rule parameters"
                    advancedLabel="Application rule parameters"
                    value={bindings}
                    schema={parameterSchema}
                    disabled={busy || runBusy || Boolean(ownAttempt)}
                    onChange={setBindings}
                  />
                  <button
                    ref={runButton}
                    {...transferAction(
                      busy ||
                        runBusy ||
                        Boolean(ownAttempt) ||
                        selected.status !== "Active" ||
                        !selected.executable ||
                        !selected.programDigest ||
                        selected.source?.active === false ||
                        sourceCurrentness !== "current",
                      run,
                    )}
                  >
                    Run rule
                  </button>
                  {selected.source && sourceCurrentness !== "current" && (
                    <p role="status">
                      {sourceCurrentness === "checking"
                        ? "Confirming the rule's current source before it can run."
                        : "The rule's bound source is unavailable or stale; refresh the exact current source before running."}
                    </p>
                  )}
                </section>
              )}
            </>
          )}
        </article>
      )}
    </section>
  );
}

function ruleReadAccessChanged(reason: unknown) {
  return (
    reason instanceof ApiError &&
    (reason.kind === "authorization" ||
      reason.kind === "authentication" ||
      reason.code === "RULE_READ_AUTHORIZATION_STALE")
  );
}

function ruleOutcomeUnavailable(reason: unknown) {
  return (
    ruleReadAccessChanged(reason) ||
    (reason instanceof ApiError &&
      [
        "APPLICATION_RULE_WORKFLOW_UNAVAILABLE",
        "APPLICATION_RULE_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED",
        "APPLICATION_UNAVAILABLE",
        "WORKSPACE_UNAVAILABLE",
        "BROWSER_IDENTITY_CHANGED",
      ].includes(reason.code))
  );
}
