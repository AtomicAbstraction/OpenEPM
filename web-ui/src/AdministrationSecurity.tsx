import { useEffect, useMemo, useRef, useState } from "react";
import { readSecurityProgram, request, requestAdmittedEffect } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";
import {
  collectSecuritySubjectOptions,
  type SecuritySubject,
} from "./security-directory";

type Grant = {
  subjectId: string;
  displayName: string | null;
  username: string | null;
  role: string;
  readTags: Record<string, string[]>;
  writeTags: Record<string, string[]>;
  rulePermissions: Record<string, boolean> | null;
  grantedAt: string;
};

type Policy = {
  stateToken: string | null;
  policyDigest: string | null;
  policy: Record<string, string> | null;
  securityRevision: number;
  authorizationEffect: boolean;
  status: string;
};

const POLICY_CHOICES = {
  acrossDimensions: ["every_protected", "any_protected"],
  withinDimension: ["any_tag", "all_tags"],
  untaggedMember: ["allow", "deny"],
  untaggedDenyPrecedence: ["absolute", "dimension_result"],
  memberTagCardinality: ["multiple", "exactly_one_when_protected"],
  hierarchyTags: ["selected_member_only", "effective_tags_resolved_by_server"],
  writeReadRelationship: ["require_read", "independent"],
  mixedSelection: [
    "filter_reads_reject_writes",
    "filter_reads_and_writes",
    "reject_all",
  ],
  administratorTreatment: ["require_assignment", "bypass"],
  factSideAuthority: ["derived_query_aid_only"],
} as const;

type PolicyKey = keyof typeof POLICY_CHOICES;
type PolicyAction = "save" | "activate" | "deactivate";

type DimensionAccess = {
  subjectId: string;
  displayName: string | null;
  username: string | null;
  role: string;
  readTags: Record<string, string[]>;
  writeTags: Record<string, string[]>;
  securityRevision: number;
};

type DimensionTag = {
  order: number;
  dimensionId: string;
  name: string;
  modelRole: string | null;
  readTags: string[];
  writeTags: string[];
};

type SecurityAuditEvent = {
  auditId: number;
  occurredAt: string;
  actorName: string;
  action: string;
  targetName: string;
  outcome: "Accepted" | "Rejected" | "Failed";
  detailsKey: string | null;
};

type SecurityAuditPage = {
  events: SecurityAuditEvent[];
  nextBeforeAuditId: number | null;
};

const MAX_AUDIT_EXPORT_EVENTS = 10_000;
const MAX_AUDIT_EXPORT_PAGES = 100;

export function accessListArguments(afterSubjectId?: string | null) {
  return afterSubjectId ? { afterSubjectId, limit: 100 } : { limit: 100 };
}

type AccessPage = { grants: Grant[]; nextAfterSubjectId: string | null };

export function collectSecuritySubjects(
  readPage: (
    arguments_: ReturnType<typeof accessListArguments>,
  ) => Promise<AccessPage>,
) {
  return collectAllContinuations<AccessPage, Grant>({
    label: "Application security subjects",
    readPage: (cursor) => readPage(accessListArguments(cursor)),
    rows: (page) => page.grants,
    nextCursor: (page) => page.nextAfterSubjectId,
    rowIdentity: (grant) => grant.subjectId,
  });
}

export function auditListArguments(beforeAuditId?: number | null) {
  return beforeAuditId ? { beforeAuditId, limit: 100 } : { limit: 100 };
}

function validatedAuditPage(
  value: SecurityAuditPage,
  beforeAuditId: number | null,
) {
  if (!value || !Array.isArray(value.events) || value.events.length > 100)
    throw new Error("Security audit page is invalid.");
  let prior = beforeAuditId;
  for (const event of value.events) {
    if (
      !event ||
      !Number.isSafeInteger(event.auditId) ||
      event.auditId < 1 ||
      (prior !== null && event.auditId >= prior) ||
      typeof event.occurredAt !== "string" ||
      !event.occurredAt ||
      typeof event.actorName !== "string" ||
      !event.actorName ||
      typeof event.action !== "string" ||
      !event.action ||
      typeof event.targetName !== "string" ||
      !event.targetName ||
      !["Accepted", "Rejected", "Failed"].includes(event.outcome) ||
      (event.detailsKey !== null &&
        (typeof event.detailsKey !== "string" ||
          !event.detailsKey ||
          event.detailsKey.length > 200))
    )
      throw new Error("Security audit page contains an invalid event.");
    prior = event.auditId;
  }
  const cursor = value.nextBeforeAuditId;
  if (
    cursor !== null &&
    (!Number.isSafeInteger(cursor) ||
      cursor < 1 ||
      !value.events.length ||
      cursor !== value.events.at(-1)?.auditId)
  )
    throw new Error("Security audit page returned an invalid cursor.");
  return value;
}

export async function collectCompleteSecurityAudit(
  readPage: (
    arguments_: ReturnType<typeof auditListArguments>,
  ) => Promise<SecurityAuditPage>,
) {
  const events: SecurityAuditEvent[] = [];
  const seen = new Set<number>();
  let cursor: number | null = null;
  for (let pageNumber = 0; pageNumber < MAX_AUDIT_EXPORT_PAGES; pageNumber++) {
    const page = validatedAuditPage(
      await readPage(auditListArguments(cursor)),
      cursor,
    );
    for (const event of page.events) {
      if (seen.has(event.auditId))
        throw new Error("Security audit continuation repeated an event.");
      seen.add(event.auditId);
      events.push(event);
      if (events.length > MAX_AUDIT_EXPORT_EVENTS)
        throw new Error(
          "Security audit export exceeds the 10,000-event bound.",
        );
    }
    if (page.nextBeforeAuditId === null) return events;
    if (events.length === MAX_AUDIT_EXPORT_EVENTS)
      throw new Error("Security audit export exceeds the 10,000-event bound.");
    cursor = page.nextBeforeAuditId;
  }
  throw new Error("Security audit export exceeds the 100-page bound.");
}

function csvValue(value: string | number | null) {
  const text = value === null ? "" : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export function securityAuditCsv(events: SecurityAuditEvent[]) {
  const rows = events.map((event) =>
    [
      event.occurredAt,
      event.actorName,
      event.action,
      event.targetName,
      event.outcome,
    ]
      .map(csvValue)
      .join(","),
  );
  return ["occurredAt,actor,action,target,outcome", ...rows].join("\r\n");
}

function grantLabel(grant: Pick<Grant, "displayName" | "username">) {
  return (
    grant.displayName || grant.username || "Unavailable directory identity"
  );
}

function securitySubjectLabel(subject: SecuritySubject) {
  return subject.username && subject.username !== subject.displayName
    ? `${subject.displayName} (${subject.username})`
    : subject.displayName;
}

export function accessMutationBody(
  app: ApplicationSummary,
  subjectId: string,
  action: "grant" | "revoke",
  role: "Reader" | "Editor" | "Administrator",
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: "security.application.access.set",
      arguments: {
        subjectId,
        action,
        role: action === "grant" ? role : null,
      },
    },
  };
}

export function ruleAccessMutationBody(
  app: ApplicationSummary,
  subjectId: string,
  action: "set" | "revoke",
  permissions: { design: boolean; publish: boolean; run: boolean },
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: "security.rule.access.set",
      arguments: {
        subjectId,
        action,
        permissions: action === "set" ? permissions : null,
      },
    },
  };
}

export function parseSecurityTags(value: string, available: string[]) {
  const tags = value
    .split(";")
    .map((tag) => tag.trim())
    .filter(Boolean);
  if (tags.length !== new Set(tags).size)
    throw new Error("Duplicate dimensional-security tag.");
  const unknown = tags.filter((tag) => !available.includes(tag));
  if (unknown.length)
    throw new Error(`Unknown dimensional-security tag: ${unknown.join(", ")}.`);
  return tags.sort();
}

export function dimensionAccessMutationBody(
  app: ApplicationSummary,
  subjectId: string,
  readTags: Record<string, string[]>,
  writeTags: Record<string, string[]>,
  expectedSecurityRevision: number,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: "security.application.dimension-access.set",
      arguments: {
        subjectId,
        readTags,
        writeTags,
        expectedSecurityRevision,
      },
    },
  };
}

export function dimensionPolicyMutationBody(
  app: ApplicationSummary,
  action: PolicyAction,
  stateToken: string | null,
  policy: Record<string, string> | null,
  expectedSecurityRevision: number,
  idempotencyKey: string,
) {
  const functionName =
    action === "save"
      ? "security.application.dimension-policy.save"
      : `security.application.dimension-policy.${action}`;
  const args =
    action === "save"
      ? stateToken
        ? { expectedStateToken: stateToken, policy }
        : { policy }
      : action === "activate"
        ? { expectedStateToken: stateToken, expectedSecurityRevision }
        : { expectedStateToken: stateToken, expectedSecurityRevision };
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: functionName,
      arguments: args,
    },
  };
}

function enabledPermissions(grant: Grant) {
  const enabled = Object.entries(grant.rulePermissions || {})
    .filter(([, value]) => value)
    .map(([name]) => name);
  return enabled.length ? enabled.join(", ") : "None";
}

function assignment(tags: Record<string, string[]>, dimensionId: string) {
  return tags[dimensionId]?.join(", ") || "Unassigned";
}

type SecurityView = "access" | "policy" | "audit";
type SecurityProps = {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  view?: SecurityView;
  onRequestTransition?: (action: () => void) => void;
};

export function AdministrationSecurity(props: SecurityProps) {
  return (
    <SecurityWorkspace
      key={`${props.app?.workspaceId || "none"}:${props.app?.applicationId || "none"}:${props.view || "access"}`}
      {...props}
    />
  );
}

function SecurityWorkspace({
  app,
  catalog,
  view = "access",
  onRequestTransition,
}: SecurityProps) {
  const [editor, setEditor] = useState<"grant" | "dimensions" | "rules" | null>(
    null,
  );
  const [policyOpen, setPolicyOpen] = useState(false);
  const [readState, setReadState] = useState<
    "idle" | "loading" | "ready" | "error"
  >("idle");
  const [operationResult, setOperationResult] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const editorHeading = useRef<HTMLHeadingElement | null>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const scopeGeneration = useRef(0);
  const readController = useRef<AbortController | null>(null);
  const exportController = useRef<AbortController | null>(null);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [policyDraft, setPolicyDraft] = useState<Record<string, string>>({});
  const [policyReviewed, setPolicyReviewed] = useState<PolicyAction | null>(
    null,
  );
  const [selected, setSelected] = useState<DimensionAccess | null>(null);
  const [dimensions, setDimensions] = useState<DimensionTag[]>([]);
  const [dimensionDraft, setDimensionDraft] = useState<{
    readTags: Record<string, string>;
    writeTags: Record<string, string>;
  }>({ readTags: {}, writeTags: {} });
  const [dimensionReviewed, setDimensionReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [accessSubject, setAccessSubject] = useState("");
  const [accessAction, setAccessAction] = useState<"grant" | "revoke">("grant");
  const [accessRole, setAccessRole] = useState<
    "Reader" | "Editor" | "Administrator"
  >("Reader");
  const [accessReviewed, setAccessReviewed] = useState(false);
  const [ruleSubject, setRuleSubject] = useState("");
  const [ruleAction, setRuleAction] = useState<"set" | "revoke">("set");
  const [rulePermissions, setRulePermissions] = useState({
    design: false,
    publish: false,
    run: false,
  });
  const [ruleReviewed, setRuleReviewed] = useState(false);
  const [auditEvents, setAuditEvents] = useState<SecurityAuditEvent[]>([]);
  const [securitySubjects, setSecuritySubjects] = useState<SecuritySubject[]>(
    [],
  );
  const [auditCursor, setAuditCursor] = useState<number | null>(null);
  const [exportingAudit, setExportingAudit] = useState(false);
  const mutationKey = useStableMutationIntentKey("security-ui");

  const canList = Boolean(
    catalog?.functions["security.application.access.list"],
  );
  const canListSubjects = Boolean(
    catalog?.functions["security.application.subject.list"],
  );
  const canReadPolicy = Boolean(
    catalog?.functions["security.application.dimension-policy.read"],
  );
  const canReadAssignments = Boolean(
    catalog?.functions["security.application.dimension-access.read"] &&
      catalog?.functions["security.application.dimension-tags.read"],
  );
  const canReadAudit = Boolean(
    catalog?.functions["security.application.audit.list"],
  );
  const canWriteAccess = Boolean(
    catalog?.functions["security.application.access.set"],
  );
  const canWriteRuleAccess = Boolean(
    catalog?.functions["security.rule.access.set"],
  );
  const canWriteDimensionAccess = Boolean(
    catalog?.functions["security.application.dimension-access.set"],
  );
  const canSavePolicy = Boolean(
    catalog?.functions["security.application.dimension-policy.save"],
  );
  const canActivatePolicy = Boolean(
    catalog?.functions["security.application.dimension-policy.activate"],
  );
  const canDeactivatePolicy = Boolean(
    catalog?.functions["security.application.dimension-policy.deactivate"],
  );
  const policyBaseline = policy?.policy || {};
  const policyChanged =
    Boolean(policy) &&
    JSON.stringify(policyDraft) !== JSON.stringify(policyBaseline);
  const dimensionBaseline = selected
    ? {
        readTags: Object.fromEntries(
          dimensions.map((dimension) => [
            dimension.dimensionId,
            (selected.readTags[dimension.dimensionId] || []).join("; "),
          ]),
        ),
        writeTags: Object.fromEntries(
          dimensions.map((dimension) => [
            dimension.dimensionId,
            (selected.writeTags[dimension.dimensionId] || []).join("; "),
          ]),
        ),
      }
    : { readTags: {}, writeTags: {} };
  const dimensionChanged =
    Boolean(selected) &&
    JSON.stringify(dimensionDraft) !== JSON.stringify(dimensionBaseline);
  const ruleGrant = grants.find((grant) => grant.subjectId === ruleSubject);
  const accessSubjectOption = securitySubjects.find(
    (subject) => subject.selectionKey === accessSubject,
  );
  const ruleBaseline = {
    design: Boolean(ruleGrant?.rulePermissions?.design),
    publish: Boolean(ruleGrant?.rulePermissions?.publish),
    run: Boolean(ruleGrant?.rulePermissions?.run),
  };
  const ruleChanged = Boolean(
    ruleSubject &&
      (ruleAction === "revoke" ||
        JSON.stringify(rulePermissions) !== JSON.stringify(ruleBaseline)),
  );
  useUnsavedWork(
    `application-security:${app?.workspaceId || "none"}:${app?.applicationId || "none"}`,
    "Unsaved application security changes",
    Boolean(
      policyChanged || dimensionChanged || accessSubject.trim() || ruleChanged,
    ),
  );

  const dirty = Boolean(
    policyChanged || dimensionChanged || accessSubject.trim() || ruleChanged,
  );
  const filteredGrants = useMemo(
    () =>
      grants.filter((grant) =>
        `${grantLabel(grant)} ${grant.username || ""} ${grant.role}`
          .toLocaleLowerCase()
          .includes(query.trim().toLocaleLowerCase()),
      ),
    [grants, query],
  );
  const first = Math.min(
    page * 50,
    Math.max(0, Math.ceil(filteredGrants.length / 50) - 1) * 50,
  );
  const visibleGrants = filteredGrants.slice(first, first + 50);
  useEffect(() => setPage(0), [query]);
  useEffect(() => {
    const generation = ++scopeGeneration.current;
    return () => {
      if (scopeGeneration.current === generation) scopeGeneration.current += 1;
      readController.current?.abort();
      exportController.current?.abort();
    };
  }, []);
  useEffect(() => {
    if (editor || policyOpen) editorHeading.current?.focus();
  }, [editor, policyOpen, selected?.subjectId, ruleSubject]);

  function resetDrafts() {
    setEditor(null);
    setPolicyOpen(false);
    setPolicyDraft(policyBaseline);
    setPolicyReviewed(null);
    setSelected(null);
    setDimensions([]);
    setDimensionDraft({ readTags: {}, writeTags: {} });
    setDimensionReviewed(false);
    setAccessSubject("");
    setAccessAction("grant");
    setAccessRole("Reader");
    setAccessReviewed(false);
    setRuleSubject("");
    setRuleAction("set");
    setRulePermissions({ design: false, publish: false, run: false });
    setRuleReviewed(false);
  }

  function transition(action: () => void, rememberFocus = true) {
    if (busy || exportingAudit) return;
    if (rememberFocus)
      returnFocus.current =
        document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null;
    const accepted = () => {
      resetDrafts();
      setError("");
      action();
    };
    if (dirty && onRequestTransition) onRequestTransition(accepted);
    else if (!dirty || window.confirm("Discard the unsaved security changes?"))
      accepted();
  }

  function closeEditor() {
    transition(() => {
      if (returnFocus.current?.isConnected) returnFocus.current.focus();
    }, false);
  }

  function beginRead() {
    readController.current?.abort();
    const controller = new AbortController();
    readController.current = controller;
    const generation = scopeGeneration.current;
    return {
      signal: controller.signal,
      current: () =>
        generation === scopeGeneration.current &&
        !controller.signal.aborted &&
        readController.current === controller,
    };
  }

  async function readSecurity() {
    const allowed =
      view === "access"
        ? canList
        : view === "policy"
          ? canReadPolicy
          : canReadAudit;
    if (!app || !allowed) return;
    const owned = beginRead();
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    setBusy(true);
    setReadState("loading");
    setError("");
    try {
      if (view === "access") {
        const [subjectResult, directoryResult] = await Promise.all([
          collectSecuritySubjects((arguments_) =>
            readSecurityProgram(
              scope,
              "security.application.access.list",
              arguments_,
              owned.signal,
            ),
          ),
          canListSubjects
            ? collectSecuritySubjectOptions((arguments_) =>
                readSecurityProgram(
                  scope,
                  "security.application.subject.list",
                  arguments_,
                  owned.signal,
                ),
              )
            : Promise.resolve({ rows: [] as SecuritySubject[] }),
        ]);
        if (!owned.current()) return;
        setGrants(subjectResult.rows);
        setSecuritySubjects(
          [...directoryResult.rows].sort(
            (left, right) =>
              left.displayName.localeCompare(right.displayName, undefined, {
                sensitivity: "base",
              }) ||
              left.username.localeCompare(right.username, undefined, {
                sensitivity: "base",
              }),
          ),
        );
      } else if (view === "policy") {
        const current = await readSecurityProgram<Policy>(
          scope,
          "security.application.dimension-policy.read",
          {},
          owned.signal,
        );
        if (!owned.current()) return;
        setPolicy(current);
        setPolicyDraft(current.policy || {});
        setPolicyReviewed(null);
      } else {
        const result = validatedAuditPage(
          await readSecurityProgram<SecurityAuditPage>(
            scope,
            "security.application.audit.list",
            auditListArguments(),
            owned.signal,
          ),
          null,
        );
        if (!owned.current()) return;
        setAuditEvents(result.events);
        setAuditCursor(result.nextBeforeAuditId);
      }
      setReadState("ready");
    } catch (reason) {
      if (!owned.current()) return;
      setReadState("error");
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read application security",
      );
    } finally {
      if (owned.current()) setBusy(false);
    }
  }

  async function loadOlderAudit() {
    if (!app || !canReadAudit || !auditCursor) return;
    const owned = beginRead();
    setBusy(true);
    setError("");
    try {
      const page = validatedAuditPage(
        await readSecurityProgram<SecurityAuditPage>(
          { workspaceId: app.workspaceId, applicationId: app.applicationId },
          "security.application.audit.list",
          auditListArguments(auditCursor),
          owned.signal,
        ),
        auditCursor,
      );
      if (!owned.current()) return;
      setAuditEvents((current) => [...current, ...page.events]);
      setAuditCursor(page.nextBeforeAuditId);
    } catch (reason) {
      if (!owned.current()) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read older security audit events",
      );
    } finally {
      if (owned.current()) setBusy(false);
    }
  }

  async function exportCompleteAudit() {
    if (!app || !canReadAudit) return;
    const controller = new AbortController();
    exportController.current?.abort();
    exportController.current = controller;
    const generation = scopeGeneration.current;
    const current = () =>
      generation === scopeGeneration.current && !controller.signal.aborted;
    setExportingAudit(true);
    setError("");
    try {
      const scope = {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
      };
      const events = await collectCompleteSecurityAudit((arguments_) =>
        readSecurityProgram<SecurityAuditPage>(
          scope,
          "security.application.audit.list",
          arguments_,
          controller.signal,
        ),
      );
      if (!current()) return;
      const blob = new Blob([securityAuditCsv(events)], {
        type: "text/csv;charset=utf-8",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${app.name.replace(/[^A-Za-z0-9._-]+/g, "-")}-security-audit.csv`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (reason) {
      if (!current()) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to export the complete security audit",
      );
    } finally {
      if (current()) setExportingAudit(false);
    }
  }

  function policyDraftValid() {
    return (Object.keys(POLICY_CHOICES) as PolicyKey[]).every((name) =>
      (POLICY_CHOICES[name] as readonly string[]).includes(policyDraft[name]),
    );
  }

  function updatePolicyDraft(name: PolicyKey, value: string) {
    if (busy) return;
    setPolicyDraft((current) => ({ ...current, [name]: value }));
    setPolicyReviewed(null);
  }

  async function applyPolicyMutation(action: PolicyAction) {
    if (busy || !app || !policy || policyReviewed !== action) return;
    if (
      (action === "save" && (!canSavePolicy || !policyDraftValid())) ||
      (action === "activate" &&
        (!canActivatePolicy ||
          !policy.stateToken ||
          policy.status !== "Saved")) ||
      (action === "deactivate" &&
        (!canDeactivatePolicy ||
          !policy.stateToken ||
          policy.status !== "Active"))
    )
      return;
    const wording =
      action === "save"
        ? "Save the current dimensional policy?"
        : action === "activate"
          ? "Activate the current dimensional policy?"
          : "Deactivate the current dimensional policy?";
    if (!window.confirm(wording)) return;
    const generation = scopeGeneration.current;
    setBusy(true);
    setOperationResult("");
    setError("");

    try {
      const response = await requestAdmittedEffect<{
        result: { changed?: boolean };
      }>(
        "/api/security",
        dimensionPolicyMutationBody(
          app,
          action,
          policy.stateToken,
          action === "save" ? policyDraft : null,
          policy.securityRevision,
          mutationKey({
            operation: "dimension-policy",
            action,
            stateToken: policy.stateToken,
            policy: action === "save" ? policyDraft : null,
            securityRevision: policy.securityRevision,
          }),
        ),
      );
      if (generation !== scopeGeneration.current) return;
      setOperationResult(
        response.result.changed === false
          ? "The reviewed policy already matched the current state."
          : "The reviewed policy change was committed.",
      );
      resetDrafts();
      setPolicyReviewed(null);
      await readSecurity();
    } catch (reason) {
      if (generation !== scopeGeneration.current) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to change dimensional policy",
      );
    } finally {
      if (generation === scopeGeneration.current) setBusy(false);
    }
  }

  async function readAssignments(grant: Grant) {
    if (!app || !canReadAssignments) return;
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    const owned = beginRead();
    setBusy(true);
    setError("");
    try {
      const [access, tags] = await Promise.all([
        readSecurityProgram<DimensionAccess>(
          scope,
          "security.application.dimension-access.read",
          { subjectId: grant.subjectId },
          owned.signal,
        ),
        readSecurityProgram<{
          dimensions: DimensionTag[];
          securityRevision: number;
        }>(scope, "security.application.dimension-tags.read", {}, owned.signal),
      ]);
      if (!owned.current()) return;
      if (access.securityRevision !== tags.securityRevision)
        throw new Error("Security revision changed while reading assignments.");
      setSelected({
        ...access,
        displayName: grant.displayName,
        username: grant.username,
      });
      setEditor("dimensions");
      setDimensions(tags.dimensions);
      setDimensionDraft({
        readTags: Object.fromEntries(
          tags.dimensions.map((dimension) => [
            dimension.dimensionId,
            (access.readTags[dimension.dimensionId] || []).join("; "),
          ]),
        ),
        writeTags: Object.fromEntries(
          tags.dimensions.map((dimension) => [
            dimension.dimensionId,
            (access.writeTags[dimension.dimensionId] || []).join("; "),
          ]),
        ),
      });
      setDimensionReviewed(false);
    } catch (reason) {
      if (!owned.current()) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read dimensional assignments",
      );
    } finally {
      if (owned.current()) setBusy(false);
    }
  }

  function updateDimensionDraft(
    kind: "readTags" | "writeTags",
    dimensionId: string,
    value: string,
  ) {
    if (busy) return;
    setDimensionDraft((current) => ({
      ...current,
      [kind]: { ...current[kind], [dimensionId]: value },
    }));
    setDimensionReviewed(false);
  }

  function collectDimensionDraft() {
    const readTags: Record<string, string[]> = {};
    const writeTags: Record<string, string[]> = {};
    for (const dimension of dimensions) {
      const reads = parseSecurityTags(
        dimensionDraft.readTags[dimension.dimensionId] || "",
        dimension.readTags,
      );
      const writes = parseSecurityTags(
        dimensionDraft.writeTags[dimension.dimensionId] || "",
        dimension.writeTags,
      );
      if (reads.length) readTags[dimension.dimensionId] = reads;
      if (writes.length) writeTags[dimension.dimensionId] = writes;
    }
    return { readTags, writeTags };
  }

  function dimensionDraftValid() {
    if (!selected || !dimensions.length) return false;
    try {
      collectDimensionDraft();
      return true;
    } catch {
      return false;
    }
  }

  async function applyDimensionMutation() {
    if (
      busy ||
      !app ||
      !selected ||
      !canWriteDimensionAccess ||
      !dimensionReviewed ||
      !dimensionDraftValid()
    )
      return;
    if (!window.confirm("Save these exact dimensional assignments?")) return;
    const generation = scopeGeneration.current;
    setBusy(true);
    setOperationResult("");
    setError("");

    try {
      const assignments = collectDimensionDraft();
      const response = await requestAdmittedEffect<{
        result: { changed: boolean; securityRevision: number };
      }>(
        "/api/security",
        dimensionAccessMutationBody(
          app,
          selected.subjectId,
          assignments.readTags,
          assignments.writeTags,
          selected.securityRevision,
          mutationKey({
            operation: "dimension-access",
            subjectId: selected.subjectId,
            ...assignments,
            securityRevision: selected.securityRevision,
          }),
        ),
      );
      if (generation !== scopeGeneration.current) return;
      setOperationResult(
        response.result.changed === false
          ? "The reviewed dimensional assignments already matched the current state."
          : "The reviewed dimensional assignments change was committed.",
      );
      resetDrafts();
      setDimensionReviewed(false);
      await readSecurity();
    } catch (reason) {
      if (generation !== scopeGeneration.current) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to change dimensional assignments",
      );
    } finally {
      if (generation === scopeGeneration.current) setBusy(false);
    }
  }

  function updateAccessSubject(value: string) {
    if (busy) return;
    setAccessSubject(value);
    setAccessReviewed(false);
  }

  async function applyAccessMutation() {
    const subjectId = accessSubject.trim();
    if (busy || !app || !canWriteAccess || !subjectId || !accessReviewed)
      return;
    const wording =
      accessAction === "grant"
        ? `Grant or update ${accessRole} access for this exact identity?`
        : "Revoke application access for this exact identity?";
    if (!window.confirm(wording)) return;
    const generation = scopeGeneration.current;
    setBusy(true);
    setOperationResult("");
    setError("");

    try {
      const response = await requestAdmittedEffect<{
        result: { changed: boolean };
      }>(
        "/api/security",
        accessMutationBody(
          app,
          subjectId,
          accessAction,
          accessRole,
          mutationKey({
            operation: "application-access",
            subjectId,
            action: accessAction,
            role: accessRole,
          }),
        ),
      );
      if (generation !== scopeGeneration.current) return;
      setOperationResult(
        response.result.changed === false
          ? "The reviewed application access already matched the current state."
          : "The reviewed application access change was committed.",
      );
      resetDrafts();
      setAccessReviewed(false);
      await readSecurity();
    } catch (reason) {
      if (generation !== scopeGeneration.current) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to change access",
      );
    } finally {
      if (generation === scopeGeneration.current) setBusy(false);
    }
  }

  function chooseRuleGrant(grant: Grant) {
    setRuleSubject(grant.subjectId);
    setRuleAction("set");
    setRulePermissions({
      design: Boolean(grant.rulePermissions?.design),
      publish: Boolean(grant.rulePermissions?.publish),
      run: Boolean(grant.rulePermissions?.run),
    });
    setRuleReviewed(false);
  }

  function updateRulePermission(
    name: "design" | "publish" | "run",
    value: boolean,
  ) {
    if (busy) return;
    setRulePermissions((current) => ({ ...current, [name]: value }));
    setRuleReviewed(false);
  }

  async function applyRuleMutation() {
    const validSet = Object.values(rulePermissions).some(Boolean);
    if (
      busy ||
      !app ||
      !canWriteRuleAccess ||
      !ruleSubject ||
      !ruleReviewed ||
      (ruleAction === "set" && !validSet)
    )
      return;
    const wording =
      ruleAction === "set"
        ? "Save these exact rule permissions for the selected identity?"
        : "Revoke all rule permissions for the selected identity?";
    if (!window.confirm(wording)) return;
    const generation = scopeGeneration.current;
    setBusy(true);
    setOperationResult("");
    setError("");

    try {
      const response = await requestAdmittedEffect<{
        result: { changed: boolean };
      }>(
        "/api/security",
        ruleAccessMutationBody(
          app,
          ruleSubject,
          ruleAction,
          rulePermissions,
          mutationKey({
            operation: "rule-access",
            subjectId: ruleSubject,
            action: ruleAction,
            permissions: rulePermissions,
          }),
        ),
      );
      if (generation !== scopeGeneration.current) return;
      setOperationResult(
        response.result.changed === false
          ? "The reviewed rule permissions already matched the current state."
          : "The reviewed rule permissions change was committed.",
      );
      resetDrafts();
      setRuleReviewed(false);
      await readSecurity();
    } catch (reason) {
      if (generation !== scopeGeneration.current) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to change rule permissions",
      );
    } finally {
      if (generation === scopeGeneration.current) setBusy(false);
    }
  }

  const allowed =
    view === "access"
      ? canList
      : view === "policy"
        ? canReadPolicy
        : canReadAudit;
  if (!allowed) return null;

  return (
    <section
      className="panel capability-activity security-workspace"
      aria-labelledby="application-security-heading"
    >
      <div className="section-heading-row">
        <div>
          <h2 id="application-security-heading" tabIndex={-1}>
            {view === "access"
              ? "Application users and roles"
              : view === "policy"
                ? "Dimensional policy"
                : "Security audit"}
          </h2>
          <p>
            {view === "access"
              ? "Inspect application access, then choose the user or permission you want to change."
              : view === "policy"
                ? "Inspect the current policy before making a reviewed change."
                : "Inspect security events and the receipts for committed changes."}
          </p>
        </div>
        <div className="security-heading-actions">
          <button
            disabled={busy || exportingAudit}
            onClick={() => transition(() => void readSecurity())}
          >
            {readState === "loading"
              ? "Reading…"
              : view === "access"
                ? "Read access"
                : view === "policy"
                  ? "Read policy"
                  : "Read audit"}
          </button>
          {view === "access" && canWriteAccess && canListSubjects && (
            <button
              className="primary"
              disabled={busy || exportingAudit || readState !== "ready"}
              aria-expanded={editor === "grant"}
              aria-controls="application-access-editor"
              onClick={() => transition(() => setEditor("grant"))}
            >
              Grant access
            </button>
          )}
        </div>
      </div>
      {operationResult && (
        <p className="operation-notice" role="status">
          {operationResult}
        </p>
      )}
      {readState === "loading" && (
        <p role="status">
          Loading{" "}
          {view === "access"
            ? "application access"
            : view === "policy"
              ? "dimensional policy"
              : "security audit"}
          …
        </p>
      )}
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {view === "policy" && !policy && readState !== "loading" && (
        <p className="empty-state">
          {readState === "error"
            ? "The policy could not be loaded. Use Read policy to retry."
            : "Read the dimensional policy to inspect its current state."}
        </p>
      )}
      {view === "policy" && policy && (
        <div aria-label="Active policy">
          <div className="security-policy-summary">
            <div>
              <small>DIMENSIONAL POLICY</small>
              <strong>{policy.status}</strong>
            </div>
            <div>
              <small>CURRENT POLICY</small>
              <strong>{policy.stateToken ? "Saved" : "None"}</strong>
            </div>
            <div>
              <small>POLICY INFORMATION</small>
              <strong>Current</strong>
            </div>
            <div>
              <small>AUTHORIZATION EFFECT</small>
              <strong>
                {policy.authorizationEffect ? "Active" : "Inactive"}
              </strong>
            </div>
          </div>
          {(canSavePolicy || canActivatePolicy || canDeactivatePolicy) && (
            <button
              disabled={busy || readState !== "ready"}
              aria-expanded={policyOpen}
              aria-controls="dimensional-policy-editor"
              onClick={() =>
                policyOpen
                  ? editorHeading.current?.focus()
                  : transition(() => setPolicyOpen(true))
              }
            >
              Change dimensional policy
            </button>
          )}
          {(canSavePolicy || canActivatePolicy || canDeactivatePolicy) &&
            policyOpen && (
              <article
                id="dimensional-policy-editor"
                className="program-inspector access-editor"
              >
                <div className="section-heading-row">
                  <h3 tabIndex={-1} ref={editorHeading}>
                    Reviewed dimensional policy
                  </h3>
                  <button disabled={busy} onClick={closeEditor}>
                    Close policy editor
                  </button>
                </div>
                <fieldset className="security-editor-fields" disabled={busy}>
                  <p>
                    Save the current definition, activate that exact saved
                    state, or explicitly deactivate it.
                  </p>
                  <div className="policy-choice-grid">
                    {(Object.keys(POLICY_CHOICES) as PolicyKey[]).map(
                      (name) => (
                        <label key={name}>
                          {name}
                          <select
                            aria-label={`Policy ${name}`}
                            value={policyDraft[name] || ""}
                            onChange={(event) =>
                              updatePolicyDraft(name, event.target.value)
                            }
                          >
                            <option value="">Choose…</option>
                            {POLICY_CHOICES[name].map((value) => (
                              <option key={value} value={value}>
                                {value}
                              </option>
                            ))}
                          </select>
                        </label>
                      ),
                    )}
                  </div>
                  {canSavePolicy && (
                    <div className="reviewed-inline-action">
                      <label className="review-check">
                        <input
                          type="checkbox"
                          checked={policyReviewed === "save"}
                          disabled={!policyDraftValid()}
                          onChange={(event) =>
                            setPolicyReviewed(
                              event.target.checked ? "save" : null,
                            )
                          }
                        />
                        I reviewed all ten choices for this current policy.
                      </label>
                      <button
                        disabled={
                          busy ||
                          policyReviewed !== "save" ||
                          !policyDraftValid()
                        }
                        onClick={() => void applyPolicyMutation("save")}
                      >
                        Save current policy
                      </button>
                    </div>
                  )}
                  {canActivatePolicy &&
                    policy.stateToken &&
                    policy.status === "Saved" && (
                      <div className="reviewed-inline-action">
                        <label className="review-check">
                          <input
                            type="checkbox"
                            checked={policyReviewed === "activate"}
                            onChange={(event) =>
                              setPolicyReviewed(
                                event.target.checked ? "activate" : null,
                              )
                            }
                          />
                          I reviewed this exact saved state.
                        </label>
                        <button
                          disabled={busy || policyReviewed !== "activate"}
                          onClick={() => void applyPolicyMutation("activate")}
                        >
                          Activate current policy
                        </button>
                      </div>
                    )}
                  {canDeactivatePolicy &&
                    policy.stateToken &&
                    policy.status === "Active" && (
                      <div className="reviewed-inline-action">
                        <label className="review-check">
                          <input
                            type="checkbox"
                            checked={policyReviewed === "deactivate"}
                            onChange={(event) =>
                              setPolicyReviewed(
                                event.target.checked ? "deactivate" : null,
                              )
                            }
                          />
                          I reviewed deactivation of the current policy.
                        </label>
                        <button
                          className="danger"
                          disabled={busy || policyReviewed !== "deactivate"}
                          onClick={() => void applyPolicyMutation("deactivate")}
                        >
                          Deactivate current policy
                        </button>
                      </div>
                    )}
                </fieldset>
              </article>
            )}
        </div>
      )}
      {view === "access" && (
        <>
          {grants.length > 0 && (
            <label className="form-field security-catalog-search">
              Find an application user
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="User name or role"
              />
            </label>
          )}
          {grants.length ? (
            <div
              className="react-grid-scroll"
              role="region"
              aria-label="Scrollable security records"
              tabIndex={0}
            >
              <table
                className="react-cube-grid security-grant-grid"
                aria-label="Application access"
              >
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Role</th>
                    <th>Rule permissions</th>
                    <th>Granted</th>
                    <th>Dimensional access</th>
                    {canWriteRuleAccess && <th>Rule access</th>}
                  </tr>
                </thead>
                <tbody>
                  {visibleGrants.map((grant) => (
                    <tr key={grant.subjectId}>
                      <th>{grantLabel(grant)}</th>
                      <td>{grant.role}</td>
                      <td>{enabledPermissions(grant)}</td>
                      <td>{new Date(grant.grantedAt).toLocaleString()}</td>
                      <td>
                        <button
                          disabled={
                            busy || readState !== "ready" || !canReadAssignments
                          }
                          onClick={() =>
                            transition(() => void readAssignments(grant))
                          }
                        >
                          Inspect
                        </button>
                      </td>
                      {canWriteRuleAccess && (
                        <td>
                          <button
                            disabled={busy || readState !== "ready"}
                            onClick={() =>
                              transition(() => {
                                chooseRuleGrant(grant);
                                setEditor("rules");
                              })
                            }
                          >
                            Manage
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            readState !== "loading" && (
              <p className="empty-state">
                {readState === "ready"
                  ? "No application users were returned."
                  : readState === "error"
                    ? "Application access could not be loaded. Use Read access to retry."
                    : "Read current application access to begin."}
              </p>
            )
          )}
          {grants.length > 0 && (
            <div className="workspace-window-controls">
              <span>
                {filteredGrants.length
                  ? `${first + 1}–${first + visibleGrants.length} of ${filteredGrants.length} users`
                  : "No users match this search"}
              </span>
              <button
                disabled={first === 0}
                onClick={() => setPage(first / 50 - 1)}
              >
                Previous users
              </button>
              <button
                disabled={first + 50 >= filteredGrants.length}
                onClick={() => setPage(first / 50 + 1)}
              >
                Next users
              </button>
            </div>
          )}
        </>
      )}
      {view === "audit" && canReadAudit && (
        <article className="program-inspector" aria-label="Security audit">
          <div className="section-heading-row">
            <div>
              <small>IMMUTABLE SECURITY EVIDENCE</small>
              <h3>Application security audit</h3>
              <p>
                Newest first. This view shows the governed action and outcome
                without exposing backend correlation values.
              </p>
            </div>
            <button
              disabled={busy || exportingAudit}
              onClick={() => void exportCompleteAudit()}
            >
              {exportingAudit
                ? "Exporting complete audit…"
                : "Export complete CSV"}
            </button>
          </div>
          {auditEvents.length ? (
            <div
              className="react-grid-scroll"
              role="region"
              aria-label="Scrollable security records"
              tabIndex={0}
            >
              <table className="react-cube-grid security-audit-grid">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Person</th>
                    <th>Action</th>
                    <th>Object</th>
                    <th>Outcome</th>
                  </tr>
                </thead>
                <tbody>
                  {auditEvents.map((event) => (
                    <tr key={event.auditId}>
                      <td>{new Date(event.occurredAt).toLocaleString()}</td>
                      <td>{event.actorName}</td>
                      <td>{event.action}</td>
                      <td>{event.targetName}</td>
                      <td>{event.outcome}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p>
              {readState === "ready"
                ? "No application security audit events were returned."
                : readState === "error"
                  ? "Security audit could not be loaded. Use Read audit to retry."
                  : readState === "loading"
                    ? "Reading security events…"
                    : "Read the security audit to inspect events."}
            </p>
          )}
          {auditCursor && (
            <button disabled={busy} onClick={() => void loadOlderAudit()}>
              Load older security events
            </button>
          )}
        </article>
      )}
      {view === "access" && editor === "dimensions" && selected && (
        <article className="program-inspector" aria-label="Dimensional access">
          <div className="section-heading-row">
            <h3 tabIndex={-1} ref={editorHeading}>
              {grantLabel(selected)}
            </h3>
            <button disabled={busy} onClick={closeEditor}>
              Close dimensional access
            </button>
          </div>
          <fieldset className="security-editor-fields" disabled={busy}>
            <p>{selected.role} · current access</p>
            {dimensions.length ? (
              <div
                className="react-grid-scroll"
                role="region"
                aria-label="Scrollable security records"
                tabIndex={0}
              >
                <table className="react-cube-grid">
                  <thead>
                    <tr>
                      <th>Dimension</th>
                      <th>Available read tags</th>
                      <th>Assigned read tags</th>
                      <th>Available write tags</th>
                      <th>Assigned write tags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dimensions.map((dimension) => (
                      <tr key={dimension.dimensionId}>
                        <th>{dimension.name}</th>
                        <td>{dimension.readTags.join(", ") || "None"}</td>
                        <td>
                          {canWriteDimensionAccess ? (
                            <input
                              aria-label={`${dimension.name} assigned read tags`}
                              value={
                                dimensionDraft.readTags[
                                  dimension.dimensionId
                                ] || ""
                              }
                              onChange={(event) =>
                                updateDimensionDraft(
                                  "readTags",
                                  dimension.dimensionId,
                                  event.target.value,
                                )
                              }
                            />
                          ) : (
                            assignment(selected.readTags, dimension.dimensionId)
                          )}
                        </td>
                        <td>{dimension.writeTags.join(", ") || "None"}</td>
                        <td>
                          {canWriteDimensionAccess ? (
                            <input
                              aria-label={`${dimension.name} assigned write tags`}
                              value={
                                dimensionDraft.writeTags[
                                  dimension.dimensionId
                                ] || ""
                              }
                              onChange={(event) =>
                                updateDimensionDraft(
                                  "writeTags",
                                  dimension.dimensionId,
                                  event.target.value,
                                )
                              }
                            />
                          ) : (
                            assignment(
                              selected.writeTags,
                              dimension.dimensionId,
                            )
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="muted-copy">No tagged dimensions are configured.</p>
            )}
            {canWriteDimensionAccess && dimensions.length > 0 && (
              <div className="reviewed-inline-action">
                <p>Separate multiple tags with semicolons.</p>
                <label className="review-check">
                  <input
                    type="checkbox"
                    checked={dimensionReviewed}
                    disabled={!dimensionDraftValid()}
                    onChange={(event) =>
                      setDimensionReviewed(event.target.checked)
                    }
                  />
                  I reviewed this exact user and dimensional assignment.
                </label>
                <button
                  disabled={
                    busy || !dimensionReviewed || !dimensionDraftValid()
                  }
                  onClick={() => void applyDimensionMutation()}
                >
                  Apply reviewed dimensional access
                </button>
              </div>
            )}
          </fieldset>
        </article>
      )}
      {view === "access" &&
        editor === "grant" &&
        canWriteAccess &&
        canListSubjects && (
          <article
            className="program-inspector access-editor"
            id="application-access-editor"
          >
            <div className="section-heading-row">
              <h3 tabIndex={-1} ref={editorHeading}>
                Reviewed application access
              </h3>
              <button disabled={busy} onClick={closeEditor}>
                Close access editor
              </button>
            </div>
            <fieldset className="security-editor-fields" disabled={busy}>
              <p>Grant, update or revoke access for one verified identity.</p>
              <div className="form-grid security-access-identity-grid">
                <label>
                  Application user
                  <select
                    value={accessSubject}
                    onChange={(event) =>
                      updateAccessSubject(event.target.value)
                    }
                  >
                    <option value="">Choose a current user</option>
                    {securitySubjects.map((subject) => (
                      <option
                        key={subject.selectionKey}
                        value={subject.selectionKey}
                      >
                        {securitySubjectLabel(subject)}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Action
                  <select
                    value={accessAction}
                    onChange={(event) => {
                      setAccessAction(event.target.value as "grant" | "revoke");
                      setAccessReviewed(false);
                    }}
                  >
                    <option value="grant">Grant or update</option>
                    <option value="revoke">Revoke</option>
                  </select>
                </label>
                <label>
                  Role
                  <select
                    disabled={accessAction === "revoke"}
                    value={accessRole}
                    onChange={(event) => {
                      setAccessRole(
                        event.target.value as
                          | "Reader"
                          | "Editor"
                          | "Administrator",
                      );
                      setAccessReviewed(false);
                    }}
                  >
                    <option>Reader</option>
                    <option>Editor</option>
                    <option>Administrator</option>
                  </select>
                </label>
              </div>
              <p className="review-intent">
                {accessSubject.trim()
                  ? accessAction === "grant"
                    ? `${accessSubjectOption ? securitySubjectLabel(accessSubjectOption) : "Current user"} · ${accessRole}`
                    : `${accessSubjectOption ? securitySubjectLabel(accessSubjectOption) : "Current user"} · revoke all application access`
                  : "Choose a current user to review."}
              </p>
              <label className="review-check">
                <input
                  type="checkbox"
                  checked={accessReviewed}
                  disabled={!accessSubject.trim()}
                  onChange={(event) => setAccessReviewed(event.target.checked)}
                />
                I reviewed this user, action and role.
              </label>
              <button
                disabled={busy || !accessSubject.trim() || !accessReviewed}
                onClick={() => void applyAccessMutation()}
              >
                Apply reviewed access
              </button>
            </fieldset>
          </article>
        )}
      {view === "access" &&
        editor === "rules" &&
        ruleSubject &&
        canWriteRuleAccess && (
          <article
            className="program-inspector access-editor"
            aria-labelledby="role-data-security-heading"
          >
            <div className="section-heading-row">
              <h3
                id="role-data-security-heading"
                tabIndex={-1}
                ref={editorHeading}
              >
                Rule permissions ·{" "}
                {ruleGrant ? grantLabel(ruleGrant) : "Current user"}
              </h3>
              <button disabled={busy} onClick={closeEditor}>
                Close rule permissions
              </button>
            </div>
            <fieldset className="security-editor-fields" disabled={busy}>
              <p>
                Set or revoke design, publish and run permissions for this
                application user.
              </p>
              <label className="form-field security-rule-action">
                Action
                <select
                  value={ruleAction}
                  onChange={(event) => {
                    setRuleAction(event.target.value as "set" | "revoke");
                    setRuleReviewed(false);
                  }}
                >
                  <option value="set">Set permissions</option>
                  <option value="revoke">Revoke all</option>
                </select>
              </label>
              <div className="permission-checks" aria-label="Rule permissions">
                {(["design", "publish", "run"] as const).map((name) => (
                  <label key={name}>
                    <input
                      type="checkbox"
                      checked={rulePermissions[name]}
                      disabled={ruleAction === "revoke"}
                      onChange={(event) =>
                        updateRulePermission(name, event.target.checked)
                      }
                    />
                    {name[0].toUpperCase() + name.slice(1)}
                  </label>
                ))}
              </div>
              <label className="review-check">
                <input
                  type="checkbox"
                  checked={ruleReviewed}
                  disabled={
                    !ruleSubject ||
                    (ruleAction === "set" &&
                      !Object.values(rulePermissions).some(Boolean))
                  }
                  onChange={(event) => setRuleReviewed(event.target.checked)}
                />
                I reviewed this exact user, action and permission set.
              </label>
              <button
                disabled={busy || !ruleSubject || !ruleReviewed}
                onClick={() => void applyRuleMutation()}
              >
                Apply reviewed rule permissions
              </button>
            </fieldset>
          </article>
        )}
      <p className="authority-note">
        Changes apply only to the reviewed application, identity and version.
      </p>
    </section>
  );
}
