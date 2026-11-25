import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError, readSecurityProgram, request } from "./api";
import {
  RequesterBenefitAudit,
  requesterBenefitSummary,
  requesterBenefitEvidence,
} from "./RequesterBenefit";
import type { RequesterBenefit, Configuration } from "./authorization-config";
import { SecurityChangeOutcome } from "./SecurityChangeOutcome";
import { useApplicationSecurityChange } from "./application-security-change";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";
import {
  collectSecuritySubjectOptions,
  readDirectoryGroups,
  type SecuritySubject,
} from "./security-directory";

type Grant = {
  principalId: string;
  displayName: string | null;
  username: string | null;
  directoryStatus?: "Active" | "Inactive" | null;
  role: string;
  readTags: Record<string, string[]>;
  writeTags: Record<string, string[]>;
  rulePermissions: Record<string, boolean> | null;
  grantedAt: string;
};

type UserGrant = Omit<Grant, "principalId"> & { subjectId: string };
type GroupGrant = Omit<Grant, "principalId" | "username"> & {
  groupId: string;
  groupName: string | null;
};

type PrincipalKind = "user" | "group";
const ACCESS_FUNCTIONS = {
  user: {
    list: "security.application.access.list",
    write: "security.application.access.set",
    ruleWrite: "security.rule.access.set",
    dimensionRead: "security.application.dimension-access.read",
    dimensionWrite: "security.application.dimension-access.set",
  },
  group: {
    list: "security.application.group-access.list",
    write: "security.application.group-access.set",
    ruleWrite: "security.rule.group-access.set",
    dimensionRead: "security.application.group-dimension-access.read",
    dimensionWrite: "security.application.group-dimension-access.set",
  },
} as const;

function principalSelection(kind: PrincipalKind, id: string) {
  return kind === "group" ? { groupId: id } : { subjectId: id };
}

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

type DimensionAccess = Pick<
  Grant,
  "principalId" | "displayName" | "username" | "role" | "readTags" | "writeTags"
> & {
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
  authorizationMode?: Configuration["authorizationMode"];
  requesterBenefit?: RequesterBenefit;
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

type AccessPage = { grants: UserGrant[]; nextAfterSubjectId: string | null };
type GroupAccessPage = {
  grants: GroupGrant[];
  nextAfterGroupId: string | null;
};

export function collectSecuritySubjects(
  readPage: (
    arguments_: ReturnType<typeof accessListArguments>,
  ) => Promise<AccessPage>,
) {
  return collectAllContinuations<AccessPage, UserGrant>({
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
      (event.requesterBenefit != null &&
        !requesterBenefitEvidence(
          event.authorizationMode,
          event.requesterBenefit,
        )) ||
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
      event.requesterBenefit
        ? [
            event.action,
            event.authorizationMode === "legacy" ? "Staged" : "Applied",
            requesterBenefitSummary(event.requesterBenefit),
          ].join(" · ")
        : event.action,
      event.targetName,
      event.outcome,
    ]
      .map(csvValue)
      .join(","),
  );
  return ["occurredAt,actor,action,target,outcome", ...rows].join("\r\n");
}

function grantLabel(
  grant: Pick<Grant, "displayName" | "username">,
  kind: PrincipalKind,
) {
  if (kind === "group" && grant.displayName && grant.username)
    return securitySubjectLabel({
      displayName: grant.displayName,
      username: grant.username,
    });
  return (
    grant.displayName || grant.username || "Unavailable directory identity"
  );
}

function securitySubjectLabel(
  subject: Pick<SecuritySubject, "displayName" | "username">,
) {
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
  kind: PrincipalKind = "user",
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: ACCESS_FUNCTIONS[kind].write,
      arguments: {
        ...principalSelection(kind, subjectId),
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
  kind: PrincipalKind = "user",
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: ACCESS_FUNCTIONS[kind].ruleWrite,
      arguments: {
        ...principalSelection(kind, subjectId),
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
  kind: PrincipalKind = "user",
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: ACCESS_FUNCTIONS[kind].dimensionWrite,
      arguments: {
        ...principalSelection(kind, subjectId),
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

type SecurityView = "access" | "groups" | "policy" | "audit";
type SecurityProps = {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  view?: SecurityView;
  canReadDirectoryGroups?: boolean;
  onRequestTransition?: (action: () => void) => void;
};

export function AdministrationSecurity(props: SecurityProps) {
  const view = props.view || "access";
  const readFunction = {
    access: ACCESS_FUNCTIONS.user.list,
    groups: ACCESS_FUNCTIONS.group.list,
    policy: "security.application.dimension-policy.read",
    audit: "security.application.audit.list",
  }[view];
  if (!props.catalog?.functions[readFunction]) return null;
  return (
    <SecurityWorkspace
      key={`${props.app?.workspaceId || "none"}:${props.app?.applicationId || "none"}:${view}`}
      {...props}
    />
  );
}

function SecurityWorkspace({
  app,
  catalog,
  view = "access",
  canReadDirectoryGroups = false,
  onRequestTransition,
}: SecurityProps) {
  const kind = view === "groups" ? "group" : "user";
  const accessView = view === "access" || view === "groups";
  const functions = ACCESS_FUNCTIONS[kind];
  const [editor, setEditor] = useState<"grant" | "dimensions" | "rules" | null>(
    null,
  );
  const [policyOpen, setPolicyOpen] = useState(false);
  const [readState, setReadState] = useState<
    "idle" | "loading" | "ready" | "error"
  >("idle");
  const snapshotReady = readState === "ready";
  const [operationResult, setOperationResult] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const readButton = useRef<HTMLButtonElement | null>(null);
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
  const [reading, setBusy] = useState(false);
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
  const [directoryGroups, setDirectoryGroups] = useState<SecuritySubject[]>([]);
  const [auditCursor, setAuditCursor] = useState<number | null>(null);
  const [exportingAudit, setExportingAudit] = useState(false);
  const mutationKey = useStableMutationIntentKey("security-ui");
  const securityChange = useApplicationSecurityChange(
    app,
    catalog,
    (notice) => {
      setOperationResult(notice);
      resetDrafts();
      void readSecurity();
    },
  );
  const busy = reading || securityChange.busy;
  const changeLocked = busy || securityChange.original;

  const canListSubjects = Boolean(
    catalog?.functions["security.application.subject.list"],
  );
  const canReadAssignments = Boolean(
    catalog?.functions[functions.dimensionRead] &&
      catalog?.functions["security.application.dimension-tags.read"],
  );
  const canWriteAccess = Boolean(catalog?.functions[functions.write]);
  const canWriteRuleAccess = Boolean(catalog?.functions[functions.ruleWrite]);
  const canWriteDimensionAccess = Boolean(
    catalog?.functions[functions.dimensionWrite],
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
  const ruleGrant = grants.find((grant) => grant.principalId === ruleSubject);
  const canSetRule = kind === "user" || ruleGrant?.directoryStatus === "Active";
  const groupOptions = grants
    .filter((grant) => grant.displayName && grant.username)
    .filter(
      (grant) =>
        accessAction === "revoke" || grant.directoryStatus === "Active",
    )
    .map((grant) => ({
      selectionKey: grant.principalId,
      displayName: grant.displayName || "",
      username: grant.username || "",
    }));
  const accessOptions =
    kind === "user"
      ? securitySubjects
      : [
          ...groupOptions,
          ...(canReadDirectoryGroups && accessAction === "grant"
            ? directoryGroups.filter(
                (group) =>
                  !groupOptions.some(
                    (option) => option.selectionKey === group.selectionKey,
                  ),
              )
            : []),
        ];
  const accessSubjectOption = accessOptions.find(
    (subject) => subject.selectionKey === accessSubject,
  );
  const canChooseAccess =
    kind === "user"
      ? canListSubjects
      : grants.some((grant) => grant.displayName && grant.username) ||
        canReadDirectoryGroups;
  const reviewAccessReady = Boolean(
    accessSubject.trim() && (kind === "user" || accessSubjectOption),
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
    !securityChange.original &&
      Boolean(
        policyChanged ||
          dimensionChanged ||
          accessSubject.trim() ||
          ruleChanged,
      ),
  );

  const dirty = Boolean(
    policyChanged || dimensionChanged || accessSubject.trim() || ruleChanged,
  );
  const filteredGrants = useMemo(
    () =>
      grants.filter((grant) =>
        `${grantLabel(grant, kind)} ${grant.username || ""} ${grant.role}`
          .toLocaleLowerCase()
          .includes(query.trim().toLocaleLowerCase()),
      ),
    [grants, kind, query],
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
  }, [editor, policyOpen, selected?.principalId, ruleSubject]);

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

  function reportReadFailure(
    reason: unknown,
    fallback: string,
    replacesSnapshot = false,
  ) {
    const signInChanged =
      reason instanceof ApiError &&
      (reason.kind === "authentication" ||
        reason.code === "BROWSER_IDENTITY_CHANGED");
    const accessDenied =
      reason instanceof ApiError && reason.kind === "authorization";
    const accessChanged =
      reason instanceof ApiError &&
      reason.code === "SECURITY_READ_AUTHORIZATION_STALE";
    const discardSnapshot =
      replacesSnapshot || signInChanged || accessDenied || accessChanged;
    if (discardSnapshot) {
      setReadState("error");
      setGrants([]);
      setSecuritySubjects([]);
      setDirectoryGroups([]);
      setPolicy(null);
      setPolicyDraft({});
      setAuditEvents([]);
      setAuditCursor(null);
    }
    if (signInChanged) {
      setError("Confirm your sign-in, then read security information again.");
    } else if (accessDenied) {
      setError(
        "This security information is unavailable under your current access.",
      );
    } else if (accessChanged) {
      setError(
        "Security access changed while loading. Read the current information again.",
      );
    } else {
      setError(reason instanceof Error ? reason.message : fallback);
    }
    return discardSnapshot;
  }

  async function readSecurity() {
    if (!app) return;
    const owned = beginRead();
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    setBusy(true);
    setReadState("loading");
    setError("");
    try {
      if (kind === "group") {
        const groupResult = await collectAllContinuations<
          GroupAccessPage,
          GroupGrant
        >({
          label: "Application security groups",
          readPage: (cursor) =>
            readSecurityProgram(
              scope,
              functions.list,
              cursor ? { afterGroupId: cursor, limit: 100 } : { limit: 100 },
              owned.signal,
            ),
          rows: (page) => page.grants,
          nextCursor: (page) => page.nextAfterGroupId,
          rowIdentity: (grant) => grant.groupId,
        });
        if (!owned.current()) return;
        setGrants(
          groupResult.rows.map(({ groupId, groupName, ...grant }) => ({
            ...grant,
            principalId: groupId,
            username: groupName,
          })),
        );
        setDirectoryGroups([]);
      } else if (accessView) {
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
        setGrants(
          subjectResult.rows.map(({ subjectId, ...grant }) => ({
            ...grant,
            principalId: subjectId,
          })),
        );
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
      reportReadFailure(reason, "Unable to read application security", true);
    } finally {
      if (owned.current()) setBusy(false);
    }
  }

  async function loadOlderAudit(trigger: HTMLButtonElement) {
    if (!app || !auditCursor || busy || exportingAudit) return;
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
      const discarded = reportReadFailure(
        reason,
        "Unable to read older security audit events",
      );
      if (discarded && document.activeElement === trigger)
        readButton.current?.focus();
    } finally {
      if (owned.current()) setBusy(false);
    }
  }

  async function exportCompleteAudit() {
    if (!app || busy || exportingAudit) return;
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
      reportReadFailure(reason, "Unable to export the complete security audit");
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
    if (changeLocked || !app || !policy || policyReviewed !== action) return;
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
    setOperationResult("");
    setError("");
    await securityChange.submit(
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
      "policy",
    );
  }

  async function readAssignments(grant: Grant) {
    if (!app || !canReadAssignments) return;
    const trigger = returnFocus.current;
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    const owned = beginRead();
    setBusy(true);
    setError("");
    try {
      const [access, tags] = await Promise.all([
        readSecurityProgram<
          Omit<DimensionAccess, "principalId" | "displayName" | "username"> & {
            subjectId?: string;
            groupId?: string;
          }
        >(
          scope,
          functions.dimensionRead,
          principalSelection(kind, grant.principalId),
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
      if (
        (kind === "group" ? access.groupId : access.subjectId) !==
        grant.principalId
      )
        throw new Error(
          "Dimensional assignments returned a different identity.",
        );
      setSelected({
        ...access,
        principalId: grant.principalId,
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
      const discarded = reportReadFailure(
        reason,
        "Unable to read dimensional assignments",
      );
      if (discarded && document.activeElement === trigger)
        readButton.current?.focus();
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
      changeLocked ||
      !app ||
      !selected ||
      !canWriteDimensionAccess ||
      !dimensionReviewed ||
      !dimensionDraftValid()
    )
      return;
    if (!window.confirm("Save these exact dimensional assignments?")) return;
    setOperationResult("");
    setError("");
    const assignments = collectDimensionDraft();
    await securityChange.submit(
      dimensionAccessMutationBody(
        app,
        selected.principalId,
        assignments.readTags,
        assignments.writeTags,
        selected.securityRevision,
        mutationKey({
          operation: functions.dimensionWrite,
          ...principalSelection(kind, selected.principalId),
          ...assignments,
          securityRevision: selected.securityRevision,
        }),
        kind,
      ),
      "dimensional assignments",
    );
  }

  function updateAccessSubject(value: string) {
    if (busy) return;
    setAccessSubject(value);
    setAccessReviewed(false);
  }

  async function loadGroupChoices() {
    if (busy || kind !== "group" || !canReadDirectoryGroups) return;
    const owned = beginRead();
    setBusy(true);
    setError("");
    setDirectoryGroups([]);
    setAccessReviewed(false);
    try {
      const { rows } = await readDirectoryGroups(owned.signal);
      if (!owned.current()) return;
      setDirectoryGroups(
        rows
          .filter((group) => group.status === "Active" && group.displayName)
          .map((group) => ({
            selectionKey: group.groupId,
            displayName: group.displayName,
            username: group.groupName,
          })),
      );
      if (!rows.some((group) => group.status === "Active" && group.displayName))
        setOperationResult("The server directory returned no eligible groups.");
    } catch (reason) {
      if (!owned.current()) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read directory groups.",
      );
    } finally {
      if (owned.current()) setBusy(false);
    }
  }

  function chooseGroupGrant(grant: Grant) {
    setAccessSubject(grant.principalId);
    setAccessAction(grant.directoryStatus === "Active" ? "grant" : "revoke");
    setAccessRole(grant.role as "Reader" | "Editor" | "Administrator");
    setEditor("grant");
  }

  async function applyAccessMutation() {
    const subjectId = accessSubject.trim();
    if (
      changeLocked ||
      !app ||
      !canWriteAccess ||
      !subjectId ||
      !accessReviewed ||
      (kind === "group" && !accessSubjectOption)
    )
      return;
    const wording =
      accessAction === "grant"
        ? `Grant or update ${accessRole} access for this exact ${kind}?`
        : `Revoke application access for this exact ${kind}?`;
    if (!window.confirm(wording)) return;
    setOperationResult("");
    setError("");
    await securityChange.submit(
      accessMutationBody(
        app,
        subjectId,
        accessAction,
        accessRole,
        mutationKey({
          operation: functions.write,
          ...principalSelection(kind, subjectId),
          action: accessAction,
          role: accessRole,
        }),
        kind,
      ),
      "application access",
    );
  }

  function chooseRuleGrant(grant: Grant) {
    setRuleSubject(grant.principalId);
    setRuleAction(
      kind === "group" && grant.directoryStatus !== "Active" ? "revoke" : "set",
    );
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
      changeLocked ||
      !app ||
      !canWriteRuleAccess ||
      !ruleSubject ||
      !ruleReviewed ||
      (ruleAction === "set" && (!validSet || !canSetRule))
    )
      return;
    const wording =
      ruleAction === "set"
        ? "Save these exact rule permissions for the selected identity?"
        : "Revoke all rule permissions for the selected identity?";
    if (!window.confirm(wording)) return;
    setOperationResult("");
    setError("");
    await securityChange.submit(
      ruleAccessMutationBody(
        app,
        ruleSubject,
        ruleAction,
        rulePermissions,
        mutationKey({
          operation: functions.ruleWrite,
          ...principalSelection(kind, ruleSubject),
          action: ruleAction,
          permissions: rulePermissions,
        }),
        kind,
      ),
      "rule permissions",
    );
  }

  return (
    <section
      className="panel capability-activity security-workspace"
      aria-labelledby="application-security-heading"
    >
      <div className="section-heading-row">
        <div>
          <h2 id="application-security-heading" tabIndex={-1}>
            {accessView
              ? kind === "group"
                ? "Application groups and roles"
                : "Application users and roles"
              : view === "policy"
                ? "Dimensional policy"
                : "Security audit"}
          </h2>
          <p>
            {accessView
              ? kind === "group"
                ? "Review group roles, rule permissions and dimensional assignments in this application."
                : "Inspect application access, then choose the user or permission you want to change."
              : view === "policy"
                ? "Inspect the current policy before making a reviewed change."
                : "Inspect security events and the receipts for committed changes."}
          </p>
        </div>
        <div className="security-heading-actions">
          <button
            ref={readButton}
            aria-disabled={busy || exportingAudit}
            onClick={() => transition(() => void readSecurity())}
          >
            {accessView
              ? "Read access"
              : view === "policy"
                ? "Read policy"
                : "Read audit"}
          </button>
          {accessView && canWriteAccess && canChooseAccess && (
            <button
              className="primary"
              disabled={changeLocked || exportingAudit || readState !== "ready"}
              aria-expanded={editor === "grant"}
              aria-controls="application-access-editor"
              onClick={() => transition(() => setEditor("grant"))}
            >
              {kind === "group" ? "Review group access" : "Grant access"}
            </button>
          )}
        </div>
      </div>
      <SecurityChangeOutcome securityChange={securityChange} busy={busy} />
      {operationResult && (
        <p className="operation-notice" role="status">
          {operationResult}
        </p>
      )}
      {readState === "loading" && (
        <p role="status">
          Loading{" "}
          {accessView
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
      {view === "policy" && snapshotReady && policy && (
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
              disabled={changeLocked || readState !== "ready"}
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
                <fieldset
                  className="security-editor-fields"
                  disabled={changeLocked}
                >
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
      {accessView && (
        <>
          {snapshotReady && grants.length > 0 && (
            <label className="form-field security-catalog-search">
              Find an application {kind}
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={
                  kind === "group" ? "Group name or role" : "User name or role"
                }
              />
            </label>
          )}
          {snapshotReady && grants.length ? (
            <div
              className="react-grid-scroll"
              role="region"
              aria-label="Scrollable security records"
              tabIndex={0}
            >
              <table
                className="react-cube-grid security-grant-grid"
                aria-label={
                  kind === "group"
                    ? "Application group access"
                    : "Application access"
                }
              >
                <thead>
                  <tr>
                    <th>{kind === "group" ? "Group" : "User"}</th>
                    {kind === "group" && <th>Directory status</th>}
                    <th>Role</th>
                    <th>Rule permissions</th>
                    <th>Granted</th>
                    <th>Dimensional access</th>
                    {canWriteRuleAccess && <th>Rule access</th>}
                    {kind === "group" && canWriteAccess && (
                      <th>Application access</th>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {visibleGrants.map((grant) => (
                    <tr key={grant.principalId}>
                      <th scope="row">{grantLabel(grant, kind)}</th>
                      {kind === "group" && (
                        <td>{grant.directoryStatus || "Unavailable"}</td>
                      )}
                      <td>{grant.role}</td>
                      <td>{enabledPermissions(grant)}</td>
                      <td>{new Date(grant.grantedAt).toLocaleString()}</td>
                      <td>
                        <button
                          aria-label={
                            kind === "group"
                              ? `Inspect dimensional access for ${grantLabel(grant, kind)}`
                              : undefined
                          }
                          aria-disabled={busy}
                          disabled={
                            !canReadAssignments ||
                            (kind === "group" &&
                              (!grant.displayName || !grant.username))
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
                            aria-label={
                              kind === "group"
                                ? `Manage rule permissions for ${grantLabel(grant, kind)}`
                                : undefined
                            }
                            disabled={
                              busy ||
                              readState !== "ready" ||
                              (kind === "group" &&
                                (!grant.displayName || !grant.username))
                            }
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
                      {kind === "group" && canWriteAccess && (
                        <td>
                          <button
                            aria-label={`Manage role for ${grantLabel(grant, kind)}`}
                            disabled={
                              busy ||
                              readState !== "ready" ||
                              !grant.displayName ||
                              !grant.username
                            }
                            onClick={() =>
                              transition(() => chooseGroupGrant(grant))
                            }
                          >
                            Manage role
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
                  ? `No application ${kind}s were returned.`
                  : readState === "error"
                    ? "Application access could not be loaded. Use Read access to retry."
                    : "Read current application access to begin."}
              </p>
            )
          )}
          {snapshotReady && grants.length > 0 && (
            <div className="workspace-window-controls">
              <span>
                {filteredGrants.length
                  ? `${first + 1}–${first + visibleGrants.length} of ${filteredGrants.length} ${kind}s`
                  : `No ${kind}s match this search`}
              </span>
              <button
                disabled={first === 0}
                onClick={() => setPage(first / 50 - 1)}
              >
                Previous {kind}s
              </button>
              <button
                disabled={first + 50 >= filteredGrants.length}
                onClick={() => setPage(first / 50 + 1)}
              >
                Next {kind}s
              </button>
            </div>
          )}
          {kind === "group" &&
            readState === "ready" &&
            !canReadDirectoryGroups &&
            !grants.length && (
              <p>
                New groups can be chosen by an administrator with access to both
                this application and the server directory.
              </p>
            )}
        </>
      )}
      {view === "audit" && (
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
              aria-disabled={busy || exportingAudit}
              onClick={() => void exportCompleteAudit()}
            >
              {exportingAudit
                ? "Exporting complete audit…"
                : "Export complete CSV"}
            </button>
          </div>
          {snapshotReady && auditEvents.length ? (
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
                      <td>
                        {event.outcome}
                        {app &&
                          event.requesterBenefit &&
                          event.authorizationMode && (
                            <RequesterBenefitAudit
                              key={JSON.stringify([
                                event.auditId,
                                event.detailsKey,
                                catalog?.accessContext,
                                catalog?.revisions.security,
                                catalog?.applicationAccess.subjectId,
                                Boolean(
                                  catalog?.functions[
                                    "security.application.receipt.read"
                                  ],
                                ),
                              ])}
                              scope={app}
                              receiptKey={
                                catalog?.functions[
                                  "security.application.receipt.read"
                                ]
                                  ? event.detailsKey
                                  : null
                              }
                              evidence={{
                                authorizationMode: event.authorizationMode,
                                requesterBenefit: event.requesterBenefit,
                              }}
                            />
                          )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : readState !== "loading" ? (
            <p>
              {snapshotReady
                ? "No application security audit events were returned."
                : readState === "error"
                  ? "Security audit could not be loaded. Use Read audit to retry."
                  : "Read the security audit to inspect events."}
            </p>
          ) : null}
          {snapshotReady && auditCursor && (
            <button
              aria-disabled={busy || exportingAudit}
              onClick={(event) => void loadOlderAudit(event.currentTarget)}
            >
              Load older security events
            </button>
          )}
        </article>
      )}
      {accessView && editor === "dimensions" && selected && (
        <article className="program-inspector" aria-label="Dimensional access">
          <div className="section-heading-row">
            <h3 tabIndex={-1} ref={editorHeading}>
              {grantLabel(selected, kind)}
            </h3>
            <button disabled={busy} onClick={closeEditor}>
              Close dimensional access
            </button>
          </div>
          <fieldset className="security-editor-fields" disabled={changeLocked}>
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
                  I reviewed this exact {kind} and dimensional assignment.
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
      {accessView &&
        editor === "grant" &&
        canWriteAccess &&
        canChooseAccess && (
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
            <fieldset
              className="security-editor-fields"
              disabled={changeLocked}
            >
              {kind === "group" ? (
                <p>
                  A group grant applies to current members. Other grants can
                  still apply after you revoke it.
                </p>
              ) : (
                <p>Grant, update or revoke access for one verified identity.</p>
              )}
              {kind === "group" &&
                canReadDirectoryGroups &&
                accessAction === "grant" && (
                  <button onClick={() => void loadGroupChoices()}>
                    Read eligible groups
                  </button>
                )}
              <div className="form-grid security-access-identity-grid">
                <label>
                  Application {kind}
                  <select
                    value={accessSubject}
                    onChange={(event) =>
                      updateAccessSubject(event.target.value)
                    }
                  >
                    <option value="">Choose a current {kind}</option>
                    {accessOptions.map((subject) => (
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
                {accessSubject.trim() && reviewAccessReady
                  ? accessAction === "grant"
                    ? `${accessSubjectOption ? securitySubjectLabel(accessSubjectOption) : "Current user"} · ${accessRole}`
                    : `${accessSubjectOption ? securitySubjectLabel(accessSubjectOption) : "Current user"} · ${kind === "group" ? "revoke this group grant" : "revoke all application access"}`
                  : `Choose a current ${kind} to review.`}
              </p>
              <label className="review-check">
                <input
                  type="checkbox"
                  checked={accessReviewed}
                  disabled={!reviewAccessReady}
                  onChange={(event) => setAccessReviewed(event.target.checked)}
                />
                I reviewed this {kind}, action and role.
              </label>
              <button
                disabled={busy || !reviewAccessReady || !accessReviewed}
                onClick={() => void applyAccessMutation()}
              >
                Apply reviewed access
              </button>
            </fieldset>
          </article>
        )}
      {accessView &&
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
                {ruleGrant ? grantLabel(ruleGrant, kind) : `Current ${kind}`}
              </h3>
              <button disabled={busy} onClick={closeEditor}>
                Close rule permissions
              </button>
            </div>
            <fieldset
              className="security-editor-fields"
              disabled={changeLocked}
            >
              <p>
                Set or revoke design, publish and run permissions for this
                application {kind}.
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
                  <option value="set" disabled={!canSetRule}>
                    Set permissions
                  </option>
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
                I reviewed this exact {kind}, action and permission set.
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
