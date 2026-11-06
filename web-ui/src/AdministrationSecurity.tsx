import { useEffect, useState } from "react";
import { readSecurityProgram, request } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";

type Grant = {
  subjectId: string;
  role: string;
  readTags: Record<string, string[]>;
  writeTags: Record<string, string[]>;
  rulePermissions: Record<string, boolean> | null;
  grantedAt: string;
};

type Policy = {
  policyVersion: number | null;
  policy: Record<string, string> | null;
  securityRevision: number;
  authorizationEffect: boolean;
  status: string;
};

type PolicyVersion = {
  policyVersion: number;
  policy: Record<string, string>;
  policyDigest?: string;
  status?: string;
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
  actorDigest: string;
  action: string;
  targetDigest: string | null;
  outcome: "Accepted" | "Rejected" | "Failed";
  operationId: string | null;
};

type SecurityAuditPage = {
  events: SecurityAuditEvent[];
  nextBeforeAuditId: number | null;
};

type SecurityReceipt = {
  workspaceId: string;
  applicationId: string;
  operationId: string;
  action: string;
  outcome: "Committed";
  committedAt: string;
  commandDigest: string;
  payloadDigest: string;
  actorDigest: string;
};

const MAX_AUDIT_EXPORT_EVENTS = 10_000;
const MAX_AUDIT_EXPORT_PAGES = 100;

export function accessListArguments(afterSubjectId?: string | null) {
  return afterSubjectId ? { afterSubjectId, limit: 100 } : { limit: 100 };
}

export function policyListArguments(afterVersion?: number | null) {
  return afterVersion ? { afterVersion, limit: 100 } : { limit: 100 };
}

type AccessPage = { grants: Grant[]; nextAfterSubjectId: string | null };
type PolicyVersionPage = {
  items: PolicyVersion[];
  nextAfterVersion: number | null;
  securityRevision: number;
};

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

export function collectPolicyVersions(
  expectedSecurityRevision: number,
  readPage: (
    arguments_: ReturnType<typeof policyListArguments>,
  ) => Promise<PolicyVersionPage>,
) {
  return collectAllContinuations<PolicyVersionPage, PolicyVersion>({
    label: "Dimensional policy versions",
    readPage: (cursor) =>
      readPage(policyListArguments(cursor === null ? null : Number(cursor))),
    rows: (page) => page.items,
    nextCursor: (page) => {
      const cursor = page.nextAfterVersion;
      if (cursor !== null && (!Number.isInteger(cursor) || cursor < 1))
        throw new Error("Dimensional policy version cursor is invalid.");
      return cursor === null ? null : String(cursor);
    },
    rowIdentity: (version) => String(version.policyVersion),
    consistencyIdentity: (page) => {
      if (page.securityRevision !== expectedSecurityRevision)
        throw new Error(
          "Security revision changed while reading policy history.",
        );
      return page.securityRevision;
    },
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
      typeof event.actorDigest !== "string" ||
      !/^[0-9a-f]{64}$/.test(event.actorDigest) ||
      typeof event.action !== "string" ||
      !event.action ||
      (event.targetDigest !== null &&
        !/^[0-9a-f]{64}$/.test(event.targetDigest)) ||
      !["Accepted", "Rejected", "Failed"].includes(event.outcome) ||
      (event.operationId !== null &&
        (typeof event.operationId !== "string" ||
          !event.operationId ||
          event.operationId.length > 200))
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
      event.auditId,
      event.occurredAt,
      event.action,
      event.outcome,
      event.actorDigest,
      event.targetDigest,
      event.operationId,
    ]
      .map(csvValue)
      .join(","),
  );
  return [
    "auditId,occurredAt,action,outcome,actorDigest,targetDigest,operationId",
    ...rows,
  ].join("\r\n");
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
  policyVersion: number | null,
  policy: Record<string, string> | null,
  expectedSecurityRevision: number,
  idempotencyKey: string,
) {
  const functionName =
    action === "save"
      ? "security.application.dimension-policy.version.save"
      : `security.application.dimension-policy.${action}`;
  const args =
    action === "save"
      ? { policyVersion, policy }
      : action === "activate"
        ? { policyVersion, expectedSecurityRevision }
        : { expectedSecurityRevision };
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

export function AdministrationSecurity({
  app,
  catalog,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
}) {
  const [grants, setGrants] = useState<Grant[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [policyVersions, setPolicyVersions] = useState<PolicyVersion[]>([]);
  const [policyDraft, setPolicyDraft] = useState<Record<string, string>>({});
  const [policyVersion, setPolicyVersion] = useState<number | null>(null);
  const [policyReviewed, setPolicyReviewed] = useState<PolicyAction | null>(
    null,
  );
  const [policyResult, setPolicyResult] = useState("");
  const [selected, setSelected] = useState<DimensionAccess | null>(null);
  const [dimensions, setDimensions] = useState<DimensionTag[]>([]);
  const [dimensionDraft, setDimensionDraft] = useState<{
    readTags: Record<string, string>;
    writeTags: Record<string, string>;
  }>({ readTags: {}, writeTags: {} });
  const [dimensionReviewed, setDimensionReviewed] = useState(false);
  const [dimensionResult, setDimensionResult] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [accessSubject, setAccessSubject] = useState("");
  const [accessAction, setAccessAction] = useState<"grant" | "revoke">("grant");
  const [accessRole, setAccessRole] = useState<
    "Reader" | "Editor" | "Administrator"
  >("Reader");
  const [accessReviewed, setAccessReviewed] = useState(false);
  const [accessResult, setAccessResult] = useState("");
  const [ruleSubject, setRuleSubject] = useState("");
  const [ruleAction, setRuleAction] = useState<"set" | "revoke">("set");
  const [rulePermissions, setRulePermissions] = useState({
    design: false,
    publish: false,
    run: false,
  });
  const [ruleReviewed, setRuleReviewed] = useState(false);
  const [ruleResult, setRuleResult] = useState("");
  const [auditEvents, setAuditEvents] = useState<SecurityAuditEvent[]>([]);
  const [auditCursor, setAuditCursor] = useState<number | null>(null);
  const [auditReceipt, setAuditReceipt] = useState<SecurityReceipt | null>(
    null,
  );
  const [exportingAudit, setExportingAudit] = useState(false);
  const mutationKey = useStableMutationIntentKey("security-ui");

  const canList = Boolean(
    catalog?.functions["security.application.access.list"],
  );
  const canReadPolicy = Boolean(
    catalog?.functions["security.application.dimension-policy.active.read"] &&
      catalog?.functions["security.application.dimension-policy.version.list"],
  );
  const canReadAssignments = Boolean(
    catalog?.functions["security.application.dimension-access.read"] &&
      catalog?.functions["security.application.dimension-tags.read"],
  );
  const canReadAudit = Boolean(
    catalog?.functions["security.application.audit.list"],
  );
  const canReadAuditReceipt = Boolean(
    catalog?.functions["security.application.receipt.read"],
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
    catalog?.functions["security.application.dimension-policy.version.save"],
  );
  const canActivatePolicy = Boolean(
    catalog?.functions["security.application.dimension-policy.activate"],
  );
  const canDeactivatePolicy = Boolean(
    catalog?.functions["security.application.dimension-policy.deactivate"],
  );
  const policyBaseline = policyVersions.at(-1)?.policy || policy?.policy || {};
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

  useEffect(() => {
    setGrants([]);
    setPolicy(null);
    setPolicyVersions([]);
    setPolicyDraft({});
    setPolicyVersion(null);
    setPolicyReviewed(null);
    setPolicyResult("");
    setSelected(null);
    setDimensions([]);
    setDimensionDraft({ readTags: {}, writeTags: {} });
    setDimensionReviewed(false);
    setDimensionResult("");
    setError("");
    setAccessSubject("");
    setAccessReviewed(false);
    setAccessResult("");
    setRuleSubject("");
    setRuleReviewed(false);
    setRuleResult("");
    setAuditEvents([]);
    setAuditCursor(null);
  }, [app?.workspaceId, app?.applicationId]);

  async function readSecurity() {
    if (!app || !canList) return;
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    setBusy(true);
    setError("");
    setSelected(null);
    setDimensions([]);
    try {
      const subjectResult = await collectSecuritySubjects((arguments_) =>
        readSecurityProgram(
          scope,
          "security.application.access.list",
          arguments_,
        ),
      );
      setGrants(subjectResult.rows);
      if (canReadPolicy) {
        const active = await readSecurityProgram<Policy>(
          scope,
          "security.application.dimension-policy.active.read",
          {},
        );
        const versionResult = await collectPolicyVersions(
          active.securityRevision,
          (arguments_) =>
            readSecurityProgram(
              scope,
              "security.application.dimension-policy.version.list",
              arguments_,
            ),
        );
        const versions = versionResult.rows;
        setPolicy(active);
        setPolicyVersions(versions);
        const latest = versions.at(-1);
        setPolicyDraft(latest?.policy || active.policy || {});
        setPolicyVersion(active.policyVersion ?? latest?.policyVersion ?? null);
        setPolicyReviewed(null);
        setPolicyResult("");
      }
      if (canReadAudit) {
        const page = validatedAuditPage(
          await readSecurityProgram<SecurityAuditPage>(
            scope,
            "security.application.audit.list",
            auditListArguments(),
          ),
          null,
        );
        setAuditEvents(page.events);
        setAuditCursor(page.nextBeforeAuditId);
      }
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read application security",
      );
    } finally {
      setBusy(false);
    }
  }

  async function loadOlderAudit() {
    if (!app || !canReadAudit || !auditCursor) return;
    setBusy(true);
    setError("");
    try {
      const page = validatedAuditPage(
        await readSecurityProgram<SecurityAuditPage>(
          { workspaceId: app.workspaceId, applicationId: app.applicationId },
          "security.application.audit.list",
          auditListArguments(auditCursor),
        ),
        auditCursor,
      );
      setAuditEvents((current) => [...current, ...page.events]);
      setAuditCursor(page.nextBeforeAuditId);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read older security audit events",
      );
    } finally {
      setBusy(false);
    }
  }

  async function exportCompleteAudit() {
    if (!app || !canReadAudit) return;
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
        ),
      );
      const blob = new Blob([securityAuditCsv(events)], {
        type: "text/csv;charset=utf-8",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${app.applicationId}-security-audit.csv`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to export the complete security audit",
      );
    } finally {
      setExportingAudit(false);
    }
  }

  async function inspectSecurityReceipt(operationId: string) {
    if (!app || !canReadAuditReceipt) return;
    setBusy(true);
    setError("");
    try {
      const receipt = await readSecurityProgram<SecurityReceipt>(
        { workspaceId: app.workspaceId, applicationId: app.applicationId },
        "security.application.receipt.read",
        { operationId },
      );
      setAuditReceipt(receipt);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to inspect the security receipt",
      );
    } finally {
      setBusy(false);
    }
  }

  function policyDraftValid() {
    return (Object.keys(POLICY_CHOICES) as PolicyKey[]).every((name) =>
      (POLICY_CHOICES[name] as readonly string[]).includes(policyDraft[name]),
    );
  }

  function updatePolicyDraft(name: PolicyKey, value: string) {
    setPolicyDraft((current) => ({ ...current, [name]: value }));
    setPolicyReviewed(null);
    setPolicyResult("");
  }

  async function applyPolicyMutation(action: PolicyAction) {
    if (!app || !policy || policyReviewed !== action) return;
    const latestVersion = policyVersions.at(-1)?.policyVersion || 0;
    const selectedIsSaved = policyVersions.some(
      (item) => item.policyVersion === policyVersion,
    );
    if (
      (action === "save" && (!canSavePolicy || !policyDraftValid())) ||
      (action === "activate" &&
        (!canActivatePolicy || !policyVersion || !selectedIsSaved)) ||
      (action === "deactivate" &&
        (!canDeactivatePolicy || policy.policyVersion === null))
    )
      return;
    const wording =
      action === "save"
        ? `Save immutable dimensional policy version ${latestVersion + 1}?`
        : action === "activate"
          ? `Activate dimensional policy version ${policyVersion}?`
          : `Deactivate dimensional policy version ${policy.policyVersion}?`;
    if (!window.confirm(wording)) return;
    setBusy(true);
    setError("");
    setPolicyResult("");
    try {
      const response = await request<{ result: { changed?: boolean } }>(
        "/api/security",
        dimensionPolicyMutationBody(
          app,
          action,
          action === "save" ? latestVersion + 1 : policyVersion,
          action === "save" ? policyDraft : null,
          policy.securityRevision,
          mutationKey({
            operation: "dimension-policy",
            action,
            policyVersion:
              action === "save" ? latestVersion + 1 : policyVersion,
            policy: action === "save" ? policyDraft : null,
            securityRevision: policy.securityRevision,
          }),
        ),
      );
      setPolicyResult(
        response.result.changed === false
          ? "The reviewed policy action already matched the authoritative state."
          : "The fixed security service applied the reviewed policy action.",
      );
      setPolicyReviewed(null);
      await readSecurity();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to change dimensional policy",
      );
    } finally {
      setBusy(false);
    }
  }

  async function readAssignments(grant: Grant) {
    if (!app || !canReadAssignments) return;
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    setBusy(true);
    setError("");
    try {
      const [access, tags] = await Promise.all([
        readSecurityProgram<DimensionAccess>(
          scope,
          "security.application.dimension-access.read",
          { subjectId: grant.subjectId },
        ),
        readSecurityProgram<{
          dimensions: DimensionTag[];
          securityRevision: number;
        }>(scope, "security.application.dimension-tags.read", {}),
      ]);
      if (access.securityRevision !== tags.securityRevision)
        throw new Error("Security revision changed while reading assignments.");
      setSelected(access);
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
      setDimensionResult("");
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read dimensional assignments",
      );
    } finally {
      setBusy(false);
    }
  }

  function updateDimensionDraft(
    kind: "readTags" | "writeTags",
    dimensionId: string,
    value: string,
  ) {
    setDimensionDraft((current) => ({
      ...current,
      [kind]: { ...current[kind], [dimensionId]: value },
    }));
    setDimensionReviewed(false);
    setDimensionResult("");
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
      !app ||
      !selected ||
      !canWriteDimensionAccess ||
      !dimensionReviewed ||
      !dimensionDraftValid()
    )
      return;
    if (!window.confirm("Save these exact dimensional assignments?")) return;
    setBusy(true);
    setError("");
    setDimensionResult("");
    try {
      const assignments = collectDimensionDraft();
      const response = await request<{
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
      setDimensionResult(
        response.result.changed
          ? "The fixed security service applied the reviewed assignments."
          : "The reviewed assignments already matched the authoritative state.",
      );
      setDimensionReviewed(false);
      const grant = grants.find(
        (item) => item.subjectId === selected.subjectId,
      );
      if (grant) await readAssignments(grant);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to change dimensional assignments",
      );
    } finally {
      setBusy(false);
    }
  }

  function updateAccessSubject(value: string) {
    setAccessSubject(value);
    setAccessReviewed(false);
    setAccessResult("");
  }

  async function applyAccessMutation() {
    const subjectId = accessSubject.trim();
    if (!app || !canWriteAccess || !subjectId || !accessReviewed) return;
    const wording =
      accessAction === "grant"
        ? `Grant or update ${accessRole} access for this exact identity?`
        : "Revoke application access for this exact identity?";
    if (!window.confirm(wording)) return;
    setBusy(true);
    setError("");
    setAccessResult("");
    try {
      const response = await request<{ result: { changed: boolean } }>(
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
      setAccessResult(
        response.result.changed
          ? "The fixed security service applied the reviewed access change."
          : "The reviewed access already matched the authoritative state.",
      );
      setAccessReviewed(false);
      await readSecurity();
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to change access",
      );
    } finally {
      setBusy(false);
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
    setRuleResult("");
  }

  function updateRulePermission(
    name: "design" | "publish" | "run",
    value: boolean,
  ) {
    setRulePermissions((current) => ({ ...current, [name]: value }));
    setRuleReviewed(false);
    setRuleResult("");
  }

  async function applyRuleMutation() {
    const validSet = Object.values(rulePermissions).some(Boolean);
    if (
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
    setBusy(true);
    setError("");
    setRuleResult("");
    try {
      const response = await request<{ result: { changed: boolean } }>(
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
      setRuleResult(
        response.result.changed
          ? "The fixed security service applied the reviewed rule permissions."
          : "The reviewed rule permissions already matched the authoritative state.",
      );
      setRuleReviewed(false);
      await readSecurity();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to change rule permissions",
      );
    } finally {
      setBusy(false);
    }
  }

  if (!canList) return null;

  return (
    <section
      className="panel capability-activity"
      aria-labelledby="application-security-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>AUTHORIZED APPLICATION ACCESS</small>
          <h2 id="application-security-heading" tabIndex={-1}>
            Application users and roles
          </h2>
          <p>
            Workspace and application administrators can grant access to this
            application and assign each verified user a Reader, Editor or
            Administrator role. The fixed security service remains
            authoritative.
          </p>
        </div>
        <button disabled={busy} onClick={() => void readSecurity()}>
          {busy ? "Reading…" : "Read access"}
        </button>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {policy && (
        <div aria-label="Active policy">
          <div className="security-policy-summary">
            <div>
              <small>DIMENSIONAL POLICY</small>
              <strong>{policy.status}</strong>
            </div>
            <div>
              <small>POLICY VERSION</small>
              <strong>{policy.policyVersion ?? "None"}</strong>
            </div>
            <div>
              <small>SECURITY REVISION</small>
              <strong>{policy.securityRevision}</strong>
            </div>
            <div>
              <small>AUTHORIZATION EFFECT</small>
              <strong>
                {policy.authorizationEffect ? "Active" : "Inactive"}
              </strong>
            </div>
          </div>
          <details className="security-policy-history">
            <summary>
              Review {policyVersions.length} saved policy version
              {policyVersions.length === 1 ? "" : "s"}
            </summary>
            {policyVersions.map((version) => (
              <article key={version.policyVersion}>
                <h3>
                  Version {version.policyVersion}
                  {version.policyVersion === policy.policyVersion
                    ? " · Active"
                    : ""}
                </h3>
                {version.policyDigest && <code>{version.policyDigest}</code>}
                <dl>
                  {Object.entries(version.policy).map(([name, value]) => (
                    <div key={name}>
                      <dt>{name}</dt>
                      <dd>{value}</dd>
                    </div>
                  ))}
                </dl>
              </article>
            ))}
          </details>
          {(canSavePolicy || canActivatePolicy || canDeactivatePolicy) && (
            <article className="program-inspector access-editor">
              <h3>Reviewed dimensional policy</h3>
              <p>
                Save an immutable version, activate an exact saved version, or
                explicitly deactivate the current policy. The fixed security
                service remains authoritative.
              </p>
              <div className="policy-choice-grid">
                {(Object.keys(POLICY_CHOICES) as PolicyKey[]).map((name) => (
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
                ))}
              </div>
              {canSavePolicy && (
                <div className="reviewed-inline-action">
                  <p>
                    Next immutable version:{" "}
                    {policyVersions.at(-1)?.policyVersion
                      ? (policyVersions.at(-1)?.policyVersion || 0) + 1
                      : 1}
                  </p>
                  <label className="review-check">
                    <input
                      type="checkbox"
                      checked={policyReviewed === "save"}
                      disabled={!policyDraftValid()}
                      onChange={(event) =>
                        setPolicyReviewed(event.target.checked ? "save" : null)
                      }
                    />
                    I reviewed all ten choices for this exact immutable version.
                  </label>
                  <button
                    disabled={
                      busy || policyReviewed !== "save" || !policyDraftValid()
                    }
                    onClick={() => void applyPolicyMutation("save")}
                  >
                    Save immutable version
                  </button>
                </div>
              )}
              {canActivatePolicy && policyVersions.length > 0 && (
                <div className="reviewed-inline-action">
                  <label>
                    Saved version to activate
                    <select
                      aria-label="Saved policy version"
                      value={policyVersion ?? ""}
                      onChange={(event) => {
                        setPolicyVersion(Number(event.target.value));
                        setPolicyReviewed(null);
                        setPolicyResult("");
                      }}
                    >
                      {policyVersions.map((version) => (
                        <option
                          key={version.policyVersion}
                          value={version.policyVersion}
                        >
                          Version {version.policyVersion}
                        </option>
                      ))}
                    </select>
                  </label>
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
                    I reviewed this exact saved version and security revision.
                  </label>
                  <button
                    disabled={busy || policyReviewed !== "activate"}
                    onClick={() => void applyPolicyMutation("activate")}
                  >
                    Activate selected version
                  </button>
                </div>
              )}
              {canDeactivatePolicy && policy.policyVersion !== null && (
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
              {policyResult && <p role="status">{policyResult}</p>}
            </article>
          )}
        </div>
      )}
      {grants.length ? (
        <div className="react-grid-scroll">
          <table className="react-cube-grid security-grant-grid">
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
              {grants.map((grant) => (
                <tr key={grant.subjectId}>
                  <th>{grant.subjectId}</th>
                  <td>{grant.role}</td>
                  <td>{enabledPermissions(grant)}</td>
                  <td>{new Date(grant.grantedAt).toLocaleString()}</td>
                  <td>
                    <button
                      disabled={busy || !canReadAssignments}
                      onClick={() => void readAssignments(grant)}
                    >
                      Inspect
                    </button>
                  </td>
                  {canWriteRuleAccess && (
                    <td>
                      <button
                        disabled={busy}
                        onClick={() => chooseRuleGrant(grant)}
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
        <p className="muted-copy">Read current application access to begin.</p>
      )}
      {canReadAudit && (
        <article className="program-inspector" aria-label="Security audit">
          <div className="section-heading-row">
            <div>
              <small>IMMUTABLE SECURITY EVIDENCE</small>
              <h3>Application security audit</h3>
              <p>
                Newest first. Identity and target values are irreversible
                digests; raw audit detail is never exposed to the browser.
              </p>
            </div>
            <button
              disabled={exportingAudit}
              onClick={() => void exportCompleteAudit()}
            >
              {exportingAudit
                ? "Exporting complete audit…"
                : "Export complete CSV"}
            </button>
          </div>
          {auditEvents.length ? (
            <div className="react-grid-scroll">
              <table className="react-cube-grid security-audit-grid">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Action</th>
                    <th>Outcome</th>
                    <th>Actor digest</th>
                    <th>Target digest</th>
                    <th>Receipt correlation</th>
                  </tr>
                </thead>
                <tbody>
                  {auditEvents.map((event) => (
                    <tr key={event.auditId}>
                      <td>{new Date(event.occurredAt).toLocaleString()}</td>
                      <td>{event.action}</td>
                      <td>{event.outcome}</td>
                      <td>
                        <code>{event.actorDigest}</code>
                      </td>
                      <td>
                        <code>{event.targetDigest || "—"}</code>
                      </td>
                      <td>
                        {event.operationId && canReadAuditReceipt ? (
                          <button
                            className="link-button"
                            aria-label={`Inspect security receipt ${event.operationId}`}
                            onClick={() =>
                              void inspectSecurityReceipt(
                                event.operationId as string,
                              )
                            }
                          >
                            <code>{event.operationId}</code>
                          </button>
                        ) : (
                          <code>{event.operationId || "—"}</code>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p>No application security audit events were returned.</p>
          )}
          {auditCursor && (
            <button disabled={busy} onClick={() => void loadOlderAudit()}>
              Load older security events
            </button>
          )}
          {auditReceipt && (
            <section
              aria-label="Security receipt"
              className="program-inspector"
            >
              <h4>Committed security receipt</h4>
              <p>
                <code>{auditReceipt.operationId}</code> · {auditReceipt.action}{" "}
                · {new Date(auditReceipt.committedAt).toLocaleString()}
              </p>
              <dl>
                <dt>Command digest</dt>
                <dd>
                  <code>{auditReceipt.commandDigest}</code>
                </dd>
                <dt>Payload digest</dt>
                <dd>
                  <code>{auditReceipt.payloadDigest}</code>
                </dd>
                <dt>Actor digest</dt>
                <dd>
                  <code>{auditReceipt.actorDigest}</code>
                </dd>
              </dl>
            </section>
          )}
        </article>
      )}
      {selected && (
        <article className="program-inspector" aria-label="Dimensional access">
          <h3>{selected.subjectId}</h3>
          <p>
            {selected.role} · security revision {selected.securityRevision}
          </p>
          {dimensions.length ? (
            <div className="react-grid-scroll">
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
                              dimensionDraft.readTags[dimension.dimensionId] ||
                              ""
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
                              dimensionDraft.writeTags[dimension.dimensionId] ||
                              ""
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
                          assignment(selected.writeTags, dimension.dimensionId)
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
                I reviewed this exact user, revision and dimensional assignment.
              </label>
              <button
                disabled={busy || !dimensionReviewed || !dimensionDraftValid()}
                onClick={() => void applyDimensionMutation()}
              >
                Apply reviewed dimensional access
              </button>
              {dimensionResult && <p role="status">{dimensionResult}</p>}
            </div>
          )}
        </article>
      )}
      {canWriteAccess && (
        <article className="program-inspector access-editor">
          <h3>Reviewed application access</h3>
          <p>
            Grant, update or revoke one verified identity through the fixed
            security service.
          </p>
          <div className="snapshot-compare-controls">
            <label>
              Verified subject
              <input
                maxLength={300}
                value={accessSubject}
                onChange={(event) => updateAccessSubject(event.target.value)}
              />
            </label>
            <label>
              Action
              <select
                value={accessAction}
                onChange={(event) => {
                  setAccessAction(event.target.value as "grant" | "revoke");
                  setAccessReviewed(false);
                  setAccessResult("");
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
                    event.target.value as "Reader" | "Editor" | "Administrator",
                  );
                  setAccessReviewed(false);
                  setAccessResult("");
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
                ? `${accessSubject.trim()} · ${accessRole}`
                : `${accessSubject.trim()} · revoke all application access`
              : "Enter the exact verified identity to review."}
          </p>
          <label className="review-check">
            <input
              type="checkbox"
              checked={accessReviewed}
              disabled={!accessSubject.trim()}
              onChange={(event) => setAccessReviewed(event.target.checked)}
            />
            I reviewed this exact identity, action and role.
          </label>
          <button
            disabled={busy || !accessSubject.trim() || !accessReviewed}
            onClick={() => void applyAccessMutation()}
          >
            Apply reviewed access
          </button>
          {accessResult && <p role="status">{accessResult}</p>}
        </article>
      )}
      {canWriteRuleAccess && (
        <article
          className="program-inspector access-editor"
          aria-labelledby="role-data-security-heading"
        >
          <small>ROLE-LEVEL CAPABILITIES</small>
          <h2 id="role-data-security-heading" tabIndex={-1}>
            Role and data security
          </h2>
          <h3>Reviewed rule permissions</h3>
          <p>
            Select an existing application user, then set or revoke their
            design, publish and run permissions.
          </p>
          <label>
            Application user
            <select
              value={ruleSubject}
              onChange={(event) => {
                const grant = grants.find(
                  (item) => item.subjectId === event.target.value,
                );
                if (grant) chooseRuleGrant(grant);
                else {
                  setRuleSubject("");
                  setRuleReviewed(false);
                }
              }}
            >
              <option value="">Select a current user</option>
              {grants.map((grant) => (
                <option key={grant.subjectId} value={grant.subjectId}>
                  {grant.subjectId} · {grant.role}
                </option>
              ))}
            </select>
          </label>
          <label>
            Action
            <select
              value={ruleAction}
              onChange={(event) => {
                setRuleAction(event.target.value as "set" | "revoke");
                setRuleReviewed(false);
                setRuleResult("");
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
          {ruleResult && <p role="status">{ruleResult}</p>}
        </article>
      )}
      <p className="authority-note">
        Server authorization, idempotency and security receipts remain
        authoritative. Every reviewed change still passes through the governed
        fixed-core security service.
      </p>
    </section>
  );
}
