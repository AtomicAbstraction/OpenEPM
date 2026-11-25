import type {
  ApplicationCatalog,
  ApplicationSummary,
  Scope,
  SessionIdentity,
} from "./types";
import {
  classifyBrowserFailure,
  setBrowserLifecycle,
} from "./browser-lifecycle";

export type ApiFailureKind =
  | "authentication"
  | "authorization"
  | "conflict"
  | "capacity"
  | "unavailable"
  | "request";

function failureKind(status: number): ApiFailureKind {
  if (status === 401) return "authentication";
  if (status === 403) return "authorization";
  if (status === 409 || status === 412) return "conflict";
  if (status === 429) return "capacity";
  if ([502, 503, 504].includes(status)) return "unavailable";
  return "request";
}

export class ApiError extends Error {
  public kind: ApiFailureKind;

  constructor(
    public status: number,
    public code: string,
    public correlationId?: string,
    public retryable?: boolean,
    public details?: Record<string, unknown>,
    message?: string,
  ) {
    super(message || code);
    this.name = "ApiError";
    this.kind = failureKind(status);
  }
}

export function isApplicationAccessDenied(reason: unknown) {
  return (
    reason instanceof ApiError &&
    reason.kind === "authorization" &&
    [
      "APPLICATION_GRANT_REQUIRED",
      "APPLICATION_UNAVAILABLE",
      "WORKSPACE_UNAVAILABLE",
    ].includes(reason.code)
  );
}

export function isDefiniteEffectRefusal(
  reason: unknown,
  refusalCodes: ReadonlySet<string>,
): reason is ApiError {
  return (
    reason instanceof ApiError &&
    [400, 403, 409, 422].includes(reason.status) &&
    reason.retryable !== true &&
    refusalCodes.has(reason.code)
  );
}

type BrowserIdentity = { binding: string | null };
let activeBrowserIdentity: BrowserIdentity = { binding: null };

function assertBrowserIdentityCurrent(identity: BrowserIdentity) {
  if (identity !== activeBrowserIdentity)
    throw new DOMException("Browser identity changed", "AbortError");
}

export async function request<T>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
  expectedIdentityBinding?: string | null,
): Promise<T> {
  const identity = activeBrowserIdentity;
  const binding =
    expectedIdentityBinding === undefined
      ? identity.binding
      : expectedIdentityBinding;
  function assertCurrent() {
    signal?.throwIfAborted();
    if (expectedIdentityBinding === undefined)
      assertBrowserIdentityCurrent(identity);
  }
  const headers: Record<string, string> = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (binding) headers["x-openepm-browser-identity"] = binding;
  let response: Response;
  assertCurrent();
  try {
    response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
      signal,
    });
  } catch (error) {
    assertCurrent();
    classifyBrowserFailure(error);
    throw error;
  }
  assertCurrent();
  if (response.redirected) {
    const error = new ApiError(401, "AUTHENTICATION_REDIRECTED");
    setBrowserLifecycle("expired", error.code, true);
    throw error;
  }
  let payload: unknown = null;
  let parsed = false;
  try {
    payload = await response.json();
    parsed = true;
  } catch (error) {
    // A navigation-owned cancellation can arrive after the headers, while
    // the body is still being read. It is not a malformed server response.
    assertCurrent();
    if (error instanceof DOMException && error.name === "AbortError")
      throw error;
    /* Malformed content is handled below. */
  }
  assertCurrent();
  if (!response.ok) {
    const failure =
      typeof payload === "object" && payload
        ? (payload as Record<string, unknown>)
        : null;
    const code =
      failure && ("code" in failure || "error" in failure)
        ? String(failure.code || failure.error)
        : `HTTP_${response.status}`;
    const correlationId =
      failure && typeof failure.correlationId === "string"
        ? failure.correlationId
        : undefined;
    const retryable =
      failure && typeof failure.retryable === "boolean"
        ? failure.retryable
        : undefined;
    const details =
      failure &&
      typeof failure.details === "object" &&
      failure.details !== null &&
      !Array.isArray(failure.details)
        ? (failure.details as Record<string, unknown>)
        : undefined;
    const error = new ApiError(
      response.status,
      code,
      correlationId,
      retryable,
      details,
      failure && typeof failure.message === "string"
        ? failure.message
        : undefined,
    );
    if (error.kind === "authentication")
      setBrowserLifecycle("expired", code, true);
    else if (
      error.kind === "unavailable" ||
      (error.status === 409 && error.code === "BROWSER_IDENTITY_CHANGED")
    )
      setBrowserLifecycle("unavailable", code);
    throw error;
  }
  if (!parsed) {
    const error = new ApiError(502, "INVALID_RESPONSE_CONTENT");
    setBrowserLifecycle("unavailable", error.code);
    throw error;
  }
  return payload as T;
}

type PreviewEnvelope = {
  previewToken?: unknown;
  programDigest?: unknown;
  planDigest?: unknown;
  revisionVector?: unknown;
  savedProgram?: unknown;
};

export type PreviewedSubmissionBody = Scope & {
  program: Record<string, unknown>;
  idempotencyKey: string;
  dependsOnJobIds: string[];
  confirmed: boolean;
};

type OperationAdmission = {
  operationId: string;
  expiresAt: number;
  intentDigest: string;
};

const operationAdmissions = new Map<
  string,
  { operationId: string; expiresAt: number }
>();
const MAX_OPERATION_ADMISSIONS = 256;

export function adoptBrowserIdentity(identity: SessionIdentity) {
  if (activeBrowserIdentity.binding === identity.identityBinding) return;
  operationAdmissions.clear();
  activeBrowserIdentity = { binding: identity.identityBinding };
}

export function resetOperationAdmissionsForTests(): void {
  operationAdmissions.clear();
  activeBrowserIdentity = { binding: null };
}

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  return JSON.stringify(value);
}

/** Resolve one caller retry intent to a bounded server-issued effect identity. */
export async function admitApplicationEffect(
  body: Pick<
    PreviewedSubmissionBody,
    "workspaceId" | "applicationId" | "program" | "idempotencyKey"
  >,
  signal?: AbortSignal,
): Promise<string> {
  const identity = activeBrowserIdentity;
  const now = Math.floor(Date.now() / 1000);
  for (const [key, value] of operationAdmissions)
    if (value.expiresAt <= now + 30) operationAdmissions.delete(key);
  const cacheKey = canonicalJson({
    workspaceId: body.workspaceId,
    applicationId: body.applicationId,
    program: body.program,
    clientIntentKey: body.idempotencyKey,
  });
  const current = operationAdmissions.get(cacheKey);
  if (current) return current.operationId;
  const admission = await request<OperationAdmission>(
    "/api/operation-admission",
    {
      workspaceId: body.workspaceId,
      applicationId: body.applicationId,
      program: body.program,
    },
    signal,
  );
  assertBrowserIdentityCurrent(identity);
  if (
    typeof admission.operationId !== "string" ||
    !/^oa1_[0-9a-z]{1,13}_[0-9a-f]{32}_[A-Za-z0-9_-]{43}$/.test(
      admission.operationId,
    ) ||
    !Number.isSafeInteger(admission.expiresAt) ||
    admission.expiresAt <= now + 30 ||
    typeof admission.intentDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(admission.intentDigest)
  )
    throw new ApiError(502, "INVALID_OPERATION_ADMISSION");
  while (operationAdmissions.size >= MAX_OPERATION_ADMISSIONS)
    operationAdmissions.delete(
      operationAdmissions.keys().next().value as string,
    );
  operationAdmissions.set(cacheKey, {
    operationId: admission.operationId,
    expiresAt: admission.expiresAt,
  });
  return admission.operationId;
}

/** Submit an application effect only after replacing its retry key with a server admission. */
export async function requestAdmittedEffect<T>(
  path: string,
  body: Scope & {
    program: Record<string, unknown>;
    idempotencyKey: string;
    [key: string]: unknown;
  },
  signal?: AbortSignal,
): Promise<T> {
  const identity = activeBrowserIdentity;
  const operationId = await admitApplicationEffect(body, signal);
  assertBrowserIdentityCurrent(identity);
  return request<T>(path, { ...body, idempotencyKey: operationId }, signal);
}

/** Admit an effect whose legacy fixed program owns its persisted retry field. */
export type AdmittedEffectPacket = {
  path: string;
  body: Scope & {
    program: Record<string, unknown>;
    idempotencyKey: string;
    [key: string]: unknown;
  };
};

/** Capture the actual admitted identity before the first possible effect.
 * Keep this packet through an uncertain response; re-admission is a new intent.
 */
export async function prepareAdmittedProgramEffect(
  path: string,
  body: Scope & {
    program: Record<string, unknown>;
    [key: string]: unknown;
  },
  clientIntentKey: string,
  signal?: AbortSignal,
): Promise<AdmittedEffectPacket> {
  const identity = activeBrowserIdentity;
  const captured = structuredClone(body);
  const operationId = await admitApplicationEffect(
    { ...captured, idempotencyKey: clientIntentKey },
    signal,
  );
  assertBrowserIdentityCurrent(identity);
  return { path, body: { ...captured, idempotencyKey: operationId } };
}

/** Replay never renews admission, rebuilds the preview or changes the intent. */
export function replayAdmittedEffect<T>(
  packet: AdmittedEffectPacket,
  signal?: AbortSignal,
): Promise<T> {
  return request<T>(packet.path, packet.body, signal);
}

export async function requestAdmittedProgramEffect<T>(
  path: string,
  body: Scope & {
    program: Record<string, unknown>;
    [key: string]: unknown;
  },
  clientIntentKey: string,
  signal?: AbortSignal,
): Promise<T> {
  const identity = activeBrowserIdentity;
  const packet = await prepareAdmittedProgramEffect(
    path,
    body,
    clientIntentKey,
    signal,
  );
  assertBrowserIdentityCurrent(identity);
  return replayAdmittedEffect<T>(packet, signal);
}

async function submitWithPreview<T>(
  body: PreviewedSubmissionBody,
  signal: AbortSignal | undefined,
  accept: (preview: PreviewEnvelope) => boolean,
): Promise<T | null> {
  const identity = activeBrowserIdentity;
  if (body.confirmed !== true)
    throw new ApiError(400, "PREVIEW_CONFIRMATION_REQUIRED");
  const preview = await request<PreviewEnvelope>(
    "/api/preview",
    {
      workspaceId: body.workspaceId,
      applicationId: body.applicationId,
      program: body.program,
    },
    signal,
  );
  assertBrowserIdentityCurrent(identity);
  if (
    typeof preview.previewToken !== "string" ||
    preview.previewToken.length < 16 ||
    preview.previewToken.length > 262144
  )
    throw new ApiError(502, "INVALID_SERVER_PREVIEW");
  if (!accept(preview)) return null;
  assertBrowserIdentityCurrent(identity);
  const operationId = await admitApplicationEffect(body, signal);
  assertBrowserIdentityCurrent(identity);
  return request<T>(
    "/api/submit",
    {
      ...body,
      idempotencyKey: operationId,
      previewToken: preview.previewToken,
    },
    signal,
  );
}

/** A single Run intent still obtains and submits an exact server-sealed preview. */
export async function previewAndSubmit<T>(
  body: PreviewedSubmissionBody,
  expected: { ruleId: string; stateToken: string; programDigest: string },
  signal?: AbortSignal,
): Promise<T> {
  return (await submitWithPreview<T>(body, signal, (preview) => {
    const pin = preview.savedProgram;
    if (
      !pin ||
      typeof pin !== "object" ||
      Array.isArray(pin) ||
      (pin as Record<string, unknown>).ruleId !== expected.ruleId ||
      (pin as Record<string, unknown>).stateToken !== expected.stateToken ||
      (pin as Record<string, unknown>).programDigest !== expected.programDigest
    )
      throw new ApiError(409, "SAVED_PROGRAM_PREVIEW_CHANGED");
    return true;
  })) as T;
}

/** Destructive callers retain their explicit human confirmation. */
export async function reviewAndSubmit<T>(
  body: PreviewedSubmissionBody,
  label: string,
  signal?: AbortSignal,
): Promise<T | null> {
  return submitWithPreview<T>(body, signal, (preview) => {
    const digest =
      typeof preview.programDigest === "string"
        ? preview.programDigest
        : typeof preview.planDigest === "string"
          ? preview.planDigest
          : "sealed by the server";
    const revisions =
      preview.revisionVector && typeof preview.revisionVector === "object"
        ? JSON.stringify(preview.revisionVector)
        : "embedded in the sealed preview";
    return window.confirm(
      `${label}\n\nServer preview: ${digest}\nDependency revisions: ${revisions}\n\nSubmit this exact preview?`,
    );
  });
}

export async function listApplications(
  signal?: AbortSignal,
  expectedIdentityBinding?: string,
): Promise<ApplicationSummary[]> {
  const identity = activeBrowserIdentity;
  const applications: ApplicationSummary[] = [];
  type Cursor = { workspaceId: string; applicationId: string };
  let after: Cursor | null = null;
  const seenApplications = new Set<string>();
  const seenCursors = new Set<string>();
  do {
    if (expectedIdentityBinding === undefined)
      assertBrowserIdentityCurrent(identity);
    const query = after
      ? `?afterWorkspaceId=${encodeURIComponent(after.workspaceId)}&afterApplicationId=${encodeURIComponent(after.applicationId)}`
      : "";
    const page = applicationPage(
      await request<unknown>(
        `/api/applications${query}`,
        undefined,
        signal,
        expectedIdentityBinding,
      ),
    );
    if (expectedIdentityBinding === undefined)
      assertBrowserIdentityCurrent(identity);
    for (const application of page.applications) {
      const identity = `${application.workspaceId}\u0000${application.applicationId}`;
      if (seenApplications.has(identity))
        throw new ApiError(502, "APPLICATION_CATALOG_REPEATED_APPLICATION");
      seenApplications.add(identity);
      applications.push(application);
    }
    if (applications.length > APPLICATION_CATALOG_MAX_ROWS)
      throw new ApiError(502, "APPLICATION_CATALOG_CAPACITY_EXCEEDED");
    after = page.nextAfter;
    if (after) {
      const cursor = `${after.workspaceId}\u0000${after.applicationId}`;
      if (seenCursors.has(cursor))
        throw new ApiError(502, "APPLICATION_CATALOG_REPEATED_CURSOR");
      seenCursors.add(cursor);
    }
  } while (after);
  return applications;
}

export const readSession = (signal?: AbortSignal) =>
  request<SessionIdentity>(
    "/api/session-identity",
    undefined,
    signal,
    null,
  ).then((identity) => {
    if (
      !identity ||
      typeof identity.subject !== "string" ||
      !identity.subject ||
      typeof identity.identityBinding !== "string" ||
      !/^[0-9a-f]{64}$/.test(identity.identityBinding) ||
      (identity.issuer !== undefined && typeof identity.issuer !== "string") ||
      (identity.displayIdentity !== undefined &&
        typeof identity.displayIdentity !== "string") ||
      (identity.applicationMcpEndpoint != null &&
        typeof identity.applicationMcpEndpoint !== "string")
    )
      throw new ApiError(502, "INVALID_SESSION_IDENTITY", undefined, true);
    return identity;
  });
export const readRuntime = (signal?: AbortSignal) =>
  request<{
    readOnlyReview: boolean;
    build: {
      applicationImage?: string;
      sourceCommit?: string;
      sourceTree?: string;
      packagedSchema?: number;
    };
  }>("/api/runtime", undefined, signal, null);

const APPLICATION_CATALOG_MAX_ROWS = 100_000;

function applicationPage(value: unknown): {
  applications: ApplicationSummary[];
  nextAfter: { workspaceId: string; applicationId: string } | null;
} {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new ApiError(502, "INVALID_APPLICATION_CATALOG_PAGE");
  const record = value as Record<string, unknown>;
  if (
    !Array.isArray(record.applications) ||
    record.applications.length > 100 ||
    !(record.nextAfter === null || typeof record.nextAfter === "object")
  )
    throw new ApiError(502, "INVALID_APPLICATION_CATALOG_PAGE");
  const applications = record.applications.map((item) => {
    if (typeof item !== "object" || item === null || Array.isArray(item))
      throw new ApiError(502, "INVALID_APPLICATION_CATALOG_PAGE");
    const application = item as Record<string, unknown>;
    for (const field of ["workspaceId", "applicationId", "name", "status"])
      if (
        typeof application[field] !== "string" ||
        application[field].length === 0
      )
        throw new ApiError(502, "INVALID_APPLICATION_CATALOG_PAGE");
    if (
      typeof application.workspaceId !== "string" ||
      typeof application.applicationId !== "string" ||
      application.workspaceId.length > 200 ||
      application.applicationId.length > 200 ||
      (application.workspaceName !== undefined &&
        typeof application.workspaceName !== "string") ||
      (application.kind !== undefined && typeof application.kind !== "string")
    )
      throw new ApiError(502, "INVALID_APPLICATION_CATALOG_PAGE");
    return application as ApplicationSummary;
  });
  if (record.nextAfter === null) return { applications, nextAfter: null };
  const cursor = record.nextAfter as Record<string, unknown>;
  if (
    Object.keys(cursor).sort().join(",") !== "applicationId,workspaceId" ||
    typeof cursor.workspaceId !== "string" ||
    typeof cursor.applicationId !== "string" ||
    cursor.workspaceId.length === 0 ||
    cursor.workspaceId.length > 200 ||
    cursor.applicationId.length === 0 ||
    cursor.applicationId.length > 200 ||
    applications.length === 0 ||
    applications.at(-1)?.workspaceId !== cursor.workspaceId ||
    applications.at(-1)?.applicationId !== cursor.applicationId
  )
    throw new ApiError(502, "INVALID_APPLICATION_CATALOG_CONTINUATION");
  return {
    applications,
    nextAfter: {
      workspaceId: cursor.workspaceId,
      applicationId: cursor.applicationId,
    },
  };
}
export const readPlatformCatalog = (
  signal: AbortSignal,
  identityBinding: string,
) =>
  request<{
    languageVersion: number;
    authorized?: boolean;
    functions: Record<string, unknown>;
  }>("/api/platform/browser/catalog", {}, signal, identityBinding);
export const readPlatformProgram = <T>(
  functionName: string,
  args: Record<string, unknown>,
  signal?: AbortSignal,
) =>
  request<T>(
    "/api/platform/browser/read",
    {
      program: {
        languageVersion: 2,
        function: functionName,
        arguments: args,
      },
    },
    signal,
  );
export const writePlatformProgram = <T>(
  functionName: string,
  args: Record<string, unknown>,
  idempotencyKey: string,
  signal?: AbortSignal,
) =>
  request<T>(
    "/api/platform/browser/write",
    {
      program: {
        languageVersion: 2,
        function: functionName,
        arguments: args,
      },
      idempotencyKey,
      confirmed: true,
    },
    signal,
  );
const applicationScope = (scope: Scope): Scope => ({
  workspaceId: scope.workspaceId,
  applicationId: scope.applicationId,
});
export const readCatalog = (scope: Scope, signal?: AbortSignal) =>
  request<ApplicationCatalog>("/api/catalog", applicationScope(scope), signal);
export const readSecurityProgram = <T>(
  scope: Scope,
  functionName: string,
  args: Record<string, unknown>,
  signal?: AbortSignal,
) =>
  request<{ result: T }>(
    "/api/security",
    {
      ...applicationScope(scope),
      program: {
        languageVersion: 2,
        function: functionName,
        arguments: args,
      },
    },
    signal,
  ).then((value) => value.result);
export const readProgram = <T>(
  scope: Scope,
  functionName: string,
  args: Record<string, unknown>,
  signal?: AbortSignal,
) =>
  request<{ result: T }>(
    "/api/read",
    {
      ...applicationScope(scope),
      program: {
        languageVersion: 2,
        function: functionName,
        arguments: args,
      },
    },
    signal,
  ).then((value) => value.result);
