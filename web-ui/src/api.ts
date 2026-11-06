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
  ) {
    super(code);
    this.name = "ApiError";
    this.kind = failureKind(status);
  }
}

export async function request<T>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers:
        body === undefined
          ? { accept: "application/json" }
          : { accept: "application/json", "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
      signal,
    });
  } catch (error) {
    classifyBrowserFailure(error);
    throw error;
  }
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
  } catch {
    /* fail below */
  }
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
    );
    if (error.kind === "authentication")
      setBrowserLifecycle("expired", code, true);
    else if (error.kind === "unavailable")
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
};

export type PreviewedSubmissionBody = Scope & {
  program: Record<string, unknown>;
  idempotencyKey: string;
  dependsOnJobIds: string[];
  confirmed: boolean;
};

/** Submit only the exact server preview the user has reviewed. */
export async function reviewAndSubmit<T>(
  body: PreviewedSubmissionBody,
  label: string,
  signal?: AbortSignal,
): Promise<T | null> {
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
  if (
    typeof preview.previewToken !== "string" ||
    preview.previewToken.length < 16 ||
    preview.previewToken.length > 262144
  )
    throw new ApiError(502, "INVALID_SERVER_PREVIEW");
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
  if (
    !window.confirm(
      `${label}\n\nServer preview: ${digest}\nDependency revisions: ${revisions}\n\nSubmit this exact preview?`,
    )
  )
    return null;
  return request<T>(
    "/api/submit",
    { ...body, previewToken: preview.previewToken },
    signal,
  );
}

export async function listApplications(
  signal?: AbortSignal,
): Promise<ApplicationSummary[]> {
  const applications: ApplicationSummary[] = [];
  type Cursor = { workspaceId: string; applicationId: string };
  let after: Cursor | null = null;
  const seenApplications = new Set<string>();
  const seenCursors = new Set<string>();
  do {
    const query = after
      ? `?afterWorkspaceId=${encodeURIComponent(after.workspaceId)}&afterApplicationId=${encodeURIComponent(after.applicationId)}`
      : "";
    const page = applicationPage(
      await request<unknown>(`/api/applications${query}`, undefined, signal),
    );
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
  request<SessionIdentity>("/api/session-identity", undefined, signal).then(
    (identity) => {
      setBrowserLifecycle("authenticated", undefined, true);
      return identity;
    },
  );
export const readRuntime = (signal?: AbortSignal) =>
  request<{
    readOnlyReview: boolean;
    build: {
      applicationImage?: string;
      sourceCommit?: string;
      sourceTree?: string;
      packagedSchema?: number;
    };
  }>("/api/runtime", undefined, signal);

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
export const readPlatformCatalog = (signal?: AbortSignal) =>
  request<{ languageVersion: number; functions: Record<string, unknown> }>(
    "/api/platform/browser/catalog",
    {},
    signal,
  );
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
export const readCatalog = (scope: Scope, signal?: AbortSignal) =>
  request<ApplicationCatalog>("/api/catalog", scope, signal);
export const readSecurityProgram = <T>(
  scope: Scope,
  functionName: string,
  args: Record<string, unknown>,
  signal?: AbortSignal,
) =>
  request<{ result: T }>(
    "/api/security",
    {
      ...scope,
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
      ...scope,
      program: {
        languageVersion: 2,
        function: functionName,
        arguments: args,
      },
    },
    signal,
  ).then((value) => value.result);
