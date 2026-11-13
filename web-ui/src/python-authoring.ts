import type { ApplicationCatalog, Scope } from "./types";
import type {
  PythonCompletionDescriptor,
  PythonDiagnostics,
} from "./python-editor-contract";

export type PythonBuildStatus = {
  buildId: string;
  status: string;
  purpose: "Validation" | "ImpactTest" | "Plan";
  current?: boolean;
  diagnostics?: PythonDiagnostics;
  errorCode?: string | null;
  definition?: {
    kind: "ApplicationRule" | "MemberList" | "CalculatedMember";
    definitionId: string;
    parameters?: Array<Record<string, unknown>>;
  };
};

export function authoringContextKey(scope: Scope, catalog: ApplicationCatalog) {
  return JSON.stringify([
    scope.workspaceId,
    scope.applicationId,
    catalog.applicationAccess.issuer,
    catalog.applicationAccess.subjectId,
    catalog.revisions.metadata,
    catalog.revisions.policy,
    catalog.revisions.security,
    catalog.revisions.schemaEpoch,
  ]);
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/** Only the versioned server envelope may become editor markers. */
export function pythonDiagnostics(
  value: unknown,
): PythonDiagnostics | undefined {
  const envelope = record(value);
  if (
    !envelope ||
    envelope.format !== "openepm-diagnostics-v1" ||
    envelope.positionEncoding !== "utf-16" ||
    typeof envelope.sourceDigest !== "string" ||
    !/^[a-f0-9]{64}$/.test(envelope.sourceDigest) ||
    typeof envelope.truncated !== "boolean" ||
    !Array.isArray(envelope.diagnostics) ||
    envelope.diagnostics.length > 100
  )
    return undefined;
  for (const value of envelope.diagnostics) {
    const item = record(value);
    if (
      !item ||
      !["error", "warning", "info"].includes(String(item.severity)) ||
      !["code", "stage", "message"].every(
        (key) => typeof item[key] === "string",
      ) ||
      ["path", "hint"].some(
        (key) => item[key] !== undefined && typeof item[key] !== "string",
      )
    )
      return undefined;
    if (item.span !== undefined) {
      const span = record(item.span);
      if (
        !span ||
        !["startLine", "startColumn", "endLine", "endColumn"].every(
          (key) => Number.isSafeInteger(span[key]) && Number(span[key]) > 0,
        )
      )
        return undefined;
    }
  }
  return envelope as unknown as PythonDiagnostics;
}

/** Grain names come from the authorized bootstrap; object references bind later. */
export function authoringCompletions(
  value: unknown,
  scope: Scope,
  catalog: ApplicationCatalog,
): PythonCompletionDescriptor[] {
  const context = record(value);
  const authority = record(context?.authority);
  const metadata = record(record(context?.references)?.metadata);
  const authoringContract = record(
    record(context?.references)?.authoringContract,
  );
  if (
    !context ||
    !metadata ||
    context.workspaceId !== scope.workspaceId ||
    context.applicationId !== scope.applicationId ||
    context.metadataRevision !== catalog.revisions.metadata ||
    context.policyRevision !== catalog.revisions.policy ||
    context.securityRevision !== catalog.revisions.security ||
    !catalog.applicationAccess.issuer ||
    !catalog.applicationAccess.subjectId ||
    authority?.issuer !== catalog.applicationAccess.issuer ||
    authority.subjectId !== catalog.applicationAccess.subjectId ||
    context.schemaEpoch !== catalog.revisions.schemaEpoch ||
    metadata.workspaceId !== scope.workspaceId ||
    metadata.applicationId !== scope.applicationId ||
    metadata.metadataRevision !== catalog.revisions.metadata ||
    typeof metadata.authorizationScopeDigest !== "string" ||
    !/^[a-f0-9]{64}$/.test(metadata.authorizationScopeDigest) ||
    !Array.isArray(metadata.dimensions) ||
    (authoringContract !== undefined &&
      (authoringContract.format !== "openepm-authoring-contract-v1" ||
        typeof authoringContract.digest !== "string" ||
        !/^[a-f0-9]{64}$/.test(authoringContract.digest)))
  )
    throw new Error(
      "Metadata suggestions are stale. Refresh the application context.",
    );
  const completions: PythonCompletionDescriptor[] = [];
  const reference =
    record(authoringContract?.references)?.pythonAuthoring ||
    "/documentation/architecture/python-authoring/";
  if (typeof reference !== "string")
    throw new Error("Invalid authorized authoring contract.");
  for (const method of [
    "member",
    "member_list",
    "hierarchy",
    "children",
    "descendants",
    "ancestors",
    "siblings",
    "leaves",
    "attribute",
  ])
    completions.push({
      label: method,
      insertText: method,
      kind: "function",
      detail: "Open EPM selection primitive",
      documentation: `Compose a typed ${method} selection against authorized application metadata.`,
      referenceUrl: reference,
    });
  for (const value of metadata.dimensions) {
    const dimension = record(value);
    if (
      !dimension ||
      typeof dimension.dimensionId !== "string" ||
      typeof dimension.name !== "string" ||
      dimension.referenceMode !== "symbolic"
    )
      throw new Error("Invalid authorized metadata context.");
    const expression = `context.app.dimension(${JSON.stringify(dimension.name)})`;
    completions.push({
      label: dimension.name,
      insertText: expression,
      kind: "field",
      detail: "Application dimension",
      referenceUrl: reference,
    });
  }
  return completions;
}

export function buildIsPending(build: PythonBuildStatus) {
  return ["accepted", "ready", "running", "cancel_requested"].includes(
    build.status,
  );
}
