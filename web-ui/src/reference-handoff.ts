import type { Scope } from "./types";

export type AnalyticalRead =
  | { semantics: "stored" | "own" }
  | { semantics: "effective"; bindingId: string; bindingStateToken: string };

export type SavedViewContext = {
  viewId: string;
  viewDigest: string;
  analyticalRead: AnalyticalRead;
};

export type TaskReference = { kind: "task"; taskId: string };
export type WorkflowReference = {
  kind: "workflowActivity";
  occurrenceId: string;
  activityId?: string;
};
export type DefinitionKind =
  | "ApplicationRule"
  | "CalculatedMember"
  | "ApplicationSequence"
  | "ApplicationSchedule";
export type ObjectReference =
  | TaskReference
  | WorkflowReference
  | { kind: "savedView"; viewId: string }
  | { kind: "definition"; artifactKind: DefinitionKind; artifactId: string };

// References carry neither authority nor an owner snapshot. Receiving clients
// must resolve these objects through their ordinary authenticated read contracts.
// Canonical saved views own dataSource/selection; analyticalRead is independent.
export type ReferenceHandoff = {
  format: "openepm.reference-handoff/v1";
  scope: Scope;
  origin: ObjectReference | null;
  target: ObjectReference;
  returnTo: TaskReference | WorkflowReference | null;
  observed: {
    viewDigest?: string;
    stateToken?: string;
    definitionDigest?: string;
  };
  pendingOperation: TaskReference | null;
  analyticalRead?: AnalyticalRead;
};

export type ResolvedReferenceContext = {
  target: ObjectReference;
  observed: ReferenceHandoff["observed"];
  analyticalRead?: AnalyticalRead;
};

const digest = /^[0-9a-f]{64}$/;
const definitionKinds = [
  "ApplicationRule",
  "CalculatedMember",
  "ApplicationSequence",
  "ApplicationSchedule",
];
const maxHandoffCharacters = 8192;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function keys(
  value: Record<string, unknown>,
  required: string[],
  optional: string[] = [],
) {
  return (
    required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every(
      (key) => required.includes(key) || optional.includes(key),
    )
  );
}

function identifier(value: unknown): value is string {
  // IDs are opaque presentation references. The native owner validates its own
  // identifier grammar; this boundary excludes empty, oversized and control text.
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= 500 &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function reference(value: unknown): value is ObjectReference {
  if (!record(value)) return false;
  switch (value.kind) {
    case "task":
      return keys(value, ["kind", "taskId"]) && identifier(value.taskId);
    case "savedView":
      return keys(value, ["kind", "viewId"]) && identifier(value.viewId);
    case "workflowActivity":
      return (
        keys(value, ["kind", "occurrenceId"], ["activityId"]) &&
        identifier(value.occurrenceId) &&
        (!Object.hasOwn(value, "activityId") || identifier(value.activityId))
      );
    case "definition":
      return (
        keys(value, ["kind", "artifactKind", "artifactId"]) &&
        definitionKinds.includes(String(value.artifactKind)) &&
        identifier(value.artifactId)
      );
    default:
      return false;
  }
}

function analyticalRead(value: unknown): value is AnalyticalRead {
  if (!record(value)) return false;
  if (value.semantics === "own" || value.semantics === "stored")
    return keys(value, ["semantics"]);
  return (
    value.semantics === "effective" &&
    keys(value, ["semantics", "bindingId", "bindingStateToken"]) &&
    identifier(value.bindingId) &&
    typeof value.bindingStateToken === "string" &&
    digest.test(value.bindingStateToken)
  );
}

export function parseReferenceHandoff(input: unknown): ReferenceHandoff {
  const invalid = () =>
    new Error(
      "Invalid or unsupported reference handoff. Request a fresh reference from the originating client.",
    );
  let value: unknown = input;
  if (typeof input === "string") {
    if (input.length > maxHandoffCharacters) throw invalid();
    try {
      value = JSON.parse(input);
    } catch {
      throw invalid();
    }
  }
  if (
    !record(value) ||
    !keys(
      value,
      [
        "format",
        "scope",
        "origin",
        "target",
        "returnTo",
        "observed",
        "pendingOperation",
      ],
      ["analyticalRead"],
    ) ||
    value.format !== "openepm.reference-handoff/v1" ||
    !record(value.scope) ||
    !keys(value.scope, ["workspaceId", "applicationId"]) ||
    !identifier(value.scope.workspaceId) ||
    !identifier(value.scope.applicationId) ||
    (value.origin !== null && !reference(value.origin)) ||
    !reference(value.target) ||
    (value.returnTo !== null &&
      (!reference(value.returnTo) ||
        !["task", "workflowActivity"].includes(value.returnTo.kind))) ||
    (value.pendingOperation !== null &&
      (!reference(value.pendingOperation) ||
        value.pendingOperation.kind !== "task")) ||
    !record(value.observed)
  )
    throw invalid();

  if (value.target.kind === "savedView") {
    if (
      !keys(value.observed, [], ["viewDigest"]) ||
      (Object.hasOwn(value.observed, "viewDigest") &&
        (typeof value.observed.viewDigest !== "string" ||
          !digest.test(value.observed.viewDigest))) ||
      !analyticalRead(value.analyticalRead)
    )
      throw invalid();
  } else {
    if (Object.hasOwn(value, "analyticalRead")) throw invalid();
    if (value.target.kind === "definition") {
      if (
        !keys(value.observed, ["stateToken", "definitionDigest"]) ||
        typeof value.observed.stateToken !== "string" ||
        !digest.test(value.observed.stateToken) ||
        typeof value.observed.definitionDigest !== "string" ||
        !digest.test(value.observed.definitionDigest)
      )
        throw invalid();
    } else if (!keys(value.observed, [])) throw invalid();
  }
  if (JSON.stringify(value).length > maxHandoffCharacters) throw invalid();
  return value as ReferenceHandoff;
}

export function referenceHandoffHash(handoff: ReferenceHandoff) {
  return `#/reference?${new URLSearchParams({ handoff: JSON.stringify(parseReferenceHandoff(handoff)) })}`;
}

export function referenceDestination(handoff: ReferenceHandoff) {
  const target = handoff.target;
  switch (target.kind) {
    case "savedView":
      return {
        page: "grid" as const,
        focus: {
          viewId: target.viewId,
          viewDigest: handoff.observed.viewDigest,
        },
      };
    case "task":
      return { page: "monitor" as const, focus: { taskId: target.taskId } };
    case "workflowActivity":
      return {
        page: "flows" as const,
        focus: {
          occurrenceId: target.occurrenceId,
          activityId: target.activityId,
        },
      };
    case "definition":
      return {
        page: "rules" as const,
        focus: {
          artifactKind: target.artifactKind,
          artifactId: target.artifactId,
          artifactStateToken: handoff.observed.stateToken,
          artifactDigest: handoff.observed.definitionDigest,
        },
      };
  }
}

export function retargetReferenceHandoff(
  handoff: ReferenceHandoff,
  target: TaskReference | WorkflowReference,
): ReferenceHandoff {
  return parseReferenceHandoff({
    format: handoff.format,
    scope: handoff.scope,
    origin: handoff.target,
    target,
    returnTo: null,
    observed: {},
    pendingOperation: null,
  });
}
