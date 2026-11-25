// Projection of postgres_definition_lifecycle.current_state. Technical builds
// and published-result freshness are separate observations, never authority.
export const DEFINITION_OWNER_REASONS = {
  ownership_unresolved: "Output ownership unresolved",
  validation_required: "Current definition validation required",
  metadata_stale: "Revalidation required · application metadata changed",
  schema_stale: "Revalidation required · application schema changed",
  dependency_stale: "Revalidation required · definition dependencies changed",
  source_environment_stale:
    "Revalidation required · source environment changed",
  compiler_unavailable: "Revalidation required · accepted compiler unavailable",
  inactive: "Validated · inactive",
} as const;

export type DefinitionLifecycle = {
  defined: true;
  status: "Inactive" | "Active" | "Unavailable";
  valid: boolean;
  active: boolean;
  sourceCurrent: boolean;
  executable: boolean;
  reason: keyof typeof DEFINITION_OWNER_REASONS | null;
};

export function isDefinitionLifecycle(
  value: unknown,
): value is DefinitionLifecycle & Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const owner = value as Record<string, unknown>;
  return (
    owner.defined === true &&
    typeof owner.status === "string" &&
    ["Inactive", "Active", "Unavailable"].includes(owner.status) &&
    typeof owner.valid === "boolean" &&
    typeof owner.active === "boolean" &&
    typeof owner.sourceCurrent === "boolean" &&
    typeof owner.executable === "boolean" &&
    (owner.reason === null ||
      (typeof owner.reason === "string" &&
        Object.hasOwn(DEFINITION_OWNER_REASONS, owner.reason))) &&
    (owner.status === "Unavailable") === !owner.sourceCurrent &&
    (owner.reason === "ownership_unresolved") === !owner.sourceCurrent &&
    (owner.reason !== "ownership_unresolved" ||
      (!owner.valid && !owner.active && !owner.executable)) &&
    owner.valid === (owner.reason === null || owner.reason === "inactive") &&
    (owner.reason !== "inactive" || !owner.active) &&
    (owner.reason !== null || owner.active) &&
    owner.executable === (owner.valid && owner.active) &&
    (owner.status === "Active") === owner.active
  );
}

export function definitionAvailabilityLabel(owner: DefinitionLifecycle) {
  return owner.reason ? DEFINITION_OWNER_REASONS[owner.reason] : "Executable";
}

export const DEFINITION_VALIDATION_EXPLANATION =
  "This technical build status is separate from the current definition's acceptance and execution validity. An expired build does not itself deactivate a definition; execution still checks current actor authority, approved environment, dependencies and execution fences.";

export type DefinitionSourceBinding = {
  programId: string;
  programSourceToken: string;
  sourceDigest: string;
  buildId: string | null;
  active: boolean;
};

export function isDefinitionSourceBinding(
  value: unknown,
): value is DefinitionSourceBinding {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const source = value as Record<string, unknown>;
  return (
    typeof source.programId === "string" &&
    source.programId.length > 0 &&
    typeof source.programSourceToken === "string" &&
    /^[a-f0-9]{64}$/.test(source.programSourceToken) &&
    typeof source.sourceDigest === "string" &&
    /^[a-f0-9]{64}$/.test(source.sourceDigest) &&
    (source.buildId === null ||
      (typeof source.buildId === "string" && source.buildId.length > 0)) &&
    typeof source.active === "boolean"
  );
}
