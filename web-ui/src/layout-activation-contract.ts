export const layoutReplacementRead = "metadata.layout.populated.replace.read";
export const activationRequest = "metadata.layout.populated.activate.request";
export const activationRead = "metadata.layout.populated.activate.read";
export const activationStatuses = [
  "Requested",
  "Activating",
  "Activated",
  "Failed",
  "Cancelled",
] as const;
export const replacementStatuses = [
  "Accepted",
  "Staging",
  "Staged",
  "Validated",
  "ValidationFailed",
  "Failed",
  "Cancelled",
] as const;
type ActivationStatus = (typeof activationStatuses)[number];
const pinKeys = [
  "metadataRevision",
  "dataRevision",
  "policyRevision",
  "schemaEpoch",
  "sourceCommitRevision",
] as const;
type Pins = Record<(typeof pinKeys)[number], number>;
type Decision = {
  kind: "rule" | "publication";
  id: string;
  decision: "Compatible" | "Invalidate" | "Rebuild";
};
export type ActivationReview = {
  requestId: string;
  targetGenerationId: string;
  validationDigest: string;
  expectedPins: Pins;
  dependencyDecisions: Decision[];
};
export type LayoutActivationTarget =
  | { kind: "replacement"; id: string; generationId?: string }
  | { kind: "activation"; id: string };
export type Acknowledgement = {
  activationId: string;
  status: ActivationStatus;
  targetSchemaEpoch?: number;
  targetProjectionGeneration?: number;
};
type Receipt = {
  committedRevision: number;
  schemaEpoch: number;
  projectionGeneration: number;
  addedDimensionId?: string;
};
export type Outcome = {
  status: ActivationStatus;
  stateVersion: number;
  receipt: Receipt | null;
  errorCode: string | null;
};

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export function identifier(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
}

function digest(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function revision(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function activationStatus(value: unknown): value is ActivationStatus {
  return activationStatuses.some((status) => status === value);
}

function pins(value: unknown) {
  const fields = record(value);
  if (!pinKeys.every((key) => revision(fields[key]))) throw new Error();
  return Object.fromEntries(pinKeys.map((key) => [key, fields[key]])) as Pins;
}

function decisions(value: unknown) {
  if (!Array.isArray(value) || value.length > 10000) throw new Error();
  const seen = new Set<string>();
  return value.map((item): Decision => {
    const { kind, id, decision } = record(item);
    const key = JSON.stringify([kind, id]);
    if (
      (kind !== "rule" && kind !== "publication") ||
      typeof id !== "string" ||
      !id ||
      Array.from(id).length > 256 ||
      (decision !== "Compatible" &&
        decision !== "Invalidate" &&
        decision !== "Rebuild") ||
      seen.has(key)
    )
      throw new Error();
    seen.add(key);
    return { kind, id, decision };
  });
}

function certificateReview(
  value: unknown,
  requestId: unknown,
  targetGenerationId: unknown,
  dependencyDecisions: unknown,
): ActivationReview {
  const certificate = record(value);
  if (
    !identifier(requestId) ||
    !identifier(targetGenerationId) ||
    !digest(certificate.validationDigest) ||
    certificate.activationEligible !== true
  )
    throw new Error();
  return {
    requestId,
    targetGenerationId,
    validationDigest: certificate.validationDigest,
    expectedPins: pins(certificate.pins),
    dependencyDecisions: decisions(dependencyDecisions),
  };
}

export function reviewReplacement(
  value: unknown,
  target: Extract<LayoutActivationTarget, { kind: "replacement" }>,
): { review: ActivationReview | null; activationId?: string } {
  const result = record(value);
  if (
    result.requestId !== target.id ||
    !identifier(result.targetGenerationId) ||
    (target.generationId && result.targetGenerationId !== target.generationId)
  )
    throw new Error();
  if (result.activationId !== null && result.activationId !== undefined) {
    if (!identifier(result.activationId)) throw new Error();
    return { review: null, activationId: result.activationId };
  }
  if (
    result.status !== "Validated" ||
    record(result.certificate).activationEligible !== true ||
    result.dependencyDecisions === null
  )
    return { review: null };
  const review = certificateReview(
    result.certificate,
    result.requestId,
    result.targetGenerationId,
    result.dependencyDecisions,
  );
  if (JSON.stringify(review.expectedPins) !== JSON.stringify(pins(result.pins)))
    throw new Error();
  return { review };
}

export function activationOutcome(
  value: unknown,
  activationId: string,
  target: LayoutActivationTarget,
  acknowledged?: { review: ActivationReview; result: Acknowledgement },
): Outcome {
  const reply = record(value);
  const status = reply.status;
  if (
    reply.activationId !== activationId ||
    (target.kind === "replacement" &&
      (reply.requestId !== target.id ||
        (target.generationId &&
          reply.targetGenerationId !== target.generationId))) ||
    !activationStatus(status) ||
    !revision(reply.stateVersion) ||
    !revision(reply.targetSchemaEpoch) ||
    !revision(reply.targetProjectionGeneration) ||
    !revision(reply.sourceProjectionGeneration) ||
    (reply.errorCode !== null && typeof reply.errorCode !== "string")
  )
    throw new Error();
  const review = certificateReview(
    reply.certificate,
    reply.requestId,
    reply.targetGenerationId,
    reply.dependencyDecisions,
  );
  if (
    reply.targetSchemaEpoch !== review.expectedPins.schemaEpoch + 1 ||
    reply.targetProjectionGeneration <= reply.sourceProjectionGeneration ||
    (acknowledged &&
      (JSON.stringify(acknowledged.review) !== JSON.stringify(review) ||
        (acknowledged.result.targetSchemaEpoch !== undefined &&
          acknowledged.result.targetSchemaEpoch !== reply.targetSchemaEpoch) ||
        (acknowledged.result.targetProjectionGeneration !== undefined &&
          acknowledged.result.targetProjectionGeneration !==
            reply.targetProjectionGeneration)))
  )
    throw new Error();
  if (status !== "Activated") {
    if (reply.receipt !== null) throw new Error();
    return {
      status,
      stateVersion: reply.stateVersion,
      receipt: null,
      errorCode: reply.errorCode,
    };
  }
  const receipt = record(reply.receipt);
  if (
    receipt.activationId !== activationId ||
    receipt.requestId !== review.requestId ||
    receipt.schemaEpoch !== reply.targetSchemaEpoch ||
    receipt.projectionGeneration !== reply.targetProjectionGeneration ||
    receipt.historyPreserved !== true ||
    !revision(receipt.committedRevision) ||
    receipt.committedRevision <= review.expectedPins.sourceCommitRevision ||
    (receipt.addedDimensionId !== undefined &&
      (typeof receipt.addedDimensionId !== "string" ||
        !receipt.addedDimensionId))
  )
    throw new Error();
  return {
    status,
    stateVersion: reply.stateVersion,
    errorCode: reply.errorCode,
    receipt: {
      committedRevision: receipt.committedRevision,
      schemaEpoch: reply.targetSchemaEpoch,
      projectionGeneration: reply.targetProjectionGeneration,
      addedDimensionId: receipt.addedDimensionId,
    },
  };
}

export function activationAcknowledgement(
  value: unknown,
  original: { details: ActivationReview },
): Acknowledgement | null {
  const reply = record(value);
  const result = record(reply.result);
  if (
    reply.languageVersion !== 2 ||
    reply.function !== activationRequest ||
    !identifier(result.activationId) ||
    !activationStatus(result.status)
  )
    return null;
  const { activationId, status } = result;
  if (result.duplicate === true) return { activationId, status };
  if (
    result.duplicate !== false ||
    status !== "Requested" ||
    !revision(result.targetSchemaEpoch) ||
    result.targetSchemaEpoch !==
      original.details.expectedPins.schemaEpoch + 1 ||
    !revision(result.targetProjectionGeneration)
  )
    return null;
  return {
    activationId,
    status,
    targetSchemaEpoch: result.targetSchemaEpoch,
    targetProjectionGeneration: result.targetProjectionGeneration,
  };
}
