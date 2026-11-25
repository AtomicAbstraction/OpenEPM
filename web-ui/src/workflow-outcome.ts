export type WorkflowOutcome = {
  workflowId: string;
  planDigest: string;
  checkpoints: Array<{
    ordinal: number;
    jobId: string;
    committed: boolean;
    receiptId: string | null;
  }>;
  status: string;
  unitCount: number;
  committedUnits: number;
  remainingUnits: number;
};
export const terminalWorkflowOutcome = (value: WorkflowOutcome) =>
  ["published", "partially_published", "failed", "cancelled"].includes(
    value.status,
  );

/** Structural/status invariants of the native WorkflowRecord wire. Owner
 * identity and request/digest checks belong to each native owner's wrapper. */
export function exactWorkflowOutcome<T extends WorkflowOutcome>(
  value: T,
  prior?: T,
): T {
  const count = (n: unknown) =>
    typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
  const identifier = (id: unknown) =>
    typeof id === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(id);
  const checkpoints = value?.checkpoints;
  const exactCheckpoints =
    Array.isArray(checkpoints) &&
    checkpoints.length <= value.unitCount &&
    checkpoints.every(
      (point, index) =>
        point &&
        typeof point === "object" &&
        point.ordinal === index + 1 &&
        identifier(point.jobId) &&
        typeof point.committed === "boolean" &&
        (point.committed
          ? identifier(point.receiptId)
          : point.receiptId === null),
    ) &&
    checkpoints.filter((point) => point.committed).length ===
      value.committedUnits;
  if (
    !value ||
    typeof value.planDigest !== "string" ||
    !/^[a-f0-9]{64}$/.test(value.planDigest) ||
    typeof value.workflowId !== "string" ||
    !/^[a-f0-9]{32}$/.test(value.workflowId) ||
    ![
      "accepted",
      "running",
      "cancel_requested",
      "published",
      "partially_published",
      "failed",
      "cancelled",
      "needs_inspection",
    ].includes(value.status) ||
    ![value.unitCount, value.committedUnits, value.remainingUnits].every(
      count,
    ) ||
    value.unitCount < 1 ||
    value.unitCount > 10_000 ||
    value.committedUnits + value.remainingUnits !== value.unitCount ||
    !exactCheckpoints ||
    (value.status === "published" && value.remainingUnits !== 0) ||
    (["failed", "cancelled"].includes(value.status) &&
      value.committedUnits !== 0) ||
    (value.status === "partially_published" && value.committedUnits < 1) ||
    (prior &&
      (value.workflowId !== prior.workflowId ||
        value.planDigest !== prior.planDigest ||
        value.unitCount !== prior.unitCount ||
        value.committedUnits < prior.committedUnits ||
        prior.checkpoints.some(
          (point, index) =>
            point.committed &&
            (!checkpoints[index]?.committed ||
              checkpoints[index].jobId !== point.jobId ||
              checkpoints[index].receiptId !== point.receiptId),
        ) ||
        (terminalWorkflowOutcome(prior) && value.status !== prior.status)))
  )
    throw new Error(
      "The server returned an invalid or inconsistent workflow outcome.",
    );
  return value;
}

/** Projection wording for native receipt-confirmed checkpoints, never a count
 * of physical effects inferred from child jobs or client history. */
export const workflowCountBasis =
  "The committed count includes only receipt-confirmed checkpoints; remaining units include unstarted, cancelled or unresolved work, including any child whose effect may already have committed. These counts do not claim rollback.";

export function workflowUnitCounts(
  value: Pick<WorkflowOutcome, "committedUnits" | "remainingUnits">,
) {
  return `${value.committedUnits} receipt-confirmed committed units · ${value.remainingUnits} remaining units without a confirmed receipt`;
}

export function workflowStatusLabel(status: string) {
  return status === "cancel_requested"
    ? "cancellation requested"
    : status.replaceAll("_", " ");
}

export function workflowCountGuidance(status: string) {
  if (status === "published") return "Every unit has a confirmed receipt.";
  return status === "cancel_requested"
    ? `Cancellation reconciliation is still pending. ${workflowCountBasis}`
    : workflowCountBasis;
}
