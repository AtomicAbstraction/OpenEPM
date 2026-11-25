import { ApiError, type AdmittedEffectPacket } from "./api";
import { useGovernedEffectRecovery } from "./governed-effect-recovery";
import type { ApplicationCatalog, Scope } from "./types";

export type PythonScheduleChange =
  | { action: "save" | "activate" | "deactivate" | "run"; scheduleId: string }
  | {
      action: "cancel";
      occurrenceId: string;
      scheduleId: string;
      dueAt: string;
    };

type ScheduleResult = {
  operationId?: unknown;
  scheduleId?: unknown;
  occurrenceId?: string;
  occurrence?: unknown;
  dueAt?: unknown;
  status: string;
  stateToken?: unknown;
  policyRevision?: unknown;
};

const refusalCodes = new Set([
  "APPLICATION_GRANT_REQUIRED",
  "APPLICATION_ADMIN_REQUIRED",
  "APPLICATION_NOT_WRITABLE",
  "PROGRAM_VALIDATION_FAILED",
  "PYTHON_SCHEDULE_ARGUMENTS_INVALID",
  "PYTHON_SCHEDULE_AUTHORITY_INVALID",
  "PYTHON_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED",
  "PYTHON_SCHEDULE_STALE_CONTEXT",
  "PYTHON_SCHEDULE_STALE_STATE",
  "PYTHON_SCHEDULE_ALREADY_ACTIVE",
  "PYTHON_SCHEDULE_NOT_ACTIVE",
  "PYTHON_SCHEDULE_INACTIVE",
  "PYTHON_SCHEDULE_OCCURRENCE_UNAVAILABLE",
]);

function exactResult(
  value: unknown,
  {
    packet,
    details,
  }: { packet: AdmittedEffectPacket; details: PythonScheduleChange },
) {
  const reply = value as {
    languageVersion?: unknown;
    function?: unknown;
    result?: ScheduleResult;
  };
  if (
    reply?.languageVersion !== 2 ||
    reply.function !== packet.body.program.function ||
    !reply.result
  )
    return null;
  const result = reply.result;
  if (details.action === "cancel") {
    return result.occurrenceId === details.occurrenceId &&
      ["cancelled", "cancel_requested", "published", "failed"].includes(
        result.status,
      )
      ? result
      : null;
  }
  if (result.scheduleId !== details.scheduleId) return null;
  if (details.action === "run") {
    if (result.status === "NotDue")
      return result.occurrence === null && result.occurrenceId === undefined
        ? result
        : null;
    return result.status === "Materialized" &&
      typeof result.occurrenceId === "string" &&
      /^[0-9a-f]{32}$/.test(result.occurrenceId) &&
      typeof result.dueAt === "string" &&
      Number.isFinite(Date.parse(result.dueAt))
      ? result
      : null;
  }
  const pins = packet.body.program.arguments as Record<string, unknown>;
  return result.operationId === packet.body.idempotencyKey &&
    result.status === (details.action === "activate" ? "Active" : "Saved") &&
    typeof result.stateToken === "string" &&
    /^[0-9a-f]{64}$/.test(result.stateToken) &&
    typeof pins.expectedPolicyRevision === "number" &&
    result.policyRevision === pins.expectedPolicyRevision + 1
    ? result
    : null;
}

const scheduleProtocol = {
  path: "/api/python-schedule",
  tool: "execute_v2_python_program_registry",
  editor: "python-schedule-change",
  pendingLabel: "Python schedule change with an unconfirmed outcome",
  functions: [
    "python.schedule.save",
    "python.schedule.activate",
    "python.schedule.deactivate",
    "python.schedule.run",
    "python.schedule.occurrence.cancel",
  ],
  subject: "schedule change",
  closePrompt:
    "Close this expired request? Read the current schedule or occurrence before reviewing another action.",
  initialRefusal: (reason: unknown) =>
    reason instanceof ApiError &&
    [400, 403, 409, 422].includes(reason.status) &&
    refusalCodes.has(reason.code),
  result: exactResult,
};

export function usePythonScheduleRecovery(
  scope: Scope | undefined,
  catalog: ApplicationCatalog | null,
  context: string,
  onRecorded: (details: PythonScheduleChange, result: ScheduleResult) => void,
) {
  return useGovernedEffectRecovery(
    scope,
    catalog,
    context,
    scheduleProtocol,
    onRecorded,
  );
}
