import { useRef, useState } from "react";
import { ApiError } from "./api";
import { useGovernedEffectRecovery } from "./governed-effect-recovery";
import {
  activationRead,
  activationStatuses,
  identifier,
  layoutReplacementRead,
  replacementStatuses,
} from "./layout-activation-contract";
import { useStableMutationIntentKey } from "./mutation-intent";
import type { ApplicationCatalog, Scope } from "./types";

const protocols = {
  replacement: {
    read: layoutReplacementRead,
    cancel: "metadata.layout.populated.replace.cancel",
    idField: "requestId",
    statuses: replacementStatuses,
    cancellable: ["Accepted", "Staged", "Validated"],
    label: "private replacement",
  },
  activation: {
    read: activationRead,
    cancel: "metadata.layout.populated.activate.cancel",
    idField: "activationId",
    statuses: activationStatuses,
    cancellable: ["Requested"],
    label: "activation",
  },
} as const;
type Kind = keyof typeof protocols;
export type LayoutWorkState = { status: string; stateVersion: number };

const definiteRefusals = new Set([
  "LAYOUT_REPLACEMENT_STATE_STALE",
  "LAYOUT_REPLACEMENT_WORK_IN_PROGRESS",
  "LAYOUT_REPLACEMENT_NOT_FOUND",
  "LAYOUT_REPLACEMENT_CANCEL_INVALID",
  "LAYOUT_ACTIVATION_STATE_STALE",
  "LAYOUT_ACTIVATION_CANCEL_INVALID",
  "APPLICATION_PROGRAM_INVALID",
  "APPLICATION_NOT_WRITABLE",
  "OPERATION_ADMISSION_MISMATCH",
  "METADATA_ACTION_CONFIRMATION_REQUIRED",
]);

export function layoutWorkState(value: unknown, kind: Kind, id: string) {
  const row = value as
    | (Partial<LayoutWorkState> & Record<string, unknown>)
    | null;
  const protocol = protocols[kind];
  if (
    !row ||
    row[protocol.idField] !== id ||
    typeof row.status !== "string" ||
    !protocol.statuses.some((status) => status === row.status) ||
    typeof row.stateVersion !== "number" ||
    !Number.isSafeInteger(row.stateVersion) ||
    row.stateVersion < 0
  )
    return null;
  return { status: row.status, stateVersion: row.stateVersion };
}

export function useLayoutCancellation({
  scope,
  catalog,
  context,
  kind,
  id,
  state,
  onRefreshNeeded,
}: {
  scope: Scope;
  catalog: ApplicationCatalog | null;
  context: string;
  kind: Kind;
  id: string;
  state: LayoutWorkState | null;
  onRefreshNeeded: () => void;
}) {
  const protocol = protocols[kind];
  const [observed, setObserved] = useState<{
    context: string;
    state: LayoutWorkState;
  }>();
  const keyFor = useStableMutationIntentKey("layout-cancel");
  const canControl = Boolean(
    identifier(id) &&
      catalog?.applicationAccess.subjectId &&
      catalog.functions[protocol.read] &&
      catalog.functions[protocol.cancel],
  );
  const editor = `layout-cancel:${kind}:${id}`;
  const recovery = useGovernedEffectRecovery<LayoutWorkState, LayoutWorkState>(
    identifier(id) ? scope : undefined,
    catalog,
    context,
    {
      path: "/api/read",
      editor,
      pendingLabel: `Unconfirmed cancellation of the ${protocol.label}`,
      functions: [protocol.cancel],
      subject: `cancellation of the ${protocol.label}`,
      closePrompt:
        "Close this expired cancellation attempt? Read the current layout state again before any new request.",
      initialRefusal: (reason) =>
        reason instanceof ApiError &&
        (reason.kind === "authorization" ||
          ([400, 409, 422].includes(reason.status) &&
            definiteRefusals.has(reason.code))),
      result: (value, original) => {
        const reply = value as {
          languageVersion?: unknown;
          function?: unknown;
          result?: unknown;
        } | null;
        if (reply?.languageVersion !== 2 || reply.function !== protocol.cancel)
          return null;
        const result = layoutWorkState(reply.result, kind, id);
        return result?.status === "Cancelled" &&
          result.stateVersion === original.details.stateVersion + 1
          ? result
          : null;
      },
      stateRead: {
        functionName: protocol.read,
        arguments: () => ({ [protocol.idField]: id }),
        reconcile: (value, original) => {
          const state = layoutWorkState(value, kind, id);
          if (!state) return null;
          if (state.stateVersion > original.stateVersion)
            return { result: state };
          return state.stateVersion === original.stateVersion &&
            state.status === original.status
            ? { unchanged: true }
            : null;
        },
      },
    },
    (_, result) => {
      setObserved({ context, state: result });
      onRefreshNeeded();
    },
  );
  const result =
    canControl && observed?.context === context ? observed.state : null;
  const canSubmit = Boolean(
    canControl &&
      state &&
      (!result || state.stateVersion >= result.stateVersion) &&
      state.stateVersion < Number.MAX_SAFE_INTEGER &&
      protocol.cancellable.some((status) => status === state.status) &&
      !recovery.pending &&
      !recovery.busy,
  );

  async function submit() {
    if (
      !state ||
      !canSubmit ||
      !window.confirm(`Cancel this ${protocol.label}?`)
    )
      return;
    const idempotencyKey = keyFor([context, kind, id, state]);
    setObserved(undefined);
    onRefreshNeeded();
    await recovery.submit(
      {
        ...scope,
        confirmed: true,
        idempotencyKey,
        program: {
          languageVersion: 2,
          function: protocol.cancel,
          arguments: {
            [protocol.idField]: id,
            expectedStatus: state.status,
            expectedStateVersion: state.stateVersion,
          },
        },
      },
      state,
    );
  }

  return {
    ...recovery,
    canControl,
    canSubmit,
    result,
    label: protocol.label,
    submit,
  };
}

export function LayoutCancellation({
  action,
  refreshAvailable,
}: {
  action: ReturnType<typeof useLayoutCancellation>;
  refreshAvailable: boolean;
}) {
  const notice = useRef<HTMLParagraphElement>(null);
  if (!action.canControl) return null;
  const pending = action.pending || action.busy;
  const result = action.result;
  const failure =
    !pending && !refreshAvailable
      ? action.message === "LAYOUT_REPLACEMENT_WORK_IN_PROGRESS"
        ? "Current worker or activation state prevents cancellation"
        : action.message
      : "";
  if (!pending && !result && !failure && !action.canSubmit) return null;
  return (
    <div className="layout-cancellation" aria-label="Layout cancellation">
      <p ref={notice} tabIndex={-1} role="status">
        {action.busy
          ? "Checking cancellation…"
          : pending
            ? action.message ||
              "Cancellation is unconfirmed. Check the current state."
            : result?.status === "Cancelled"
              ? `The ${action.label} is cancelled.`
              : result
                ? `The ${action.label} advanced to ${result.status}. The original cancellation can no longer apply.`
                : failure
                  ? `${failure}. Read the current state before requesting cancellation again.`
                  : "Cancellation leaves the published layout intact."}
      </p>
      {action.canSubmit && (
        <button
          type="button"
          onClick={() => {
            notice.current?.focus();
            void action.submit();
          }}
        >
          Cancel {action.label}
        </button>
      )}
      {action.canCheckReceipt && (
        <button
          type="button"
          disabled={action.busy}
          onClick={() => void action.checkReceipt()}
        >
          Check cancellation status
        </button>
      )}
      {action.retryReady && (
        <button
          type="button"
          disabled={action.busy}
          onClick={() => {
            notice.current?.focus();
            void action.retry();
          }}
        >
          Retry original cancellation
        </button>
      )}
    </div>
  );
}
