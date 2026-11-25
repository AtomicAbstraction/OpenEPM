import { useEffect, useId, useRef, useState } from "react";
import { ApiError, readProgram } from "./api";
import type { ApplicationCatalog, Scope } from "./types";

type Receipt = {
  operationId: string;
  commandDigest: string;
  actorId: string;
  committedRevision: number;
  committedAt: string;
  outcome: Record<string, string | number | boolean>;
};

const HEX_32 = /^[0-9a-f]{32}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const INVALID_RECEIPT = "INVALID_OPERATION_RECEIPT_RESPONSE";
export const RECEIPT_AUTHORIZATION_STALE =
  "OPERATION_RECEIPT_AUTHORIZATION_STALE";
const SAFE_TEXT = /^[^\u0000-\u001f\u007f]{1,200}$/;
const WORKFLOW_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}(?![\s\S])/;
const ISO_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const OUTCOME_FIELDS = new Set([
  "function",
  "status",
  "changedCount",
  "setCount",
  "clearCount",
  "committedCount",
  "rejectedCount",
  "occurrenceId",
  "activityId",
  "returnedToActivityId",
  "jobId",
  "batchId",
  "requestId",
  "activationId",
  "resultKey",
]);
const VISIBLE_OUTCOME_FIELDS = new Set([
  "function",
  "status",
  "changedCount",
  "setCount",
  "clearCount",
  "committedCount",
  "rejectedCount",
]);
const COUNT_FIELDS = new Set([
  "changedCount",
  "setCount",
  "clearCount",
  "committedCount",
  "rejectedCount",
]);
const HEX_32_FIELDS = new Set([
  "occurrenceId",
  "jobId",
  "batchId",
  "requestId",
  "activationId",
]);

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = ISO_TIMESTAMP.exec(value);
  if (!match) return false;
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] =
    match;
  const calendar = new Date(
    Date.UTC(Number(year), Number(month) - 1, Number(day)),
  );
  if (
    calendar.getUTCFullYear() !== Number(year) ||
    calendar.getUTCMonth() + 1 !== Number(month) ||
    calendar.getUTCDate() !== Number(day) ||
    Number(hour) > 23 ||
    Number(minute) > 59 ||
    Number(second) > 59 ||
    (offsetHour !== undefined && Number(offsetHour) > 23) ||
    (offsetMinute !== undefined && Number(offsetMinute) > 59)
  )
    return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed);
}

function safeOutcome(value: unknown): value is Receipt["outcome"] {
  if (!object(value) || Object.keys(value).length > OUTCOME_FIELDS.size)
    return false;
  return Object.entries(value).every(([key, item]) => {
    if (!OUTCOME_FIELDS.has(key)) return false;
    if (COUNT_FIELDS.has(key))
      return Number.isSafeInteger(item) && Number(item) >= 0;
    if (key === "activityId" || key === "returnedToActivityId")
      return (
        (key === "activityId" ||
          value.function === "application.workflow.activity.return") &&
        typeof item === "string" &&
        WORKFLOW_IDENTIFIER.test(item)
      );
    if (typeof item !== "string" || !SAFE_TEXT.test(item)) return false;
    if (HEX_32_FIELDS.has(key)) return HEX_32.test(item);
    if (key === "resultKey") return HEX_64.test(item);
    if (key === "function") return /^[a-z][a-z0-9_.-]{0,127}$/.test(item);
    return true;
  });
}

export function exactOperationReceipt(
  value: unknown,
  operationId: string,
): Receipt {
  if (
    !object(value) ||
    Object.keys(value).sort().join("\u0000") !==
      [
        "actorId",
        "commandDigest",
        "committedAt",
        "committedRevision",
        "operationId",
        "outcome",
      ].join("\u0000") ||
    typeof value.operationId !== "string" ||
    value.operationId !== operationId ||
    !SAFE_TEXT.test(value.operationId) ||
    typeof value.commandDigest !== "string" ||
    !HEX_64.test(value.commandDigest) ||
    typeof value.actorId !== "string" ||
    !SAFE_TEXT.test(value.actorId) ||
    !Number.isSafeInteger(value.committedRevision) ||
    Number(value.committedRevision) < 1 ||
    !exactTimestamp(value.committedAt) ||
    !safeOutcome(value.outcome)
  )
    throw new Error(INVALID_RECEIPT);
  return value as unknown as Receipt;
}

export function receiptForActorAfterRevision(
  value: unknown,
  operationId: string,
  actorId: string,
  previousRevision: number,
): Receipt | null {
  const receipt = exactOperationReceipt(value, operationId);
  return receipt.actorId === actorId &&
    receipt.committedRevision > previousRevision
    ? receipt
    : null;
}

export function outcomeAuthorityKey(scope: Scope, catalog: ApplicationCatalog) {
  return JSON.stringify([
    scope.workspaceId,
    scope.applicationId,
    catalog.accessContext,
    catalog.applicationAccess.issuer,
    catalog.applicationAccess.subjectId,
    catalog.applicationAccess.role,
    catalog.applicationAccess.workspaceAdministrator,
    catalog.revisions.security,
    catalog.revisions.capability,
  ]);
}

export function copyOperationReceiptCheck(scope: Scope, operationId: string) {
  return navigator.clipboard.writeText(
    JSON.stringify({
      workspace_id: scope.workspaceId,
      application_id: scope.applicationId,
      program: {
        languageVersion: 2,
        function: "application.operation.receipt.read",
        arguments: { operationId },
      },
    }),
  );
}

export function outcomeReadError(reason: unknown): string {
  if (reason instanceof ApiError) {
    if (reason.code === RECEIPT_AUTHORIZATION_STALE)
      return "Access changed while reading this activity outcome. Check the same outcome again under current access.";
    if (reason.code === "OPERATION_RECEIPT_NOT_FOUND")
      return "No activity outcome is available in the current application. Return to the activity to check its current status.";
    if (
      reason.code === "APPLICATION_UNAVAILABLE" ||
      reason.code === "WORKSPACE_UNAVAILABLE"
    )
      return "The application scope is unavailable. Return to Applications to choose an available application.";
    if (reason.kind === "authorization")
      return "Current access does not allow this outcome to be read. Return to the activity to see what is available.";
  }
  if (reason instanceof Error && reason.message === INVALID_RECEIPT)
    return `The activity outcome could not be verified (${INVALID_RECEIPT}). Reopen the outcome to try again.`;
  return "The activity outcome could not be read. Reopen the outcome to try again.";
}

function ReceiptOutcome({
  scope: { workspaceId, applicationId },
  operationId,
}: {
  scope: Scope;
  operationId: string;
}) {
  const [readAttempt, setReadAttempt] = useState(0);
  const [result, setResult] = useState<
    { receipt: Receipt } | { error: string; accessChanged: boolean } | null
  >(null);
  useEffect(() => {
    const controller = new AbortController();
    readProgram<unknown>(
      { workspaceId, applicationId },
      "application.operation.receipt.read",
      { operationId },
      controller.signal,
    )
      .then((value) => {
        if (!controller.signal.aborted)
          setResult({ receipt: exactOperationReceipt(value, operationId) });
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted)
          setResult({
            error: outcomeReadError(reason),
            accessChanged:
              reason instanceof ApiError &&
              reason.code === RECEIPT_AUTHORIZATION_STALE,
          });
      });
    return () => controller.abort();
  }, [workspaceId, applicationId, operationId, readAttempt]);

  return (
    <>
      {!result ? (
        <p role="status">Reading outcome…</p>
      ) : "error" in result ? (
        <p className="inline-error" role="alert">
          {result.error}
        </p>
      ) : (
        <ReceiptSummary receipt={result.receipt} />
      )}
      {(readAttempt > 0 ||
        (result && "error" in result && result.accessChanged)) && (
        <button
          type="button"
          aria-disabled={!result || undefined}
          onClick={() => {
            if (!result) return;
            setResult(null);
            setReadAttempt((attempt) => attempt + 1);
          }}
        >
          Check outcome again
        </button>
      )}
    </>
  );
}

function ReceiptSummary({ receipt }: { receipt: Receipt }) {
  const visibleOutcome = Object.entries(receipt.outcome).filter(([key]) =>
    VISIBLE_OUTCOME_FIELDS.has(key),
  );
  return (
    <>
      <p role="status">Activity outcome loaded.</p>
      <dl className="receipt-facts">
        <div>
          <dt>Recorded at</dt>
          <dd>{new Date(receipt.committedAt).toLocaleString()}</dd>
        </div>
      </dl>
      <h3>Outcome summary</h3>
      {visibleOutcome.length ? (
        <dl className="receipt-facts">
          {visibleOutcome.map(([key, value]) => (
            <div key={key}>
              <dt>{key}</dt>
              <dd>{String(value)}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p>No additional safe outcome fields were recorded.</p>
      )}
    </>
  );
}

export function ReceiptInspector({
  scope,
  catalog,
  operationId,
  close,
  title = "Activity outcome",
}: {
  scope: Scope;
  catalog: ApplicationCatalog | null;
  operationId: string;
  close: () => void;
  title?: string;
}) {
  const headingId = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const panel = useRef<HTMLElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  useEffect(() => {
    const active = heading.current?.ownerDocument.activeElement;
    if (active instanceof HTMLElement && !panel.current?.contains(active))
      returnFocus.current = active;
    heading.current?.focus({ preventScroll: true });
  }, [operationId]);
  useEffect(
    () => () => {
      if (returnFocus.current?.isConnected) returnFocus.current.focus();
    },
    [],
  );

  return (
    <section
      ref={panel}
      className="panel receipt-inspector"
      aria-labelledby={headingId}
    >
      <div className="section-title">
        <h2 id={headingId} ref={heading} tabIndex={-1}>
          {title}
        </h2>
        <button type="button" onClick={close}>
          Close
        </button>
      </div>
      {!catalog ? (
        <p role="status">Checking activity outcome availability…</p>
      ) : !catalog.functions["application.operation.receipt.read"] ? (
        <p role="alert">
          Activity outcomes are unavailable in the current application. Return
          to the activity to see its status.
        </p>
      ) : (
        <ReceiptOutcome
          key={JSON.stringify([
            outcomeAuthorityKey(scope, catalog),
            operationId,
          ])}
          scope={scope}
          operationId={operationId}
        />
      )}
    </section>
  );
}
