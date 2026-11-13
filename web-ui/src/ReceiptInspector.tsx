import { useEffect, useRef, useState } from "react";
import { readProgram } from "./api";
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
const SAFE_TEXT = /^[^\u0000-\u001f\u007f]{1,200}$/;
const SAFE_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
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
    if (typeof item !== "string" || !SAFE_TEXT.test(item)) return false;
    if (HEX_32_FIELDS.has(key)) return HEX_32.test(item);
    if (key === "resultKey") return HEX_64.test(item);
    if (key === "activityId") return SAFE_TOKEN.test(item);
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
    throw new Error("INVALID_OPERATION_RECEIPT_RESPONSE");
  return value as unknown as Receipt;
}

export function ReceiptInspector({
  scope,
  catalog,
  operationId,
  close,
}: {
  scope: Scope;
  catalog: ApplicationCatalog | null;
  operationId: string;
  close: () => void;
}) {
  const title = useRef<HTMLHeadingElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [error, setError] = useState("");
  const supported = Boolean(
    catalog?.functions["application.operation.receipt.read"],
  );
  useEffect(() => {
    returnFocus.current =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    title.current?.focus({ preventScroll: true });
    return () => {
      if (returnFocus.current?.isConnected) returnFocus.current.focus();
    };
  }, []);

  useEffect(() => {
    if (!supported) return;
    const controller = new AbortController();
    readProgram<unknown>(
      scope,
      "application.operation.receipt.read",
      { operationId },
      controller.signal,
    )
      .then((value) => {
        setReceipt(exactOperationReceipt(value, operationId));
      })
      .catch((reason: Error) => {
        if (reason.name !== "AbortError") setError(reason.message);
      });
    return () => controller.abort();
  }, [scope.workspaceId, scope.applicationId, operationId, supported]);

  return (
    <section
      className="panel receipt-inspector"
      aria-labelledby="receipt-title"
    >
      <div className="section-title">
        <div>
          <span>Authorized activity</span>
          <h2 id="receipt-title" ref={title} tabIndex={-1}>
            Activity outcome
          </h2>
        </div>
        <button type="button" onClick={close}>
          Close
        </button>
      </div>
      {!supported && (
        <p role="alert">Activity details are unavailable in this release.</p>
      )}
      {error && (
        <p className="inline-error" role="alert">
          Activity details are unavailable: {error}
        </p>
      )}
      {!receipt && supported && !error && <p role="status">Reading outcome…</p>}
      {receipt && (
        <>
          <p role="status">Activity outcome loaded.</p>
          <dl className="receipt-facts">
            <div>
              <dt>Recorded at</dt>
              <dd>{new Date(receipt.committedAt).toLocaleString()}</dd>
            </div>
          </dl>
          <h3>Outcome summary</h3>
          {Object.keys(receipt.outcome).length ? (
            <dl className="receipt-facts">
              {Object.entries(receipt.outcome)
                .filter(([key]) => VISIBLE_OUTCOME_FIELDS.has(key))
                .map(([key, value]) => (
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
      )}
    </section>
  );
}
