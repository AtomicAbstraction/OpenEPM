import { useLayoutEffect, useRef, useState } from "react";
import { ApiError, readProgram, type AdmittedEffectPacket } from "./api";
import { useGovernedEffectRecovery } from "./governed-effect-recovery";
import { useStableMutationIntentKey } from "./mutation-intent";
import { receiptForActorAfterRevision } from "./ReceiptInspector";
import { usePreservedDraft } from "./unsaved-work";
import type { ApplicationCatalog, Scope } from "./types";

const calendarRead = "metadata.calendar.period.read";
const calendarSet = "metadata.calendar.period.set";

type PeriodTarget = { yearId: string; periodId: string };
type DateRange = { ordinal: number; startsOn: string; endsBefore: string };
type CalendarPeriod = { commitRevision: number; changeId: string } & (
  | { defined: false }
  | ({ defined: true } & DateRange)
);
type CalendarDraft = PeriodTarget & {
  ordinal: string;
  startsOn: string;
  endsBefore: string;
};
type CalendarIntent = PeriodTarget &
  DateRange & {
    expectedMetadataRevision: number;
    expectedChangeId: string;
  };
type CalendarAttempt = {
  actorId: string;
  previousCommitRevision: number;
  intent: CalendarIntent;
};
type Original = { packet: AdmittedEffectPacket; details: CalendarAttempt };
const conflicts = new Set([
  "STALE_CALENDAR_METADATA_REVISION",
  "STALE_CALENDAR_CHANGE_ID",
  "CALENDAR_AUTHORIZATION_STALE",
]);
const refusals = new Set([
  "CALENDAR_CONTEXT_MEMBER_UNAVAILABLE",
  "CALENDAR_MODEL_ROLE_AMBIGUOUS",
  "CALENDAR_MODEL_ROLES_REQUIRED",
  "CALENDAR_ISO_DATE_REQUIRED",
  "CALENDAR_PERIOD_RANGE_INVALID",
  "CALENDAR_PERIOD_OVERLAP",
  "CALENDAR_ORDINAL_CONFLICT",
  "APPLICATION_NOT_WRITABLE",
  "APPLICATION_PROGRAM_INVALID",
  "METADATA_ACTION_CONFIRMATION_REQUIRED",
  "OPERATION_ADMISSION_MISMATCH",
]);

function isoDate(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length !== 10 ||
    !/^\d{4}-\d{2}-\d{2}$/.test(value) ||
    value.startsWith("0000-")
  )
    return false;
  const timestamp = Date.parse(`${value}T00:00:00Z`);
  return (
    Number.isFinite(timestamp) &&
    new Date(timestamp).toISOString().slice(0, 10) === value
  );
}

function verifiedPeriod(
  value: unknown,
  yearId: string,
  periodId: string,
  metadataRevision: number,
  commitRevision: number,
): CalendarPeriod {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const result = value as Record<string, unknown>;
    if (
      result.yearId === yearId &&
      result.periodId === periodId &&
      result.metadataRevision === metadataRevision &&
      typeof result.commitRevision === "number" &&
      Number.isSafeInteger(result.commitRevision) &&
      result.commitRevision >= commitRevision
    ) {
      const { defined, ordinal, startsOn, endsBefore, changeId } = result;
      if (
        defined === false &&
        ordinal === null &&
        startsOn === null &&
        endsBefore === null &&
        changeId === ""
      )
        return { defined, changeId, commitRevision: result.commitRevision };
      if (
        defined === true &&
        typeof ordinal === "number" &&
        Number.isInteger(ordinal) &&
        ordinal >= 1 &&
        ordinal <= 366 &&
        isoDate(startsOn) &&
        isoDate(endsBefore) &&
        startsOn < endsBefore &&
        typeof changeId === "string" &&
        changeId.length > 0
      )
        return {
          defined,
          ordinal,
          startsOn,
          endsBefore,
          changeId,
          commitRevision: result.commitRevision,
        };
    }
  }
  throw new Error("The calendar period does not match the worked coordinate.");
}

function calendarReply(value: unknown, { packet, details }: Original) {
  const reply = value as {
    languageVersion?: unknown;
    function?: unknown;
    result?: Partial<CalendarIntent> & {
      operationId?: string;
      changeId?: string;
      metadataRevision?: number;
      committedRevision?: number;
      impactDigest?: string;
    };
  } | null;
  const result = reply?.result;
  const { intent, previousCommitRevision } = details;
  return reply?.languageVersion === 2 &&
    reply.function === calendarSet &&
    result?.operationId === packet.body.idempotencyKey &&
    result.yearId === intent.yearId &&
    result.periodId === intent.periodId &&
    result.ordinal === intent.ordinal &&
    result.startsOn === intent.startsOn &&
    result.endsBefore === intent.endsBefore &&
    result.metadataRevision === intent.expectedMetadataRevision + 1 &&
    typeof result.committedRevision === "number" &&
    Number.isSafeInteger(result.committedRevision) &&
    result.committedRevision > previousCommitRevision &&
    result.committedRevision >= result.metadataRevision &&
    typeof result.changeId === "string" &&
    /^[0-9a-f]{32}$/.test(result.changeId) &&
    result.changeId !== intent.expectedChangeId &&
    typeof result.impactDigest === "string" &&
    /^[0-9a-f]{64}$/.test(result.impactDigest)
    ? "reply"
    : null;
}

function calendarReceipt(value: unknown, { packet, details }: Original) {
  // The admission binds this exact program to the operation ID. The receipt
  // proves its commit, while a separate period read establishes currentness.
  const receipt = receiptForActorAfterRevision(
    value,
    packet.body.idempotencyKey,
    details.actorId,
    details.previousCommitRevision,
  );
  return receipt &&
    (!receipt.outcome.function || receipt.outcome.function === calendarSet)
    ? "receipt"
    : null;
}

export function WorkedCalendarPeriod({
  scope,
  catalog,
  context,
  contextBlocked,
  selection,
  metadataRevision,
  onReadFailure,
  onRecorded,
}: {
  scope: Scope;
  catalog: ApplicationCatalog;
  context: string;
  contextBlocked: boolean;
  selection: PeriodTarget | null;
  metadataRevision: number;
  onReadFailure: (failure: unknown) => boolean;
  onRecorded: () => void;
}) {
  const [reading, setReading] = useState<{
    key: string;
    result: "loading" | "failed" | CalendarPeriod;
  } | null>(null);
  const [draft, setDraft] = useState<CalendarDraft | null>(null);
  const [review, setReview] = useState<{
    source: CalendarPeriod;
    intent: CalendarIntent;
  } | null>(null);
  const request = useRef<AbortController | null>(null);
  const readButton = useRef<HTMLButtonElement>(null);
  const ordinalField = useRef<HTMLInputElement>(null);
  const pendingHeading = useRef<HTMLHeadingElement>(null);
  const focusAfterRender = useRef<"read" | "ordinal" | "recovery" | null>(null);
  const mutationKey = useStableMutationIntentKey("calendar-period");
  const { subjectId: actorId } = catalog.applicationAccess;
  const canRead =
    !contextBlocked &&
    metadataRevision === catalog.revisions.metadata &&
    Boolean(catalog.functions[calendarRead]);
  const canEdit = Boolean(actorId && catalog.functions[calendarSet]);
  const recovery = useGovernedEffectRecovery(
    scope,
    catalog,
    context,
    {
      path: "/api/metadata-action",
      tool: "execute_v2_calendar_program",
      editor: "metadata-calendar-effect",
      pendingLabel: "Calendar change with an unconfirmed outcome",
      functions: [calendarSet],
      subject: "calendar change",
      closePrompt:
        "Close this unconfirmed request? Read the current period before reviewing another change.",
      initialRefusal(reason) {
        if (!(reason instanceof ApiError)) return false;
        if (conflicts.has(reason.code) || reason.kind === "authorization") {
          setReading(null);
          setReview(null);
          onReadFailure(reason);
          return true;
        }
        const rejected =
          [400, 409, 422].includes(reason.status) && refusals.has(reason.code);
        if (rejected) setReview(null);
        return rejected;
      },
      result: calendarReply,
      receiptResult: calendarReceipt,
    },
    () => {
      setDraft(null);
      setReview(null);
      setReading(null);
      onRecorded();
    },
  );
  usePreservedDraft(
    scope.workspaceId,
    scope.applicationId,
    "metadata-calendar-draft",
    "Calendar period draft",
    draft !== null && !recovery.pending,
    draft,
    setDraft,
  );
  const target = (canEdit ? draft : null) ?? selection;
  const yearId = target?.yearId;
  const periodId = target?.periodId;
  const key = JSON.stringify([context, yearId, periodId, canRead, canEdit]);
  const state = reading?.key === key ? reading.result : "idle";
  const period = typeof state === "object" ? state : null;
  const reviewed = period && review?.source === period ? review : null;
  const ordinal = Number(draft?.ordinal);
  const valid =
    draft &&
    /^[0-9]{1,3}$/.test(draft.ordinal) &&
    ordinal >= 1 &&
    ordinal <= 366 &&
    isoDate(draft.startsOn) &&
    isoDate(draft.endsBefore) &&
    draft.startsOn < draft.endsBefore;
  const changed =
    draft &&
    (!period?.defined ||
      ordinal !== period.ordinal ||
      draft.startsOn !== period.startsOn ||
      draft.endsBefore !== period.endsBefore);
  const canReview = canEdit && period && draft && valid && changed;
  useLayoutEffect(() => () => request.current?.abort(), [key]);
  useLayoutEffect(() => {
    const control =
      focusAfterRender.current === "ordinal"
        ? ordinalField.current
        : focusAfterRender.current === "recovery"
          ? pendingHeading.current
          : focusAfterRender.current === "read"
            ? readButton.current
            : null;
    if (!control) return;
    focusAfterRender.current = null;
    control.focus();
  }, [draft, recovery.pending]);

  async function inspect() {
    if (
      request.current ||
      !canRead ||
      !yearId ||
      !periodId ||
      recovery.pending ||
      recovery.busy
    )
      return;
    const controller = new AbortController();
    request.current = controller;
    setReview(null);
    setReading({ key, result: "loading" });
    try {
      const result = await readProgram<unknown>(
        scope,
        calendarRead,
        { yearId, periodId },
        controller.signal,
      );
      if (!controller.signal.aborted)
        setReading({
          key,
          result: verifiedPeriod(
            result,
            yearId,
            periodId,
            metadataRevision,
            catalog.revisions.commit,
          ),
        });
    } catch (failure) {
      if (!controller.signal.aborted && !onReadFailure(failure))
        setReading({ key, result: "failed" });
    } finally {
      if (request.current === controller) request.current = null;
    }
  }

  function begin() {
    if (!period || !yearId || !periodId || !canEdit || recovery.pending) return;
    focusAfterRender.current = "ordinal";
    setDraft({
      yearId,
      periodId,
      ordinal: period.defined ? String(period.ordinal) : "",
      startsOn: period.defined ? period.startsOn : "",
      endsBefore: period.defined ? period.endsBefore : "",
    });
  }

  function update(field: "ordinal" | "startsOn" | "endsBefore", value: string) {
    setReview(null);
    setDraft((current) => (current ? { ...current, [field]: value } : null));
  }

  function reviewChange() {
    if (!canReview) return;
    setReview({
      source: period,
      intent: {
        yearId: draft.yearId,
        periodId: draft.periodId,
        ordinal,
        startsOn: draft.startsOn,
        endsBefore: draft.endsBefore,
        expectedMetadataRevision: metadataRevision,
        expectedChangeId: period.changeId,
      },
    });
  }

  function save() {
    if (!canReview || !reviewed || recovery.pending || !actorId) return;
    focusAfterRender.current = "recovery";
    const program = {
      languageVersion: 2,
      function: calendarSet,
      arguments: reviewed.intent,
    };
    void recovery.submit(
      {
        workspaceId: scope.workspaceId,
        applicationId: scope.applicationId,
        program,
        idempotencyKey: mutationKey(program),
        confirmed: true,
      },
      {
        actorId,
        intent: reviewed.intent,
        previousCommitRevision: period.commitRevision,
      },
    );
  }

  if (recovery.pending) {
    return (
      <section aria-label="Unconfirmed calendar change">
        <h3 ref={pendingHeading} tabIndex={-1}>
          Unconfirmed calendar change
        </h3>
        {recovery.review && (
          <p>
            Year {recovery.review.intent.yearId}, period{" "}
            {recovery.review.intent.periodId}. Check the original outcome before
            editing.
          </p>
        )}
        {!canEdit && (
          <p>Calendar editing access is required to recover this request.</p>
        )}
        {recovery.message && <p role="alert">{recovery.message}</p>}
        <div className="button-row">
          {canEdit && recovery.canCheckReceipt && (
            <button
              type="button"
              disabled={recovery.busy}
              onClick={() => void recovery.checkReceipt()}
            >
              Check original calendar receipt
            </button>
          )}
          {canEdit && recovery.retryReady && (
            <button
              type="button"
              disabled={recovery.busy}
              onClick={() => void recovery.retry()}
            >
              Retry original calendar request
            </button>
          )}
          {canEdit && recovery.review && (
            <button
              type="button"
              disabled={recovery.busy}
              onClick={() => void recovery.copyOriginal()}
            >
              Copy original calendar request for MCP
            </button>
          )}
          {canEdit && recovery.canCloseRecovery && (
            <button
              type="button"
              disabled={recovery.busy}
              onClick={() => {
                const original = recovery.closeRecovery();
                if (!original) return;
                focusAfterRender.current = "read";
                const { yearId, periodId, ordinal, startsOn, endsBefore } =
                  original.intent;
                setReview(null);
                setReading(null);
                setDraft({
                  yearId,
                  periodId,
                  ordinal: String(ordinal),
                  startsOn,
                  endsBefore,
                });
              }}
            >
              Close unconfirmed calendar request
            </button>
          )}
        </div>
      </section>
    );
  }
  if (!canRead || !target) return null;

  return (
    <section aria-label="Declared calendar period">
      <button
        type="button"
        ref={readButton}
        aria-disabled={state === "loading" || recovery.busy || undefined}
        onClick={() => void inspect()}
      >
        Read declared calendar period
      </button>
      {state === "loading" && <p role="status">Reading the declared period…</p>}
      {state === "failed" && (
        <p role="alert">
          The calendar period could not be verified for this coordinate. Refresh
          the model or try the read again.
        </p>
      )}
      {period && (
        <p role="status">
          {period.defined ? (
            <>
              Period {period.ordinal} starts on{" "}
              <time dateTime={period.startsOn}>{period.startsOn}</time> and ends
              before{" "}
              <time dateTime={period.endsBefore}>{period.endsBefore}</time>.
            </>
          ) : (
            "No calendar interval is defined for this year and period."
          )}
        </p>
      )}
      {canEdit && period && !draft && (
        <button type="button" onClick={begin}>
          {period.defined ? "Edit calendar period" : "Define calendar period"}
        </button>
      )}
      {canEdit && draft && (
        <fieldset disabled={recovery.busy}>
          <legend>
            Calendar draft for {draft.yearId} / {draft.periodId}
          </legend>
          <label>
            Period ordinal
            <input
              ref={ordinalField}
              type="number"
              min="1"
              max="366"
              step="1"
              value={draft.ordinal}
              onChange={(event) => update("ordinal", event.target.value)}
            />
          </label>
          <label>
            First date included
            <input
              type="date"
              value={draft.startsOn}
              onChange={(event) => update("startsOn", event.target.value)}
            />
          </label>
          <label>
            First date excluded
            <input
              type="date"
              value={draft.endsBefore}
              onChange={(event) => update("endsBefore", event.target.value)}
            />
          </label>
          <p>
            Choose an ordinal from 1 to 366. The first excluded date must be
            after the first included date.
          </p>
          {!period && (
            <p>Read the current period before reviewing this draft.</p>
          )}
          {period && valid && !changed && (
            <p>The draft matches the current period.</p>
          )}
          {recovery.message && <p role="alert">{recovery.message}</p>}
          <div className="button-row">
            <button type="button" disabled={!canReview} onClick={reviewChange}>
              Review calendar change
            </button>
            <button
              type="button"
              onClick={() => {
                focusAfterRender.current = "read";
                setDraft(null);
                setReview(null);
              }}
            >
              Discard calendar draft
            </button>
          </div>
          {reviewed && (
            <section aria-label="Reviewed calendar change">
              <p>
                Year {reviewed.intent.yearId}, period {reviewed.intent.periodId}
                . Ordinal {reviewed.intent.ordinal}, from{" "}
                {reviewed.intent.startsOn} through the day before{" "}
                {reviewed.intent.endsBefore}.
              </p>
              <button type="button" onClick={save}>
                Save reviewed calendar change
              </button>
            </section>
          )}
          {recovery.busy && (
            <p role="status">Submitting the reviewed calendar change…</p>
          )}
        </fieldset>
      )}
    </section>
  );
}
