import { useEffect, useMemo, useRef, useState } from "react";
import { request, requestAdmittedEffect } from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import "./rule-workspaces.css";

type ScheduleSummary = {
  scheduleId: string;
  stateToken: string;
  definition: Record<string, unknown>;
  definitionDigest: string;
  status: "Saved" | "Active";
  targetStatus: "Current" | "Stale";
  effectiveStatus: "Saved" | "Active" | "Blocked";
  reasonCode: null | "APPLICATION_SCHEDULE_TARGET_STALE";
  updatedAt: string;
};
type ScheduleTarget = {
  scheduleId: string;
  stateToken: string;
  digest: string;
};
const SCHEDULE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const DIGEST = /^[0-9a-f]{64}$/;

export function exactApplicationSchedule(
  value: unknown,
  target: ScheduleTarget,
  requirePublished = true,
): ScheduleSummary {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("INVALID_APPLICATION_SCHEDULE_RESPONSE");
  const envelope = value as Record<string, unknown>;
  const schedule = envelope.schedule as Record<string, unknown> | null;
  const definition = schedule?.definition as
    | Record<string, unknown>
    | undefined;
  if (
    envelope.defined !== true ||
    !schedule ||
    schedule.scheduleId !== target.scheduleId ||
    schedule.stateToken !== target.stateToken ||
    schedule.definitionDigest !== target.digest ||
    !["Current", "Stale"].includes(String(schedule.targetStatus)) ||
    !["Saved", "Active", "Blocked"].includes(
      String(schedule.effectiveStatus),
    ) ||
    (schedule.targetStatus === "Current"
      ? schedule.reasonCode !== null ||
        schedule.effectiveStatus !== schedule.status
      : schedule.reasonCode !== "APPLICATION_SCHEDULE_TARGET_STALE" ||
        schedule.effectiveStatus !== "Blocked") ||
    (requirePublished
      ? schedule.status !== "Active" || schedule.effectiveStatus !== "Active"
      : !["Saved", "Active"].includes(String(schedule.status))) ||
    !SCHEDULE_ID.test(target.scheduleId) ||
    !DIGEST.test(target.digest) ||
    !definition ||
    definition.format !== "openepm-application-schedule-v1" ||
    definition.scheduleId !== target.scheduleId ||
    !DIGEST.test(String(schedule.stateToken)) ||
    typeof schedule.updatedAt !== "string" ||
    !Number.isFinite(Date.parse(schedule.updatedAt))
  )
    throw new Error("INVALID_APPLICATION_SCHEDULE_RESPONSE");
  return schedule as ScheduleSummary;
}

export const scheduleReadBody = (scope: Scope, scheduleId: string) => ({
  ...scope,
  program: {
    languageVersion: 2,
    function: "schedule.read",
    arguments: { scheduleId },
  },
});

export const scheduleListBody = (scope: Scope, afterScheduleId?: string) => ({
  ...scope,
  program: {
    languageVersion: 2,
    function: "schedule.list",
    arguments: { limit: 100, ...(afterScheduleId ? { afterScheduleId } : {}) },
  },
});

export const scheduleMutationBody = (
  app: ApplicationSummary,
  catalog: ApplicationCatalog,
  functionName: "schedule.save" | "schedule.activate" | "schedule.deactivate",
  argumentsValue: Record<string, unknown>,
  idempotencyKey: string,
) => ({
  workspaceId: app.workspaceId,
  applicationId: app.applicationId,
  confirmed: true,
  idempotencyKey,
  program: {
    languageVersion: 2,
    function: functionName,
    arguments: {
      ...argumentsValue,
      expectedMetadataRevision: catalog.revisions.metadata,
      expectedPolicyRevision: catalog.revisions.policy,
      expectedSchemaEpoch: catalog.revisions.schemaEpoch,
    },
  },
});

function parseDefinition(value: string) {
  const parsed: unknown = JSON.parse(value);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new Error("Schedule definition must be one JSON object.");
  return parsed as Record<string, unknown>;
}

export function BuildSchedules({
  app,
  catalog,
  target,
  onRequestTransition = (action) => action(),
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  target?: ScheduleTarget;
  onRequestTransition?: (action: () => void) => void;
}) {
  const activeRead = useRef<AbortController | null>(null);
  useEffect(
    () => () => activeRead.current?.abort(),
    [app?.workspaceId, app?.applicationId],
  );
  function beginRead() {
    activeRead.current?.abort();
    const controller = new AbortController();
    activeRead.current = controller;
    return controller;
  }
  const mutationIntentKey = useStableMutationIntentKey("schedule-ui");
  const functions = catalog?.functions || {};
  const available = Boolean(
    functions["schedule.list"] && functions["schedule.read"],
  );
  const canRead = Boolean(functions["schedule.read"]);
  const canSave = Boolean(functions["schedule.save"]);
  const canActivate = Boolean(functions["schedule.activate"]);
  const canDeactivate = Boolean(functions["schedule.deactivate"]);
  const [schedules, setSchedules] = useState<ScheduleSummary[]>([]);
  const [catalogueRead, setCatalogueRead] = useState(false);
  const [editorOpen, setEditorOpen] = useState(false);
  const editorHeading = useRef<HTMLHeadingElement>(null);
  const editorTrigger = useRef<HTMLElement | null>(null);
  const [selected, setSelected] = useState<ScheduleSummary | null>(null);
  const [after, setAfter] = useState<string | null>(null);
  const [definition, setDefinition] = useState("{}");
  const [definitionTouched, setDefinitionTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  useEffect(() => {
    if (editorOpen) editorHeading.current?.focus();
  }, [editorOpen, selected?.scheduleId, selected?.stateToken]);
  const scope = app
    ? { workspaceId: app.workspaceId, applicationId: app.applicationId }
    : null;
  const parsed = useMemo(() => {
    try {
      return parseDefinition(definition);
    } catch {
      return null;
    }
  }, [definition]);
  const exactSelected = Boolean(
    selected &&
      parsed?.scheduleId === selected.scheduleId &&
      JSON.stringify(parsed) === JSON.stringify(selected.definition),
  );
  useUnsavedWork(
    `build-schedule:${app?.workspaceId || "none"}:${app?.applicationId || "none"}`,
    "Unsaved schedule definition",
    definitionTouched,
  );

  useEffect(() => {
    setSchedules([]);
    setCatalogueRead(false);
    setEditorOpen(false);
    setSelected(null);
    setAfter(null);
    setDefinition("{}");
    setDefinitionTouched(false);
    setError("");
    setResult("");
  }, [app?.workspaceId, app?.applicationId]);

  function changeContext(action: () => void) {
    if (busy) return;
    const trigger = document.activeElement;
    if (
      trigger instanceof HTMLElement &&
      !trigger.closest(".rule-editor-frame")
    )
      editorTrigger.current = trigger;
    const change = () => {
      setSelected(null);
      setDefinition("{}");
      setDefinitionTouched(false);
      setEditorOpen(false);
      setResult("");
      setError("");
      action();
    };
    if (definitionTouched) onRequestTransition(change);
    else change();
  }

  async function load(append = false) {
    if (!scope || !available) return;
    const controller = beginRead();
    setBusy(true);
    setError("");
    try {
      const response = await request<{
        result: {
          schedules: ScheduleSummary[];
          nextAfterScheduleId: string | null;
        };
      }>(
        "/api/application-schedule",
        scheduleListBody(scope, append ? after || undefined : undefined),
        controller.signal,
      );
      if (controller.signal.aborted) return;
      setSchedules((current) =>
        append
          ? [...current, ...response.result.schedules]
          : response.result.schedules,
      );
      setAfter(response.result.nextAfterScheduleId);
      setCatalogueRead(true);
    } catch (reason) {
      if (controller.signal.aborted) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to read schedules",
      );
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  async function open(
    row: Pick<
      ScheduleSummary,
      "scheduleId" | "stateToken" | "definitionDigest"
    >,
    requirePublished = false,
  ) {
    if (!scope || !canRead) return;
    const controller = beginRead();
    setBusy(true);
    setError("");
    try {
      const response = await request<{
        result: { defined: boolean; schedule: ScheduleSummary | null };
      }>(
        "/api/application-schedule",
        scheduleReadBody(scope, row.scheduleId),
        controller.signal,
      );
      if (controller.signal.aborted) return;
      const exact = exactApplicationSchedule(
        response.result,
        {
          scheduleId: row.scheduleId,
          stateToken: row.stateToken,
          digest: row.definitionDigest,
        },
        requirePublished,
      );
      setEditorOpen(true);
      setSelected(exact);
      setDefinition(JSON.stringify(exact.definition, null, 2));
      setDefinitionTouched(false);
      setResult("");
    } catch (reason) {
      if (controller.signal.aborted) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to read schedule",
      );
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  useEffect(() => {
    if (target)
      void open(
        {
          scheduleId: target.scheduleId,
          stateToken: target.stateToken,
          definitionDigest: target.digest,
        },
        true,
      );
  }, [
    app?.workspaceId,
    app?.applicationId,
    target?.scheduleId,
    target?.stateToken,
    target?.digest,
    canRead,
  ]);

  async function mutate(action: "save" | "activate" | "deactivate") {
    if (!app || !catalog || catalog.revisions.schemaEpoch === undefined) return;
    let body;
    try {
      if (action === "save") {
        if (!parsed) throw new Error("Enter one valid schedule definition.");
        body = scheduleMutationBody(
          app,
          catalog,
          "schedule.save",
          {
            definition: parsed,
            ...(selected ? { expectedStateToken: selected.stateToken } : {}),
          },
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            action,
            definition: parsed,
            expectedStateToken: selected?.stateToken,
          }),
        );
      } else {
        if (!selected || !exactSelected)
          throw new Error("Open the exact current schedule first.");
        body = scheduleMutationBody(
          app,
          catalog,
          `schedule.${action}`,
          {
            scheduleId: selected.scheduleId,
            expectedStateToken: selected.stateToken,
          },
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            action,
            scheduleId: selected.scheduleId,
            stateToken: selected.stateToken,
          }),
        );
      }
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Invalid schedule intent",
      );
      return;
    }
    setBusy(true);
    setError("");
    try {
      const response = await requestAdmittedEffect<{
        result?: { status?: string; operationId?: string };
      }>("/api/application-schedule", body);
      setResult(`Schedule ${response.result?.status || action} recorded.`);
      setDefinitionTouched(false);
      setSelected(null);
      await load(false);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : `Unable to ${action} schedule`,
      );
    } finally {
      setBusy(false);
    }
  }

  if (!canRead)
    return target ? (
      <p role="alert">Schedule inspection is not authorized.</p>
    ) : null;
  return (
    <section
      className="panel capability-activity"
      aria-labelledby="generic-schedule-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>GENERIC AUTOMATION</small>
          <h2 id="generic-schedule-heading" tabIndex={-1}>
            Rule schedules
          </h2>
          <p>
            Schedule a published rule with a defined recurrence and retry
            policy. Save validates the current definition before activation.
          </p>
        </div>
        <div className="rule-workspace-actions">
          <button
            disabled={busy}
            onClick={() => changeContext(() => void load(false))}
          >
            {busy ? "Working…" : "Read schedules"}
          </button>
          {canSave && (
            <button
              className="primary"
              disabled={busy}
              aria-controls="rule-schedule-editor"
              aria-expanded={editorOpen}
              onClick={() => changeContext(() => setEditorOpen(true))}
            >
              New schedule
            </button>
          )}
        </div>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {schedules.length ? (
        <div className="react-grid-scroll">
          <table className="react-cube-grid">
            <thead>
              <tr>
                <th>Schedule</th>
                <th>Status</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {schedules.map((row) => (
                <tr key={row.scheduleId}>
                  <th>{row.scheduleId}</th>
                  <td>
                    {row.effectiveStatus}
                    {row.targetStatus === "Stale" && (
                      <small className="authority-note">
                        Target changed; rebind this schedule to the current
                        rule.
                      </small>
                    )}
                  </td>
                  <td>
                    <button
                      disabled={busy}
                      onClick={() => changeContext(() => void open(row))}
                    >
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="rule-workspace-empty" role="status">
          <strong>
            {busy
              ? "Reading rule schedules…"
              : catalogueRead
                ? "No rule schedules yet"
                : "Choose a rule schedule"}
          </strong>
          <p>
            {catalogueRead
              ? "Create a schedule to run a published rule on a defined recurrence."
              : "Read the catalogue to inspect a schedule, or create a new definition."}
          </p>
        </div>
      )}
      {after && (
        <button disabled={busy} onClick={() => void load(true)}>
          Read next schedules
        </button>
      )}
      {editorOpen && (
        <fieldset
          id="rule-schedule-editor"
          className="rule-editor-frame rule-editor-single"
          disabled={busy}
          aria-labelledby="schedule-editor-title"
        >
          <div className="rule-editor-heading">
            <div>
              <small>
                {selected ? "CURRENT DEFINITION" : "NEW DEFINITION"}
              </small>
              <h3 id="schedule-editor-title" ref={editorHeading} tabIndex={-1}>
                {selected ? selected.scheduleId : "Create a rule schedule"}
              </h3>
            </div>
            <button
              type="button"
              onClick={() =>
                changeContext(() => {
                  queueMicrotask(() =>
                    (
                      editorTrigger.current ||
                      document.getElementById("generic-schedule-heading")
                    )?.focus(),
                  );
                })
              }
            >
              Close editor
            </button>
          </div>
          <div className="governed-action-grid">
            <article className="governed-action-card">
              <small>CURRENT DEFINITION</small>
              <h4>Schedule definition</h4>
              <label>
                Schedule definition JSON
                <textarea
                  aria-label="Schedule definition JSON"
                  readOnly={!canSave}
                  className="code-editor"
                  rows={16}
                  value={definition}
                  onChange={(event) => {
                    setDefinition(event.target.value);
                    setDefinitionTouched(true);
                    setResult("");
                  }}
                />
              </label>
              <p className="authority-note">
                The definition pins one published generic rule, bindings, POV,
                recurrence, retry policy and delegated execution authority.
              </p>
              {selected?.targetStatus === "Stale" && (
                <p className="inline-error" role="alert">
                  This schedule is blocked because its target rule changed.
                  Review the current rule and save the schedule again to rebind
                  it.
                </p>
              )}
              {(["save", "activate", "deactivate"] as const).map((action) => {
                if (action !== "save" && !selected) return null;
                const allowed =
                  action === "save"
                    ? canSave && Boolean(parsed)
                    : action === "activate"
                      ? canActivate &&
                        exactSelected &&
                        selected?.status !== "Active" &&
                        selected?.targetStatus === "Current"
                      : canDeactivate &&
                        exactSelected &&
                        selected?.status === "Active";
                return (
                  <div key={action} className="review-row">
                    <button
                      disabled={!allowed || busy}
                      onClick={() => void mutate(action)}
                    >
                      {action[0].toUpperCase() + action.slice(1)}
                    </button>
                  </div>
                );
              })}
              {result && <p role="status">{result}</p>}
            </article>
          </div>
        </fieldset>
      )}
    </section>
  );
}
