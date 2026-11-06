import { useEffect, useMemo, useState } from "react";
import { request } from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";

type ScheduleSummary = {
  scheduleId: string;
  version: number;
  definition: Record<string, unknown>;
  definitionDigest: string;
  status: "Saved" | "Published";
  stateRevision: number;
  createdRevision: number;
  createdAt: string;
};
type ScheduleTarget = { scheduleId: string; version: number; digest: string };
const SCHEDULE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const DIGEST = /^[0-9a-f]{64}$/;

export function exactApplicationSchedule(
  value: unknown,
  target: ScheduleTarget,
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
    schedule.version !== target.version ||
    schedule.definitionDigest !== target.digest ||
    schedule.status !== "Published" ||
    !SCHEDULE_ID.test(target.scheduleId) ||
    !DIGEST.test(target.digest) ||
    !definition ||
    definition.format !== "openepm-application-schedule-v1" ||
    definition.scheduleId !== target.scheduleId ||
    definition.version !== target.version ||
    !Number.isSafeInteger(schedule.stateRevision) ||
    Number(schedule.stateRevision) < 1 ||
    !Number.isSafeInteger(schedule.createdRevision) ||
    Number(schedule.createdRevision) < 1 ||
    typeof schedule.createdAt !== "string" ||
    !Number.isFinite(Date.parse(schedule.createdAt))
  )
    throw new Error("INVALID_APPLICATION_SCHEDULE_RESPONSE");
  return schedule as ScheduleSummary;
}

export const scheduleReadBody = (
  scope: Scope,
  scheduleId: string,
  version?: number,
) => ({
  ...scope,
  program: {
    languageVersion: 2,
    function: "schedule.version.read",
    arguments: { scheduleId, ...(version === undefined ? {} : { version }) },
  },
});

export const scheduleListBody = (scope: Scope, afterScheduleId?: string) => ({
  ...scope,
  program: {
    languageVersion: 2,
    function: "schedule.version.list",
    arguments: { limit: 100, ...(afterScheduleId ? { afterScheduleId } : {}) },
  },
});

export const scheduleMutationBody = (
  app: ApplicationSummary,
  catalog: ApplicationCatalog,
  functionName:
    | "schedule.version.save"
    | "schedule.version.publish"
    | "schedule.version.deactivate",
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
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  target?: ScheduleTarget;
}) {
  const mutationIntentKey = useStableMutationIntentKey("schedule-ui");
  const functions = catalog?.functions || {};
  const available = Boolean(
    functions["schedule.version.list"] && functions["schedule.version.read"],
  );
  const canRead = Boolean(functions["schedule.version.read"]);
  const canSave = Boolean(functions["schedule.version.save"]);
  const canPublish = Boolean(functions["schedule.version.publish"]);
  const canDeactivate = Boolean(functions["schedule.version.deactivate"]);
  const [schedules, setSchedules] = useState<ScheduleSummary[]>([]);
  const [selected, setSelected] = useState<ScheduleSummary | null>(null);
  const [after, setAfter] = useState<string | null>(null);
  const [definition, setDefinition] = useState("{}");
  const [definitionTouched, setDefinitionTouched] = useState(false);
  const [reviewed, setReviewed] = useState<
    "save" | "publish" | "deactivate" | null
  >(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
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
      parsed?.version === selected.version,
  );
  useUnsavedWork(
    `build-schedule:${app?.workspaceId || "none"}:${app?.applicationId || "none"}`,
    "Unsaved schedule definition",
    definitionTouched,
  );

  useEffect(() => {
    setSchedules([]);
    setSelected(null);
    setAfter(null);
    setDefinition("{}");
    setDefinitionTouched(false);
    setReviewed(null);
    setError("");
    setResult("");
  }, [app?.workspaceId, app?.applicationId]);

  async function load(append = false) {
    if (!scope || !available) return;
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
      );
      setSchedules((current) =>
        append
          ? [...current, ...response.result.schedules]
          : response.result.schedules,
      );
      setAfter(response.result.nextAfterScheduleId);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read schedules",
      );
    } finally {
      setBusy(false);
    }
  }

  async function open(
    row: Pick<ScheduleSummary, "scheduleId" | "version" | "definitionDigest">,
  ) {
    if (!scope || !canRead) return;
    setBusy(true);
    setError("");
    try {
      const response = await request<{
        result: { defined: boolean; schedule: ScheduleSummary | null };
      }>(
        "/api/application-schedule",
        scheduleReadBody(scope, row.scheduleId, row.version),
      );
      const exact = exactApplicationSchedule(response.result, {
        scheduleId: row.scheduleId,
        version: row.version,
        digest: row.definitionDigest,
      });
      setSelected(exact);
      setDefinition(JSON.stringify(exact.definition, null, 2));
      setDefinitionTouched(false);
      setReviewed(null);
      setResult("");
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read schedule",
      );
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (target)
      void open({
        scheduleId: target.scheduleId,
        version: target.version,
        definitionDigest: target.digest,
      });
  }, [
    app?.workspaceId,
    app?.applicationId,
    target?.scheduleId,
    target?.version,
    target?.digest,
    canRead,
  ]);

  async function mutate(action: "save" | "publish" | "deactivate") {
    if (
      !app ||
      !catalog ||
      catalog.revisions.schemaEpoch === undefined ||
      reviewed !== action
    )
      return;
    let body;
    try {
      if (action === "save") {
        if (!parsed) throw new Error("Enter one valid schedule definition.");
        const stateRevision = selected?.stateRevision ?? 0;
        body = scheduleMutationBody(
          app,
          catalog,
          "schedule.version.save",
          {
            definition: parsed,
            expectedStateRevision: stateRevision,
          },
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            action,
            definition: parsed,
            expectedStateRevision: stateRevision,
          }),
        );
      } else {
        if (!selected || !exactSelected)
          throw new Error("Open the exact immutable schedule version first.");
        body = scheduleMutationBody(
          app,
          catalog,
          `schedule.version.${action}`,
          {
            scheduleId: selected.scheduleId,
            ...(action === "publish" ? { version: selected.version } : {}),
            expectedStateRevision: selected.stateRevision,
          },
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            action,
            scheduleId: selected.scheduleId,
            version: selected.version,
            expectedStateRevision: selected.stateRevision,
          }),
        );
      }
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Invalid schedule intent",
      );
      return;
    }
    if (
      !window.confirm(
        `${action[0].toUpperCase()}${action.slice(1)} this exact generic schedule version?`,
      )
    )
      return;
    setBusy(true);
    setError("");
    try {
      const response = await request<{
        result?: { status?: string; operationId?: string };
      }>("/api/application-schedule", body);
      setResult(
        `Fixed core recorded ${response.result?.status || action}${response.result?.operationId ? ` by receipt ${response.result.operationId}` : ""}.`,
      );
      setReviewed(null);
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
          <h2 id="generic-schedule-heading">Rule schedules</h2>
          <p>
            Version and schedule an exact published application rule. Due-time
            calculation, execution and recovery remain fixed-core services.
          </p>
        </div>
        <button disabled={busy} onClick={() => void load(false)}>
          {busy ? "Working…" : "Read schedules"}
        </button>
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
                <th>Version</th>
                <th>Status</th>
                <th>Definition digest</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {schedules.map((row) => (
                <tr key={row.scheduleId}>
                  <th>{row.scheduleId}</th>
                  <td>{row.version}</td>
                  <td>{row.status}</td>
                  <td>
                    <code>{row.definitionDigest.slice(0, 12)}…</code>
                  </td>
                  <td>
                    <button disabled={busy} onClick={() => void open(row)}>
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted-copy">No generic schedule catalogue read yet.</p>
      )}
      {after && (
        <button disabled={busy} onClick={() => void load(true)}>
          Read next schedules
        </button>
      )}
      <div className="governed-action-grid">
        <article className="governed-action-card">
          <small>REVIEWED IMMUTABLE DEFINITION</small>
          <h3>Author and control</h3>
          <label>
            Schedule definition JSON
            <textarea
              aria-label="Schedule definition JSON"
              rows={16}
              value={definition}
              onChange={(event) => {
                setDefinition(event.target.value);
                setDefinitionTouched(true);
                setReviewed(null);
                setResult("");
              }}
            />
          </label>
          <p className="authority-note">
            The definition pins one published generic rule, bindings, POV,
            recurrence, retry policy and delegated execution authority.
          </p>
          {(["save", "publish", "deactivate"] as const).map((action) => {
            const allowed =
              action === "save"
                ? canSave && Boolean(parsed)
                : action === "publish"
                  ? canPublish && exactSelected
                  : canDeactivate && exactSelected;
            return (
              <div key={action} className="review-row">
                <label>
                  <input
                    type="checkbox"
                    checked={reviewed === action}
                    disabled={!allowed || busy}
                    onChange={(event) =>
                      setReviewed(event.target.checked ? action : null)
                    }
                  />{" "}
                  Review exact {action} intent
                </label>
                <button
                  disabled={!allowed || reviewed !== action || busy}
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
    </section>
  );
}
