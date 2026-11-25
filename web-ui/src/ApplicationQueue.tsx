import { useEffect, useRef, useState } from "react";
import { ApiError, request } from "./api";
import type { Scope } from "./types";

type QueueRow = {
  family: string;
  depth: number;
  oldestSeconds: number;
  liveLeases: number;
  expiredLeases: number;
};

type QueueSnapshot = {
  queueObservedAt: string;
  rows: QueueRow[];
  impactFailure?: string;
};

type Observation =
  | { state: "loading" }
  | ({ state: "ready" } & QueueSnapshot)
  | { state: "unavailable"; message: string };

const familyLabels = new Map([
  ["business", "Business jobs"],
  ["aggregate", "Aggregate queries"],
  ["pythonBuild", "Python builds"],
  ["pythonWorkflow", "Python workflows"],
  ["pythonSchedule", "Python schedules"],
  ["applicationRule", "Application rules"],
  ["applicationSchedule", "Application schedules"],
  ["importExecution", "Import execution"],
  ["exportProducer", "Export production"],
  ["layoutReplacementBuild", "Layout replacement builds"],
  ["layoutActivation", "Layout activation"],
  ["expressionRuleSequence", "Expression rule sequences"],
  ["fullAggregateSequence", "Full aggregate sequences"],
  ["calculationImpact", "Calculation impacts"],
]);
const QUEUE_READ_BUSY = new Set([
  "PROCESSING_LOCK_BUSY_RETRY",
  "ADMISSION_CAPACITY_EXCEEDED",
]);

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function count(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function readQueues(value: unknown, scope: Scope): QueueSnapshot | null {
  if (
    !record(value) ||
    !record(value.scope) ||
    value.scope.workspaceId !== scope.workspaceId ||
    value.scope.applicationId !== scope.applicationId ||
    typeof value.queueObservedAt !== "string" ||
    value.queueObservedAt.length !== 24 ||
    !Number.isFinite(Date.parse(value.queueObservedAt)) ||
    new Date(value.queueObservedAt).toISOString() !== value.queueObservedAt ||
    !record(value.metricScopes) ||
    value.metricScopes.queueDepths !== "authorized_application_only" ||
    value.metricScopes.queueOldestAgeSeconds !==
      "authorized_application_fixed_family_only" ||
    value.metricScopes.workers !== "authorized_application_only" ||
    !record(value.queueDepths) ||
    !record(value.queueOldestAgeSeconds) ||
    !record(value.workers) ||
    !record(value.workers.byFamily)
  )
    return null;
  const { queueDepths, queueOldestAgeSeconds } = value;
  const { byFamily } = value.workers;
  const families = Object.keys(queueDepths);
  if (
    !families.length ||
    families.length !== Object.keys(queueOldestAgeSeconds).length ||
    families.length !== Object.keys(byFamily).length
  )
    return null;
  const rows: QueueRow[] = [];
  for (const family of families.sort()) {
    const depth = queueDepths[family];
    const oldestSeconds = queueOldestAgeSeconds[family];
    const leases = byFamily[family];
    if (
      !/^[a-z][A-Za-z0-9]{0,63}$/.test(family) ||
      !count(depth) ||
      !count(oldestSeconds) ||
      !record(leases) ||
      !count(leases.activeClaims) ||
      !count(leases.liveClaims) ||
      !count(leases.expiredClaims) ||
      leases.liveClaims + leases.expiredClaims > leases.activeClaims
    )
      return null;
    rows.push({
      family,
      depth,
      oldestSeconds,
      liveLeases: leases.liveClaims,
      expiredLeases: leases.expiredClaims,
    });
  }
  let impactFailure: string | undefined;
  const impact = value.calculationImpact;
  const impactDepth = queueDepths.calculationImpact;
  const impactScope = value.metricScopes.calculationImpact;
  if (
    impact !== undefined ||
    impactDepth !== undefined ||
    impactScope !== undefined
  ) {
    if (
      !record(impact) ||
      !count(impactDepth) ||
      impactScope !== "authorized_application_only"
    )
      return null;
    if (impact.status === "failed") {
      if (
        impactDepth === 0 ||
        typeof impact.failureCode !== "string" ||
        !/^CALCULATION_IMPACT_[A-Z0-9_]{1,64}$/.test(impact.failureCode)
      )
        return null;
      impactFailure = impact.failureCode;
    } else if (
      impact.status !== (impactDepth === 0 ? "clear" : "pending") ||
      impact.failureCode !== undefined
    )
      return null;
  }
  return { queueObservedAt: value.queueObservedAt, rows, impactFailure };
}

export function ApplicationQueue({ scope }: { scope: Scope }) {
  const [observation, setObservation] = useState<Observation | null>(null);
  const inFlight = useRef<AbortController | null>(null);
  useEffect(() => () => inFlight.current?.abort(), []);
  const loading = observation?.state === "loading";

  async function refresh() {
    if (inFlight.current) return;
    const controller = new AbortController();
    inFlight.current = controller;
    setObservation({ state: "loading" });
    try {
      const value = await request<unknown>(
        "/api/capacity-metrics",
        { ...scope, view: "queues" },
        controller.signal,
      );
      const snapshot = readQueues(value, scope);
      if (!controller.signal.aborted)
        setObservation(
          snapshot
            ? { state: "ready", ...snapshot }
            : {
                state: "unavailable",
                message:
                  "The queue snapshot could not be verified. Refresh queue to try again.",
              },
        );
    } catch (failure) {
      if (controller.signal.aborted) return;
      const code = failure instanceof ApiError ? failure.code : undefined;
      const message =
        code === "APPLICATION_GRANT_REQUIRED"
          ? "Current access does not allow queue observations for this application."
          : code === "CAPACITY_READ_AUTHORIZATION_STALE"
            ? "Access changed while reading the queue. Check current application access and refresh the queue."
            : failure instanceof ApiError &&
                failure.status === 429 &&
                QUEUE_READ_BUSY.has(failure.code)
              ? "The application is busy and could not return a queue observation. Refresh queue to check again."
              : "Queue observations are unavailable. Refresh queue to try again.";
      setObservation({ state: "unavailable", message });
    } finally {
      if (inFlight.current === controller) inFlight.current = null;
    }
  }

  function toggle() {
    if (observation) {
      inFlight.current?.abort();
      inFlight.current = null;
      setObservation(null);
    } else void refresh();
  }

  return (
    <section
      className="panel workload-matrix"
      aria-labelledby="application-queue-title"
    >
      <div className="section-title">
        <h2 id="application-queue-title">Application queue and leases</h2>
        <div className="page-actions">
          <button
            type="button"
            onClick={toggle}
            aria-expanded={Boolean(observation)}
            aria-controls="application-queue-body"
          >
            {observation ? "Hide queue" : "Show queue"}
          </button>
        </div>
      </div>
      <div id="application-queue-body" hidden={!observation}>
        <p>
          Unsettled work includes units waiting or executing. Parent and child
          work can appear in separate families. An expired lease is a claim past
          its deadline. Check the task outcome before retrying.
        </p>
        <div className="page-actions">
          <button
            type="button"
            aria-disabled={loading || undefined}
            onClick={() => void refresh()}
          >
            Refresh queue
          </button>
        </div>
        <p role="status" id="application-queue-observation">
          {loading ? (
            "Reading queue observations…"
          ) : observation?.state === "ready" ? (
            <>
              Queue observed at{" "}
              <time dateTime={observation.queueObservedAt}>
                {observation.queueObservedAt.slice(0, 19).replace("T", " ")} UTC
              </time>
              .
              {observation.rows.some((row) => row.expiredLeases > 0) && (
                <>
                  {" "}
                  Some worker leases had expired at that time. Check the
                  original job for its recorded outcome before starting new
                  work.
                </>
              )}
              {observation.impactFailure && (
                <>
                  {" "}
                  Calculation impact processing failed and later impacts were
                  waiting at that time. If the failure persists after
                  refreshing, check worker diagnostics for{" "}
                  <code>{observation.impactFailure}</code>.
                </>
              )}
            </>
          ) : (
            ""
          )}
        </p>
        {observation?.state === "unavailable" && (
          <p className="inline-error" role="alert">
            {observation.message}
          </p>
        )}
        {observation?.state === "ready" && (
          <div
            className="workload-matrix-scroll"
            tabIndex={0}
            role="region"
            aria-label="Queue observations by work family"
            aria-describedby="application-queue-observation"
          >
            <table>
              <thead>
                <tr>
                  <th scope="col">Work family</th>
                  <th scope="col">Unsettled work</th>
                  <th scope="col">Oldest work (seconds)</th>
                  <th scope="col">Live leases</th>
                  <th scope="col">Expired leases</th>
                </tr>
              </thead>
              <tbody>
                {observation.rows.map((row) => (
                  <tr key={row.family}>
                    <th scope="row">
                      {familyLabels.get(row.family) ?? row.family}
                    </th>
                    <td>{row.depth}</td>
                    <td>{row.depth ? row.oldestSeconds : "—"}</td>
                    <td>{row.liveLeases}</td>
                    <td>{row.expiredLeases}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
