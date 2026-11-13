import { useEffect, useRef, useState } from "react";
import { PythonDefinitionEditor } from "./PythonDefinitionEditor";
import type { PythonSourceBinding } from "./PythonDefinitionEditor";
import { pythonDefinitionTemplates } from "./python-definition-templates";
import { readProgram } from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const RESULT_KEY = /^[A-Za-z0-9._-]{8,128}$/;

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function exactTarget(value: unknown): value is {
  dimensionId: string;
  memberId: string;
} {
  return (
    object(value) &&
    Object.keys(value).sort().join("\u0000") ===
      ["dimensionId", "memberId"].sort().join("\u0000") &&
    typeof value.dimensionId === "string" &&
    ID.test(value.dimensionId) &&
    typeof value.memberId === "string" &&
    ID.test(value.memberId)
  );
}

function exactDependencies(
  value: unknown,
): value is Array<{ definitionId: string }> {
  if (!Array.isArray(value) || value.length > 100) return false;
  const seen = new Set<string>();
  for (const dependency of value) {
    if (
      !object(dependency) ||
      Object.keys(dependency).sort().join("\u0000") !==
        ["definitionId"].sort().join("\u0000") ||
      typeof dependency.definitionId !== "string" ||
      !ID.test(dependency.definitionId)
    )
      return false;
    const key = dependency.definitionId;
    if (seen.has(key)) return false;
    seen.add(key);
  }
  return true;
}

type Summary = {
  definitionId: string;
  stateToken: string;
  status: "Saved" | "Active";
  programDigest: string;
  evaluation: "dynamic" | "materialized";
  dependencies: Array<{ definitionId: string }>;
  metadataCurrent: boolean;
  definitionMetadataRevision: number;
  target: Record<string, unknown>;
  resultUnit: string;
};

type Detail = {
  source?: PythonSourceBinding | null;
  defined: boolean;
  definitionId: string;
  stateToken: string;
  status: "Saved" | "Active" | null;
  program: {
    function: string;
    arguments: {
      evaluation: "dynamic" | "materialized";
      format: "openepm-calculated-member-v1";
      definitionId: string;
      name: string;
      sourceSelection: Record<string, unknown>;
      expression: unknown;
      dependencies: Array<{ definitionId: string }>;
      resultKey: string | null;
      target: { dimensionId: string; memberId: string };
      resultUnit: "amount" | "ratio";
      maxSourceCells: number;
      maxOutputCells: number;
    };
  };
  programDigest: string;
  definitionMetadataRevision: number;
  currentMetadataRevision: number;
  updatedAt: string;
  policyRevision: number;
};

type Target = { definitionId: string; stateToken: string; digest: string };

type CalculationStatusRow = {
  bindingDigest: string;
  stage: string;
  partitionKey: string;
  freshness: string;
  coverage: string;
  presence: string;
  reasons: string[];
  requiredEpoch: number;
  publishedEpoch: number;
};

type CalculationStatus = {
  rows: CalculationStatusRow[];
  nextAfter: string | null;
  impactBarrier: { pending?: boolean };
};

type Page = {
  rows: unknown[];
  metadataRevision: number;
  policyRevision: number;
  hasMore: boolean;
  nextAfterDefinitionId: string | null;
};

function exactPage(value: unknown): Page {
  if (
    !object(value) ||
    !Array.isArray(value.rows) ||
    !nonNegativeInteger(value.metadataRevision) ||
    !nonNegativeInteger(value.policyRevision) ||
    typeof value.hasMore !== "boolean" ||
    !(
      value.nextAfterDefinitionId === null ||
      (typeof value.nextAfterDefinitionId === "string" &&
        ID.test(value.nextAfterDefinitionId))
    )
  )
    throw new Error("INVALID_CALCULATED_MEMBER_LIST_RESPONSE");
  return value as Page;
}

function exactSummary(value: unknown): value is Summary {
  if (!object(value)) return false;
  const item = value;
  return (
    typeof item.definitionId === "string" &&
    ID.test(item.definitionId) &&
    typeof item.stateToken === "string" &&
    DIGEST.test(item.stateToken) &&
    typeof item.programDigest === "string" &&
    DIGEST.test(item.programDigest) &&
    (item.evaluation === "dynamic" || item.evaluation === "materialized") &&
    exactDependencies(item.dependencies) &&
    typeof item.metadataCurrent === "boolean" &&
    nonNegativeInteger(item.definitionMetadataRevision) &&
    (item.status === "Saved" || item.status === "Active") &&
    exactTarget(item.target) &&
    (item.resultUnit === "amount" || item.resultUnit === "ratio")
  );
}

export function exactCalculatedMemberDetail(
  value: unknown,
  target: Target,
): Detail {
  if (!object(value)) throw new Error("INVALID_CALCULATED_MEMBER_RESPONSE");
  const item = value;
  const program = object(item.program) ? item.program : null;
  const args = program && object(program.arguments) ? program.arguments : null;
  if (
    item.defined !== true ||
    item.definitionId !== target.definitionId ||
    item.stateToken !== target.stateToken ||
    item.programDigest !== target.digest ||
    program?.function !== "calculated.member.definition" ||
    !args ||
    Object.keys(args).sort().join("\u0000") !==
      [
        "format",
        "definitionId",
        "name",
        "target",
        "evaluation",
        "sourceSelection",
        "expression",
        "dependencies",
        "resultUnit",
        "resultKey",
        "maxSourceCells",
        "maxOutputCells",
      ]
        .sort()
        .join("\u0000") ||
    args.format !== "openepm-calculated-member-v1" ||
    args.definitionId !== target.definitionId ||
    typeof args.name !== "string" ||
    args.name.trim().length < 1 ||
    args.name.trim().length > 200 ||
    !object(args.sourceSelection) ||
    !object(args.expression) ||
    (args.evaluation !== "dynamic" && args.evaluation !== "materialized") ||
    !exactDependencies(args.dependencies) ||
    !exactTarget(args.target) ||
    (args.resultUnit !== "amount" && args.resultUnit !== "ratio") ||
    (args.evaluation === "dynamic"
      ? args.resultKey !== null
      : typeof args.resultKey !== "string" ||
        !RESULT_KEY.test(args.resultKey)) ||
    !positiveInteger(args.maxSourceCells) ||
    Number(args.maxSourceCells) > 1_000_000 ||
    !positiveInteger(args.maxOutputCells) ||
    Number(args.maxOutputCells) > 100_000 ||
    (item.status !== "Active" && item.status !== "Saved") ||
    !nonNegativeInteger(item.definitionMetadataRevision) ||
    !nonNegativeInteger(item.currentMetadataRevision) ||
    typeof item.updatedAt !== "string" ||
    !Number.isFinite(Date.parse(item.updatedAt)) ||
    !nonNegativeInteger(item.policyRevision)
  )
    throw new Error("INVALID_CALCULATED_MEMBER_RESPONSE");
  return item as Detail;
}

async function allCurrent(
  scope: Scope,
  signal: AbortSignal,
): Promise<Summary[]> {
  const rows: Summary[] = [];
  let after: string | null = null;
  let metadata: number | undefined;
  let policy: number | undefined;
  const seen = new Set<string>();
  do {
    const page: Page = exactPage(
      await readProgram<unknown>(
        scope,
        "calculated.member.list",
        {
          limit: 100,
          ...(after
            ? {
                afterDefinitionId: after,
                expectedMetadataRevision: metadata,
                expectedPolicyRevision: policy,
              }
            : {}),
        },
        signal,
      ),
    );
    metadata ??= page.metadataRevision;
    policy ??= page.policyRevision;
    if (page.metadataRevision !== metadata || page.policyRevision !== policy)
      throw new Error("CALCULATED_MEMBER_LIST_REVISION_CHANGED");
    for (const row of page.rows) {
      if (!exactSummary(row) || seen.has(row.definitionId))
        throw new Error("INVALID_CALCULATED_MEMBER_LIST_RESPONSE");
      seen.add(row.definitionId);
      rows.push(row);
    }
    after = page.nextAfterDefinitionId ?? null;
    if (page.hasMore !== Boolean(after))
      throw new Error("INVALID_CALCULATED_MEMBER_LIST_CONTINUATION");
    if (after && (!ID.test(after) || seen.has(after) === false))
      throw new Error("INVALID_CALCULATED_MEMBER_LIST_CONTINUATION");
  } while (after);
  return rows;
}

export function CalculatedMembers({
  app,
  catalog,
  target,
  onRequestTransition = (action) => action(),
  onRefreshCatalog,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  target?: Target;
  onRequestTransition?: (action: () => void) => void;
  onRefreshCatalog?: () => Promise<ApplicationCatalog>;
}) {
  const [creating, setCreating] = useState(false);
  const [rows, setRows] = useState<Summary[]>([]);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [listState, setListState] = useState<
    "unread" | "loading" | "loaded" | "error"
  >("unread");
  const [listError, setListError] = useState("");
  const [detailError, setDetailError] = useState("");
  const [calculationStatus, setCalculationStatus] =
    useState<CalculationStatus | null>(null);
  const [impactExplanation, setImpactExplanation] = useState<Record<
    string,
    unknown
  > | null>(null);
  const [readingTarget, setReadingTarget] = useState<Target | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const listRequest = useRef<AbortController | null>(null);
  const detailRequest = useRef<AbortController | null>(null);
  const detailHeading = useRef<HTMLHeadingElement | null>(null);
  const detailTrigger = useRef<HTMLButtonElement | null>(null);
  const inventoryHeading = useRef<HTMLHeadingElement | null>(null);
  const authorized = Boolean(catalog?.functions["calculated.member.read"]);
  const canList = Boolean(catalog?.functions["calculated.member.list"]);
  const scope = app
    ? { workspaceId: app.workspaceId, applicationId: app.applicationId }
    : null;

  async function readList() {
    if (!scope || !canList) return;
    listRequest.current?.abort();
    const controller = new AbortController();
    listRequest.current = controller;
    setListState("loading");
    setListError("");
    try {
      const values = await allCurrent(scope, controller.signal);
      if (controller.signal.aborted) return;
      setRows(values);
      setListState("loaded");
      setPage(0);
      return values;
    } catch (reason) {
      if (controller.signal.aborted) return;
      setListState("error");
      setListError(
        reason instanceof Error
          ? reason.message
          : "Unable to read calculated members.",
      );
    }
  }

  async function readExact(next: Target) {
    if (!scope || !authorized) return;
    detailRequest.current?.abort();
    const controller = new AbortController();
    detailRequest.current = controller;
    setDetail(null);
    setCalculationStatus(null);
    setImpactExplanation(null);
    setCreating(false);
    setDetailError("");
    setReadingTarget(next);
    try {
      const value = await readProgram<unknown>(
        scope,
        "calculated.member.read",
        { definitionId: next.definitionId },
        controller.signal,
      );
      const exact = exactCalculatedMemberDetail(value, next);
      if (!controller.signal.aborted) {
        setDetail(exact);
        if (catalog?.functions["calculation.status.read"])
          setCalculationStatus(
            await readProgram<CalculationStatus>(
              scope,
              "calculation.status.read",
              {
                definitionId: next.definitionId,
                definitionStateToken: next.stateToken,
                limit: 500,
              },
              controller.signal,
            ),
          );
      }
    } catch (reason) {
      if (!controller.signal.aborted)
        setDetailError(
          reason instanceof Error
            ? reason.message
            : "Unable to read calculated member.",
        );
    } finally {
      if (!controller.signal.aborted) setReadingTarget(null);
    }
  }

  function closeDetail(restoreFocus = false) {
    detailRequest.current?.abort();
    setDetail(null);
    setCalculationStatus(null);
    setImpactExplanation(null);
    setCreating(false);
    setReadingTarget(null);
    setDetailError("");
    if (restoreFocus) {
      const trigger = detailTrigger.current;
      if (trigger?.isConnected) trigger.focus();
      else inventoryHeading.current?.focus();
    }
  }

  async function explainImpact(bindingDigest: string) {
    if (!scope || !catalog?.functions["calculation.impact.explain"]) return;
    setDetailError("");
    try {
      setImpactExplanation(
        await readProgram<Record<string, unknown>>(
          scope,
          "calculation.impact.explain",
          { bindingDigest, mode: "affected" },
        ),
      );
    } catch (reason) {
      setDetailError(
        reason instanceof Error ? reason.message : "Unable to explain impact.",
      );
    }
  }

  useEffect(() => {
    if (detail) detailHeading.current?.focus();
  }, [detail]);

  useEffect(() => {
    setRows([]);
    setListState("unread");
    setListError("");
    setQuery("");
    setPage(0);
    closeDetail();
    if (canList) void readList();
    return () => {
      listRequest.current?.abort();
      detailRequest.current?.abort();
    };
  }, [app?.workspaceId, app?.applicationId, authorized, canList]);

  useEffect(() => {
    if (target) void readExact(target);
  }, [
    app?.workspaceId,
    app?.applicationId,
    target?.definitionId,
    target?.stateToken,
    target?.digest,
    authorized,
  ]);

  const filtered = rows.filter((row) =>
    `${row.definitionId} ${row.evaluation} ${row.target.dimensionId} ${row.target.memberId}`
      .toLocaleLowerCase()
      .includes(query.trim().toLocaleLowerCase()),
  );
  const start = Math.min(
    page * 50,
    Math.max(0, Math.ceil(filtered.length / 50) - 1) * 50,
  );
  const visible = filtered.slice(start, start + 50);

  if (!authorized || !scope) {
    return target ? (
      <p className="inline-error" role="alert">
        Calculated-member inspection is not authorized.
      </p>
    ) : null;
  }
  return (
    <section
      className="panel capability-activity calculated-members"
      aria-labelledby="calculated-member-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>CURRENT CALCULATION DEFINITIONS</small>
          <h2
            id="calculated-member-heading"
            ref={inventoryHeading}
            tabIndex={-1}
          >
            Calculated members
          </h2>
        </div>
        <button
          disabled={!canList || listState === "loading"}
          onClick={() => onRequestTransition(() => void readList())}
        >
          {listState === "loading"
            ? "Refreshing…"
            : "Refresh calculated members"}
        </button>
        {Boolean(
          catalog?.functions["python.program.save"] &&
            catalog.functions["python.environment.list"],
        ) && (
          <button
            onClick={() =>
              onRequestTransition(() => {
                closeDetail();
                setCreating(true);
              })
            }
          >
            New calculated member
          </button>
        )}
      </div>
      <p className="muted-copy">
        Author a calculated member in Python and inspect its exact target and
        dependencies.
      </p>
      {listError && (
        <p className="inline-error" role="alert">
          {listError}
        </p>
      )}
      {listState === "loading" && (
        <p role="status">Loading current calculated members…</p>
      )}
      {listState === "loaded" && !rows.length && (
        <div className="workspace-empty">
          <h3>No calculated members</h3>
          <p>Current definitions will appear here for inspection.</p>
        </div>
      )}
      {!canList && (
        <p className="muted-copy">
          The calculated-member inventory is not available to your current role.
        </p>
      )}
      {rows.length > 0 && (
        <>
          <div className="workspace-list-toolbar">
            <label>
              Find a calculated member
              <input
                aria-label="Find a calculated member"
                value={query}
                placeholder="Definition, target or evaluation"
                onChange={(event) => {
                  setQuery(event.target.value);
                  setPage(0);
                }}
              />
            </label>
            <span>
              {filtered.length} of {rows.length} definitions
            </span>
          </div>
          <div
            className="react-grid-scroll"
            role="region"
            aria-label="Calculated-member inventory"
            tabIndex={0}
            aria-busy={listState === "loading"}
          >
            <table
              className="react-cube-grid"
              aria-label="Current calculated members"
            >
              <thead>
                <tr>
                  <th>Definition</th>
                  <th>State</th>
                  <th>Evaluation</th>
                  <th>Target</th>
                  <th>Metadata</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((row) => (
                  <tr key={row.definitionId}>
                    <th>
                      <button
                        aria-label={`Open current ${row.definitionId}`}
                        aria-controls="calculated-member-inspector"
                        aria-expanded={
                          detail?.definitionId === row.definitionId &&
                          detail.stateToken === row.stateToken
                        }
                        onClick={(event) => {
                          detailTrigger.current = event.currentTarget;
                          onRequestTransition(
                            () =>
                              void readExact({
                                definitionId: row.definitionId,
                                stateToken: row.stateToken,
                                digest: row.programDigest,
                              }),
                          );
                        }}
                      >
                        {row.definitionId}
                      </button>
                    </th>
                    <td>{row.status}</td>
                    <td>{row.evaluation}</td>
                    <td>
                      {String(row.target.dimensionId)} /{" "}
                      {String(row.target.memberId)}
                    </td>
                    <td>{row.metadataCurrent ? "Current" : "Stale"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!visible.length && (
            <p className="muted-copy">No definitions match your search.</p>
          )}
          <div className="workspace-window-controls">
            <span>
              {filtered.length
                ? `${start + 1}–${start + visible.length} of ${filtered.length}`
                : "0 definitions"}
            </span>
            <button
              disabled={start === 0}
              onClick={() => setPage(start / 50 - 1)}
            >
              Previous definitions
            </button>
            <button
              disabled={start + 50 >= filtered.length}
              onClick={() => setPage(start / 50 + 1)}
            >
              Next definitions
            </button>
          </div>
        </>
      )}
      {readingTarget && (
        <p role="status">Loading current {readingTarget.definitionId}…</p>
      )}
      {detailError && (
        <p className="inline-error" role="alert">
          {detailError}
        </p>
      )}
      {creating && app && catalog && (
        <article aria-label="New calculated member">
          <button onClick={() => onRequestTransition(() => closeDetail())}>
            Close definition
          </button>
          <PythonDefinitionEditor
            app={app}
            catalog={catalog}
            kind="CalculatedMember"
            template={pythonDefinitionTemplates.CalculatedMember}
            onRefreshCatalog={onRefreshCatalog}
            onChanged={async (definition) => {
              const rows = await readList();
              const row = rows?.find(
                (row) => row.definitionId === definition?.definitionId,
              );
              if (row)
                await readExact({
                  definitionId: row.definitionId,
                  stateToken: row.stateToken,
                  digest: row.programDigest,
                });
            }}
          />
        </article>
      )}
      {detail && (
        <article
          id="calculated-member-inspector"
          className="program-inspector calculated-member-inspector"
          aria-label="Calculated member detail"
        >
          <p role="status">Calculated-member definition loaded.</p>
          <div className="section-heading-row">
            <h3 ref={detailHeading} tabIndex={-1}>
              {detail.definitionId}
            </h3>
            <button
              onClick={() => onRequestTransition(() => closeDetail(true))}
            >
              Close definition
            </button>
          </div>
          <p>
            {detail.status} · {detail.program.arguments.evaluation} ·{" "}
            {detail.definitionMetadataRevision ===
            detail.currentMetadataRevision
              ? "Current"
              : "Stale"}
          </p>
          {detail.source && app && catalog ? (
            <PythonDefinitionEditor
              key={`${detail.definitionId}:${detail.stateToken}`}
              app={app}
              catalog={catalog}
              kind="CalculatedMember"
              binding={detail.source}
              definitionId={detail.definitionId}
              onRefreshCatalog={onRefreshCatalog}
              onChanged={async (definition) => {
                const rows = await readList();
                const row = rows?.find(
                  (row) =>
                    row.definitionId ===
                    (definition?.definitionId ?? detail.definitionId),
                );
                if (row)
                  await readExact({
                    definitionId: row.definitionId,
                    stateToken: row.stateToken,
                    digest: row.programDigest,
                  });
              }}
            />
          ) : (
            <p>This calculation has no bound Python source.</p>
          )}
          <dl className="calculated-member-facts">
            <div>
              <dt>Target</dt>
              <dd>
                <code>
                  {detail.program.arguments.target.dimensionId}:
                  {detail.program.arguments.target.memberId}
                </code>
              </dd>
            </div>
            <div>
              <dt>Result unit</dt>
              <dd>{detail.program.arguments.resultUnit}</dd>
            </div>
            <div>
              <dt>Evaluation</dt>
              <dd>
                {detail.program.arguments.evaluation === "dynamic"
                  ? "Calculated when requested"
                  : "Stored calculation result"}
              </dd>
            </div>
          </dl>
          <h4>Dependencies</h4>
          {detail.program.arguments.dependencies.length ? (
            <ul>
              {detail.program.arguments.dependencies.map((dependency) => (
                <li key={dependency.definitionId}>{dependency.definitionId}</li>
              ))}
            </ul>
          ) : (
            <p>No calculated-member dependencies.</p>
          )}
          <h4>Calculation status</h4>
          {!catalog?.functions["calculation.status.read"] ? (
            <p>Status inspection is not available to your current client.</p>
          ) : calculationStatus?.rows.length ? (
            <div className="react-grid-scroll">
              <table
                className="react-cube-grid"
                aria-label="Calculation status"
              >
                <thead>
                  <tr>
                    <th>Scope</th>
                    <th>Freshness</th>
                    <th>Reason</th>
                    <th>Presence</th>
                    <th>Impact</th>
                  </tr>
                </thead>
                <tbody>
                  {calculationStatus.rows.map((row) => (
                    <tr
                      key={`${row.bindingDigest}:${row.stage}:${row.partitionKey}`}
                    >
                      <th>
                        {row.stage} / {row.partitionKey}
                      </th>
                      <td>
                        {row.freshness} · {row.coverage}
                      </td>
                      <td>
                        {row.reasons.length ? row.reasons.join(", ") : "None"}
                      </td>
                      <td>{row.presence}</td>
                      <td>
                        <button
                          type="button"
                          onClick={() => void explainImpact(row.bindingDigest)}
                        >
                          Explain affected work
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p>No materialized calculation scope exists for this definition.</p>
          )}
          {calculationStatus?.impactBarrier.pending && (
            <p role="status">
              Impact processing is pending; currentness is conservative.
            </p>
          )}
          {impactExplanation && (
            <details open>
              <summary>Affected-work explanation</summary>
              <pre
                tabIndex={0}
                role="region"
                aria-label="Affected-work explanation"
              >
                {JSON.stringify(impactExplanation, null, 2)}
              </pre>
            </details>
          )}
          <details>
            <summary>Compiled calculation inspection</summary>
            <pre
              tabIndex={0}
              role="region"
              aria-label="Calculated-member expression"
            >
              {JSON.stringify(detail.program.arguments, null, 2)}
            </pre>
          </details>
          <p className="authority-note">
            This view shows the definition, current calculation scope and a
            bounded server explanation. Test and Run remain separate actions.
          </p>
        </article>
      )}
    </section>
  );
}
