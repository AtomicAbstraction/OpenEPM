import { useEffect, useRef, useState } from "react";
import { PythonDefinitionEditor } from "./PythonDefinitionEditor";
import { pythonDefinitionTemplates } from "./python-definition-templates";
import { ApiError, readProgram } from "./api";
import {
  definitionAvailabilityLabel,
  isDefinitionLifecycle,
  isDefinitionSourceBinding,
} from "./definition-lifecycle";
import type {
  DefinitionLifecycle,
  DefinitionSourceBinding,
} from "./definition-lifecycle";
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

const OPAQUE_VALUE = /^(?:[0-9a-f]{32,}|oa1_[A-Za-z0-9_-]+)$/i;

export function readableCalculationLabel(value: string): string {
  if (!value || OPAQUE_VALUE.test(value)) return "Current calculation scope";
  const words = value
    .replace(/[_-]+/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .trim();
  return words ? words[0].toUpperCase() + words.slice(1) : "Current";
}

function impactCount(value: Record<string, unknown> | null, key: string) {
  const count = value?.[key];
  return nonNegativeInteger(count) ? count : null;
}

function impactWarnings(value: Record<string, unknown> | null): string[] {
  const cost = value?.cost;
  if (!object(cost) || !Array.isArray(cost.warnings)) return [];
  return cost.warnings
    .filter((item): item is string => typeof item === "string")
    .slice(0, 20)
    .map(readableCalculationLabel);
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

type CompiledSummary = {
  programDigest: string;
  evaluation: "dynamic" | "materialized";
  dependencies: Array<{ definitionId: string }>;
  target: { dimensionId: string; memberId: string };
  resultUnit: "amount" | "ratio";
};

type Summary = DefinitionLifecycle & {
  definitionId: string;
  stateToken: string;
  metadataCurrent: boolean;
  definitionMetadataRevision: number;
} & (
    | CompiledSummary
    | {
        programDigest: null;
        evaluation?: never;
        dependencies?: never;
        target?: never;
        resultUnit?: never;
      }
  );

type CompiledProgram = {
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

type Detail = DefinitionLifecycle & {
  source: DefinitionSourceBinding | null;
  definitionId: string;
  stateToken: string;
  definitionMetadataRevision: number;
  currentMetadataRevision: number;
  updatedAt: string;
  policyRevision: number;
} & (
    | { program: CompiledProgram; programDigest: string }
    | {
        program: null;
        programDigest: null;
      }
  );

type Target = {
  definitionId: string;
  stateToken: string;
  digest: string | null;
};

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
  if (!object(value) || !isDefinitionLifecycle(value)) return false;
  const item = value;
  if (
    !(
      typeof item.definitionId === "string" &&
      ID.test(item.definitionId) &&
      typeof item.stateToken === "string" &&
      DIGEST.test(item.stateToken) &&
      typeof item.metadataCurrent === "boolean" &&
      nonNegativeInteger(item.definitionMetadataRevision)
    )
  )
    return false;
  if (item.programDigest === null)
    return (
      !item.valid &&
      !item.executable &&
      (item.reason === "validation_required" ||
        item.reason === "ownership_unresolved") &&
      ["evaluation", "dependencies", "target", "resultUnit"].every(
        (field) => !Object.hasOwn(item, field),
      )
    );
  return (
    typeof item.programDigest === "string" &&
    DIGEST.test(item.programDigest) &&
    (item.evaluation === "dynamic" || item.evaluation === "materialized") &&
    exactDependencies(item.dependencies) &&
    exactTarget(item.target) &&
    (item.resultUnit === "amount" || item.resultUnit === "ratio")
  );
}

export function exactCalculatedMemberDetail(
  value: unknown,
  target: Target,
): Detail {
  if (!object(value) || !isDefinitionLifecycle(value))
    throw new Error("INVALID_CALCULATED_MEMBER_RESPONSE");
  const item = value;
  if (
    typeof item.definitionId !== "string" ||
    !ID.test(item.definitionId) ||
    typeof item.stateToken !== "string" ||
    !DIGEST.test(item.stateToken) ||
    item.definitionId !== target.definitionId ||
    item.stateToken !== target.stateToken ||
    item.programDigest !== target.digest ||
    !(
      item.source === null ||
      (isDefinitionSourceBinding(item.source) &&
        item.sourceCurrent &&
        item.source.active === item.active)
    ) ||
    !nonNegativeInteger(item.definitionMetadataRevision) ||
    !nonNegativeInteger(item.currentMetadataRevision) ||
    typeof item.updatedAt !== "string" ||
    !Number.isFinite(Date.parse(item.updatedAt)) ||
    !nonNegativeInteger(item.policyRevision)
  )
    throw new Error("INVALID_CALCULATED_MEMBER_RESPONSE");
  if (item.program === null) {
    if (
      item.programDigest !== null ||
      item.valid ||
      item.executable ||
      (item.reason !== "validation_required" &&
        item.reason !== "ownership_unresolved")
    )
      throw new Error("INVALID_CALCULATED_MEMBER_RESPONSE");
    return item as Detail;
  }
  const program = object(item.program) ? item.program : null;
  const args = program && object(program.arguments) ? program.arguments : null;
  if (
    typeof item.programDigest !== "string" ||
    !DIGEST.test(item.programDigest) ||
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
    Number(args.maxOutputCells) > 100_000
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
  const impactRequest = useRef<AbortController | null>(null);
  const detailHeading = useRef<HTMLHeadingElement | null>(null);
  const detailTrigger = useRef<HTMLButtonElement | null>(null);
  const inventoryHeading = useRef<HTMLHeadingElement | null>(null);
  const canRead = Boolean(catalog?.functions["calculated.member.read"]);
  const canList = Boolean(catalog?.functions["calculated.member.list"]);
  const scope = app
    ? { workspaceId: app.workspaceId, applicationId: app.applicationId }
    : null;
  const contextKey = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.applicationAccess,
    catalog?.revisions.metadata,
    catalog?.revisions.policy,
    catalog?.revisions.security,
    catalog?.revisions.schemaEpoch,
    Object.keys(catalog?.functions || {}).sort(),
  ]);
  const activeContext = useRef(contextKey);
  activeContext.current = contextKey;
  const [stateContext, setStateContext] = useState(contextKey);
  const isCurrent = (controller: AbortController) =>
    !controller.signal.aborted && activeContext.current === contextKey;

  async function readList() {
    if (!scope || !canList) return;
    listRequest.current?.abort();
    const controller = new AbortController();
    listRequest.current = controller;
    setListState("loading");
    setListError("");
    try {
      const values = await allCurrent(scope, controller.signal);
      if (!isCurrent(controller)) return;
      setRows(values);
      setListState("loaded");
      setPage(0);
      return values;
    } catch (reason) {
      if (!isCurrent(controller)) return;
      setRows([]);
      setListState("error");
      setListError(
        reason instanceof ApiError &&
          [
            "RULE_READ_AUTHORIZATION_STALE",
            "STALE_EXPRESSION_RULE_LIST_REVISION",
          ].includes(reason.code)
          ? "Calculated-member access or definitions changed. Choose Refresh calculated members to check again."
          : reason instanceof Error
            ? reason.message
            : "Unable to read calculated members.",
      );
    }
  }

  async function readExact(next: Target) {
    if (!scope || !canRead) return;
    detailRequest.current?.abort();
    impactRequest.current?.abort();
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
      if (isCurrent(controller)) {
        setDetail(exact);
        if (catalog?.functions["calculation.status.read"]) {
          const status = await readProgram<CalculationStatus>(
            scope,
            "calculation.status.read",
            {
              definitionId: next.definitionId,
              definitionStateToken: next.stateToken,
              limit: 500,
            },
            controller.signal,
          );
          if (isCurrent(controller)) setCalculationStatus(status);
        }
      }
    } catch (reason) {
      if (isCurrent(controller))
        setDetailError(
          reason instanceof Error
            ? reason.message
            : "Unable to read calculated member.",
        );
    } finally {
      if (isCurrent(controller)) setReadingTarget(null);
    }
  }

  function closeDetail(restoreFocus = false) {
    detailRequest.current?.abort();
    impactRequest.current?.abort();
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
    impactRequest.current?.abort();
    const controller = new AbortController();
    impactRequest.current = controller;
    setDetailError("");
    try {
      const explanation = await readProgram<Record<string, unknown>>(
        scope,
        "calculation.impact.explain",
        { bindingDigest, mode: "affected" },
        controller.signal,
      );
      if (isCurrent(controller)) setImpactExplanation(explanation);
    } catch (reason) {
      if (isCurrent(controller))
        setDetailError(
          reason instanceof Error
            ? reason.message
            : "Unable to explain impact.",
        );
    }
  }

  useEffect(() => {
    if (detail) detailHeading.current?.focus();
  }, [detail]);

  useEffect(() => {
    setStateContext(contextKey);
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
      impactRequest.current?.abort();
    };
  }, [contextKey, canRead, canList]);

  useEffect(() => {
    if (target) void readExact(target);
  }, [
    contextKey,
    target?.definitionId,
    target?.stateToken,
    target?.digest,
    canRead,
  ]);

  const filtered = rows.filter((row) =>
    `${row.definitionId} ${row.evaluation ?? ""} ${row.target?.dimensionId ?? ""} ${row.target?.memberId ?? ""}`
      .toLocaleLowerCase()
      .includes(query.trim().toLocaleLowerCase()),
  );
  const start = Math.min(
    page * 50,
    Math.max(0, Math.ceil(filtered.length / 50) - 1) * 50,
  );
  const visible = filtered.slice(start, start + 50);

  if (!scope)
    return (
      <p role="status">Select an application to inspect calculated members.</p>
    );
  if (!catalog)
    return <p role="status">Checking calculated-member availability…</p>;
  if (!canRead)
    return (
      <p role="status">
        Calculated-member inspection is not available in the current application
        context.
      </p>
    );
  if (stateContext !== contextKey)
    return <p role="status">Loading current calculated members…</p>;
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
          The calculated-member inventory is not available in the current
          application context.
        </p>
      )}
      {listState === "loaded" && rows.length > 0 && (
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
          >
            <table
              className="react-cube-grid"
              aria-label="Current calculated members"
            >
              <thead>
                <tr>
                  <th>Definition</th>
                  <th>State</th>
                  <th>Execution validity</th>
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
                    <td>{definitionAvailabilityLabel(row)}</td>
                    <td>{row.evaluation ?? "Compiled details unavailable"}</td>
                    <td>
                      {row.target
                        ? `${row.target.dimensionId} / ${row.target.memberId}`
                        : "Compiled details unavailable"}
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
            {detail.status} · {definitionAvailabilityLabel(detail)}
          </p>
          <p>
            {detail.definitionMetadataRevision ===
            detail.currentMetadataRevision
              ? "Metadata current"
              : "Metadata changed"}
            . Result freshness is inspected separately below.
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
          {detail.program ? (
            <>
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
                    <li key={dependency.definitionId}>
                      {dependency.definitionId}
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No calculated-member dependencies.</p>
              )}
            </>
          ) : (
            <p>
              Current compiled details are unavailable. Target, evaluation,
              result unit and dependencies cannot be inspected from this owner
              payload.
            </p>
          )}
          <h4>Calculation status</h4>
          {!catalog?.functions["calculation.status.read"] ? (
            <p>Status inspection is not available to your current client.</p>
          ) : calculationStatus === null ? (
            <p role="status">
              {readingTarget
                ? "Loading calculation status…"
                : "Calculation status has not been read successfully."}
            </p>
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
                      <th>{readableCalculationLabel(row.partitionKey)}</th>
                      <td>
                        {readableCalculationLabel(row.freshness)} ·{" "}
                        {readableCalculationLabel(row.coverage)}
                      </td>
                      <td>
                        {row.reasons.length
                          ? row.reasons.map(readableCalculationLabel).join(", ")
                          : "None"}
                      </td>
                      <td>{readableCalculationLabel(row.presence)}</td>
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
            <section
              className="calculation-impact-summary"
              aria-label="Affected-work explanation"
            >
              <h4>Affected-work explanation</h4>
              <p>
                {impactCount(impactExplanation, "affectedUnitCount") === 0
                  ? "No calculation work is currently affected."
                  : `${impactCount(impactExplanation, "affectedUnitCount") ?? "Some"} calculation ${impactCount(impactExplanation, "affectedUnitCount") === 1 ? "scope is" : "scopes are"} affected.`}
              </p>
              {impactWarnings(impactExplanation).length > 0 && (
                <ul>
                  {impactWarnings(impactExplanation).map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              )}
            </section>
          )}
          <p className="authority-note">
            This view shows the definition, current calculation scope and a
            bounded server explanation. Test and Run remain separate actions.
            Execution also requires current actor authority, environment,
            dependency and execution checks.
          </p>
        </article>
      )}
    </section>
  );
}
