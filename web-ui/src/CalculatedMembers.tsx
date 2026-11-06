import { useEffect, useRef, useState } from "react";
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
): value is Array<{ definitionId: string; version: number }> {
  if (!Array.isArray(value) || value.length > 100) return false;
  const seen = new Set<string>();
  for (const dependency of value) {
    if (
      !object(dependency) ||
      Object.keys(dependency).sort().join("\u0000") !==
        ["definitionId", "version"].sort().join("\u0000") ||
      typeof dependency.definitionId !== "string" ||
      !ID.test(dependency.definitionId) ||
      !positiveInteger(dependency.version)
    )
      return false;
    const key = `${dependency.definitionId}\u0000${dependency.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
  }
  return true;
}

type Summary = {
  definitionId: string;
  version: number;
  programDigest: string;
  evaluation: "dynamic" | "materialized";
  dependencies: Array<{ definitionId: string; version: number }>;
  metadataCurrent: boolean;
  definitionMetadataRevision: number;
  publishedRevision: number;
  target: Record<string, unknown>;
  resultUnit: string;
};

type Detail = {
  defined: boolean;
  definitionId: string;
  version: number;
  status: "Saved" | "Published" | null;
  program: {
    function: string;
    arguments: {
      evaluation: "dynamic" | "materialized";
      format: "openepm-calculated-member-v1";
      definitionId: string;
      version: number;
      name: string;
      sourceSelection: Record<string, unknown>;
      expression: unknown;
      dependencies: Array<{ definitionId: string; version: number }>;
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
  publishedRevision: number | null;
  createdRevision: number;
  createdAt: string;
  policyRevision: number;
  commitRevision: number;
};

type Target = { definitionId: string; version: number; digest: string };

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
    positiveInteger(item.version) &&
    typeof item.programDigest === "string" &&
    DIGEST.test(item.programDigest) &&
    (item.evaluation === "dynamic" || item.evaluation === "materialized") &&
    exactDependencies(item.dependencies) &&
    typeof item.metadataCurrent === "boolean" &&
    nonNegativeInteger(item.definitionMetadataRevision) &&
    positiveInteger(item.publishedRevision) &&
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
    item.version !== target.version ||
    item.programDigest !== target.digest ||
    program?.function !== "calculated.member.definition" ||
    !args ||
    Object.keys(args).sort().join("\u0000") !==
      [
        "format",
        "definitionId",
        "version",
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
    args.version !== target.version ||
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
    item.status !== "Published" ||
    !nonNegativeInteger(item.definitionMetadataRevision) ||
    !nonNegativeInteger(item.currentMetadataRevision) ||
    !positiveInteger(item.createdRevision) ||
    typeof item.createdAt !== "string" ||
    !Number.isFinite(Date.parse(item.createdAt)) ||
    !nonNegativeInteger(item.policyRevision) ||
    !nonNegativeInteger(item.commitRevision) ||
    !positiveInteger(item.publishedRevision)
  )
    throw new Error("INVALID_CALCULATED_MEMBER_RESPONSE");
  return item as Detail;
}

async function allPublished(scope: Scope): Promise<Summary[]> {
  const rows: Summary[] = [];
  let after: string | null = null;
  let metadata: number | undefined;
  let policy: number | undefined;
  const seen = new Set<string>();
  do {
    const page: Page = exactPage(
      await readProgram<unknown>(scope, "calculated.member.version.list", {
        limit: 100,
        ...(after
          ? {
              afterDefinitionId: after,
              expectedMetadataRevision: metadata,
              expectedPolicyRevision: policy,
            }
          : {}),
      }),
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
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  target?: Target;
}) {
  const [rows, setRows] = useState<Summary[]>([]);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState("");
  const readSequence = useRef(0);
  const authorized = Boolean(
    catalog?.functions["calculated.member.version.read"],
  );
  const scope = app
    ? { workspaceId: app.workspaceId, applicationId: app.applicationId }
    : null;

  async function readExact(next: Target) {
    if (!scope || !authorized) return;
    const sequence = ++readSequence.current;
    setError("");
    try {
      const value = await readProgram<unknown>(
        scope,
        "calculated.member.version.read",
        { definitionId: next.definitionId, version: next.version },
      );
      const exact = exactCalculatedMemberDetail(value, next);
      if (sequence === readSequence.current) setDetail(exact);
    } catch (reason) {
      if (sequence === readSequence.current) {
        setDetail(null);
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to read calculated member",
        );
      }
    }
  }

  useEffect(() => {
    if (target) void readExact(target);
  }, [
    app?.workspaceId,
    app?.applicationId,
    target?.definitionId,
    target?.version,
    target?.digest,
    authorized,
  ]);

  if (!authorized || !scope) {
    return target ? (
      <p className="inline-error" role="alert">
        Calculated-member inspection is not authorized.
      </p>
    ) : null;
  }
  return (
    <section
      className="panel capability-activity"
      aria-labelledby="calculated-member-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>IMMUTABLE CALCULATION DEFINITIONS</small>
          <h2 id="calculated-member-heading">Calculated members</h2>
        </div>
        <button
          onClick={() =>
            void allPublished(scope)
              .then(setRows)
              .catch((reason: Error) => setError(reason.message))
          }
        >
          Read published calculated members
        </button>
      </div>
      {error && (
        <p className="inline-error" role="alert">
          {error}
        </p>
      )}
      {rows.map((row) => (
        <button
          key={row.definitionId}
          onClick={() =>
            void readExact({
              definitionId: row.definitionId,
              version: row.version,
              digest: row.programDigest,
            })
          }
        >
          {row.definitionId} v{row.version} · {row.evaluation} ·{" "}
          {row.metadataCurrent ? "Current" : "Stale"}
        </button>
      ))}
      {detail && (
        <article
          className="program-inspector"
          aria-label="Calculated member detail"
        >
          <p role="status">Calculated-member definition loaded.</p>
          <h3>
            {detail.definitionId} v{detail.version}
          </h3>
          <p>
            {detail.status} · {detail.program.arguments.evaluation} ·{" "}
            {detail.definitionMetadataRevision ===
            detail.currentMetadataRevision
              ? "Current"
              : "Stale"}
          </p>
          <dl className="receipt-facts">
            <div>
              <dt>Program digest</dt>
              <dd>
                <code>{detail.programDigest}</code>
              </dd>
            </div>
            <div>
              <dt>Published revision</dt>
              <dd>{detail.publishedRevision ?? "Not published"}</dd>
            </div>
            <div>
              <dt>Result key</dt>
              <dd>
                {detail.program.arguments.resultKey ? (
                  <code>{detail.program.arguments.resultKey}</code>
                ) : (
                  "Not persisted"
                )}
              </dd>
            </div>
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
                  ? "Dynamic; no persisted result"
                  : "Materialized result key"}
              </dd>
            </div>
          </dl>
          <h4>Dependencies</h4>
          {detail.program.arguments.dependencies.length ? (
            <ul>
              {detail.program.arguments.dependencies.map((dependency) => (
                <li key={`${dependency.definitionId}:${dependency.version}`}>
                  {dependency.definitionId} v{dependency.version}
                </li>
              ))}
            </ul>
          ) : (
            <p>No calculated-member dependencies.</p>
          )}
          <h4>Expression</h4>
          <pre>
            {JSON.stringify(detail.program.arguments.expression, null, 2)}
          </pre>
          <p className="authority-note">
            The calculated-member read contract does not expose a
            materialization generation or linked operation receipt, so this
            inspector does not infer either.
          </p>
        </article>
      )}
    </section>
  );
}
