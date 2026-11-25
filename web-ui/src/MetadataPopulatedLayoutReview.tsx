import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { ApiError, readProgram } from "./api";
import { canonicalProgramDigest } from "./canonical-program-digest";
import { validMetadataText } from "./MetadataCreate";
import type { ReviewedLayoutReplacement } from "./LayoutReplacementRequest";
import type { ApplicationCatalog, Scope } from "./types";

export const layoutSourceRead = "metadata.layout.populated.source.read";
export const layoutPreviewRead = "metadata.layout.populated.preview";
export const layoutDependencyReview = "metadata.layout.populated.review";
const maxPreviewBytes = 10_000_000;
const dependencyPageSize = 25;
const stableId = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;

type Pins = {
  metadataRevision: number;
  dataRevision: number;
  policyRevision: number;
  schemaEpoch?: number;
  sourceCommitRevision: number;
};
type Axis = { dimensionId: string; valueKind: "member" };
type Source = {
  format: "openepm-populated-layout-source-v1";
  complete: boolean;
  pins: Pins;
  sourceAxes: Axis[];
  coordinateCount: number;
  sourceCoordinates: {
    sourceCoordinateId: number;
    sourceMembers: Record<string, string>;
  }[];
};
export type LayoutDimensionDraft = {
  dimensionId: string;
  name: string;
  shortDescription: string;
  detailedDescription: string;
};
export type LayoutMemberDraft = { memberId: string; name: string };
type Preview = {
  format: "openepm-populated-layout-preview-v2";
  pins: Pins;
  planDigest: string;
  previewDigest: string;
  impact: {
    coordinates: number;
    facts: { numericCells: number; textCells: number; detailLines: number };
    hierarchies: number;
    rules: number;
    publications: {
      calculations: number;
      eliminations: number;
      pythonPrograms: number;
    };
  };
};
type Dependency = {
  kind: "rule" | "publication";
  id: string;
  stateToken: string;
  contentDigest: string;
};
type Decision = "Invalidate" | "Rebuild";
type DependencyReview = {
  preview: Preview;
  dependencies: Dependency[];
  dependencyDigest: string;
};
function dependencyKey(dependency: Dependency) {
  return JSON.stringify([dependency.kind, dependency.id]);
}

const layoutDigest = (value: unknown) => canonicalProgramDigest(value, true);

function samePins(actual: Pins, expected: Pins) {
  return (
    actual.metadataRevision === expected.metadataRevision &&
    actual.dataRevision === expected.dataRevision &&
    actual.policyRevision === expected.policyRevision &&
    actual.schemaEpoch === expected.schemaEpoch &&
    actual.sourceCommitRevision === expected.sourceCommitRevision
  );
}

function layoutError(reason: unknown, fallback: string) {
  if (reason instanceof ApiError) {
    if (reason.kind === "conflict" || /STALE|CHANGED_DURING/.test(reason.code))
      return "The model changed. Refresh the current layout and review the mapping again.";
    return `${fallback} (${reason.code}).`;
  }
  return reason instanceof Error ? reason.message : fallback;
}

export function useLayoutSource(
  app: Scope | undefined,
  catalog: ApplicationCatalog | null,
  active: boolean,
) {
  const workspaceId = app?.workspaceId;
  const applicationId = app?.applicationId;
  const available = Boolean(catalog?.functions[layoutSourceRead]);
  const { revisions, applicationAccess } = catalog ?? {};
  const context = JSON.stringify([
    workspaceId,
    applicationId,
    revisions,
    applicationAccess,
  ]);
  const [revision, setRevision] = useState(0);
  const [read, setRead] = useState<{
    context: string;
    revision: number;
    source?: Source;
    error?: string;
  }>();
  const current =
    active &&
    available &&
    read?.context === context &&
    read.revision === revision
      ? read
      : undefined;
  useEffect(() => {
    setRead(undefined);
    if (!active || !available || !workspaceId || !applicationId || !revisions)
      return;
    const controller = new AbortController();
    const signal = controller.signal;
    const scope = { workspaceId, applicationId };
    const expected = {
      metadataRevision: revisions.metadata,
      dataRevision: revisions.data,
      policyRevision: revisions.policy,
      schemaEpoch: revisions.schemaEpoch,
      sourceCommitRevision: revisions.commit,
    };
    void readProgram<Source>(scope, layoutSourceRead, {}, signal)
      .then((source) => {
        if (
          source.format !== "openepm-populated-layout-source-v1" ||
          source.complete !== true ||
          !source.sourceAxes.length ||
          source.sourceCoordinates.length !== source.coordinateCount
        )
          throw new Error("The server did not return a complete layout.");
        if (!samePins(source.pins, expected))
          throw new Error(
            "The layout changed. Refresh it before reviewing the dimension.",
          );
        if (!signal.aborted) setRead({ context, revision, source });
      })
      .catch((reason: unknown) => {
        if (!signal.aborted)
          setRead({
            context,
            revision,
            error: layoutError(reason, "Could not inspect the current layout"),
          });
      });
    return () => controller.abort();
  }, [
    active,
    applicationId,
    available,
    context,
    revision,
    revisions,
    workspaceId,
  ]);
  return {
    source: current?.source,
    error: current?.error,
    checking: active && available && !current,
    refresh: () => setRevision((value) => value + 1),
  };
}

export function MetadataPopulatedLayoutReview({
  app,
  source,
  dimension,
  member,
  onMemberChange,
  canPreview,
  canReviewDependencies,
  onRequestReplacement,
}: {
  app: Scope;
  source: Source;
  dimension: LayoutDimensionDraft;
  member: LayoutMemberDraft;
  onMemberChange: (member: LayoutMemberDraft) => void;
  canPreview: boolean;
  canReviewDependencies: boolean;
  onRequestReplacement?: (intent: ReviewedLayoutReplacement) => void;
}) {
  const controller = useRef<AbortController | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [review, setReview] = useState<{
    preview: Preview;
    plan: Record<string, unknown>;
    inventory?: DependencyReview;
  }>();
  const [decisions, setDecisions] = useState<Partial<Record<string, Decision>>>(
    {},
  );
  const [dependencyPage, setDependencyPage] = useState(0);
  const decisionControlId = useId();
  const mappingContext = JSON.stringify([
    app.workspaceId,
    app.applicationId,
    dimension,
    member,
    canPreview,
    canReviewDependencies,
  ]);
  useLayoutEffect(() => {
    setReview(undefined);
    setDecisions({});
    setDependencyPage(0);
    setError("");
    setBusy(false);
    return () => controller.current?.abort();
  }, [mappingContext, source]);

  const count = source.coordinateCount.toLocaleString();
  const coordinates =
    source.coordinateCount === 1 ? "coordinate" : "coordinates";
  const valid =
    canPreview &&
    stableId.test(dimension.dimensionId) &&
    stableId.test(member.memberId) &&
    validMetadataText(member.name);

  async function reviewMapping() {
    if (busy || !valid) return;
    controller.current?.abort();
    const next = new AbortController();
    controller.current = next;
    const signal = next.signal;
    setBusy(true);
    setError("");
    setReview(undefined);
    setDecisions({});
    setDependencyPage(0);
    const functionName = canReviewDependencies
      ? layoutDependencyReview
      : layoutPreviewRead;
    const targetAxes = [
      ...source.sourceAxes,
      { dimensionId: dimension.dimensionId, valueKind: "member" },
    ];
    const axisMapping = Object.fromEntries(
      source.sourceAxes.map(({ dimensionId }) => [dimensionId, dimensionId]),
    );
    const coordinateMappings = source.sourceCoordinates.map((row) => ({
      ...row,
      targetMembers: {
        ...row.sourceMembers,
        [dimension.dimensionId]: member.memberId,
      },
    }));
    const targetMetadata = {
      dimension: {
        ...dimension,
        modelRole: "Custom",
        members: [{ ...member, shortDescription: "", detailedDescription: "" }],
      },
    };
    const args = {
      expectedPins: source.pins,
      targetAxes,
      axisMapping,
      coordinateMappings,
      targetMetadata,
    };
    try {
      const bytes = new TextEncoder().encode(
        JSON.stringify({
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          program: {
            languageVersion: 2,
            function: functionName,
            arguments: args,
          },
        }),
      ).length;
      if (bytes > maxPreviewBytes)
        throw new Error(
          "This mapping exceeds the browser preview limit. Use the layout preview capability in your MCP client.",
        );
      let inventory: DependencyReview | undefined;
      let preview: Preview;
      if (canReviewDependencies) {
        inventory = await readProgram<DependencyReview>(
          app,
          functionName,
          args,
          signal,
        );
        if (
          !inventory?.preview ||
          !Array.isArray(inventory.dependencies) ||
          !/^[0-9a-f]{64}$/.test(inventory.dependencyDigest) ||
          inventory.dependencies.some(
            (row) =>
              !row ||
              !["rule", "publication"].includes(row.kind) ||
              typeof row.id !== "string" ||
              !row.id ||
              !/^[0-9a-f]{64}$/.test(row.stateToken) ||
              !/^[0-9a-f]{64}$/.test(row.contentDigest),
          ) ||
          new Set(inventory.dependencies.map(dependencyKey)).size !==
            inventory.dependencies.length
        )
          throw new Error(
            "The server did not return a complete dependency review.",
          );
        preview = inventory.preview;
      } else {
        preview = await readProgram<Preview>(app, functionName, args, signal);
      }
      const plan = {
        format: "openepm-populated-layout-plan-v2",
        pins: source.pins,
        sourceAxes: source.sourceAxes,
        targetAxes,
        axisMapping,
        coordinateMappings,
        targetMetadata,
        sourceCoordinateCount: source.coordinateCount,
        targetCoordinateCount: source.coordinateCount,
      };
      const { previewDigest, ...previewContent } = preview;
      const [planHash, previewHash] = await Promise.all([
        layoutDigest(plan),
        layoutDigest(previewContent),
      ]);
      if (
        preview.format !== "openepm-populated-layout-preview-v2" ||
        !samePins(preview.pins, source.pins) ||
        preview.impact.coordinates !== source.coordinateCount ||
        preview.planDigest !== planHash ||
        previewDigest !== previewHash
      )
        throw new Error(
          "The server preview does not match this layout and mapping.",
        );
      if (!signal.aborted) setReview({ preview, plan, inventory });
    } catch (reason) {
      if (!signal.aborted)
        setError(
          layoutError(reason, "Could not preview the proposed dimension"),
        );
    } finally {
      if (!signal.aborted) setBusy(false);
    }
  }

  function reviewedReplacement(): ReviewedLayoutReplacement | null {
    if (!review?.inventory || !valid || busy) return null;
    const dependencyDecisions: ReviewedLayoutReplacement["dependencyDecisions"] =
      [];
    for (const row of review.inventory.dependencies) {
      const decision = decisions[dependencyKey(row)];
      if (!decision) return null;
      dependencyDecisions.push({ kind: row.kind, id: row.id, decision });
    }
    return {
      dimensionName: dimension.name,
      plan: review.plan,
      preview: review.preview,
      dependencyDecisions,
      expectedDependencyDigest: review.inventory.dependencyDigest,
    };
  }

  function downloadReview() {
    if (!review || !valid || busy || remainingDecisions > 0) return;
    const { workspaceId, applicationId } = app;
    const { preview, plan, inventory } = review;
    const replacement = reviewedReplacement();
    const reviewedDependencies =
      inventory && replacement
        ? {
            dependencies: inventory.dependencies,
            expectedDependencyDigest: replacement.expectedDependencyDigest,
            dependencyDecisions: replacement.dependencyDecisions,
          }
        : {};
    const url = URL.createObjectURL(
      new Blob(
        [
          JSON.stringify({
            workspaceId,
            applicationId,
            preview,
            plan,
            ...reviewedDependencies,
          }),
        ],
        {
          type: "application/json",
        },
      ),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `layout-review-${dimension.dimensionId.replaceAll(":", "-")}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const impact = review?.preview.impact;
  const dependencies = review?.inventory?.dependencies;
  const remainingDecisions =
    dependencies?.filter((row) => !decisions[dependencyKey(row)]).length ?? 0;
  const windowStart = dependencyPage * dependencyPageSize;
  return (
    <section
      className="metadata-layout-review"
      aria-label="Populated layout review"
    >
      <h3>Map existing data to the new dimension</h3>
      <p>
        Current grain{" "}
        {source.sourceAxes.map((axis) => axis.dimensionId).join(" × ")}
      </p>
      <p>
        The preview preserves each existing coordinate and adds the member you
        choose below. For different mappings across coordinates, use your MCP
        client.
      </p>
      <div className="metadata-dimension-draft-name">
        <label>
          Existing data member ID
          <input
            value={member.memberId}
            maxLength={200}
            onChange={(event) =>
              onMemberChange({ ...member, memberId: event.target.value })
            }
          />
        </label>
        <label>
          Existing data member name
          <input
            value={member.name}
            maxLength={200}
            onChange={(event) =>
              onMemberChange({ ...member, name: event.target.value })
            }
          />
        </label>
      </div>
      <button
        type="button"
        disabled={!valid || busy}
        onClick={() => void reviewMapping()}
      >
        {busy
          ? "Checking layout impact…"
          : `Preview mapping ${count} ${coordinates}`}
      </button>
      {error && (
        <p className="inline-error" role="alert">
          {error}
        </p>
      )}
      {impact && (
        <div className="metadata-layout-impact">
          <h4>
            Proposed grain{" "}
            {source.sourceAxes.map((axis) => axis.dimensionId).join(" × ")} ×{" "}
            {dimension.dimensionId}
          </h4>
          <p>
            {count} {coordinates} would gain {member.name} ({member.memberId}
            ).
          </p>
          <ul>
            <li>{impact.facts.numericCells.toLocaleString()} numeric cells</li>
            <li>{impact.facts.textCells.toLocaleString()} text cells</li>
            <li>{impact.facts.detailLines.toLocaleString()} detail lines</li>
            <li>{impact.hierarchies.toLocaleString()} hierarchies</li>
            <li>{impact.rules.toLocaleString()} active expression rules</li>
            <li>
              {impact.publications.calculations.toLocaleString()} calculation
              publications
            </li>
            <li>
              {impact.publications.eliminations.toLocaleString()} elimination
              publications
            </li>
            <li>
              {impact.publications.pythonPrograms.toLocaleString()} active
              Python programs
            </li>
          </ul>
          {dependencies ? (
            <section aria-label="Layout dependency decisions">
              <h4>Dependency decisions</h4>
              {dependencies.length === 0 ? (
                <p>No rules or calculation publications require a decision.</p>
              ) : (
                <>
                  <p role="status">
                    {remainingDecisions} of {dependencies.length} dependencies
                    still need a decision.
                  </p>
                  <p>
                    Rebuilding requires a separate operation after activation.
                  </p>
                  <button
                    type="button"
                    onClick={() =>
                      setDecisions(
                        Object.fromEntries(
                          dependencies.map((row) => [
                            dependencyKey(row),
                            "Invalidate",
                          ]),
                        ),
                      )
                    }
                  >
                    Set all to Invalidate
                  </button>
                  <ul>
                    {dependencies
                      .slice(windowStart, windowStart + dependencyPageSize)
                      .map((row, index) => {
                        const key = dependencyKey(row);
                        const id = `${decisionControlId}-${windowStart + index}`;
                        return (
                          <li key={key}>
                            <label htmlFor={id}>
                              {row.kind === "rule"
                                ? "Rule"
                                : "Calculation publication"}{" "}
                              {row.id}
                            </label>
                            <select
                              id={id}
                              value={decisions[key] ?? ""}
                              onChange={(event) => {
                                const { value } = event.target;
                                const decision =
                                  value === "Rebuild" || value === "Invalidate"
                                    ? value
                                    : undefined;
                                setDecisions((previous) => ({
                                  ...previous,
                                  [key]: decision,
                                }));
                              }}
                            >
                              <option value="">Choose a decision</option>
                              <option value="Invalidate">Invalidate</option>
                              <option value="Rebuild">Rebuild</option>
                            </select>
                          </li>
                        );
                      })}
                  </ul>
                  {dependencies.length > dependencyPageSize && (
                    <div>
                      <button
                        type="button"
                        disabled={dependencyPage === 0}
                        onClick={() => setDependencyPage(dependencyPage - 1)}
                      >
                        Previous dependencies
                      </button>
                      <span>
                        {windowStart + 1}–
                        {Math.min(
                          windowStart + dependencyPageSize,
                          dependencies.length,
                        )}{" "}
                        of {dependencies.length}
                      </span>
                      <button
                        type="button"
                        disabled={
                          windowStart + dependencyPageSize >=
                          dependencies.length
                        }
                        onClick={() => setDependencyPage(dependencyPage + 1)}
                      >
                        Next dependencies
                      </button>
                    </div>
                  )}
                </>
              )}
            </section>
          ) : (
            <p>
              Review dependency decisions in your MCP client before submitting a
              replacement request.
            </p>
          )}
          <button
            type="button"
            disabled={remainingDecisions > 0}
            onClick={downloadReview}
          >
            Download reviewed mapping
          </button>
          {dependencies && onRequestReplacement && (
            <button
              type="button"
              disabled={remainingDecisions > 0 || !valid || busy}
              onClick={() => {
                const intent = reviewedReplacement();
                if (intent) onRequestReplacement(intent);
              }}
            >
              Request private replacement
            </button>
          )}
        </div>
      )}
    </section>
  );
}
