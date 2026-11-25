import { useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { ApiError, readProgram } from "./api";
import type { MetadataDimension } from "./metadata-data";
import { MemberSelectionDialog } from "./member-selection/MemberSelectionDialog";
import type { ScenarioCopySource } from "./ScenarioPromotion";
import type { ApplicationCatalog, ApplicationSummary } from "./types";

export const SCENARIO_COMPARISON = "facts.cube.scenario.compare.read";

export type ComparisonUnit =
  | "amount"
  | { type: "Ratio"; scale: 12 }
  | { type: "Currency"; dimensionId: string; memberId: string };
type PublishedComparison = {
  resultKey: string;
  resultStateToken: string;
  unit: ComparisonUnit;
};

export function isComparisonUnit(value: unknown): value is ComparisonUnit {
  if (value === "amount") return true;
  if (typeof value !== "object" || !value || !("type" in value)) return false;
  if (value.type === "Ratio")
    return (
      "scale" in value && value.scale === 12 && Object.keys(value).length === 2
    );
  return (
    value.type === "Currency" &&
    "dimensionId" in value &&
    typeof value.dimensionId === "string" &&
    Boolean(value.dimensionId) &&
    "memberId" in value &&
    typeof value.memberId === "string" &&
    Boolean(value.memberId) &&
    Object.keys(value).length === 3
  );
}

const unitKey = (unit: ComparisonUnit) =>
  JSON.stringify(
    typeof unit === "string"
      ? unit
      : unit.type === "Ratio"
        ? [unit.type, unit.scale]
        : [unit.type, unit.dimensionId, unit.memberId],
  );
const unitLabel = (unit: ComparisonUnit) =>
  typeof unit === "string"
    ? "Amount"
    : unit.type === "Ratio"
      ? "Ratio"
      : `${unit.memberId} (${unit.dimensionId})`;

type Observation =
  | { kind: "numeric" | "text"; value: string; lastRevision?: number }
  | { kind: "missing"; value: null; lastRevision?: null };
type Comparison = {
  members: Record<string, string>;
  baseline: Observation;
  alternative: Observation;
  status:
    | "numeric"
    | "missing_input"
    | "different_types"
    | "text_equal"
    | "text_changed";
  difference: string | null;
};
type ComparisonResult = {
  scenarioDimensionId: string;
  baselineMemberId: string;
  alternativeMemberId: string;
  layer: "raw" | "calculated";
  calculation?: PublishedComparison;
  complete: boolean;
  snapshot: {
    metadataRevision: number;
    securityRevision: number;
    policyRevision: number;
    dataRevision: number;
    commitRevision: number;
  };
  comparisons: Comparison[];
};

const canonicalMembers = (members: Record<string, string>) =>
  JSON.stringify(Object.entries(members).sort());
const exactAmount = /^-?[0-9]{1,20}\.[0-9]{8}$/;
const exactDifference = /^-?[0-9]{1,21}\.[0-9]{8}$/;
const exactRatio = /^-?[0-9]{1,8}\.[0-9]{12}$/;
const exactRatioDifference = /^-?[0-9]{1,9}\.[0-9]{12}$/;
const revision = (value: number) => Number.isSafeInteger(value) && value >= 0;

function validObservation(
  value: Observation,
  commit: number,
  calculation?: PublishedComparison,
) {
  if (!value) return false;
  if (calculation) {
    const decimal =
      typeof calculation.unit === "object" && calculation.unit.type === "Ratio"
        ? exactRatio
        : exactAmount;
    return (
      value.lastRevision === undefined &&
      (value.kind === "missing"
        ? value.value === null
        : value.kind === "numeric" &&
          typeof value.value === "string" &&
          decimal.test(value.value))
    );
  }
  if (value.kind === "missing")
    return value.value === null && value.lastRevision === null;
  return (
    typeof value.value === "string" &&
    (value.kind === "text" ||
      (value.kind === "numeric" && exactAmount.test(value.value))) &&
    typeof value.lastRevision === "number" &&
    revision(value.lastRevision) &&
    value.lastRevision <= commit
  );
}

function confirmedComparison(
  result: ComparisonResult,
  context: {
    axis: string;
    baseline: string;
    alternative: string;
    members: Record<string, string>;
    revisions: ApplicationCatalog["revisions"];
    calculation?: PublishedComparison;
  },
) {
  const snapshot = result?.snapshot;
  const pair = result?.comparisons?.[0];
  const calculation = context.calculation;
  const published = result?.calculation;
  const boundSource = calculation
    ? result?.layer === "calculated" &&
      published?.resultKey === calculation.resultKey &&
      published.resultStateToken === calculation.resultStateToken &&
      isComparisonUnit(published.unit) &&
      unitKey(published.unit) === unitKey(calculation.unit)
    : result?.layer === "raw" && published === undefined;
  if (
    result?.complete !== true ||
    !boundSource ||
    result.scenarioDimensionId !== context.axis ||
    result.baselineMemberId !== context.baseline ||
    result.alternativeMemberId !== context.alternative ||
    !snapshot ||
    snapshot.metadataRevision !== context.revisions.metadata ||
    snapshot.securityRevision !== context.revisions.security ||
    snapshot.policyRevision !== context.revisions.policy ||
    !revision(snapshot.dataRevision) ||
    snapshot.dataRevision < context.revisions.data ||
    !revision(snapshot.commitRevision) ||
    snapshot.commitRevision < context.revisions.commit ||
    !Array.isArray(result.comparisons) ||
    result.comparisons.length !== 1 ||
    !pair?.members ||
    canonicalMembers(pair.members) !== canonicalMembers(context.members) ||
    !validObservation(pair.baseline, snapshot.commitRevision, calculation) ||
    !validObservation(pair.alternative, snapshot.commitRevision, calculation)
  )
    throw new Error(
      "The comparison did not match the requested scenarios and current application context.",
    );
  const { baseline, alternative, status, difference } = pair;
  const decimal =
    typeof calculation?.unit === "object" && calculation.unit.type === "Ratio"
      ? exactRatioDifference
      : exactDifference;
  const expected =
    baseline.kind === "missing" || alternative.kind === "missing"
      ? "missing_input"
      : baseline.kind !== alternative.kind
        ? "different_types"
        : baseline.kind === "numeric"
          ? "numeric"
          : baseline.value === alternative.value
            ? "text_equal"
            : "text_changed";
  if (
    status !== expected ||
    (status === "numeric"
      ? typeof difference !== "string" || !decimal.test(difference)
      : difference !== null)
  )
    throw new Error("The scenario comparison could not be verified.");
  return pair;
}

function observationText(value: Observation) {
  if (value.kind === "missing") return "Missing";
  return value.kind === "text" && value.value === ""
    ? "Empty text"
    : value.value;
}

/** Aligned current observations for the selected Grid coordinate. */
export function ScenarioComparison({
  app,
  catalog,
  axis,
  coordinate,
  baselineName,
  dialogHost,
  published,
  onGridAuthorityFailure,
  onStalePublication,
  offerCopySource,
}: {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
  axis: MetadataDimension;
  coordinate: Record<string, string>;
  baselineName?: string;
  dialogHost: HTMLElement;
  published?: Omit<PublishedComparison, "unit"> & { units: ComparisonUnit[] };
  onGridAuthorityFailure?: (reason: unknown) => boolean;
  onStalePublication?: (message: string) => void;
  offerCopySource?: (source: ScenarioCopySource) => boolean;
}) {
  const baseline = coordinate[axis.dimension_id];
  const [alternative, setAlternative] = useState("");
  const target = alternative.trim();
  const [unitChoice, setUnitChoice] = useState("");
  const unit =
    published?.units.length === 1
      ? published.units[0]
      : published?.units.find((candidate) => unitKey(candidate) === unitChoice);
  const calculation =
    published && unit !== undefined
      ? {
          resultKey: published.resultKey,
          resultStateToken: published.resultStateToken,
          unit,
        }
      : undefined;
  const canBrowse = Boolean(catalog.functions["metadata.member.select"]);
  const [picker, setPicker] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ReturnType<
    typeof confirmedComparison
  > | null>(null);
  const active = useRef<AbortController | null>(null);
  useLayoutEffect(() => () => active.current?.abort(), []);

  function chooseAlternative(member: string) {
    setAlternative(member);
    setResult(null);
    setError("");
  }
  async function compare() {
    if (
      active.current ||
      !target ||
      target === baseline ||
      (published && !calculation)
    )
      return;
    const abort = new AbortController();
    active.current = abort;
    const aligned = Object.fromEntries(
      Object.entries(coordinate).filter(
        ([dimension]) => dimension !== axis.dimension_id,
      ),
    );
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const response = await readProgram<ComparisonResult>(
        app,
        SCENARIO_COMPARISON,
        {
          baselineMemberId: baseline,
          alternativeMemberId: target,
          expectedMetadataRevision: catalog.revisions.metadata,
          coordinates: [aligned],
          ...(calculation ? { calculation } : {}),
        },
        abort.signal,
      );
      if (!abort.signal.aborted)
        setResult(
          confirmedComparison(response, {
            axis: axis.dimension_id,
            baseline,
            alternative: target,
            members: aligned,
            revisions: catalog.revisions,
            calculation,
          }),
        );
    } catch (reason) {
      if (abort.signal.aborted || onGridAuthorityFailure?.(reason)) return;
      if (
        reason instanceof ApiError &&
        [
          "CALCULATION_REQUIRED",
          "CALCULATION_RESULT_STATE_CHANGED_RESTART",
        ].includes(reason.code)
      ) {
        const message =
          "The published calculation changed or is out of date. Read Grid again before comparing.";
        if (calculation && onStalePublication) onStalePublication(message);
        else setError(message);
        return;
      }
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to compare these scenarios.",
      );
    } finally {
      if (active.current === abort) {
        active.current = null;
        if (!abort.signal.aborted) setBusy(false);
      }
    }
  }

  return (
    <details
      className="cell-details"
      onToggle={(event) => {
        if (!event.currentTarget.open) {
          active.current?.abort();
          active.current = null;
          setBusy(false);
          setPicker(false);
          setResult(null);
          setError("");
        }
      }}
    >
      <summary>Compare scenarios</summary>
      <p>
        {published
          ? "Compare published values at this coordinate. Both scenarios use the same output unit."
          : "Compare stored inputs at this coordinate. Time, unit and all other fact members stay the same."}
      </p>
      {published && published.units.length > 1 ? (
        <label>
          Output unit
          <select
            disabled={busy}
            value={unitChoice}
            onChange={(event) => {
              setUnitChoice(event.target.value);
              setResult(null);
              setError("");
            }}
          >
            <option value="">Choose one unit</option>
            {published.units.map((candidate) => (
              <option key={unitKey(candidate)} value={unitKey(candidate)}>
                {unitLabel(candidate)}
              </option>
            ))}
          </select>
        </label>
      ) : unit !== undefined ? (
        <p>Output unit is {unitLabel(unit)}.</p>
      ) : null}
      <p>
        Baseline:{" "}
        {baselineName && baselineName !== baseline
          ? `${baselineName} (${baseline})`
          : baseline}
      </p>
      <label>
        Alternative scenario ID
        <input
          disabled={busy}
          value={alternative}
          onChange={(event) => chooseAlternative(event.target.value)}
        />
      </label>
      {canBrowse && (
        <button type="button" disabled={busy} onClick={() => setPicker(true)}>
          Choose alternative scenario
        </button>
      )}
      <button
        type="button"
        aria-disabled={
          busy ||
          !target ||
          target === baseline ||
          Boolean(published && !calculation) ||
          undefined
        }
        onClick={() => void compare()}
      >
        Read comparison
      </button>
      {target === baseline && <p>Choose a different alternative scenario.</p>}
      {busy && <p role="status">Reading both scenarios…</p>}
      {error && <p role="alert">{error}</p>}
      {result && (
        <section
          aria-label={
            published
              ? "Calculated scenario comparison"
              : "Stored scenario comparison"
          }
        >
          <p role="status">Scenarios read together.</p>
          <dl>
            <div>
              <dt>Baseline</dt>
              <dd>{observationText(result.baseline)}</dd>
            </div>
            <div>
              <dt>Alternative</dt>
              <dd>{observationText(result.alternative)}</dd>
            </div>
            <div>
              <dt>Alternative minus baseline</dt>
              <dd>
                {result.difference ??
                  (result.status === "missing_input"
                    ? published
                      ? "A value in the selected unit is missing"
                      : "A stored value is missing"
                    : result.status === "different_types"
                      ? "The value types differ"
                      : result.status === "text_equal"
                        ? "Text matches"
                        : "Text has changed")}
              </dd>
            </div>
          </dl>
          {!published &&
            result.alternative.kind !== "missing" &&
            offerCopySource && (
              <button
                type="button"
                onClick={() => {
                  if (
                    !offerCopySource({
                      dimensionId: axis.dimension_id,
                      sourceMemberId: target,
                      members: result.members,
                    })
                  )
                    setError(
                      "The current copy setup cannot use this comparison. Refresh the application context and compare again.",
                    );
                }}
              >
                Set up copy from alternative
              </button>
            )}
        </section>
      )}
      {picker &&
        canBrowse &&
        createPortal(
          <MemberSelectionDialog
            app={app}
            catalog={catalog}
            members={[]}
            request={{
              dimensionId: axis.dimension_id,
              dimensionName: axis.name,
              metadataRevision: catalog.revisions.metadata,
              title: "Choose alternative scenario",
              cardinality: { kind: "exactly-one" },
              initial: null,
              capability: {
                allowExplicitMembers: true,
                allowHierarchySelector: false,
                allowNamedMemberList: false,
                allowAttributeSelector: false,
                allowInlineExpression: false,
                allowExclusion: false,
                orderMatters: false,
              },
            }}
            onCancel={() => setPicker(false)}
            onApply={(selection) => {
              if (
                selection.dimensionId !== axis.dimension_id ||
                selection.metadataRevision !== catalog.revisions.metadata ||
                selection.exclude !== null ||
                selection.include.kind !== "member"
              )
                return;
              chooseAlternative(selection.include.memberId);
              setPicker(false);
            }}
          />,
          dialogHost,
        )}
    </details>
  );
}
