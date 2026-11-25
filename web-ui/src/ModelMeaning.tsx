import { useEffect, useRef, useState } from "react";
import { ApiError, readProgram } from "./api";
import {
  activeFactDimensions,
  type MetadataDimension,
  type MetadataMember,
} from "./metadata-data";
import { authorizedAuthoringContext } from "./python-authoring";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { WorkedMemberAttribute } from "./WorkedMemberAttribute";
import { WorkedCalendarPeriod } from "./WorkedCalendarPeriod";
import { MemberSelectionDialog } from "./member-selection/MemberSelectionDialog";

type Example = {
  context: string;
  members: Record<string, string>;
  meanings: Array<MetadataMember & { dimension: string }>;
  rows: Array<{ kind: string; amount?: string; text?: string }>;
};
type GrainCheck = {
  context: string;
  status: "ready" | "unavailable" | "failed";
};
type ContextRecheck = {
  context: string;
  message: string;
  pending: boolean;
  recorded?: boolean;
};
const staleContextCodes = new Set([
  "CALENDAR_AUTHORIZATION_STALE",
  "CUBE_READ_AUTHORIZATION_STALE",
  "METADATA_ATTRIBUTE_READ_AUTHORIZATION_STALE",
  "METADATA_DIRECTORY_READ_AUTHORIZATION_STALE",
  "METADATA_DIRECTORY_CURSOR_REQUIRED",
  "METADATA_DIRECTORY_CURSOR_STALE",
  "METADATA_CHANGED_DURING_READ",
  "STALE_CALENDAR_CHANGE_ID",
  "STALE_CALENDAR_METADATA_REVISION",
  "STALE_METADATA_REVISION",
]);
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
export function workedCoordinateRows(
  value: unknown,
  coordinate: Record<string, string>,
  catalog: ApplicationCatalog,
  metadataRevision: number,
): Example["rows"] {
  const fail = () => {
    throw new Error(
      "The worked-coordinate evidence is incomplete or does not match the requested stored input. Refresh and read again.",
    );
  };
  if (
    !object(value) ||
    value.format !== "openepm-cube-view-read-v1" ||
    value.complete !== true ||
    !object(value.dataSource) ||
    value.dataSource.kind !== "raw" ||
    value.dataSource.resultKey !== null ||
    !object(value.readPolicy) ||
    value.readPolicy.semantics !== "stored" ||
    Object.keys(value.readPolicy).length !== 1 ||
    !object(value.snapshot) ||
    !object(value.presentation) ||
    !Array.isArray(value.rows) ||
    value.rows.length > 1 ||
    value.presentation.rowCount !== value.rows.length ||
    value.snapshot.metadataRevision !== metadataRevision ||
    value.snapshot.securityRevision !== catalog.revisions.security ||
    value.snapshot.policyRevision !== catalog.revisions.policy
  )
    return fail();
  for (const [field, minimum] of [
    ["dataRevision", catalog.revisions.data],
    ["commitRevision", catalog.revisions.commit],
  ] as const)
    if (
      !Number.isSafeInteger(value.snapshot[field]) ||
      Number(value.snapshot[field]) < minimum
    )
      return fail();
  const result: Example["rows"] = [];
  for (const row of value.rows) {
    if (
      !object(row) ||
      !object(row.members) ||
      JSON.stringify(Object.entries(row.members).sort()) !==
        JSON.stringify(Object.entries(coordinate).sort()) ||
      !object(row.values) ||
      Object.keys(row.values).length !== 1 ||
      !Array.isArray(row.values.raw) ||
      row.values.raw.length < 1 ||
      row.values.raw.length > 2
    )
      return fail();
    const units = new Set<unknown>();
    for (const item of row.values.raw) {
      if (
        !object(item) ||
        typeof item.present !== "boolean" ||
        item.origin !== "input" ||
        item.currentness !== "current" ||
        item.resultStateToken !== null ||
        units.has(item.unit)
      )
        return fail();
      units.add(item.unit);
      if (!item.present) {
        if (
          item.value !== null ||
          item.unit !== null ||
          row.values.raw.length !== 1
        )
          return fail();
      } else if (
        item.unit === "amount" &&
        typeof item.value === "string" &&
        /^-?\d{1,20}\.\d{8}$/.test(item.value)
      ) {
        result.push({ kind: "amount", amount: item.value });
      } else if (item.unit === "text" && typeof item.value === "string") {
        result.push({ kind: "text", text: item.value });
      } else return fail();
    }
  }
  return result;
}

/** A read-only projection of accepted metadata; worksheet guidance is not saved policy. */
export function ModelMeaning({
  app,
  catalog,
  dimensions,
  metadataRevision,
  onRefreshCatalog,
}: {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
  dimensions: MetadataDimension[];
  metadataRevision: number;
  onRefreshCatalog?: (signal?: AbortSignal) => Promise<ApplicationCatalog>;
}) {
  const [open, setOpen] = useState(false);
  const [checkedGrain, setCheckedGrain] = useState<GrainCheck | null>(null);
  const [members, setMembers] = useState<Record<string, string>>({});
  const [picker, setPicker] = useState<{
    context: string;
    dimension: MetadataDimension;
  } | null>(null);
  const [example, setExample] = useState<Example | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [recheck, setRecheck] = useState<ContextRecheck | null>(null);
  const active = dimensions.filter(
    (dimension) => dimension.status === "Active",
  );
  const factDimensions = activeFactDimensions(dimensions);
  const canCheck = Boolean(catalog.functions["metadata.authoring.context"]);
  const canPickMember = Boolean(catalog.functions["metadata.member.select"]);
  const canReadAttributes = Boolean(
    catalog.functions["metadata.attribute-definition.list"] &&
      catalog.functions["metadata.attribute-value.read"],
  );
  const years = factDimensions.filter((axis) => axis.model_role === "Year");
  const periods = factDimensions.filter((axis) => axis.model_role === "Period");
  const readContract = catalog.functions["facts.cube.resolved.read"] as
    | { canonicalViewRead?: string }
    | undefined;
  const canInspect = Boolean(
    catalog.functions["metadata.member.resolve"] &&
      readContract?.canonicalViewRead === "openepm-cube-view-read-v1",
  );
  const context = JSON.stringify([
    app.workspaceId,
    app.applicationId,
    catalog.accessContext,
    catalog.applicationAccess,
    catalog.revisions,
    metadataRevision,
    active,
    canCheck,
    canInspect,
    canPickMember,
    canReadAttributes,
  ]);
  const current = useRef(context);
  current.current = context;
  const controller = useRef<AbortController | null>(null);
  const summary = useRef<HTMLElement>(null);
  const refreshButton = useRef<HTMLButtonElement>(null);
  const mounted = useRef(true);
  const currentRecheck = recheck?.context === context ? recheck : null;
  const needsRecheck = currentRecheck !== null;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    controller.current?.abort();
    setMembers({});
    setPicker(null);
    setExample(null);
    setError("");
    setRecheck(null);
    setBusy(false);
    return () => controller.current?.abort();
  }, [context]);
  useEffect(() => {
    if (!open || !canCheck || needsRecheck) return;
    const abort = new AbortController();
    function publish(status: GrainCheck["status"]) {
      if (!abort.signal.aborted && current.current === context)
        setCheckedGrain({ context, status });
    }
    void readProgram<unknown>(
      app,
      "metadata.authoring.context",
      {},
      abort.signal,
    )
      .then((result) => {
        const authorized = authorizedAuthoringContext(result, app, catalog);
        if (!authorized.cubeGrainAvailable) {
          publish("unavailable");
          return;
        }
        const namesById = new Map(
          authorized.dimensions.map(({ dimensionId, name }) => [
            dimensionId,
            name,
          ]),
        );
        const agrees =
          metadataRevision === catalog.revisions.metadata &&
          namesById.size === authorized.dimensions.length &&
          namesById.size === factDimensions.length &&
          factDimensions.every(
            ({ dimension_id, name }) => namesById.get(dimension_id) === name,
          );
        publish(agrees ? "ready" : "failed");
      })
      .catch((failure: unknown) => {
        if (
          !abort.signal.aborted &&
          current.current === context &&
          !invalidateContext(failure)
        )
          publish("failed");
      });
    return () => abort.abort();
  }, [context, open, canCheck, needsRecheck]);
  const grainStatus = canCheck
    ? checkedGrain?.context === context
      ? checkedGrain.status
      : "loading"
    : "unavailable";
  const inspectAvailable =
    !needsRecheck &&
    grainStatus === "ready" &&
    canInspect &&
    factDimensions.length > 1;
  const currentPicker =
    open && inspectAvailable && canPickMember && picker?.context === context
      ? picker
      : null;
  const ready =
    inspectAvailable &&
    factDimensions.every((dimension) =>
      members[dimension.dimension_id]?.trim(),
    );
  function invalidateContext(failure: unknown) {
    if (
      !mounted.current ||
      current.current !== context ||
      !(failure instanceof ApiError) ||
      (failure.kind !== "authorization" && !staleContextCodes.has(failure.code))
    )
      return false;
    if (summary.current?.parentElement?.contains(document.activeElement))
      summary.current.focus();
    controller.current?.abort();
    setCheckedGrain(null);
    setMembers({});
    setPicker(null);
    setExample(null);
    setError("");
    setBusy(false);
    setRecheck({
      context,
      message:
        failure.kind === "authorization"
          ? "Access to the worked coordinate was refused. Refresh the application context to check again."
          : "The worked-coordinate context changed during the read. Refresh the application context to check again.",
      pending: false,
    });
    return true;
  }
  function calendarRecorded() {
    summary.current?.focus();
    controller.current?.abort();
    setCheckedGrain(null);
    setExample(null);
    setPicker(null);
    setBusy(false);
    setRecheck({
      context,
      message:
        "Calendar change recorded. Refresh the application context to read the current period.",
      pending: false,
      recorded: true,
    });
  }
  async function refreshContext() {
    if (!currentRecheck || currentRecheck.pending || !onRefreshCatalog) return;
    const abort = new AbortController();
    controller.current?.abort();
    controller.current = abort;
    setRecheck({ ...currentRecheck, pending: true });
    const isCurrent = () =>
      mounted.current && !abort.signal.aborted && current.current === context;
    try {
      await onRefreshCatalog(abort.signal);
      if (isCurrent()) {
        if (document.activeElement === refreshButton.current)
          summary.current?.focus();
        setRecheck(null);
      }
    } catch {
      if (isCurrent())
        setRecheck({
          context,
          message: "The application context could not be refreshed. Try again.",
          pending: false,
        });
    }
  }
  function editMember(dimensionId: string, memberId: string) {
    if (members[dimensionId] === memberId) return;
    setMembers((previous) => ({ ...previous, [dimensionId]: memberId }));
    setExample(null);
    setError("");
  }
  async function inspect() {
    if (!ready || current.current !== context) return;
    const captured = context;
    const abort = new AbortController();
    controller.current?.abort();
    controller.current = abort;
    const coordinate = Object.fromEntries(
      factDimensions.map((dimension) => [
        dimension.dimension_id,
        members[dimension.dimension_id].trim(),
      ]),
    );
    setBusy(true);
    setExample(null);
    setError("");
    try {
      const meanings = await Promise.all(
        factDimensions.map(async (dimension) => {
          const member = await readProgram<
            MetadataMember & { dimension_id: string }
          >(
            app,
            "metadata.member.resolve",
            {
              dimension: dimension.dimension_id,
              reference: coordinate[dimension.dimension_id],
            },
            abort.signal,
          );
          if (
            member.dimension_id !== dimension.dimension_id ||
            member.member_id !== coordinate[dimension.dimension_id] ||
            member.status !== "Active"
          )
            throw new Error(
              "Use an active member's exact ID for every fact dimension.",
            );
          return { ...member, dimension: dimension.dimension_id };
        }),
      );
      const result = await readProgram<unknown>(
        app,
        "facts.cube.resolved.read",
        {
          format: "openepm-cube-view-read-v1",
          view: {
            format: "openepm-cube-view-v1",
            viewId: "model-example",
            name: "Worked coordinate",
            selection: {
              format: "openepm-cube-selection-v1",
              metadataRevision,
              dimensions: factDimensions.map((dimension) => ({
                dimensionId: dimension.dimension_id,
                include: {
                  kind: "member",
                  memberId: coordinate[dimension.dimension_id],
                },
                exclude: null,
              })),
            },
            layout: {
              rows: [factDimensions[0].dimension_id],
              columns: [factDimensions[1].dimension_id],
              pages: [],
              filters: factDimensions
                .slice(2)
                .map((dimension) => dimension.dimension_id),
            },
            dataSource: { kind: "raw", resultKey: null },
            suppression: { missing: false, zero: false },
            pageSize: 1,
          },
          readPolicy: { semantics: "stored" },
          limits: { maxRows: 10, maxSourceRows: 10, timeoutMs: 5000 },
        },
        abort.signal,
      );
      const rows = workedCoordinateRows(
        result,
        coordinate,
        catalog,
        metadataRevision,
      );
      if (
        mounted.current &&
        !abort.signal.aborted &&
        current.current === captured
      )
        setExample({ context: captured, members: coordinate, meanings, rows });
    } catch (failure) {
      if (
        mounted.current &&
        !abort.signal.aborted &&
        current.current === captured &&
        !invalidateContext(failure)
      )
        setError(
          failure instanceof Error
            ? failure.message
            : "The example could not be read.",
        );
    } finally {
      if (
        mounted.current &&
        !abort.signal.aborted &&
        current.current === captured
      )
        setBusy(false);
    }
  }
  const visible =
    inspectAvailable && example?.context === context ? example : null;
  return (
    <details
      className="context-note"
      onToggle={(event) => {
        const expanded = event.currentTarget.open;
        setOpen(expanded);
        if (!expanded) setPicker(null);
      }}
    >
      <summary ref={summary}>Model meaning and one worked coordinate</summary>
      <p>
        Start with a business question, such as “What capacity follows from
        these hours and rates?” Define the quantity, its unit, the time basis
        and what an absent value means before writing a calculation.
      </p>
      {currentRecheck && (
        <>
          <p
            role={
              currentRecheck.pending || currentRecheck.recorded
                ? "status"
                : "alert"
            }
          >
            {currentRecheck.pending
              ? "Refreshing the application context…"
              : currentRecheck.message}
          </p>
          {onRefreshCatalog && (
            <button
              type="button"
              ref={refreshButton}
              aria-disabled={currentRecheck.pending || undefined}
              onClick={() => void refreshContext()}
            >
              Refresh application context
            </button>
          )}
        </>
      )}
      {!needsRecheck && grainStatus === "loading" && (
        <p role="status">Checking the active fact dimensions…</p>
      )}
      {grainStatus === "failed" && (
        <p role="alert">
          The current grain could not be verified. Refresh the application
          metadata and try again.
        </p>
      )}
      {grainStatus === "unavailable" && (
        <p>
          A complete fact coordinate is unavailable in the current application
          context.
        </p>
      )}
      {grainStatus === "ready" && (
        <p>
          The current grain is{" "}
          {factDimensions.map((dimension) => dimension.name).join(" × ")}.
          Choose one member per fact axis. If an axis uses a neutral member,
          record that choice in its description.
        </p>
      )}
      <table className="react-cube-grid">
        <caption>
          Persisted dimension meaning at metadata revision {metadataRevision}
        </caption>
        <thead>
          <tr>
            <th>Dimension and ID</th>
            <th>Role</th>
            <th>Current description</th>
          </tr>
        </thead>
        <tbody>
          {active.map((dimension) => (
            <tr key={dimension.dimension_id}>
              <th>
                {dimension.name} ({dimension.dimension_id})
              </th>
              <td>
                {dimension.model_role === "Currency"
                  ? "Currency (context)"
                  : dimension.model_role}
              </td>
              <td>
                {dimension.detailed_description ||
                  dimension.short_description ||
                  "Meaning has not been described in metadata."}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p>
        Record model meaning in dimension and member descriptions and typed
        attributes. Define eligibility and relationships explicitly; a shared
        resource must not gain capacity merely because it has several eligible
        skills. Declare time order and conversion rules. Amount and Ratio are
        arithmetic kinds; physical units such as hours, FTE and cases need
        explicit application meaning.
      </p>
      <p>
        Business scenarios contain their own facts and assumptions. A private
        Test and activating a current definition are separate operations.
        Copying a scenario requires an explicit source, destination, scope and
        destination policy.
      </p>
      {grainStatus === "ready" && !inspectAvailable && (
        <p>Worked-coordinate inspection is unavailable in this context.</p>
      )}
      {inspectAvailable && (
        <fieldset disabled={busy}>
          <legend>Choose one member per fact dimension</legend>
          {factDimensions.map((dimension) => (
            <div
              className="model-coordinate-member"
              key={dimension.dimension_id}
            >
              <label>
                {dimension.name} ({dimension.dimension_id})
                <input
                  aria-label={`Example ${dimension.dimension_id}`}
                  value={members[dimension.dimension_id] || ""}
                  onChange={(event) =>
                    editMember(dimension.dimension_id, event.target.value)
                  }
                />
              </label>
              {canPickMember && (
                <button
                  type="button"
                  aria-label={`Choose ${dimension.name} member`}
                  onClick={() => setPicker({ context, dimension })}
                >
                  Choose member
                </button>
              )}
            </div>
          ))}
          <button
            type="button"
            disabled={!ready}
            onClick={() => void inspect()}
          >
            Inspect worked coordinate
          </button>
        </fieldset>
      )}
      {currentPicker && (
        <MemberSelectionDialog
          app={app}
          catalog={catalog}
          request={{
            dimensionId: currentPicker.dimension.dimension_id,
            dimensionName: currentPicker.dimension.name,
            metadataRevision,
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
          members={[]}
          onCancel={() => setPicker(null)}
          onApply={(result) => {
            if (
              current.current !== currentPicker.context ||
              result.dimensionId !== currentPicker.dimension.dimension_id ||
              result.metadataRevision !== metadataRevision ||
              result.include.kind !== "member" ||
              result.exclude !== null
            )
              return;
            editMember(result.dimensionId, result.include.memberId);
            setPicker(null);
          }}
        />
      )}
      {busy && <p role="status">Reading the exact coordinate…</p>}
      {error && <p role="alert">{error}</p>}
      {visible && (
        <section aria-label="Worked coordinate evidence">
          <p>
            Stored raw inputs. No calculation or policy is inferred from the
            member names.
          </p>
          <ul>
            {visible.meanings.map((member) => (
              <li key={member.dimension}>
                {member.dimension}: {member.member_id} —{" "}
                {member.detailed_description ||
                  member.short_description ||
                  "No persisted description"}
                {member.numeric_value_kind
                  ? `; arithmetic kind ${member.numeric_value_kind}`
                  : ""}
              </li>
            ))}
          </ul>
          {visible.rows.length ? (
            visible.rows.map((row, index) => (
              <p key={index}>
                {row.kind === "amount"
                  ? "Stored numeric value"
                  : "Stored text value"}
                :{" "}
                {row.amount !== undefined
                  ? row.amount
                  : row.text !== undefined
                    ? JSON.stringify(row.text)
                    : "No present value"}
              </p>
            ))
          ) : (
            <p>No stored value is visible at this exact coordinate.</p>
          )}
          {canReadAttributes && (
            <WorkedMemberAttribute
              scope={app}
              dimensions={factDimensions}
              coordinate={visible.members}
              metadataRevision={metadataRevision}
              onReadFailure={invalidateContext}
            />
          )}
        </section>
      )}
      <WorkedCalendarPeriod
        key={JSON.stringify([
          app.workspaceId,
          app.applicationId,
          catalog.applicationAccess.issuer,
          catalog.applicationAccess.subjectId,
        ])}
        scope={app}
        catalog={catalog}
        context={context}
        contextBlocked={needsRecheck}
        selection={
          visible && years.length === 1 && periods.length === 1
            ? {
                yearId: visible.members[years[0].dimension_id],
                periodId: visible.members[periods[0].dimension_id],
              }
            : null
        }
        metadataRevision={metadataRevision}
        onReadFailure={invalidateContext}
        onRecorded={calendarRecorded}
      />
    </details>
  );
}
