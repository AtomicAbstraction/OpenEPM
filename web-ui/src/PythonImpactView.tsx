import { useMemo, useState } from "react";

type Row = {
  seriesKey: string;
  members: Record<string, string>;
  before: unknown;
  after: unknown;
  delta: string | null;
  units?: number[];
  storage?: "calculation";
  resultKey?: string;
};
function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}
function ImpactCell({ value }: { value: unknown }) {
  const [open, setOpen] = useState(false);
  const [page, setPage] = useState(0);
  const cell = object(value);
  if (cell?.present === false) return <span>Not present</span>;
  if (cell?.present !== true) return <span>Unrecognized value</span>;
  if (cell.kind === "text" && typeof cell.text === "string")
    return (
      <span>
        Text: <q>{cell.text}</q>
      </span>
    );
  if (
    cell.kind === "line-detail" &&
    typeof cell.amount === "string" &&
    Array.isArray(cell.items)
  )
    return (
      <details
        open={open}
        onToggle={(event) => setOpen(event.currentTarget.open)}
      >
        <summary>
          Detail total: {cell.amount} ({cell.items.length} lines)
        </summary>
        {open && (
          <>
            <ul>
              {cell.items
                .slice(page * 100, (page + 1) * 100)
                .map((item, index) => {
                  const line = object(item);
                  return (
                    <li key={index}>
                      {typeof line?.description === "string"
                        ? line.description
                        : "Unrecognized detail"}
                      : {typeof line?.amount === "string" ? line.amount : "—"}
                    </li>
                  );
                })}
            </ul>
            <button
              disabled={page === 0}
              onClick={() => setPage((value) => value - 1)}
            >
              Previous detail lines
            </button>
            <button
              disabled={(page + 1) * 100 >= cell.items.length}
              onClick={() => setPage((value) => value + 1)}
            >
              Next detail lines
            </button>
          </>
        )}
      </details>
    );
  if (
    (cell.kind === undefined || cell.kind === "numeric") &&
    typeof cell.amount === "string"
  ) {
    const unit = object(cell.outputUnit);
    if (
      cell.outputUnit !== undefined &&
      (typeof unit?.dimensionId !== "string" ||
        !unit.dimensionId ||
        typeof unit.memberId !== "string" ||
        !unit.memberId ||
        cell.valueType === "RatioLiteral")
    )
      return <span>Unrecognized value</span>;
    return (
      <span>
        {cell.amount}
        {cell.valueType === "RatioLiteral" ? " (ratio)" : ""}
        {unit ? ` (${unit.dimensionId}: ${unit.memberId})` : ""}
      </span>
    );
  }
  return <span>Unrecognized value</span>;
}

function DefinitionImpact({ value }: { value: unknown }) {
  const [page, setPage] = useState(0);
  const result = object(value);
  if (!result) return null;
  const kind = result.kind;
  if (
    !["ApplicationRule", "MemberList", "CalculatedMember"].includes(
      String(kind),
    ) ||
    typeof result.definitionId !== "string" ||
    !result.definitionId
  )
    return (
      <p role="alert">The definition result is unavailable for display.</p>
    );
  let content;
  if (kind === "MemberList") {
    if (
      !Array.isArray(result.memberIds) ||
      result.memberIds.length > 100000 ||
      result.memberCount !== result.memberIds.length ||
      !result.memberIds.every((id) => typeof id === "string")
    )
      return <p role="alert">The tested member selection is incomplete.</p>;
    content = (
      <>
        <p>
          {result.memberCount} selected members · {String(result.dimensionId)}
        </p>
        <ul>
          {result.memberIds.slice(page * 100, (page + 1) * 100).map((id) => (
            <li key={id}>{id}</li>
          ))}
        </ul>
        <button
          disabled={page === 0}
          onClick={() => setPage((value) => value - 1)}
        >
          Previous tested members
        </button>
        <button
          disabled={(page + 1) * 100 >= result.memberIds.length}
          onClick={() => setPage((value) => value + 1)}
        >
          Next tested members
        </button>
      </>
    );
  } else if (kind === "CalculatedMember") {
    if (
      result.persisted !== false ||
      !Array.isArray(result.rows) ||
      result.rows.length > 100000 ||
      result.rowCount !== result.rows.length ||
      !result.rows.every((value) => {
        const row = object(value),
          amount = object(row?.value);
        return (
          row &&
          object(row.members) &&
          typeof amount?.decimal === "string" &&
          ["AmountLiteral", "RatioLiteral"].includes(String(amount.type))
        );
      })
    )
      return <p role="alert">The tested calculation result is incomplete.</p>;
    content = (
      <>
        <p>
          {result.rowCount} calculated values · {String(result.evaluation)} · no
          persisted result
        </p>
        <table className="react-cube-grid">
          <caption>Calculated test values</caption>
          <thead>
            <tr>
              <th>Coordinate</th>
              <th>Value</th>
              <th>Unit</th>
            </tr>
          </thead>
          <tbody>
            {result.rows
              .slice(page * 50, (page + 1) * 50)
              .map((value, index) => {
                const row = object(value)!,
                  amount = object(row.value)!;
                return (
                  <tr key={page * 50 + index}>
                    <th>
                      {Object.entries(object(row.members)!).map(
                        ([dimension, member]) => (
                          <div key={dimension}>
                            {dimension}: {String(member)}
                          </div>
                        ),
                      )}
                    </th>
                    <td>{String(amount.decimal)}</td>
                    <td>
                      {amount.type === "RatioLiteral" ? "ratio" : "amount"}
                    </td>
                  </tr>
                );
              })}
          </tbody>
        </table>
        <button
          disabled={page === 0}
          onClick={() => setPage((value) => value - 1)}
        >
          Previous calculated values
        </button>
        <button
          disabled={(page + 1) * 50 >= result.rows.length}
          onClick={() => setPage((value) => value + 1)}
        >
          Next calculated values
        </button>
      </>
    );
  }
  return (
    <section aria-label="Tested definition result">
      <h5>{String(kind)} test result</h5>
      {content}
      <details>
        <summary>Tested rule parameters</summary>
        <pre>{JSON.stringify(result.bindings ?? {}, null, 2)}</pre>
      </details>
    </section>
  );
}

export function PythonImpactView({
  text,
  complete,
  sourceDigest,
}: {
  text: string;
  complete: boolean;
  sourceDigest: string;
}) {
  const [page, setPage] = useState(0);
  const [rawOpen, setRawOpen] = useState(false);
  const impact = useMemo(() => {
    if (!complete) return undefined;
    try {
      const value = object(JSON.parse(text));
      if (
        value?.format !== "openepm-python-impact-v1" ||
        value.status !== "complete" ||
        value.businessDataChanged !== false ||
        value.sourceDigest !== sourceDigest ||
        !Array.isArray(value.rows) ||
        value.rows.length > 10000
      )
        return undefined;
      for (const item of value.rows) {
        const row = object(item);
        if (
          !row ||
          typeof row.seriesKey !== "string" ||
          !object(row.members) ||
          !Object.values(row.members as object).every(
            (member) => typeof member === "string",
          ) ||
          (row.delta !== null && typeof row.delta !== "string") ||
          (row.storage !== undefined && row.storage !== "calculation") ||
          (row.storage === "calculation" &&
            (typeof row.resultKey !== "string" || !row.resultKey)) ||
          (row.storage === undefined && row.resultKey !== undefined)
        )
          return undefined;
      }
      return {
        definitionResult: value.definitionResult,
        baseline: value.baseline,
        counts: value.counts,
        rows: value.rows as Row[],
      };
    } catch {
      return undefined;
    }
  }, [text, complete, sourceDigest]);
  const lastPage = impact
    ? Math.max(0, Math.ceil(impact.rows.length / 50) - 1)
    : 0;
  const visiblePage = Math.min(page, lastPage);
  const baseline = object(impact?.baseline);
  const counts = object(impact?.counts);
  return (
    <section aria-label="Python test impact">
      {!complete && (
        <p>Read the remaining impact pages to review the complete result.</p>
      )}
      {complete && !impact && (
        <p role="alert">
          The impact cannot be rendered as a complete result for this source.
          Inspect its technical artifact.
        </p>
      )}
      {impact && (
        <>
          <p>Private test completed; application data was unchanged.</p>
          <DefinitionImpact key={text} value={impact.definitionResult} />
          <p>
            {String(counts?.selected ?? impact.rows.length)} selected ·{" "}
            {String(counts?.changed ?? "—")} changed ·{" "}
            {String(counts?.created ?? "—")} created ·{" "}
            {String(counts?.cleared ?? "—")} cleared
          </p>
          <p>Compared with the current authorized application state.</p>
          <div
            className="react-grid-scroll"
            role="region"
            aria-label="Before and after effects scroll area"
            tabIndex={0}
          >
            <table className="react-cube-grid">
              <caption>Before and after effects</caption>
              <thead>
                <tr>
                  <th>Coordinate</th>
                  <th>Storage / result</th>
                  <th>Before</th>
                  <th>After</th>
                  <th>Delta</th>
                </tr>
              </thead>
              <tbody>
                {impact.rows
                  .slice(visiblePage * 50, (visiblePage + 1) * 50)
                  .map((row) => (
                    <tr
                      key={JSON.stringify([
                        row.storage ?? "raw",
                        row.resultKey ?? null,
                        row.seriesKey,
                      ])}
                    >
                      <th>
                        {Object.entries(row.members).map(
                          ([dimension, member]) => (
                            <div key={dimension}>
                              {dimension}: {member}
                            </div>
                          ),
                        )}
                      </th>
                      <td>
                        {row.storage === "calculation"
                          ? "Calculation result"
                          : "Raw cell"}
                      </td>
                      <td>
                        <ImpactCell value={row.before} />
                      </td>
                      <td>
                        <ImpactCell value={row.after} />
                      </td>
                      <td>
                        {row.delta === null ? "Not applicable" : row.delta}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
          {!impact.rows.length && <p>This test has no cell effects.</p>}
          <p>
            Cells {impact.rows.length ? visiblePage * 50 + 1 : 0}–
            {Math.min((visiblePage + 1) * 50, impact.rows.length)} of{" "}
            {impact.rows.length}
          </p>
          <button
            disabled={visiblePage === 0}
            onClick={() => setPage(visiblePage - 1)}
          >
            Previous cells
          </button>
          <button
            disabled={visiblePage >= lastPage}
            onClick={() => setPage(visiblePage + 1)}
          >
            Next cells
          </button>
        </>
      )}
      <details
        open={rawOpen}
        onToggle={(event) => setRawOpen(event.currentTarget.open)}
      >
        <summary>Technical impact artifact</summary>
        {rawOpen && (
          <pre role="region" aria-label="Python impact artifact" tabIndex={0}>
            {text}
          </pre>
        )}
      </details>
    </section>
  );
}
