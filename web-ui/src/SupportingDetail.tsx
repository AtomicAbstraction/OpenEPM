import { useEffect, useState } from "react";
import { readProgram, request, reviewAndSubmit } from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";

type DetailItem = { description: string; decimal: string };

type ExportRow = {
  members: Record<string, string>;
  value:
    | { type: "AmountLiteral"; decimal: string }
    | { type: "TextLiteral"; text: string }
    | { type: "LineDetailLiteral"; items: DetailItem[] };
  sourceRef: string;
};

type ExportPage = {
  rows: ExportRow[];
  nextCursor?: string | null;
  snapshotRevision: number;
};

type CubeRow = {
  members: Record<string, string>;
  kind: "numeric" | "text";
  numericChangeId?: string;
};

type CubePage = { rows: CubeRow[]; snapshotRevision: number };

export function supportingDetailProgram(
  coordinate: Record<string, string>,
  items: DetailItem[],
  changeId: string,
) {
  return {
    languageVersion: 2,
    function: "facts.line-detail.replace",
    arguments: {
      coordinate,
      items: items.map((item) => ({
        description: item.description,
        amount: { type: "AmountLiteral", decimal: item.decimal },
      })),
      expectedCellChangeId: changeId,
      expectedDetailChangeId: changeId,
    },
  };
}

export function validDetailItems(items: DetailItem[]) {
  const decimal = /^[+-]?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;
  return (
    items.length <= 500 &&
    items.every(
      (item) =>
        item.description.length <= 500 && decimal.test(item.decimal.trim()),
    )
  );
}

function sameCoordinate(
  left: Record<string, string>,
  right: Record<string, string>,
) {
  return (
    Object.keys(left).length === Object.keys(right).length &&
    Object.entries(left).every(([axis, member]) => right[axis] === member)
  );
}

export function SupportingDetail({
  app,
  catalog,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
}) {
  const mutationIntentKey = useStableMutationIntentKey("detail-ui");
  const scope: Scope | null = app
    ? { workspaceId: app.workspaceId, applicationId: app.applicationId }
    : null;
  const [rows, setRows] = useState<ExportRow[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [selected, setSelected] = useState<ExportRow | null>(null);
  const [items, setItems] = useState<DetailItem[]>([]);
  const [detailTouched, setDetailTouched] = useState(false);
  const [changeId, setChangeId] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");

  const canRead = Boolean(catalog?.functions["facts.export.page"]);
  const canWrite = Boolean(catalog?.functions["facts.line-detail.replace"]);
  useUnsavedWork(
    `supporting-detail:${app?.workspaceId || "none"}:${app?.applicationId || "none"}`,
    "Unsaved supporting-detail replacement",
    Boolean(selected && detailTouched),
  );

  useEffect(() => {
    setRows([]);
    setCursor(null);
    setSelected(null);
    setItems([]);
    setDetailTouched(false);
    setChangeId("");
    setReviewed(false);
    setError("");
    setResult("");
  }, [app?.workspaceId, app?.applicationId]);

  useEffect(() => setReviewed(false), [items]);

  async function readDetails(next?: string | null) {
    if (!scope || !canRead) return;
    setBusy(true);
    setError("");
    try {
      const page = await readProgram<ExportPage>(
        scope,
        "facts.export.page",
        next ? { cursor: next, limit: 50 } : { members: {}, limit: 50 },
      );
      const detail = page.rows.filter(
        (row) => row.value.type === "LineDetailLiteral",
      );
      setRows((current) => (next ? [...current, ...detail] : detail));
      setCursor(page.nextCursor || null);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read supporting detail",
      );
    } finally {
      setBusy(false);
    }
  }

  async function openDetail(row: ExportRow) {
    if (!scope || row.value.type !== "LineDetailLiteral") return;
    setBusy(true);
    setError("");
    setResult("");
    setReviewed(false);
    try {
      const cube = await readProgram<CubePage>(scope, "facts.cube.scan", {
        members: row.members,
        limit: 2,
        includeMissing: true,
      });
      const exact = cube.rows.find((candidate) =>
        sameCoordinate(row.members, candidate.members),
      );
      if (!exact || exact.kind !== "numeric" || !exact.numericChangeId)
        throw new Error("SUPPORTING_DETAIL_CURRENT_IDENTITY_UNAVAILABLE");
      const latest = await readProgram<ExportPage>(scope, "facts.export.page", {
        members: row.members,
        limit: 2,
        snapshotRevision: cube.snapshotRevision,
      });
      const current = latest.rows.find(
        (candidate) =>
          sameCoordinate(row.members, candidate.members) &&
          candidate.value.type === "LineDetailLiteral",
      );
      if (!current || current.value.type !== "LineDetailLiteral")
        throw new Error("SUPPORTING_DETAIL_CURRENT_VALUE_UNAVAILABLE");
      setSelected(current);
      setItems(current.value.items.map((item) => ({ ...item })));
      setDetailTouched(false);
      setChangeId(exact.numericChangeId);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to resolve supporting detail",
      );
    } finally {
      setBusy(false);
    }
  }

  function updateItem(index: number, field: keyof DetailItem, value: string) {
    setDetailTouched(true);
    setItems((current) =>
      current.map((item, position) =>
        position === index ? { ...item, [field]: value } : item,
      ),
    );
  }

  async function replaceDetail() {
    if (
      !scope ||
      !selected ||
      !changeId ||
      !canWrite ||
      !reviewed ||
      !validDetailItems(items) ||
      busy
    )
      return;
    setBusy(true);
    setError("");
    setResult("");
    try {
      const program = supportingDetailProgram(
        selected.members,
        items,
        changeId,
      );
      const response = await reviewAndSubmit<{ jobId?: string }>(
        {
          ...scope,
          program,
          idempotencyKey: mutationIntentKey({ scope, program }),
          dependsOnJobIds: [],
          confirmed: true,
        },
        "Review the supporting-detail replacement preview.",
      );
      if (!response) return;
      setResult(
        response.jobId
          ? `Replacement accepted as durable job ${response.jobId}.`
          : "Replacement request accepted.",
      );
      setDetailTouched(false);
      setReviewed(false);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to replace supporting detail",
      );
    } finally {
      setBusy(false);
    }
  }

  if (!canRead && !canWrite) return null;
  return (
    <section
      className="panel supporting-detail"
      aria-labelledby="detail-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>EXACT DETAIL AND TOTAL</small>
          <h2 id="detail-heading" tabIndex={-1}>
            Supporting detail
          </h2>
          <p>
            Inspect authoritative detail lines and replace them as one reviewed,
            atomic detail-plus-total operation.
          </p>
        </div>
        <button disabled={busy || !canRead} onClick={() => void readDetails()}>
          {busy ? "Reading…" : "Read detail"}
        </button>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {result && <p role="status">{result}</p>}
      <div className="react-grid-scroll">
        <table className="react-cube-grid">
          <thead>
            <tr>
              <th>Coordinate</th>
              <th>Lines</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.sourceRef}>
                <th>
                  {Object.entries(row.members)
                    .map(([axis, member]) => `${axis}: ${member}`)
                    .join(" · ")}
                </th>
                <td>
                  {row.value.type === "LineDetailLiteral"
                    ? row.value.items.length
                    : 0}
                </td>
                <td>
                  <button disabled={busy} onClick={() => void openDetail(row)}>
                    Open
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!rows.length && !busy && (
        <p className="muted-copy">No supporting-detail rows read yet.</p>
      )}
      <button
        disabled={busy || !cursor}
        onClick={() => void readDetails(cursor)}
      >
        Next source rows
      </button>
      {selected && (
        <div className="detail-editor" aria-label="Supporting detail editor">
          <h3>Reviewed replacement</h3>
          <p>
            {Object.entries(selected.members)
              .map(([axis, member]) => `${axis}: ${member}`)
              .join(" · ")}
          </p>
          {items.map((item, index) => (
            <div className="detail-item" key={index}>
              <label>
                Description
                <input
                  maxLength={500}
                  value={item.description}
                  onChange={(event) =>
                    updateItem(index, "description", event.target.value)
                  }
                />
              </label>
              <label>
                Exact amount
                <input
                  inputMode="decimal"
                  value={item.decimal}
                  onChange={(event) =>
                    updateItem(index, "decimal", event.target.value)
                  }
                />
              </label>
              <button
                aria-label={`Remove line ${index + 1}`}
                onClick={() =>
                  setItems((current) =>
                    current.filter((_, position) => position !== index),
                  )
                }
              >
                Remove
              </button>
            </div>
          ))}
          <button
            disabled={items.length >= 500}
            onClick={() =>
              setItems((current) => [
                ...current,
                { description: "", decimal: "0" },
              ])
            }
          >
            Add line
          </button>
          <label className="review-check">
            <input
              type="checkbox"
              checked={reviewed}
              disabled={!canWrite || !validDetailItems(items)}
              onChange={(event) => setReviewed(event.target.checked)}
            />
            I reviewed this exact replacement and its total.
          </label>
          <button
            disabled={
              busy || !canWrite || !reviewed || !validDetailItems(items)
            }
            onClick={() => void replaceDetail()}
          >
            Replace supporting detail
          </button>
        </div>
      )}
      <p className="authority-note">
        The fixed core validates the exact total, concurrency identities,
        authorization and atomic publication. The browser performs no summation.
      </p>
    </section>
  );
}
