import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { readProgram } from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import {
  ExactMutationOutcome,
  useExactCellMutation,
} from "./exact-cell-mutation";
import { transferAction } from "./data-transfer-action";
import "./data-workspaces.css";

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
  amount?: string;
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
        amount: item.decimal,
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
        item.description.length >= 1 &&
        item.description.length <= 80 &&
        !item.description.includes("\0") &&
        decimal.test(item.decimal),
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
  onRequestTransition = (action) => action(),
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  onRequestTransition?: (action: () => void) => void;
}) {
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
  const [hasRead, setHasRead] = useState(false);
  const [currentTotal, setCurrentTotal] = useState<string | null>(null);
  const context = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
    catalog?.applicationAccess.role,
    catalog?.applicationAccess.workspaceAdministrator,
    catalog?.revisions,
  ]);
  const active = useRef(context);
  active.current = context;
  const readController = useRef<AbortController | null>(null);
  const readButton = useRef<HTMLButtonElement>(null);
  const workspaceHeading = useRef<HTMLHeadingElement>(null);
  const editor = useRef<HTMLFieldSetElement>(null);
  const editorHeading = useRef<HTMLHeadingElement>(null);
  const addButton = useRef<HTMLButtonElement>(null);
  const outcomeTarget = useRef<HTMLDivElement>(null);
  const detailOrigin = useRef<HTMLElement | null>(null);
  const pendingFocus = useRef<{
    context: string;
    from: HTMLElement;
    target: () => HTMLElement | null | undefined;
  } | null>(null);

  function focusAfterUpdate(
    from: HTMLElement,
    target: () => HTMLElement | null | undefined,
  ) {
    pendingFocus.current = { context, from, target };
  }
  useLayoutEffect(() => {
    const request = pendingFocus.current;
    pendingFocus.current = null;
    if (!request || request.context !== context) return;
    const focused = document.activeElement;
    if (
      focused === request.from ||
      (focused === document.body && !request.from.isConnected)
    )
      request.target()?.focus();
  });

  const canRead = Boolean(catalog?.functions["facts.export.page"]);
  const canWrite = Boolean(catalog?.functions["facts.line-detail.replace"]);
  const program =
    selected && changeId && validDetailItems(items)
      ? supportingDetailProgram(selected.members, items, changeId)
      : null;
  const mutation = useExactCellMutation(
    scope,
    context,
    "supporting-detail-mutation",
    program,
    JSON.stringify([
      catalog?.applicationAccess.issuer,
      catalog?.applicationAccess.subjectId,
    ]),
  );
  const editorLocked = busy || mutation.busy || mutation.frozen;
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
    setHasRead(false);
  }, [app?.workspaceId, app?.applicationId]);

  useEffect(() => {
    readController.current?.abort();
    setRows([]);
    setCursor(null);
    setHasRead(false);
    setChangeId("");
    setReviewed(false);
    setCurrentTotal(null);
    setBusy(false);
    if (!detailTouched) {
      setSelected(null);
      setItems([]);
    }
    return () => readController.current?.abort();
  }, [context]);

  useEffect(() => setReviewed(false), [items]);

  async function readDetails(next?: string | null) {
    if (!scope || !canRead) return;
    setBusy(true);
    setError("");
    const at = context;
    readController.current?.abort();
    const controller = new AbortController();
    readController.current = controller;
    try {
      const page = await readProgram<ExportPage>(
        scope,
        "facts.export.page",
        next ? { cursor: next, limit: 50 } : { members: {}, limit: 50 },
        controller.signal,
      );
      if (controller.signal.aborted || active.current !== at) return;
      const detail = page.rows.filter(
        (row) => row.value.type === "LineDetailLiteral",
      );
      setRows((current) => (next ? [...current, ...detail] : detail));
      setCursor(page.nextCursor || null);
      setHasRead(true);
    } catch (reason) {
      if (controller.signal.aborted || active.current !== at) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read supporting detail",
      );
    } finally {
      if (!controller.signal.aborted && active.current === at) setBusy(false);
    }
  }

  async function openDetail(
    row: ExportRow,
    preserveDraft = false,
    origin?: HTMLButtonElement,
  ) {
    if (!scope || row.value.type !== "LineDetailLiteral") return;
    setBusy(true);
    setError("");
    setReviewed(false);
    setChangeId("");
    setCurrentTotal(null);
    const at = context;
    readController.current?.abort();
    const controller = new AbortController();
    readController.current = controller;
    try {
      const cube = await readProgram<CubePage>(
        scope,
        "facts.cube.scan",
        {
          members: row.members,
          limit: 2,
          includeMissing: true,
        },
        controller.signal,
      );
      if (controller.signal.aborted || active.current !== at) return;
      const exact = cube.rows.find((candidate) =>
        sameCoordinate(row.members, candidate.members),
      );
      if (!exact || exact.kind !== "numeric" || !exact.numericChangeId)
        throw new Error("SUPPORTING_DETAIL_CURRENT_IDENTITY_UNAVAILABLE");
      const latest = await readProgram<ExportPage>(
        scope,
        "facts.export.page",
        {
          members: row.members,
          limit: 2,
          snapshotRevision: cube.snapshotRevision,
        },
        controller.signal,
      );
      if (controller.signal.aborted || active.current !== at) return;
      const current = latest.rows.find(
        (candidate) =>
          sameCoordinate(row.members, candidate.members) &&
          candidate.value.type === "LineDetailLiteral",
      );
      if (!current || current.value.type !== "LineDetailLiteral")
        throw new Error("SUPPORTING_DETAIL_CURRENT_VALUE_UNAVAILABLE");
      if (origin) {
        detailOrigin.current = origin;
        focusAfterUpdate(origin, () => editorHeading.current);
      }
      setSelected(current);
      if (!preserveDraft) {
        setItems(current.value.items.map((item) => ({ ...item })));
        setDetailTouched(false);
      }
      setChangeId(exact.numericChangeId);
      setCurrentTotal(exact.amount ?? null);
    } catch (reason) {
      if (controller.signal.aborted || active.current !== at) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to resolve supporting detail",
      );
    } finally {
      if (!controller.signal.aborted && active.current === at) setBusy(false);
    }
  }

  function closeDetail(from: HTMLElement) {
    if (editorLocked) return;
    const close = () => {
      const origin = detailOrigin.current;
      focusAfterUpdate(from, () =>
        origin?.isConnected && origin.getAttribute("aria-disabled") !== "true"
          ? origin
          : canRead
            ? readButton.current
            : workspaceHeading.current,
      );
      detailOrigin.current = null;
      setSelected(null);
      setItems([]);
      setChangeId("");
      setCurrentTotal(null);
      setDetailTouched(false);
      setReviewed(false);
    };
    if (detailTouched) onRequestTransition(close);
    else close();
  }

  function updateItem(index: number, field: keyof DetailItem, value: string) {
    if (!canWrite || editorLocked) return;
    setDetailTouched(true);
    setItems((current) =>
      current.map((item, position) =>
        position === index ? { ...item, [field]: value } : item,
      ),
    );
  }

  async function replaceDetail(from: HTMLButtonElement) {
    if (
      !scope ||
      !selected ||
      !changeId ||
      !canWrite ||
      !reviewed ||
      !validDetailItems(items) ||
      busy ||
      !mutation.review
    )
      return;
    await mutation.submit();
    if (active.current === context)
      focusAfterUpdate(from, () => outcomeTarget.current);
    setReviewed(false);
  }

  if (!canRead && !canWrite) return null;
  return (
    <section
      className="panel supporting-detail"
      aria-labelledby="detail-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>SUPPORTING DETAIL WORKSPACE</small>
          <h2 id="detail-heading" ref={workspaceHeading} tabIndex={-1}>
            Supporting detail
          </h2>
          <p>
            Open a coordinate to inspect its lines. Review a replacement to
            update the detail and its total together.
          </p>
        </div>
        <button
          ref={readButton}
          {...transferAction(busy || !canRead, () => readDetails())}
        >
          Read detail
        </button>
      </div>
      <div
        className="data-stage-summary"
        aria-label="Supporting detail read status"
        role="status"
      >
        <span>
          {busy
            ? "Reading supporting detail…"
            : mutation.phase === "preview"
              ? "Preparing the exact replacement preview…"
              : hasRead
                ? `${rows.length} loaded coordinates`
                : "Read supporting detail to begin"}
        </span>
        {cursor && <span>More source rows available</span>}
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {mutation.error && <p role="alert">{mutation.error}</p>}
      {scope && (
        <div
          ref={outcomeTarget}
          tabIndex={-1}
          aria-label="Supporting detail outcome"
          role="region"
          hidden={!mutation.pending}
        >
          <ExactMutationOutcome
            mutation={mutation}
            scope={scope}
            catalog={catalog}
            refresh={
              selected
                ? () => void openDetail(selected)
                : () => void readDetails()
            }
          />
        </div>
      )}
      <div className="react-grid-scroll">
        <table
          className="react-cube-grid"
          aria-label="Supporting detail coordinates"
          aria-busy={busy}
        >
          <thead>
            <tr>
              <th>Coordinate</th>
              <th>Lines</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.sourceRef}
                className={
                  selected?.sourceRef === row.sourceRef
                    ? "selected-detail-row"
                    : ""
                }
              >
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
                  <button
                    aria-pressed={selected?.sourceRef === row.sourceRef}
                    {...transferAction(editorLocked, (origin) =>
                      detailTouched
                        ? onRequestTransition(() => {
                            setDetailTouched(false);
                            setSelected(null);
                            setItems([]);
                            setChangeId("");
                            void openDetail(row, false, origin);
                          })
                        : void openDetail(row, false, origin),
                    )}
                  >
                    Open
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!rows.length && !busy && (
        <p className="muted-copy">
          {hasRead
            ? cursor
              ? "No supporting detail in these source rows. Read the next source rows to continue."
              : "No supporting detail was found in the selected source."
            : "No supporting-detail rows read yet."}
        </p>
      )}
      <button {...transferAction(busy || !cursor, () => readDetails(cursor))}>
        Next source rows
      </button>
      {selected && (
        <fieldset
          ref={editor}
          className="detail-editor"
          aria-label="Supporting detail editor"
          aria-busy={busy || mutation.busy}
          onKeyDown={(event) => {
            if (
              event.key !== "Escape" ||
              editorLocked ||
              event.defaultPrevented ||
              event.nativeEvent.isComposing
            )
              return;
            if (!(event.target instanceof HTMLElement)) return;
            event.preventDefault();
            event.stopPropagation();
            closeDetail(event.target);
          }}
        >
          <div className="data-section-heading">
            <span>↳</span>
            <div>
              <h3 ref={editorHeading} tabIndex={-1}>
                Reviewed replacement
              </h3>
              <p>
                {items.length} detail lines · the complete set is replaced
                together
              </p>
            </div>
          </div>
          <button {...transferAction(editorLocked, closeDetail)}>
            Close detail
          </button>
          <p>
            {Object.entries(selected.members)
              .map(([axis, member]) => `${axis}: ${member}`)
              .join(" · ")}
          </p>
          <p>
            {currentTotal === null
              ? "Reread the current cell before previewing a replacement."
              : `Current stored total: ${currentTotal}`}
          </p>
          <p>
            The proposal replaces the complete detail set and its numeric total
            atomically. An empty set remains present with total zero.
          </p>
          {changeId && selected.value.type === "LineDetailLiteral" && (
            <details>
              <summary>Current stored detail for comparison</summary>
              <ul>
                {selected.value.items.map((item, index) => (
                  <li key={index}>
                    {item.description}: {item.decimal}
                  </li>
                ))}
              </ul>
              <p>
                Rereading preserves your entire proposal below. Compare each
                line before replacing the current set; no automatic merge is
                applied.
              </p>
            </details>
          )}
          {!validDetailItems(items) && (
            <p role="status">
              Each description needs 1–80 characters without NUL, and each
              amount needs an exact decimal without spaces or exponent notation.
            </p>
          )}
          {items.map((item, index) => (
            <div className="detail-item" key={index}>
              <label>
                Description
                <input
                  maxLength={80}
                  data-detail-description={index}
                  readOnly={!canWrite || editorLocked}
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
                  readOnly={!canWrite || editorLocked}
                  value={item.decimal}
                  onChange={(event) =>
                    updateItem(index, "decimal", event.target.value)
                  }
                />
              </label>
              <button
                aria-label={`Remove line ${index + 1}`}
                data-detail-remove={index}
                {...transferAction(editorLocked || !canWrite, (origin) => {
                  const next = Math.min(index, items.length - 2);
                  focusAfterUpdate(
                    origin,
                    () =>
                      editor.current?.querySelector<HTMLButtonElement>(
                        `[data-detail-remove="${next}"]`,
                      ) || addButton.current,
                  );
                  setDetailTouched(true);
                  setItems((current) =>
                    current.filter((_, position) => position !== index),
                  );
                })}
              >
                Remove
              </button>
            </div>
          ))}
          <button
            ref={addButton}
            {...transferAction(
              editorLocked || !canWrite || items.length >= 500,
              (origin) => {
                focusAfterUpdate(origin, () =>
                  editor.current?.querySelector<HTMLInputElement>(
                    `[data-detail-description="${items.length}"]`,
                  ),
                );
                setDetailTouched(true);
                setItems((current) => [
                  ...current,
                  { description: "", decimal: "0" },
                ]);
              },
            )}
          >
            Add line
          </button>
          <button
            {...transferAction(editorLocked || !canWrite || !program, () => {
              setReviewed(false);
              void mutation.preview();
            })}
          >
            Preview exact replacement
          </button>
          {mutation.review?.detail && (
            <p role="status">
              Proposed exact total: {mutation.review.detail.total.decimal} ·{" "}
              {mutation.review.detail.itemCount} items · complete set
              replacement
            </p>
          )}
          <button
            {...transferAction(editorLocked, () => openDetail(selected, true))}
          >
            Reread current detail and keep my edits
          </button>
          <label className="review-check">
            <input
              type="checkbox"
              checked={reviewed}
              disabled={
                editorLocked ||
                !canWrite ||
                !validDetailItems(items) ||
                !mutation.review
              }
              onChange={(event) => setReviewed(event.target.checked)}
            />
            I reviewed this exact replacement and its total.
          </label>
          <button
            {...transferAction(
              editorLocked ||
                !canWrite ||
                !reviewed ||
                !validDetailItems(items) ||
                !mutation.review,
              replaceDetail,
            )}
          >
            Replace supporting detail
          </button>
        </fieldset>
      )}
      <p className="authority-note">
        A replacement updates all detail lines and the matching numeric total
        together. Values remain exact; review every line before submitting.
      </p>
    </section>
  );
}
