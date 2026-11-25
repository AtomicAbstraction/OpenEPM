import { useState } from "react";
import { ReceiptInspector } from "./ReceiptInspector";
import { transferAction } from "./data-transfer-action";
import type { ApplicationCatalog, Scope } from "./types";
import type { WorkflowOutcome } from "./workflow-outcome";

const pageSize = 20;

export function WorkflowCheckpointEvidence({
  workflow,
  scope,
  catalog,
  unitNames,
}: {
  workflow: WorkflowOutcome;
  scope: Scope;
  catalog: ApplicationCatalog;
  unitNames?: ReadonlyArray<{ unitName: string }>;
}) {
  const [page, setPage] = useState(0);
  const [selection, setSelection] = useState<{
    ordinal: number;
    receiptId: string;
  } | null>(null);
  if (!workflow.checkpoints.length) return null;

  const start = page * pageSize;
  const end = Math.min(start + pageSize, workflow.unitCount);
  const canReadReceipt = Boolean(
    catalog.functions["application.operation.receipt.read"],
  );
  const selected = selection && workflow.checkpoints[selection.ordinal - 1];
  const receipt =
    canReadReceipt &&
    selection &&
    selected?.committed &&
    selected.receiptId === selection.receiptId
      ? selection
      : null;

  function movePage(page: number) {
    setSelection(null);
    setPage(page);
  }

  return (
    <details
      onToggle={(event) => {
        if (!event.currentTarget.open) setSelection(null);
      }}
    >
      <summary>Workflow checkpoint evidence</summary>
      <ol start={start + 1}>
        {Array.from({ length: end - start }, (_, index) => {
          const slot = start + index;
          const ordinal = slot + 1;
          const checkpoint = workflow.checkpoints[slot];
          const name = unitNames?.[slot]?.unitName;
          const receiptId = checkpoint?.committed ? checkpoint.receiptId : null;
          return (
            <li key={ordinal}>
              {name && <strong>{name} · </strong>}
              {receiptId
                ? "Committed with receipt"
                : checkpoint
                  ? "Checkpoint recorded without a confirmed receipt"
                  : "No checkpoint recorded"}
              {receiptId && canReadReceipt && (
                <>
                  {" "}
                  <button
                    type="button"
                    onClick={() => setSelection({ ordinal, receiptId })}
                    aria-label={`Inspect receipt for step ${ordinal}${name ? ` (${name})` : ""}`}
                  >
                    Inspect receipt
                  </button>
                </>
              )}
            </li>
          );
        })}
      </ol>
      {workflow.unitCount > pageSize && (
        <div className="inline-actions">
          <span role="status">
            Steps {start + 1}–{end} of {workflow.unitCount}
          </span>
          <button {...transferAction(page === 0, () => movePage(page - 1))}>
            Previous steps
          </button>
          <button
            {...transferAction(end === workflow.unitCount, () =>
              movePage(page + 1),
            )}
          >
            Next steps
          </button>
        </div>
      )}
      {!canReadReceipt && workflow.committedUnits > 0 && (
        <p>
          Receipt details are unavailable in the current application context.
        </p>
      )}
      {receipt && (
        <ReceiptInspector
          title={`Step ${receipt.ordinal} receipt`}
          scope={scope}
          catalog={catalog}
          operationId={receipt.receiptId}
          close={() => setSelection(null)}
        />
      )}
    </details>
  );
}
