import { useEffect, useRef, useState } from "react";
import { ApiError, readProgram } from "./api";
import type { Scope } from "./types";

export const WORKFLOW_LIST = "application.workflow.list";
export const WORKFLOW_READ = "application.workflow.read";
export const WORKFLOW_START = "application.workflow.occurrence.start";

const TOKEN = /^[0-9a-f]{64}$/;
const FLOW_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}$/;

type WorkflowSummary = {
  flowId: string;
  name: string;
  status: "Active";
  stateToken: string;
  definitionDigest: string;
};
type Page = {
  workflows: WorkflowSummary[];
  collectionToken: string;
  nextAfterFlowId: string | null;
};
type Cursor = Pick<Page, "collectionToken"> & { afterFlowId: string };
export type WorkflowStartReview = WorkflowSummary & {
  metadataRevision: number;
  policyRevision: number;
  schemaEpoch: number;
};

function validSummary(row: WorkflowSummary) {
  return (
    row &&
    typeof row.flowId === "string" &&
    FLOW_ID.test(row.flowId) &&
    typeof row.name === "string" &&
    row.name.length > 0 &&
    row.name.length <= 200 &&
    row.status === "Active" &&
    typeof row.stateToken === "string" &&
    TOKEN.test(row.stateToken) &&
    typeof row.definitionDigest === "string" &&
    TOKEN.test(row.definitionDigest)
  );
}

export function WorkflowStarter({
  scope,
  blocked,
  activityDraft,
  onStart,
}: {
  scope: Scope;
  blocked: boolean;
  activityDraft: boolean;
  onStart: (
    review: WorkflowStartReview,
    origin: HTMLButtonElement,
  ) => Promise<{ reloadNotice: string } | undefined>;
}) {
  const [request, setRequest] = useState<{ cursor?: Cursor } | null>(null);
  const [page, setPage] = useState<Page | null>(null);
  const [selected, setSelected] = useState<WorkflowSummary | null>(null);
  const [review, setReview] = useState<WorkflowStartReview | null>(null);
  const [error, setError] = useState("");
  const heading = useRef<HTMLHeadingElement>(null);
  const { workspaceId, applicationId } = scope;

  function load(next: { cursor?: Cursor } | null) {
    setRequest(next);
    setPage(null);
    setSelected(null);
    setReview(null);
    setError("");
  }

  function changePage(next: { cursor?: Cursor }) {
    heading.current?.focus();
    load(next);
  }

  async function submit(
    reviewed: WorkflowStartReview,
    button: HTMLButtonElement,
  ) {
    const document = button.ownerDocument;
    const startedWithFocus = document.activeElement === button;
    const refusal = await onStart(reviewed, button);
    if (!refusal || !heading.current) return;
    if (
      document.activeElement === button ||
      (startedWithFocus && document.activeElement === document.body)
    )
      heading.current.focus();
    setPage(null);
    setSelected(null);
    setReview(null);
    setError(refusal.reloadNotice);
  }

  useEffect(() => {
    if (!request) return;
    const controller = new AbortController();
    void readProgram<Page>(
      { workspaceId, applicationId },
      WORKFLOW_LIST,
      { limit: 50, status: "Active", ...request.cursor },
      controller.signal,
    )
      .then((value) => {
        if (controller.signal.aborted) return;
        if (
          !value ||
          !Array.isArray(value.workflows) ||
          value.workflows.length > 50 ||
          !value.workflows.every(validSummary) ||
          new Set(value.workflows.map((row) => row.flowId)).size !==
            value.workflows.length ||
          typeof value.collectionToken !== "string" ||
          !TOKEN.test(value.collectionToken) ||
          (request.cursor &&
            (value.workflows.length === 0 ||
              request.cursor.collectionToken !== value.collectionToken ||
              value.workflows.some(
                (row) => row.flowId === request.cursor?.afterFlowId,
              ))) ||
          (value.nextAfterFlowId !== null &&
            (typeof value.nextAfterFlowId !== "string" ||
              value.nextAfterFlowId !== value.workflows.at(-1)?.flowId))
        )
          throw new Error("Invalid workflow page");
        setPage(value);
      })
      .catch((failure) => {
        if (!controller.signal.aborted)
          setError(
            failure instanceof ApiError &&
              failure.code === "APPLICATION_WORKFLOW_COLLECTION_CHANGED"
              ? "The workflow list changed. Open the first page again."
              : "The workflow list could not be read. Open the first page to retry.",
          );
      });
    return () => controller.abort();
  }, [request, workspaceId, applicationId]);

  useEffect(() => {
    if (!selected) return;
    const controller = new AbortController();
    void readProgram<
      WorkflowStartReview & { definition: Scope & { flowId: string } }
    >(
      { workspaceId, applicationId },
      WORKFLOW_READ,
      { flowId: selected.flowId },
      controller.signal,
    )
      .then((value) => {
        if (controller.signal.aborted) return;
        if (
          !validSummary(value) ||
          value.flowId !== selected.flowId ||
          value.stateToken !== selected.stateToken ||
          value.definitionDigest !== selected.definitionDigest ||
          value.definition?.flowId !== selected.flowId ||
          value.definition.workspaceId !== workspaceId ||
          value.definition.applicationId !== applicationId ||
          ![
            value.metadataRevision,
            value.policyRevision,
            value.schemaEpoch,
          ].every((pin) => Number.isSafeInteger(pin) && pin >= 0)
        )
          throw new Error("Invalid workflow start pins");
        setReview(value);
      })
      .catch((failure) => {
        if (controller.signal.aborted) return;
        if (
          failure instanceof ApiError &&
          (failure.kind === "authorization" ||
            failure.kind === "authentication" ||
            [
              "APPLICATION_WORKFLOW_UNAVAILABLE",
              "APPLICATION_WORKFLOW_AUTHORIZATION_STALE",
              "APPLICATION_WORKFLOW_READ_STALE",
            ].includes(failure.code))
        ) {
          heading.current?.focus();
          setPage(null);
          setSelected(null);
          setReview(null);
        }
        setError(
          "The current workflow could not be confirmed. Open the first page to refresh it.",
        );
      });
    return () => controller.abort();
  }, [selected, workspaceId, applicationId]);

  const active = page?.workflows ?? [];
  return (
    <section className="panel" aria-label="Start a workflow">
      <button
        type="button"
        aria-expanded={Boolean(request)}
        disabled={blocked}
        onClick={() => load(request ? null : {})}
      >
        {request ? "Hide published workflows" : "Show published workflows"}
      </button>
      {request && (
        <>
          <h2 ref={heading} tabIndex={-1}>
            Published workflows
          </h2>
          {error ? (
            <p role="alert">{error}</p>
          ) : !page ? (
            <p role="status">Reading workflows…</p>
          ) : null}
          {(request.cursor || error) && (
            <button
              type="button"
              disabled={blocked}
              onClick={() => changePage({})}
            >
              First workflow page
            </button>
          )}
          {page && (
            <>
              {active.length === 0 && <p>No active workflows.</p>}
              {active.length > 0 && (
                <label>
                  <span>Published workflow</span>
                  <select
                    value={selected?.flowId ?? ""}
                    disabled={blocked}
                    onChange={(event) => {
                      setReview(null);
                      setError("");
                      setSelected(
                        active.find(
                          (row) => row.flowId === event.target.value,
                        ) ?? null,
                      );
                    }}
                  >
                    <option value="">Choose a published workflow</option>
                    {active.map((row) => (
                      <option key={row.flowId} value={row.flowId}>
                        {row.name} ({row.flowId})
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {page.nextAfterFlowId && (
                <button
                  type="button"
                  disabled={blocked}
                  onClick={() =>
                    changePage({
                      cursor: {
                        afterFlowId: page.nextAfterFlowId!,
                        collectionToken: page.collectionToken,
                      },
                    })
                  }
                >
                  Next workflow page
                </button>
              )}
            </>
          )}
          {selected && !review && !error && (
            <p role="status">Checking the current workflow…</p>
          )}
          {review && (
            <>
              {activityDraft && (
                <p>
                  Finish the current activity draft before starting another
                  workflow.
                </p>
              )}
              <button
                type="button"
                disabled={blocked || activityDraft}
                onClick={(event) => void submit(review, event.currentTarget)}
              >
                Start occurrence
              </button>
            </>
          )}
        </>
      )}
    </section>
  );
}
