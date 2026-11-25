import { useEffect, useMemo, useRef, useState } from "react";
import { readProgram } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";
import { useMetadataMutationRecovery } from "./metadata-mutation-recovery";
import {
  focusWhenInteractive,
  MetadataReceiptRecovery,
} from "./MetadataReceiptRecovery";

export type SecurityTagRow = {
  dimension_id: string;
  tag_id: string;
  display_name: string;
  short_description: string;
  semantic_description: string;
  status: "Active" | "Inactive";
};

type SecurityTagPage = {
  rows: SecurityTagRow[];
  nextAfterTagId: string | null;
  metadataRevision: number;
};

type SecurityTagDraft = Pick<
  SecurityTagRow,
  "display_name" | "short_description" | "semantic_description"
>;

const emptyDraft: SecurityTagDraft = {
  display_name: "",
  short_description: "",
  semantic_description: "",
};

const tagWrites = [
  "metadata.security-tag.create",
  "metadata.security-tag.update",
  "metadata.security-tag.status.set",
] as const;

const tagRefusals = new Set([
  "SECURITY_TAG_ID_INVALID",
  "SECURITY_TAG_STATUS_INVALID",
  "SECURITY_TAG_ALREADY_EXISTS",
  "SECURITY_TAG_UNAVAILABLE",
  "SECURITY_TAG_UNCHANGED",
  "SECURITY_TAG_STATUS_UNCHANGED",
  "SECURITY_TAG_IN_USE",
  "ACTIVE_DIMENSION_REQUIRED",
]);

type ReviewedAction =
  | { kind: "create" }
  | { kind: "update"; tagId: string }
  | { kind: "status"; tagId: string; status: "Active" | "Inactive" }
  | null;

export function securityTagListArguments(
  dimension: string,
  afterTagId?: string | null,
  expectedMetadataRevision?: number,
) {
  return afterTagId
    ? { dimension, limit: 100, afterTagId, expectedMetadataRevision }
    : { dimension, limit: 100 };
}

export async function collectSecurityTags(
  dimension: string,
  readPage: (
    arguments_: ReturnType<typeof securityTagListArguments>,
  ) => Promise<SecurityTagPage>,
) {
  let revision: number | undefined;
  return collectAllContinuations<SecurityTagPage, SecurityTagRow>({
    label: "Security Tag catalogue",
    readPage: async (afterTagId) => {
      const page = await readPage(
        securityTagListArguments(dimension, afterTagId, revision),
      );
      revision = page.metadataRevision;
      return page;
    },
    rows: (page) => page.rows,
    nextCursor: (page) => page.nextAfterTagId,
    rowIdentity: (row) => row.tag_id,
    consistencyIdentity: (page) => page.metadataRevision,
  });
}

export function securityTagMutationBody(
  app: ApplicationSummary,
  functionName: (typeof tagWrites)[number],
  args: Record<string, unknown>,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: functionName,
      arguments: args,
    },
  };
}

export function validSecurityTagId(value: string) {
  return (
    value.length >= 1 &&
    value.length <= 20 &&
    value === value.trim() &&
    !value.includes(";") &&
    ![...value].some((character) => character.charCodeAt(0) < 32)
  );
}

const validDraft = (draft: SecurityTagDraft) =>
  draft.display_name.length >= 1 &&
  draft.display_name.length <= 200 &&
  draft.display_name === draft.display_name.trim() &&
  draft.short_description.length <= 500 &&
  draft.semantic_description.length <= 10000;

type SecurityTagCatalogProps = {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimensionId: string;
  metadataRevision: number | null;
  onChanged: () => Promise<void>;
};

export function SecurityTagCatalog(props: SecurityTagCatalogProps) {
  const { app, catalog, dimensionId } = props;
  const owner = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
    dimensionId,
  ]);
  return <SecurityTagEditor key={owner} {...props} />;
}

function SecurityTagEditor({
  app,
  catalog,
  dimensionId,
  metadataRevision,
  onChanged,
}: SecurityTagCatalogProps) {
  const mutationIntentKey = useStableMutationIntentKey("security-tag-ui");
  const [rows, setRows] = useState<SecurityTagRow[]>([]);
  const [drafts, setDrafts] = useState<
    Record<string, Partial<SecurityTagDraft>>
  >({});
  const [tagId, setTagId] = useState("");
  const [createDraft, setCreateDraft] = useState(emptyDraft);
  const [readRevision, setReadRevision] = useState<number | null>(null);
  const [reviewedAction, setReviewedAction] = useState<ReviewedAction>(null);
  const [reading, setReading] = useState(false);
  const [reload, setReload] = useState(0);
  const [recordedAt, setRecordedAt] = useState(0);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const [refreshError, setRefreshError] = useState(false);
  const resultStatus = useRef<HTMLParagraphElement>(null);
  const focusReceipt = useRef(false);

  const canRead = Boolean(catalog?.functions["metadata.security-tag.list"]);
  const canCreate = Boolean(catalog?.functions["metadata.security-tag.create"]);
  const canUpdate = Boolean(catalog?.functions["metadata.security-tag.update"]);
  const canSetStatus = Boolean(
    catalog?.functions["metadata.security-tag.status.set"],
  );
  const actorId = catalog?.applicationAccess.subjectId;
  const workspaceId = app?.workspaceId;
  const applicationId = app?.applicationId;
  const owner = JSON.stringify([
    catalog?.applicationAccess.issuer,
    actorId,
    dimensionId,
  ]);
  const requiredRevision = Math.max(
    metadataRevision ?? 0,
    catalog?.revisions.metadata ?? 0,
    recordedAt,
  );
  const context = JSON.stringify([
    owner,
    canRead,
    catalog?.applicationAccess.role,
    catalog?.revisions.security,
    catalog?.revisions.capability,
  ]);
  const recovery = useMetadataMutationRecovery<{
    actorId: string;
    metadataRevision: number;
    action: Exclude<ReviewedAction, null>;
  }>(
    app,
    catalog,
    context,
    {
      editor: `security-tag-catalog-change:${owner}`,
      pendingLabel: "Security Tag change with an unconfirmed outcome",
      functions: tagWrites,
      subject: "security tag change",
      closePrompt:
        "Close this unconfirmed Security Tag change? Read the current catalogue before reviewing a new change.",
      refuses: (code) => tagRefusals.has(code),
    },
    ({ action, metadataRevision: previous }, source) => {
      if (action.kind === "create") {
        setTagId("");
        setCreateDraft(emptyDraft);
      } else if (action.kind === "update") {
        setDrafts((current) => {
          const next = { ...current };
          delete next[action.tagId];
          return next;
        });
      }
      setReviewedAction(null);
      setRecordedAt(previous + 1);
      setReload((current) => current + 1);
      focusReceipt.current = source === "receipt";
      setResult(
        source === "receipt"
          ? "The original Security Tag change was recorded."
          : "The reviewed security-tag change was applied.",
      );
      setRefreshError(false);
      void Promise.resolve()
        .then(onChanged)
        .catch(() => setRefreshError(true));
    },
  );
  const busy = reading || recovery.busy || recovery.pending;
  const canReview = Boolean(
    actorId &&
      !busy &&
      !error &&
      readRevision !== null &&
      readRevision >= requiredRevision,
  );

  const rowById = useMemo(
    () => new Map(rows.map((row) => [row.tag_id, row])),
    [rows],
  );
  usePreservedDraft(
    workspaceId || "",
    applicationId || "",
    `security-tag-catalog:${owner}`,
    "Unsaved Security Tag catalogue changes",
    Boolean(tagId) ||
      Object.values(createDraft).some(Boolean) ||
      Object.keys(drafts).length > 0,
    { tagId, createDraft, drafts },
    (saved) => {
      setTagId(saved.tagId);
      setCreateDraft(saved.createDraft);
      setDrafts(saved.drafts);
      setReviewedAction(null);
    },
  );

  useEffect(() => {
    if (!workspaceId || !applicationId || !dimensionId || !canRead) return;
    const controller = new AbortController();
    const scope = { workspaceId, applicationId };
    setReading(true);
    setReviewedAction(null);
    setError("");
    void collectSecurityTags(dimensionId, (arguments_) =>
      readProgram(
        scope,
        "metadata.security-tag.list",
        arguments_,
        controller.signal,
      ),
    )
      .then(({ rows, finalPage }) => {
        if (controller.signal.aborted) return;
        if (
          !Number.isSafeInteger(finalPage.metadataRevision) ||
          finalPage.metadataRevision < requiredRevision ||
          rows.some((row) => row.dimension_id !== dimensionId)
        )
          throw new Error(
            "Read the current Security Tag catalogue before editing.",
          );
        setRows(rows);
        setReadRevision(finalPage.metadataRevision);
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted)
          setError(
            reason instanceof Error
              ? reason.message
              : "Unable to read the Security Tag catalogue.",
          );
      })
      .finally(() => {
        if (!controller.signal.aborted) setReading(false);
      });
    return () => controller.abort();
  }, [
    workspaceId,
    applicationId,
    dimensionId,
    canRead,
    context,
    requiredRevision,
    reload,
  ]);

  useEffect(() => {
    if (!result || !focusReceipt.current) return;
    focusReceipt.current = false;
    return focusWhenInteractive(resultStatus.current);
  }, [result]);

  function invalidate() {
    setReviewedAction(null);
    setResult("");
  }

  function edit(
    row: SecurityTagRow,
    field: keyof SecurityTagDraft,
    value: string,
  ) {
    setDrafts((current) => {
      const patch = { ...current[row.tag_id], [field]: value };
      if (value === row[field]) delete patch[field];
      if (Object.keys(patch).length) return { ...current, [row.tag_id]: patch };
      const next = { ...current };
      delete next[row.tag_id];
      return next;
    });
    invalidate();
  }

  async function execute(
    action: Exclude<ReviewedAction, null>,
    functionName: (typeof tagWrites)[number],
    args: Record<string, unknown>,
    confirmation: string,
  ) {
    if (
      !app ||
      !actorId ||
      !canReview ||
      !catalog?.functions[functionName] ||
      readRevision === null ||
      JSON.stringify(reviewedAction) !== JSON.stringify(action) ||
      !window.confirm(confirmation)
    )
      return;
    setReviewedAction(null);
    setResult("");
    await recovery.submit(
      securityTagMutationBody(
        app,
        functionName,
        args,
        mutationIntentKey({
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          functionName,
          args,
        }),
      ),
      { actorId, metadataRevision: readRevision, action },
    );
  }

  if (!canRead) return null;

  const createValid =
    canCreate &&
    validSecurityTagId(tagId) &&
    !rowById.has(tagId) &&
    validDraft(createDraft) &&
    canReview;

  return (
    <section
      className="metadata-subsection"
      aria-labelledby="security-tags-heading"
    >
      <div className="metadata-sheet-heading">
        <div>
          <small>SECURITY TAG CATALOGUE</small>
          <h2 id="security-tags-heading">Governed Security Strings</h2>
          <p>
            Define the exact tag vocabulary for this dimension. Member Security
            Strings can reference only active catalogue tags.
          </p>
        </div>
        <span role="status">
          {reading
            ? "Reading Security Tags…"
            : `${rows.length} ${error ? "previously read" : "current"} rows`}
        </span>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      <MetadataReceiptRecovery
        object="security tag"
        recovery={recovery}
        copyReceiptCheck={recovery.copyReceiptCheck}
        onClose={() => {
          if (!recovery.closeRecovery()) return;
          setReadRevision(null);
          setReviewedAction(null);
          setReload((current) => current + 1);
        }}
      />
      {result && (
        <p role="status" tabIndex={-1} ref={resultStatus}>
          {result}
        </p>
      )}
      {refreshError && (
        <p role="status">
          The change was recorded. Refresh the metadata workspace to update
          related views.
        </p>
      )}
      <button
        type="button"
        disabled={busy}
        onClick={() => setReload((current) => current + 1)}
      >
        Read current Security Tags
      </button>
      <div
        className="react-grid-scroll metadata-sheet"
        tabIndex={0}
        aria-label="Scrollable Security Tag catalogue"
      >
        <table className="react-cube-grid security-tag-grid">
          <thead>
            <tr>
              <th>Stable ID</th>
              <th>Display name</th>
              <th>Short description</th>
              <th>Semantic description</th>
              <th>Status</th>
              <th>Reviewed action</th>
            </tr>
          </thead>
          <tbody>
            {canCreate && (
              <tr className="creation-row">
                <th>
                  <input
                    aria-label="New Security Tag stable ID"
                    value={tagId}
                    maxLength={20}
                    disabled={busy}
                    onChange={(event) => {
                      setTagId(event.target.value);
                      invalidate();
                    }}
                  />
                </th>
                <td>
                  <input
                    aria-label="New Security Tag display name"
                    value={createDraft.display_name}
                    maxLength={200}
                    disabled={busy}
                    onChange={(event) => {
                      setCreateDraft((current) => ({
                        ...current,
                        display_name: event.target.value,
                      }));
                      invalidate();
                    }}
                  />
                </td>
                <td>
                  <input
                    aria-label="New Security Tag short description"
                    value={createDraft.short_description}
                    maxLength={500}
                    disabled={busy}
                    onChange={(event) => {
                      setCreateDraft((current) => ({
                        ...current,
                        short_description: event.target.value,
                      }));
                      invalidate();
                    }}
                  />
                </td>
                <td>
                  <input
                    aria-label="New Security Tag semantic description"
                    value={createDraft.semantic_description}
                    maxLength={10000}
                    disabled={busy}
                    onChange={(event) => {
                      setCreateDraft((current) => ({
                        ...current,
                        semantic_description: event.target.value,
                      }));
                      invalidate();
                    }}
                  />
                </td>
                <td>Active</td>
                <td>
                  <label className="review-check compact-review">
                    <input
                      type="checkbox"
                      checked={reviewedAction?.kind === "create"}
                      disabled={!createValid}
                      onChange={(event) =>
                        setReviewedAction(
                          event.target.checked ? { kind: "create" } : null,
                        )
                      }
                    />
                    Review
                  </label>
                  <button
                    disabled={!createValid || reviewedAction?.kind !== "create"}
                    onClick={() =>
                      void execute(
                        { kind: "create" },
                        "metadata.security-tag.create",
                        {
                          dimensionId,
                          tagId,
                          displayName: createDraft.display_name,
                          shortDescription: createDraft.short_description,
                          semanticDescription: createDraft.semantic_description,
                          expectedMetadataRevision: readRevision,
                        },
                        `Create Security Tag ${tagId} in ${dimensionId}?`,
                      )
                    }
                  >
                    Create
                  </button>
                </td>
              </tr>
            )}
            {rows.map((row) => {
              const draft = {
                display_name: row.display_name,
                short_description: row.short_description,
                semantic_description: row.semantic_description,
                ...drafts[row.tag_id],
              };
              const changed =
                draft.display_name !== row.display_name ||
                draft.short_description !== row.short_description ||
                draft.semantic_description !== row.semantic_description;
              const updateAction: Exclude<ReviewedAction, null> = {
                kind: "update",
                tagId: row.tag_id,
              };
              const nextStatus =
                row.status === "Active" ? "Inactive" : "Active";
              const statusAction: Exclude<ReviewedAction, null> = {
                kind: "status",
                tagId: row.tag_id,
                status: nextStatus,
              };
              return (
                <tr key={row.tag_id}>
                  <th>{row.tag_id}</th>
                  <td>
                    <input
                      aria-label={`${row.tag_id} display name`}
                      value={draft.display_name}
                      maxLength={200}
                      disabled={!canUpdate || busy}
                      onChange={(event) =>
                        edit(row, "display_name", event.target.value)
                      }
                    />
                  </td>
                  <td>
                    <input
                      aria-label={`${row.tag_id} short description`}
                      value={draft.short_description}
                      maxLength={500}
                      disabled={!canUpdate || busy}
                      onChange={(event) =>
                        edit(row, "short_description", event.target.value)
                      }
                    />
                  </td>
                  <td>
                    <input
                      aria-label={`${row.tag_id} semantic description`}
                      value={draft.semantic_description}
                      maxLength={10000}
                      disabled={!canUpdate || busy}
                      onChange={(event) =>
                        edit(row, "semantic_description", event.target.value)
                      }
                    />
                  </td>
                  <td>
                    <span className={`status-chip ${row.status.toLowerCase()}`}>
                      {row.status}
                    </span>
                    {canSetStatus && (
                      <button
                        className="table-link"
                        disabled={!canReview}
                        onClick={() => setReviewedAction(statusAction)}
                      >
                        {nextStatus === "Active" ? "Reactivate" : "Inactivate"}
                      </button>
                    )}
                  </td>
                  <td>
                    {canUpdate && changed && validDraft(draft) && (
                      <>
                        <label className="review-check compact-review">
                          <input
                            type="checkbox"
                            checked={
                              reviewedAction?.kind === "update" &&
                              reviewedAction.tagId === row.tag_id
                            }
                            disabled={!canReview}
                            onChange={(event) =>
                              setReviewedAction(
                                event.target.checked ? updateAction : null,
                              )
                            }
                          />
                          Review edit
                        </label>
                        <button
                          disabled={
                            !canReview ||
                            reviewedAction?.kind !== "update" ||
                            reviewedAction.tagId !== row.tag_id
                          }
                          onClick={() =>
                            void execute(
                              updateAction,
                              "metadata.security-tag.update",
                              {
                                dimensionId,
                                tagId: row.tag_id,
                                displayName: draft.display_name,
                                shortDescription: draft.short_description,
                                semanticDescription: draft.semantic_description,
                                expectedMetadataRevision: readRevision,
                              },
                              `Save the reviewed descriptions for ${row.tag_id}?`,
                            )
                          }
                        >
                          Save
                        </button>
                      </>
                    )}
                    {reviewedAction?.kind === "status" &&
                      reviewedAction.tagId === row.tag_id && (
                        <div className="status-review-action">
                          <span>Review {reviewedAction.status}</span>
                          <button
                            disabled={!canReview || !canSetStatus}
                            onClick={() =>
                              void execute(
                                statusAction,
                                "metadata.security-tag.status.set",
                                {
                                  dimensionId,
                                  tagId: row.tag_id,
                                  status: nextStatus,
                                  expectedMetadataRevision: readRevision,
                                },
                                `${nextStatus} Security Tag ${row.tag_id}?`,
                              )
                            }
                          >
                            Confirm
                          </button>
                          <button
                            disabled={busy}
                            onClick={() => setReviewedAction(null)}
                          >
                            Cancel
                          </button>
                        </div>
                      )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="authority-note">
        Stable IDs are immutable. Display text is editable. In-use tags cannot
        be inactivated, and every accepted change advances the authoritative
        current model and records the governed outcome.
      </p>
    </section>
  );
}
