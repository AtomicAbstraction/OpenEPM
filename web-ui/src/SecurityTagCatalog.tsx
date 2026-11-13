import { useEffect, useMemo, useState } from "react";
import { readProgram, requestAdmittedEffect } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";

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
  functionName:
    | "metadata.security-tag.create"
    | "metadata.security-tag.update"
    | "metadata.security-tag.status.set",
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

export function SecurityTagCatalog({
  app,
  catalog,
  dimensionId,
  metadataRevision,
  onChanged,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimensionId: string;
  metadataRevision: number | null;
  onChanged: () => Promise<void>;
}) {
  const mutationIntentKey = useStableMutationIntentKey("security-tag-ui");
  const [rows, setRows] = useState<SecurityTagRow[]>([]);
  const [drafts, setDrafts] = useState<Record<string, SecurityTagDraft>>({});
  const [tagId, setTagId] = useState("");
  const [createDraft, setCreateDraft] = useState<SecurityTagDraft>({
    display_name: "",
    short_description: "",
    semantic_description: "",
  });
  const [readRevision, setReadRevision] = useState<number | null>(null);
  const [reviewedAction, setReviewedAction] = useState<ReviewedAction>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");

  const canRead = Boolean(catalog?.functions["metadata.security-tag.list"]);
  const canCreate = Boolean(catalog?.functions["metadata.security-tag.create"]);
  const canUpdate = Boolean(catalog?.functions["metadata.security-tag.update"]);
  const canSetStatus = Boolean(
    catalog?.functions["metadata.security-tag.status.set"],
  );

  const rowById = useMemo(
    () => new Map(rows.map((row) => [row.tag_id, row])),
    [rows],
  );
  const createChanged =
    Boolean(tagId) ||
    createDraft.display_name !== "" ||
    createDraft.short_description !== "" ||
    createDraft.semantic_description !== "";
  const existingChanged = rows.some((row) => {
    const draft = drafts[row.tag_id];
    return Boolean(
      draft &&
        (draft.display_name !== row.display_name ||
          draft.short_description !== row.short_description ||
          draft.semantic_description !== row.semantic_description),
    );
  });
  useUnsavedWork(
    `security-tag-catalog:${app?.workspaceId || "none"}:${app?.applicationId || "none"}:${dimensionId || "none"}`,
    "Unsaved Security Tag catalogue changes",
    createChanged || existingChanged,
  );

  async function readTags() {
    if (!app || !dimensionId || !canRead) return;
    setBusy(true);
    setError("");
    try {
      const collected = await collectSecurityTags(dimensionId, (arguments_) =>
        readProgram(
          { workspaceId: app.workspaceId, applicationId: app.applicationId },
          "metadata.security-tag.list",
          arguments_,
        ),
      );
      const found = collected.rows;
      setRows(found);
      setDrafts(
        Object.fromEntries(
          found.map((row) => [
            row.tag_id,
            {
              display_name: row.display_name,
              short_description: row.short_description,
              semantic_description: row.semantic_description,
            },
          ]),
        ),
      );
      setReadRevision(collected.finalPage.metadataRevision);
      setReviewedAction(null);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read the Security Tag catalogue",
      );
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    setRows([]);
    setDrafts({});
    setReadRevision(null);
    setTagId("");
    setCreateDraft({
      display_name: "",
      short_description: "",
      semantic_description: "",
    });
    setReviewedAction(null);
    setError("");
    setResult("");
    if (app && dimensionId && canRead) void readTags();
  }, [app?.workspaceId, app?.applicationId, dimensionId, canRead]);

  useEffect(() => {
    if (
      app &&
      dimensionId &&
      canRead &&
      metadataRevision !== null &&
      readRevision !== null &&
      metadataRevision !== readRevision
    )
      void readTags();
  }, [metadataRevision]);

  function invalidate() {
    setReviewedAction(null);
    setResult("");
  }

  async function execute(
    action: Exclude<ReviewedAction, null>,
    functionName:
      | "metadata.security-tag.create"
      | "metadata.security-tag.update"
      | "metadata.security-tag.status.set",
    args: Record<string, unknown>,
    confirmation: string,
  ) {
    if (
      !app ||
      readRevision === null ||
      busy ||
      JSON.stringify(reviewedAction) !== JSON.stringify(action) ||
      !window.confirm(confirmation)
    )
      return;
    setBusy(true);
    setError("");
    setResult("");
    try {
      await requestAdmittedEffect<{
        receiptId?: string;
        result?: { receiptId?: string };
      }>(
        "/api/metadata-action",
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
      );
      setReviewedAction(null);
      setResult("The reviewed security-tag change was applied.");
      await onChanged();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to apply the Security Tag change",
      );
    } finally {
      setBusy(false);
    }
  }

  if (!canRead) return null;

  const createValid =
    canCreate &&
    validSecurityTagId(tagId) &&
    !rowById.has(tagId) &&
    validDraft(createDraft) &&
    readRevision !== null;

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
        <span>{rows.length} current rows</span>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {result && <p role="status">{result}</p>}
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
                    disabled={busy || reviewedAction?.kind !== "create"}
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
              const draft = drafts[row.tag_id] || {
                display_name: row.display_name,
                short_description: row.short_description,
                semantic_description: row.semantic_description,
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
                      disabled={!canUpdate}
                      onChange={(event) => {
                        setDrafts((current) => ({
                          ...current,
                          [row.tag_id]: {
                            ...draft,
                            display_name: event.target.value,
                          },
                        }));
                        invalidate();
                      }}
                    />
                  </td>
                  <td>
                    <input
                      aria-label={`${row.tag_id} short description`}
                      value={draft.short_description}
                      maxLength={500}
                      disabled={!canUpdate}
                      onChange={(event) => {
                        setDrafts((current) => ({
                          ...current,
                          [row.tag_id]: {
                            ...draft,
                            short_description: event.target.value,
                          },
                        }));
                        invalidate();
                      }}
                    />
                  </td>
                  <td>
                    <input
                      aria-label={`${row.tag_id} semantic description`}
                      value={draft.semantic_description}
                      maxLength={10000}
                      disabled={!canUpdate}
                      onChange={(event) => {
                        setDrafts((current) => ({
                          ...current,
                          [row.tag_id]: {
                            ...draft,
                            semantic_description: event.target.value,
                          },
                        }));
                        invalidate();
                      }}
                    />
                  </td>
                  <td>
                    <span className={`status-chip ${row.status.toLowerCase()}`}>
                      {row.status}
                    </span>
                    {canSetStatus && (
                      <button
                        className="table-link"
                        disabled={busy}
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
                            busy ||
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
                            disabled={busy}
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
                          <button onClick={() => setReviewedAction(null)}>
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
