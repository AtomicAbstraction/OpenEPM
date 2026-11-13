import { useEffect, useMemo, useState } from "react";
import { readProgram, requestAdmittedEffect } from "./api";
import { AttributeValueEditor } from "./AttributeValueEditor";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";

type AttributeScope = "Dimension" | "Member" | "Relationship";
type AttributeStatus = "Active" | "Inactive";
type AttributeValueType = "Text" | "Decimal" | "Boolean" | "MemberReference";

export type AttributeDefinition = {
  attribute_id: string;
  default_name: string;
  display_name: string;
  short_description: string;
  semantic_description: string;
  value_type: AttributeValueType;
  validation_constraints: Record<string, unknown>;
  status: AttributeStatus;
  state_token: string;
};

type AttributeDraft = {
  displayName: string;
  shortDescription: string;
  semanticDescription: string;
  valueType: AttributeValueType;
  constraintsText: string;
};

type Usage = {
  attributeId: string;
  valueCount: number;
  sampleObjectIds: string[];
  sampleTruncated: boolean;
};

type ReviewedAction =
  | { kind: "create" }
  | { kind: "update"; attributeId: string }
  | { kind: "status"; attributeId: string; status: AttributeStatus }
  | null;

const VALUE_TYPES: AttributeValueType[] = [
  "Text",
  "Decimal",
  "Boolean",
  "MemberReference",
];

const emptyDraft = (): AttributeDraft => ({
  displayName: "",
  shortDescription: "",
  semanticDescription: "",
  valueType: "Text",
  constraintsText: "{}",
});

export function validAttributeId(value: string) {
  return /^[A-Za-z][A-Za-z0-9._-]{0,199}$/.test(value);
}

export function parseAttributeConstraints(value: string) {
  const parsed: unknown = JSON.parse(value);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object")
    throw new Error("Validation constraints must be a JSON object.");
  return parsed as Record<string, unknown>;
}

export function attributeListArguments(
  scope: AttributeScope,
  dimensionId: string,
  query: string,
  status: "All" | AttributeStatus,
  afterAttributeId?: string | null,
) {
  return {
    scope,
    ...(scope === "Dimension" ? {} : { dimensionId }),
    ...(query.trim() ? { query: query.trim() } : {}),
    ...(status === "All" ? {} : { status }),
    limit: 100,
    ...(afterAttributeId ? { afterAttributeId } : {}),
  };
}

export function attributeMutationBody(
  app: ApplicationSummary,
  functionName: string,
  args: Record<string, unknown>,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: { languageVersion: 2, function: functionName, arguments: args },
  };
}

function draftFrom(row: AttributeDefinition): AttributeDraft {
  return {
    displayName: row.display_name,
    shortDescription: row.short_description,
    semanticDescription: row.semantic_description,
    valueType: row.value_type,
    constraintsText: JSON.stringify(row.validation_constraints),
  };
}

function validDraft(draft: AttributeDraft) {
  try {
    parseAttributeConstraints(draft.constraintsText);
  } catch {
    return false;
  }
  return (
    draft.displayName.length >= 1 &&
    draft.displayName.length <= 200 &&
    draft.displayName === draft.displayName.trim() &&
    draft.shortDescription.length <= 500 &&
    draft.semanticDescription.length <= 10000
  );
}

export function AttributeCatalog({
  app,
  catalog,
  dimensions,
  dimensionId,
  metadataRevision,
  onChanged,
  contextLocked = false,
  initialScope = "Dimension",
  onRequestTransition = (action) => action(),
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimensions: { dimension_id: string; name: string; status: string }[];
  dimensionId: string;
  metadataRevision: number | null;
  onChanged: () => Promise<void>;
  contextLocked?: boolean;
  initialScope?: AttributeScope;
  onRequestTransition?: (action: () => void) => void;
}) {
  const mutationIntentKey = useStableMutationIntentKey("attribute-ui");
  const [scope, setScope] = useState<AttributeScope>(initialScope);
  const [contextDimension, setContextDimension] = useState(dimensionId);
  const [queryDraft, setQueryDraft] = useState("");
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<"All" | AttributeStatus>("All");
  const [rows, setRows] = useState<AttributeDefinition[]>([]);
  const [drafts, setDrafts] = useState<Record<string, AttributeDraft>>({});
  const [readRevision, setReadRevision] = useState<number | null>(null);
  const [attributeId, setAttributeId] = useState("");
  const [defaultName, setDefaultName] = useState("");
  const [createDraft, setCreateDraft] = useState(emptyDraft);
  const [reviewedAction, setReviewedAction] = useState<ReviewedAction>(null);
  const [usage, setUsage] = useState<Usage | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");

  const canRead = Boolean(
    catalog?.functions["metadata.attribute-definition.list"],
  );
  const canCreate = Boolean(
    catalog?.functions["metadata.attribute-definition.create"],
  );
  const canUpdate = Boolean(
    catalog?.functions["metadata.attribute-definition.update"],
  );
  const canSetStatus = Boolean(
    catalog?.functions["metadata.attribute-definition.status.set"],
  );
  const canReadUsage = Boolean(
    catalog?.functions["metadata.attribute-definition.usage.read"],
  );
  const effectiveDimension =
    scope === "Dimension" ? "" : contextLocked ? dimensionId : contextDimension;
  const rowById = useMemo(
    () => new Map(rows.map((row) => [row.attribute_id, row])),
    [rows],
  );
  const createChanged =
    Boolean(attributeId || defaultName) ||
    JSON.stringify(createDraft) !== JSON.stringify(emptyDraft());
  const existingChanged = rows.some(
    (row) =>
      JSON.stringify(drafts[row.attribute_id] || draftFrom(row)) !==
      JSON.stringify(draftFrom(row)),
  );
  useUnsavedWork(
    `attribute-catalog:${app?.workspaceId || "none"}:${app?.applicationId || "none"}:${scope}:${effectiveDimension || "all"}`,
    "Unsaved Attribute Catalog changes",
    createChanged || existingChanged,
  );

  useEffect(() => {
    setContextDimension((current) =>
      dimensions.some((item) => item.dimension_id === current)
        ? current
        : dimensionId || dimensions[0]?.dimension_id || "",
    );
  }, [dimensionId, dimensions]);

  async function readDefinitions() {
    if (!app || !canRead || (scope !== "Dimension" && !effectiveDimension))
      return;
    setBusy(true);
    setError("");
    setUsage(null);
    try {
      type AttributePage = {
        rows: AttributeDefinition[];
        nextAfterAttributeId: string | null;
        metadataRevision: number;
      };
      const collected = await collectAllContinuations<
        AttributePage,
        AttributeDefinition
      >({
        label: "Attribute Catalog",
        readPage: (after) =>
          readProgram(
            { workspaceId: app.workspaceId, applicationId: app.applicationId },
            "metadata.attribute-definition.list",
            attributeListArguments(
              scope,
              effectiveDimension,
              query,
              status,
              after,
            ),
          ),
        rows: (page) => page.rows,
        nextCursor: (page) => page.nextAfterAttributeId,
        rowIdentity: (row) => row.attribute_id,
        consistencyIdentity: (page) => page.metadataRevision,
      });
      const found = collected.rows;
      const revision = collected.finalPage.metadataRevision;
      setRows(found);
      setDrafts(
        Object.fromEntries(
          found.map((row) => [row.attribute_id, draftFrom(row)]),
        ),
      );
      setReadRevision(revision);
      setReviewedAction(null);
    } catch (reason) {
      setRows([]);
      setDrafts({});
      setReadRevision(null);
      setError(
        reason instanceof Error ? reason.message : "Unable to read attributes",
      );
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    setRows([]);
    setDrafts({});
    setReadRevision(null);
    setAttributeId("");
    setDefaultName("");
    setCreateDraft(emptyDraft());
    setReviewedAction(null);
    setUsage(null);
    setError("");
    setResult("");
    if (app && canRead && (scope === "Dimension" || effectiveDimension))
      void readDefinitions();
  }, [
    app?.workspaceId,
    app?.applicationId,
    scope,
    effectiveDimension,
    query,
    status,
    canRead,
  ]);

  useEffect(() => {
    if (
      metadataRevision !== null &&
      readRevision !== null &&
      metadataRevision !== readRevision
    )
      void readDefinitions();
  }, [metadataRevision]);

  function invalidate() {
    setReviewedAction(null);
    setResult("");
  }

  function contextArguments() {
    return scope === "Dimension"
      ? { scope }
      : { scope, dimensionId: effectiveDimension };
  }

  async function mutate(
    action: Exclude<ReviewedAction, null>,
    functionName: string,
    args: Record<string, unknown>,
    confirmation: string,
  ) {
    if (
      !app ||
      readRevision === null ||
      busy ||
      JSON.stringify(action) !== JSON.stringify(reviewedAction) ||
      !window.confirm(confirmation)
    )
      return;
    setBusy(true);
    setError("");
    setResult("");
    try {
      await requestAdmittedEffect<{
        result?: { operationId?: string; receiptId?: string };
        receiptId?: string;
      }>(
        "/api/metadata-action",
        attributeMutationBody(
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
      setResult("The reviewed attribute change was applied.");
      setReviewedAction(null);
      setAttributeId("");
      setDefaultName("");
      setCreateDraft(emptyDraft());
      await onChanged();
      await readDefinitions();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to apply the Attribute Catalog change",
      );
    } finally {
      setBusy(false);
    }
  }

  async function readUsage(row: AttributeDefinition) {
    if (!app || !canReadUsage) return;
    setBusy(true);
    setError("");
    try {
      const value = await readProgram<{
        valueCount: number;
        sampleObjectIds: string[];
        sampleTruncated: boolean;
      }>(
        { workspaceId: app.workspaceId, applicationId: app.applicationId },
        "metadata.attribute-definition.usage.read",
        { ...contextArguments(), attributeId: row.attribute_id },
      );
      setUsage({ attributeId: row.attribute_id, ...value });
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read usage",
      );
    } finally {
      setBusy(false);
    }
  }

  if (!canRead) return null;

  const createValid =
    canCreate &&
    readRevision !== null &&
    validAttributeId(attributeId) &&
    !rowById.has(attributeId) &&
    defaultName.length > 0 &&
    defaultName.length <= 200 &&
    defaultName === defaultName.trim() &&
    validDraft(createDraft);

  return (
    <section
      className="metadata-subsection"
      aria-labelledby="attribute-catalog-heading"
    >
      <div className="metadata-sheet-heading">
        <div>
          <small>APPLICATION ATTRIBUTE CATALOG</small>
          <h2 id="attribute-catalog-heading">Attribute definitions</h2>
          <p>
            Search and govern stable attributes. Default names and IDs are
            immutable; display labels and semantic guidance can evolve.
          </p>
        </div>
        <span>{rows.length} current rows</span>
      </div>
      <div className="metadata-workbook-toolbar attribute-catalog-toolbar">
        <label>
          Scope
          <select
            aria-label="Attribute scope"
            value={scope}
            onChange={(event) => {
              const value = event.target.value as AttributeScope;
              onRequestTransition(() => setScope(value));
            }}
          >
            <option>Dimension</option>
            <option>Member</option>
            <option>Relationship</option>
          </select>
        </label>
        {scope !== "Dimension" && !contextLocked && (
          <label>
            Dimension
            <select
              aria-label="Attribute dimension"
              value={contextDimension}
              onChange={(event) => {
                const value = event.target.value;
                onRequestTransition(() => setContextDimension(value));
              }}
            >
              {dimensions.map((item) => (
                <option key={item.dimension_id} value={item.dimension_id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
        )}
        <label>
          Status
          <select
            aria-label="Attribute status filter"
            value={status}
            onChange={(event) => {
              const value = event.target.value as typeof status;
              onRequestTransition(() => setStatus(value));
            }}
          >
            <option>All</option>
            <option>Active</option>
            <option>Inactive</option>
          </select>
        </label>
        <form
          className="attribute-search"
          onSubmit={(event) => {
            event.preventDefault();
            const value = queryDraft.trim();
            onRequestTransition(() => setQuery(value));
          }}
        >
          <label>
            Search
            <input
              aria-label="Search attributes"
              value={queryDraft}
              maxLength={200}
              onChange={(event) => setQueryDraft(event.target.value)}
            />
          </label>
          <button type="submit" disabled={busy}>
            Search
          </button>
        </form>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {result && <p role="status">{result}</p>}
      {usage && (
        <aside className="attribute-usage" aria-label="Attribute usage">
          <strong>{usage.attributeId}</strong> is populated on{" "}
          {usage.valueCount} object{usage.valueCount === 1 ? "" : "s"}.
          {usage.sampleObjectIds.length > 0 && (
            <span>
              {" "}
              Sample: {usage.sampleObjectIds.join(", ")}
              {usage.sampleTruncated ? "…" : ""}
            </span>
          )}
          <button onClick={() => setUsage(null)}>Close</button>
        </aside>
      )}
      <div
        className="react-grid-scroll metadata-sheet"
        tabIndex={0}
        aria-label="Scrollable Attribute Catalog"
      >
        <table className="react-cube-grid attribute-catalog-grid">
          <thead>
            <tr>
              <th>Stable ID</th>
              <th>Default name</th>
              <th>Display name</th>
              <th>Short description</th>
              <th>Semantic description</th>
              <th>Type</th>
              <th>Constraints</th>
              <th>Status / usage</th>
              <th>Reviewed action</th>
            </tr>
          </thead>
          <tbody>
            {canCreate && (
              <tr className="creation-row">
                <th>
                  <input
                    aria-label="New Attribute stable ID"
                    value={attributeId}
                    maxLength={200}
                    onChange={(event) => {
                      setAttributeId(event.target.value);
                      invalidate();
                    }}
                  />
                </th>
                <td>
                  <input
                    aria-label="New Attribute default name"
                    value={defaultName}
                    maxLength={200}
                    onChange={(event) => {
                      setDefaultName(event.target.value);
                      invalidate();
                    }}
                  />
                </td>
                <td>
                  <input
                    aria-label="New Attribute display name"
                    value={createDraft.displayName}
                    maxLength={200}
                    onChange={(event) => {
                      setCreateDraft((current) => ({
                        ...current,
                        displayName: event.target.value,
                      }));
                      invalidate();
                    }}
                  />
                </td>
                <td>
                  <input
                    aria-label="New Attribute short description"
                    value={createDraft.shortDescription}
                    maxLength={500}
                    onChange={(event) => {
                      setCreateDraft((current) => ({
                        ...current,
                        shortDescription: event.target.value,
                      }));
                      invalidate();
                    }}
                  />
                </td>
                <td>
                  <input
                    aria-label="New Attribute semantic description"
                    value={createDraft.semanticDescription}
                    maxLength={10000}
                    onChange={(event) => {
                      setCreateDraft((current) => ({
                        ...current,
                        semanticDescription: event.target.value,
                      }));
                      invalidate();
                    }}
                  />
                </td>
                <td>
                  <select
                    aria-label="New Attribute value type"
                    value={createDraft.valueType}
                    onChange={(event) => {
                      setCreateDraft((current) => ({
                        ...current,
                        valueType: event.target.value as AttributeValueType,
                      }));
                      invalidate();
                    }}
                  >
                    {VALUE_TYPES.map((value) => (
                      <option key={value}>{value}</option>
                    ))}
                  </select>
                </td>
                <td>
                  <input
                    aria-label="New Attribute constraints"
                    value={createDraft.constraintsText}
                    onChange={(event) => {
                      setCreateDraft((current) => ({
                        ...current,
                        constraintsText: event.target.value,
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
                      void mutate(
                        { kind: "create" },
                        "metadata.attribute-definition.create",
                        {
                          ...contextArguments(),
                          attributeId,
                          defaultName,
                          displayName: createDraft.displayName,
                          shortDescription: createDraft.shortDescription,
                          semanticDescription: createDraft.semanticDescription,
                          valueType: createDraft.valueType,
                          validationConstraints: parseAttributeConstraints(
                            createDraft.constraintsText,
                          ),
                          expectedMetadataRevision: readRevision,
                        },
                        `Create Attribute ${attributeId}?`,
                      )
                    }
                  >
                    Create
                  </button>
                </td>
              </tr>
            )}
            {rows.map((row) => {
              const draft = drafts[row.attribute_id] || draftFrom(row);
              const changed =
                JSON.stringify(draft) !== JSON.stringify(draftFrom(row));
              const updateAction: Exclude<ReviewedAction, null> = {
                kind: "update",
                attributeId: row.attribute_id,
              };
              const nextStatus: AttributeStatus =
                row.status === "Active" ? "Inactive" : "Active";
              const statusAction: Exclude<ReviewedAction, null> = {
                kind: "status",
                attributeId: row.attribute_id,
                status: nextStatus,
              };
              return (
                <tr key={row.attribute_id}>
                  <th>{row.attribute_id}</th>
                  <td>{row.default_name}</td>
                  <td>
                    <input
                      aria-label={`${row.attribute_id} display name`}
                      value={draft.displayName}
                      disabled={!canUpdate}
                      onChange={(event) => {
                        setDrafts((current) => ({
                          ...current,
                          [row.attribute_id]: {
                            ...draft,
                            displayName: event.target.value,
                          },
                        }));
                        invalidate();
                      }}
                    />
                  </td>
                  <td>
                    <input
                      aria-label={`${row.attribute_id} short description`}
                      value={draft.shortDescription}
                      disabled={!canUpdate}
                      onChange={(event) => {
                        setDrafts((current) => ({
                          ...current,
                          [row.attribute_id]: {
                            ...draft,
                            shortDescription: event.target.value,
                          },
                        }));
                        invalidate();
                      }}
                    />
                  </td>
                  <td>
                    <input
                      aria-label={`${row.attribute_id} semantic description`}
                      value={draft.semanticDescription}
                      disabled={!canUpdate}
                      onChange={(event) => {
                        setDrafts((current) => ({
                          ...current,
                          [row.attribute_id]: {
                            ...draft,
                            semanticDescription: event.target.value,
                          },
                        }));
                        invalidate();
                      }}
                    />
                  </td>
                  <td>
                    <select
                      aria-label={`${row.attribute_id} value type`}
                      value={draft.valueType}
                      disabled={!canUpdate}
                      onChange={(event) => {
                        setDrafts((current) => ({
                          ...current,
                          [row.attribute_id]: {
                            ...draft,
                            valueType: event.target.value as AttributeValueType,
                          },
                        }));
                        invalidate();
                      }}
                    >
                      {VALUE_TYPES.map((value) => (
                        <option key={value}>{value}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <input
                      aria-label={`${row.attribute_id} constraints`}
                      value={draft.constraintsText}
                      disabled={!canUpdate}
                      onChange={(event) => {
                        setDrafts((current) => ({
                          ...current,
                          [row.attribute_id]: {
                            ...draft,
                            constraintsText: event.target.value,
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
                    {canReadUsage && (
                      <button
                        className="table-link"
                        onClick={() => void readUsage(row)}
                      >
                        Usage
                      </button>
                    )}
                    {canSetStatus && (
                      <button
                        className="table-link"
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
                              reviewedAction.attributeId === row.attribute_id
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
                            reviewedAction.attributeId !== row.attribute_id
                          }
                          onClick={() =>
                            void mutate(
                              updateAction,
                              "metadata.attribute-definition.update",
                              {
                                ...contextArguments(),
                                attributeId: row.attribute_id,
                                displayName: draft.displayName,
                                shortDescription: draft.shortDescription,
                                semanticDescription: draft.semanticDescription,
                                valueType: draft.valueType,
                                validationConstraints:
                                  parseAttributeConstraints(
                                    draft.constraintsText,
                                  ),
                                expectedStateToken: row.state_token,
                                expectedMetadataRevision: readRevision,
                              },
                              `Save the reviewed definition for ${row.attribute_id}?`,
                            )
                          }
                        >
                          Save
                        </button>
                      </>
                    )}
                    {reviewedAction?.kind === "status" &&
                      reviewedAction.attributeId === row.attribute_id && (
                        <div className="status-review-action">
                          <span>Review {nextStatus}</span>
                          <button
                            disabled={busy}
                            onClick={() =>
                              void mutate(
                                statusAction,
                                "metadata.attribute-definition.status.set",
                                {
                                  ...contextArguments(),
                                  attributeId: row.attribute_id,
                                  status: nextStatus,
                                  expectedStateToken: row.state_token,
                                  expectedMetadataRevision: readRevision,
                                },
                                `${nextStatus} Attribute ${row.attribute_id}?`,
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
      <AttributeValueEditor
        app={app}
        catalog={catalog}
        scope={scope}
        dimensionId={effectiveDimension}
        definitions={rows}
        dimensions={dimensions}
        definitionRevision={readRevision}
        onChanged={async () => {
          await onChanged();
          await readDefinitions();
        }}
      />
      <p className="authority-note">
        The browser stores no definition authority. Every accepted edit is
        revalidated by the fixed core and recorded as a governed change.
      </p>
    </section>
  );
}
