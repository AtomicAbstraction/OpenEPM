import { useEffect, useRef, useState } from "react";
import { readProgram } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import {
  collectCapabilityDimensions,
  type MetadataDimension,
} from "./metadata-data";
import {
  collectMetadataHierarchies,
  type MetadataHierarchy,
} from "./metadata-hierarchies";
import { collectAllContinuations } from "./continuation";
import { useUnsavedWork } from "./unsaved-work";
import { parseParameterJson } from "./exact-parameters";

const hierarchyKinds = [
  "parents",
  "base",
  "children",
  "descendants",
  "ancestors",
  "siblings",
  "leaves",
];
type Expression = Record<string, unknown>;
type Attribute = {
  attribute_id: string;
  display_name: string;
  value_type: string;
  status: string;
};
type AttributePage = {
  rows: Attribute[];
  nextAfterAttributeId: string | null;
  metadataRevision: number;
  hasMore: boolean;
};
export type SelectionDefinition = {
  format: "openepm-member-list-v1";
  listId: string;
  dimensionId: string;
  name: string;
  parameters: unknown[];
  expression: Expression;
};
function object(value: unknown): value is Expression {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function simple(expression: unknown): expression is Expression {
  return (
    object(expression) &&
    (["explicit", ...hierarchyKinds].includes(String(expression.kind)) ||
      (expression.kind === "attribute" &&
        expression.operator !== "in" &&
        ["string", "boolean"].includes(typeof expression.value)))
  );
}
function newExpression(kind: string): Expression {
  if (kind === "explicit") return { kind, memberIds: [] };
  if (kind === "attribute")
    return { kind, attributeId: "", operator: "eq", value: "" };
  return { kind, hierarchyId: "", memberId: "", includeSelf: false };
}
export function NativeSelectionEditor({
  app,
  catalog,
  initial,
  current,
  busy,
  onSave,
  onDirtyChange,
}: {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
  initial?: Record<string, unknown> | null;
  current: boolean;
  busy: boolean;
  onSave: (definition: SelectionDefinition) => Promise<void>;
  onDirtyChange: (dirty: boolean) => void;
}) {
  const [listId, setListId] = useState(String(initial?.listId ?? ""));
  const [name, setName] = useState(String(initial?.name ?? ""));
  const [dimensionId, setDimensionId] = useState(
    String(initial?.dimensionId ?? ""),
  );
  const [expression, setExpression] = useState<Expression>(
    object(initial?.expression)
      ? initial.expression
      : newExpression("explicit"),
  );
  const [memberText, setMemberText] = useState(
    object(initial?.expression) && Array.isArray(initial.expression.memberIds)
      ? initial.expression.memberIds.join("\n")
      : "",
  );
  const [advanced, setAdvanced] = useState(
    Boolean(initial) && !simple(initial?.expression),
  );
  const [expressionJson, setExpressionJson] = useState(
    JSON.stringify(initial?.expression ?? newExpression("explicit"), null, 2),
  );
  const [parametersJson, setParametersJson] = useState(
    JSON.stringify(initial?.parameters ?? [], null, 2),
  );
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState("");
  const [dimensions, setDimensions] = useState<MetadataDimension[]>([]);
  const [hierarchies, setHierarchies] = useState<MetadataHierarchy[]>([]);
  const [attributes, setAttributes] = useState<Attribute[]>([]);
  const [metadataError, setMetadataError] = useState("");
  const generation = useRef(0);
  const disabled =
    busy || !current || !catalog.functions["metadata.member_list.save"];
  useEffect(() => {
    onDirtyChange(dirty);
  }, [dirty, onDirtyChange]);
  useUnsavedWork(
    "native-selection-definition",
    "Unsaved named selection",
    dirty,
  );
  useEffect(() => {
    const abort = new AbortController();
    setDimensions([]);
    if (current && catalog.functions["metadata.dimension.list"]) {
      void collectCapabilityDimensions((args) =>
        readProgram(app, "metadata.dimension.list", args, abort.signal),
      )
        .then((result) => {
          if (abort.signal.aborted) return;
          if (result.finalPage.metadataRevision !== catalog.revisions.metadata)
            throw new Error(
              "Metadata changed. Reload the selection before editing.",
            );
          setDimensions(result.rows.filter((row) => row.status === "Active"));
        })
        .catch((reason) => {
          if (!abort.signal.aborted)
            setMetadataError(String(reason.message ?? reason));
        });
    }
    return () => abort.abort();
  }, [
    app.workspaceId,
    app.applicationId,
    current,
    catalog.revisions.metadata,
    catalog.revisions.policy,
    catalog.revisions.security,
  ]);
  useEffect(() => {
    const abort = new AbortController();
    const reading = ++generation.current;
    setHierarchies([]);
    setAttributes([]);
    setMetadataError("");
    if (!dimensionId || !current) return () => abort.abort();
    const load = async () => {
      if (
        hierarchyKinds.includes(String(expression.kind)) &&
        catalog.functions["metadata.hierarchy.list"]
      ) {
        const result = await collectMetadataHierarchies(
          dimensionId,
          catalog.revisions.metadata,
          (args) =>
            readProgram(app, "metadata.hierarchy.list", args, abort.signal),
        );
        if (!abort.signal.aborted && reading === generation.current)
          setHierarchies(result.rows.filter((row) => row.status === "Active"));
      }
      if (
        expression.kind === "attribute" &&
        catalog.functions["metadata.attribute-definition.list"]
      ) {
        const result = await collectAllContinuations<AttributePage, Attribute>({
          label: "Member attributes",
          readPage: (cursor) =>
            readProgram(
              app,
              "metadata.attribute-definition.list",
              {
                scope: "Member",
                dimensionId,
                status: "Active",
                limit: 200,
                ...(cursor ? { afterAttributeId: cursor } : {}),
              },
              abort.signal,
            ),
          rows: (page) => {
            if (page.hasMore !== (page.nextAfterAttributeId !== null))
              throw new Error("Invalid attribute continuation.");
            return page.rows;
          },
          nextCursor: (page) => page.nextAfterAttributeId,
          rowIdentity: (row) => row.attribute_id,
          consistencyIdentity: (page) => {
            if (page.metadataRevision !== catalog.revisions.metadata)
              throw new Error("Metadata changed while reading attributes.");
            return page.metadataRevision;
          },
        });
        if (!abort.signal.aborted && reading === generation.current)
          setAttributes(result.rows);
      }
    };
    void load().catch((reason) => {
      if (!abort.signal.aborted)
        setMetadataError(String(reason.message ?? reason));
    });
    return () => abort.abort();
  }, [
    dimensionId,
    expression.kind,
    current,
    catalog.revisions.metadata,
    catalog.revisions.policy,
    catalog.revisions.security,
    app.workspaceId,
    app.applicationId,
  ]);
  function preparedExpression(): Expression {
    return expression.kind === "explicit"
      ? {
          ...expression,
          memberIds: memberText
            .split(/\n/)
            .map((value) => value.trim())
            .filter(Boolean),
        }
      : expression;
  }
  function change(value: Expression) {
    setExpression(value);
    setDirty(true);
  }
  function setField(key: string, value: unknown) {
    change({ ...expression, [key]: value });
  }
  async function save() {
    setError("");
    try {
      const selectedExpression: unknown = advanced
        ? parseParameterJson(expressionJson)
        : preparedExpression();
      const parameters: unknown = parseParameterJson(parametersJson);
      if (!object(selectedExpression))
        throw new Error("Selection expression must be a JSON object.");
      if (!Array.isArray(parameters))
        throw new Error("Parameter declarations must be a JSON array.");
      if (!listId.trim() || !name.trim() || !dimensionId.trim())
        throw new Error("Provide the selection ID, name and dimension.");
      if (
        selectedExpression.kind === "explicit" &&
        (!Array.isArray(selectedExpression.memberIds) ||
          !selectedExpression.memberIds.length)
      )
        throw new Error("Choose at least one member ID.");
      await onSave({
        format: "openepm-member-list-v1",
        listId: listId.trim(),
        name: name.trim(),
        dimensionId: dimensionId.trim(),
        parameters,
        expression: selectedExpression,
      });
      setDirty(false);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to save selection.",
      );
    }
  }
  return (
    <section className="member-list-editor" aria-label="Named selection editor">
      <p className="member-list-editor-intro">
        Save a selection when it has a reusable business meaning. Ordinary
        member navigation does not require a saved selection.
      </p>
      {!current && (
        <p role="status">
          Application metadata or access changed. Your draft is retained; reopen
          the current selection before saving.
        </p>
      )}
      {error && <p role="alert">{error}</p>}
      {metadataError && <p role="alert">{metadataError}</p>}
      <fieldset disabled={disabled}>
        <div className="member-list-identity-grid">
          <label>
            Selection ID
            <input
              value={listId}
              readOnly={Boolean(initial)}
              onChange={(event) => {
                setListId(event.target.value);
                setDirty(true);
              }}
            />
          </label>
          <label>
            Selection name
            <input
              value={name}
              onChange={(event) => {
                setName(event.target.value);
                setDirty(true);
              }}
            />
          </label>
          <label>
            Dimension
            <input
              list="selection-dimensions"
              value={dimensionId}
              readOnly={Boolean(initial)}
              onChange={(event) => {
                setDimensionId(event.target.value);
                setDirty(true);
              }}
            />
          </label>
          <datalist id="selection-dimensions">
            {dimensions.map((dimension) => (
              <option
                key={dimension.dimension_id}
                value={dimension.dimension_id}
              >
                {dimension.name}
              </option>
            ))}
          </datalist>
        </div>
        {!advanced && (
          <>
            <label>
              Selection method
              <select
                value={String(expression.kind)}
                onChange={(event) => change(newExpression(event.target.value))}
              >
                <option value="explicit">Selected members</option>
                <option value="parents">Parents</option>
                <option value="base">Base members</option>
                <option value="children">Children</option>
                <option value="descendants">Descendants</option>
                <option value="ancestors">Ancestors</option>
                <option value="siblings">Siblings</option>
                <option value="leaves">Leaves</option>
                <option value="attribute">Member attribute</option>
              </select>
            </label>
            {expression.kind === "explicit" && (
              <label>
                Member IDs, one per line
                <textarea
                  rows={5}
                  value={memberText}
                  onChange={(event) => {
                    setMemberText(event.target.value);
                    setDirty(true);
                  }}
                />
              </label>
            )}
            {hierarchyKinds.includes(String(expression.kind)) && (
              <div className="member-list-identity-grid">
                <label>
                  Hierarchy
                  <input
                    list="selection-hierarchies"
                    value={String(expression.hierarchyId ?? "")}
                    onChange={(event) =>
                      setField("hierarchyId", event.target.value)
                    }
                  />
                </label>
                <datalist id="selection-hierarchies">
                  {hierarchies.map((hierarchy) => (
                    <option
                      key={hierarchy.hierarchyId}
                      value={hierarchy.hierarchyId}
                    >
                      {hierarchy.name}
                    </option>
                  ))}
                </datalist>
                <label>
                  Starting member ID
                  <input
                    value={String(expression.memberId ?? "")}
                    onChange={(event) =>
                      setField("memberId", event.target.value)
                    }
                  />
                </label>
                {expression.kind !== "base" && (
                  <label>
                    <input
                      type="checkbox"
                      checked={expression.includeSelf === true}
                      onChange={(event) =>
                        setField("includeSelf", event.target.checked)
                      }
                    />
                    Include starting member
                  </label>
                )}
                {expression.kind === "base" && (
                  <p>
                    Base includes the starting member when it belongs to the
                    hierarchy and has no qualifying children.
                  </p>
                )}
              </div>
            )}
            {expression.kind === "attribute" && (
              <div className="member-list-identity-grid">
                <label>
                  Member attribute
                  <input
                    list="selection-attributes"
                    value={String(expression.attributeId ?? "")}
                    onChange={(event) =>
                      setField("attributeId", event.target.value)
                    }
                  />
                </label>
                <datalist id="selection-attributes">
                  {attributes.map((attribute) => (
                    <option
                      key={attribute.attribute_id}
                      value={attribute.attribute_id}
                    >
                      {attribute.display_name} ({attribute.value_type})
                    </option>
                  ))}
                </datalist>
                <label>
                  Attribute comparison
                  <select
                    value={String(expression.operator)}
                    onChange={(event) =>
                      change({
                        ...expression,
                        operator: event.target.value,
                        value: event.target.value === "exists" ? true : "",
                      })
                    }
                  >
                    <option value="eq">Equals</option>
                    <option value="ne">Does not equal</option>
                    <option value="lt">Less than</option>
                    <option value="lte">At most</option>
                    <option value="gt">Greater than</option>
                    <option value="gte">At least</option>
                    <option value="contains">Contains</option>
                    <option value="starts_with">Starts with</option>
                    <option value="exists">Has a value</option>
                  </select>
                </label>
                {expression.operator === "exists" ||
                attributes.find(
                  (attribute) =>
                    attribute.attribute_id === expression.attributeId,
                )?.value_type === "Boolean" ? (
                  <label>
                    Attribute value
                    <select
                      value={String(expression.value)}
                      onChange={(event) =>
                        setField("value", event.target.value === "true")
                      }
                    >
                      <option value="">Choose a value</option>
                      <option value="true">True</option>
                      <option value="false">False</option>
                    </select>
                  </label>
                ) : (
                  <label>
                    Attribute value
                    <input
                      value={String(expression.value ?? "")}
                      onChange={(event) =>
                        setField("value", event.target.value)
                      }
                    />
                  </label>
                )}
              </div>
            )}
          </>
        )}
        <details
          className="member-list-disclosure"
          open={advanced || undefined}
        >
          <summary>Advanced selection expression and parameters</summary>
          <p>
            Combine selections, set ordering or declare typed parameters. The
            same fixed validation applies.
          </p>
          <label>
            <input
              type="checkbox"
              checked={advanced}
              onChange={(event) => {
                if (event.target.checked) {
                  setExpressionJson(
                    JSON.stringify(preparedExpression(), null, 2),
                  );
                  setAdvanced(true);
                } else {
                  try {
                    const parsed: unknown = parseParameterJson(expressionJson);
                    if (!simple(parsed))
                      throw new Error(
                        "This compound selection requires the advanced editor.",
                      );
                    setExpression(parsed);
                    if (
                      parsed.kind === "explicit" &&
                      Array.isArray(parsed.memberIds)
                    )
                      setMemberText(parsed.memberIds.join("\n"));
                    setAdvanced(false);
                  } catch (reason) {
                    setError(
                      reason instanceof Error
                        ? reason.message
                        : "Invalid expression.",
                    );
                  }
                }
              }}
            />
            Edit expression JSON
          </label>
          {advanced && (
            <label>
              Selection expression JSON
              <textarea
                rows={12}
                value={expressionJson}
                onChange={(event) => {
                  setExpressionJson(event.target.value);
                  setDirty(true);
                }}
              />
            </label>
          )}
          <label>
            Parameter declarations JSON
            <textarea
              rows={4}
              value={parametersJson}
              onChange={(event) => {
                setParametersJson(event.target.value);
                setDirty(true);
              }}
            />
          </label>
        </details>
      </fieldset>
      <button
        disabled={disabled || !catalog.functions["metadata.member_list.save"]}
        onClick={() => void save()}
      >
        Save named selection
      </button>
    </section>
  );
}
