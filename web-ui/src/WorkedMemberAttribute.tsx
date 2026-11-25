import { useEffect, useRef, useState } from "react";
import { readProgram } from "./api";
import {
  attributeDefinitionContinuation,
  type MetadataDimension,
} from "./metadata-data";
import type { Scope } from "./types";

type AttributeDefinition = {
  attribute_id: string;
  display_name: string;
  value_type: string;
  state_token: string;
};
type AttributeObservation = {
  type: string;
  value: string | boolean | null;
};

const identifier = /^[A-Za-z][A-Za-z0-9._-]{0,199}(?![\s\S])/;
const decimal = /^-?\d{1,20}\.\d{8}(?![\s\S])/;
const types = ["Text", "Decimal", "Boolean", "MemberReference"];
const pageLimit = 200;

const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function validDefinition(value: unknown): value is AttributeDefinition {
  return (
    object(value) &&
    typeof value.attribute_id === "string" &&
    identifier.test(value.attribute_id) &&
    typeof value.display_name === "string" &&
    value.display_name.length > 0 &&
    typeof value.value_type === "string" &&
    types.includes(value.value_type) &&
    value.status === "Active" &&
    typeof value.state_token === "string" &&
    value.state_token.length === 64 &&
    /^[a-f0-9]+$/.test(value.state_token)
  );
}

function typedValue(value: unknown, type: string): value is string | boolean {
  if (type === "Boolean") return typeof value === "boolean";
  if (typeof value !== "string") return false;
  if (type === "Decimal") return decimal.test(value);
  if (type === "MemberReference") return identifier.test(value);
  return value.length <= 10000 && !value.includes("\u0000");
}

export function WorkedMemberAttribute({
  scope,
  dimensions,
  coordinate,
  metadataRevision,
  onReadFailure,
}: {
  scope: Scope;
  dimensions: MetadataDimension[];
  coordinate: Record<string, string>;
  metadataRevision: number;
  onReadFailure: (failure: unknown) => boolean;
}) {
  const [axis, setAxis] = useState("");
  const [definitions, setDefinitions] = useState<AttributeDefinition[]>([]);
  const [continuation, setContinuation] = useState<{
    afterAttributeId: string;
    nextPageToken?: string | null;
  } | null>(null);
  const nextAfter = continuation?.afterAttributeId ?? null;
  const [loadedContinuation, setLoadedContinuation] = useState(false);
  const [attribute, setAttribute] = useState("");
  const [observation, setObservation] = useState<AttributeObservation>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);

  async function observe<T>(
    action: (signal: AbortSignal) => Promise<T>,
    accept: (result: T) => void,
  ) {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setLoading(true);
    setError("");
    try {
      const result = await action(controller.signal);
      if (!controller.signal.aborted) accept(result);
    } catch (failure) {
      if (!controller.signal.aborted && !onReadFailure(failure))
        setError(
          "The attribute evidence could not be verified for this coordinate. Inspect it again against current metadata.",
        );
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }

  function readDefinitions(dimensionId: string, after: string | null) {
    const previous = after === null ? [] : definitions;
    void observe(
      (signal) =>
        readProgram<unknown>(
          scope,
          "metadata.attribute-definition.list",
          {
            scope: "Member",
            dimensionId,
            status: "Active",
            limit: pageLimit,
            ...attributeDefinitionContinuation(after, {
              metadataRevision,
              nextPageToken: continuation?.nextPageToken,
            }),
          },
          signal,
        ),
      (result) => {
        if (
          !object(result) ||
          result.scope !== "Member" ||
          result.dimensionId !== dimensionId ||
          result.metadataRevision !== metadataRevision ||
          typeof result.hasMore !== "boolean" ||
          !Array.isArray(result.rows) ||
          result.rows.length > pageLimit ||
          !result.rows.every(validDefinition) ||
          (result.nextPageToken !== undefined &&
            result.nextPageToken !== null &&
            (typeof result.nextPageToken !== "string" ||
              !result.nextPageToken ||
              !result.hasMore)) ||
          new Set([...previous, ...result.rows].map((row) => row.attribute_id))
            .size !==
            previous.length + result.rows.length ||
          (result.hasMore
            ? result.rows.length === 0 ||
              result.nextAfterAttributeId !== result.rows.at(-1)?.attribute_id
            : result.nextAfterAttributeId !== null)
        )
          throw new Error("Invalid member attribute catalogue.");
        setDefinitions([...previous, ...result.rows]);
        setContinuation(
          result.hasMore
            ? {
                afterAttributeId: result.rows.at(-1)!.attribute_id,
                nextPageToken: result.nextPageToken,
              }
            : null,
        );
        if (after !== null) setLoadedContinuation(true);
      },
    );
  }

  function chooseAxis(dimensionId: string) {
    request.current?.abort();
    setAxis(dimensionId);
    setDefinitions([]);
    setContinuation(null);
    setLoadedContinuation(false);
    setAttribute("");
    setObservation(undefined);
    setError("");
    setLoading(false);
    if (dimensionId) readDefinitions(dimensionId, null);
  }

  function chooseAttribute(attributeId: string) {
    request.current?.abort();
    setAttribute(attributeId);
    setObservation(undefined);
    setError("");
    setLoading(false);
    const definition = definitions.find(
      (item) => item.attribute_id === attributeId,
    );
    if (!definition) return;
    const objectId = coordinate[axis];
    void observe(
      (signal) =>
        readProgram<unknown>(
          scope,
          "metadata.attribute-value.read",
          { scope: "Member", dimensionId: axis, objectId, attributeId },
          signal,
        ),
      (result) => {
        if (
          !object(result) ||
          result.scope !== "Member" ||
          result.dimensionId !== axis ||
          result.objectId !== objectId ||
          result.metadataRevision !== metadataRevision ||
          !validDefinition(result.definition) ||
          result.definition.attribute_id !== attributeId ||
          result.definition.value_type !== definition.value_type ||
          result.definition.state_token !== definition.state_token ||
          typeof result.present !== "boolean" ||
          !(result.present
            ? typedValue(result.value, definition.value_type)
            : result.value === null)
        )
          throw new Error("Invalid member attribute evidence.");
        setObservation({
          type: definition.value_type,
          value: result.value as string | boolean | null,
        });
      },
    );
  }

  return (
    <fieldset>
      <legend>Declared member attributes</legend>
      <label>
        Attribute dimension
        <select
          value={axis}
          onChange={(event) => chooseAxis(event.target.value)}
        >
          <option value="">Choose a dimension</option>
          {dimensions.map((dimension) => (
            <option key={dimension.dimension_id} value={dimension.dimension_id}>
              {dimension.name}
            </option>
          ))}
        </select>
      </label>
      {definitions.length > 0 && (
        <label>
          Member attribute
          <select
            value={attribute}
            onChange={(event) => chooseAttribute(event.target.value)}
          >
            <option value="">Choose an attribute</option>
            {definitions.map((definition) => (
              <option
                key={definition.attribute_id}
                value={definition.attribute_id}
              >
                {definition.display_name} ({definition.attribute_id})
              </option>
            ))}
          </select>
        </label>
      )}
      {(nextAfter !== null || loadedContinuation) && (
        <button
          type="button"
          aria-disabled={loading || nextAfter === null || undefined}
          onClick={() => {
            if (!loading && nextAfter !== null)
              readDefinitions(axis, nextAfter);
          }}
        >
          {nextAfter === null
            ? "All attributes loaded"
            : "Load more attributes"}
        </button>
      )}
      {loading && <p role="status">Reading member attributes…</p>}
      {error && <p role="alert">{error}</p>}
      {axis && !loading && !error && !definitions.length && (
        <p>No active member attributes for this dimension.</p>
      )}
      {observation && (
        <p>
          {observation.type} value{" "}
          <output>
            {observation.value === null
              ? "Unassigned"
              : observation.value === ""
                ? "Empty text"
                : String(observation.value)}
          </output>
        </p>
      )}
    </fieldset>
  );
}
