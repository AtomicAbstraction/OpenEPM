import { useEffect, useId, useRef, useState } from "react";
import "./parameter-fields.css";
import {
  exactIntegerInput,
  InexactParameterNumber,
  parseParameterJson,
} from "./exact-parameters";

function NumericParameter({
  id,
  value,
  integer,
  disabled,
  onChange,
}: {
  id: string;
  value: unknown;
  integer: boolean;
  disabled?: boolean;
  onChange: (value: unknown) => void;
}) {
  const [text, setText] = useState(value === undefined ? "" : String(value));
  const sent = useRef(value);
  useEffect(() => {
    if (value !== sent.current)
      setText(value === undefined ? "" : String(value));
    sent.current = value;
  }, [value]);
  return (
    <input
      id={id}
      disabled={disabled}
      inputMode={integer ? "numeric" : "decimal"}
      value={text}
      onChange={(event) => {
        const raw = event.target.value;
        const next = exactIntegerInput(raw) ?? raw;
        setText(raw);
        sent.current = next;
        onChange(next);
      }}
    />
  );
}

export function parameterObject(
  value: unknown,
): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/** Translate the fixed core's parameter declarations, preserving exact decimals
 * as strings. Samples are examples, never silently supplied execution bindings. */
export function definitionParameterSchema(
  value: unknown,
): Record<string, unknown> | undefined {
  if (!Array.isArray(value)) return undefined;
  const properties: Record<string, unknown> = {};
  const required: string[] = [];
  for (const item of value) {
    const spec = parameterObject(item);
    if (!spec || typeof spec.name !== "string") return undefined;
    const type = spec.type;
    if (
      ![
        "Amount",
        "Ratio",
        "Decimal",
        "Member",
        "MemberList",
        "String",
        "Boolean",
        "Date",
      ].includes(String(type))
    )
      return undefined;
    properties[spec.name] =
      type === "MemberList"
        ? {
            type: "object",
            title: spec.name,
            description: `Saved member list for dimension ${String(spec.dimensionId)}.`,
            properties: {
              listId: { type: "string" },
              parameters: { type: "object", default: {} },
            },
            required: ["listId", "parameters"],
          }
        : {
            type: type === "Boolean" ? "boolean" : "string",
            ...(type === "Date" ? { format: "date" } : {}),
            ...(spec.dimensionId
              ? {
                  description: `Member ID in dimension ${String(spec.dimensionId)}.`,
                }
              : {}),
            ...(["Amount", "Ratio", "Decimal"].includes(String(type))
              ? { description: "Exact decimal value.", inputMode: "decimal" }
              : {}),
            ...(typeof spec.sample === "string"
              ? { examples: [spec.sample] }
              : {}),
          };
    if (spec.required !== false) required.push(spec.name);
  }
  return { type: "object", properties, required, additionalProperties: false };
}

/** Small input checks only; the fixed server validator remains authoritative. */
export function parameterInputError(
  text: string,
  schema?: Record<string, unknown>,
): string | null {
  let values: unknown;
  try {
    values = parseParameterJson(text);
  } catch (error) {
    return error instanceof InexactParameterNumber
      ? error.message
      : "Parameters must form a valid object.";
  }
  if (!parameterObject(values)) return "Parameters must form an object.";
  function check(
    value: unknown,
    spec: Record<string, unknown>,
    path: string,
  ): string | null {
    if (value === undefined) return null;
    if (
      Array.isArray(spec.enum) &&
      !spec.enum.some(
        (choice) => JSON.stringify(choice) === JSON.stringify(value),
      )
    )
      return `${path}: choose a listed value.`;
    if (
      spec.type === "integer" &&
      (typeof value !== "number" || !Number.isSafeInteger(value))
    )
      return `${path}: enter a whole number within the exact integer range.`;
    if (
      spec.type === "number" &&
      (typeof value !== "number" || !Number.isSafeInteger(value))
    )
      return `${path}: enter a whole number within the exact integer range. Declare exact decimal parameters as strings.`;
    if (spec.type === "string" && typeof value !== "string")
      return `${path}: enter text.`;
    if (spec.type === "boolean" && typeof value !== "boolean")
      return `${path}: choose true or false.`;
    if (spec.type === "array") {
      if (!Array.isArray(value)) return `${path}: enter an array.`;
      const itemSchema = parameterObject(spec.items);
      if (itemSchema) {
        for (let index = 0; index < value.length; index++) {
          const error = check(value[index], itemSchema, `${path}[${index}]`);
          if (error) return error;
        }
      }
    }
    if (spec.type === "object") {
      const object = parameterObject(value);
      if (!object) return `${path}: enter an object.`;
      const properties = parameterObject(spec.properties) ?? {};
      for (const key of Array.isArray(spec.required) ? spec.required : []) {
        if (typeof key === "string" && object[key] === undefined)
          return `${path}.${key}: provide a value.`;
      }
      for (const [key, child] of Object.entries(properties)) {
        const error = check(
          object[key],
          parameterObject(child) ?? {},
          `${path}.${key}`,
        );
        if (error) return error;
      }
    }
    return null;
  }
  return schema ? check(values, schema, "Parameters") : null;
}

export function ParameterFields({
  label,
  advancedLabel,
  value,
  schema,
  disabled,
  onChange,
}: {
  label: string;
  advancedLabel: string;
  value: string;
  schema?: Record<string, unknown>;
  disabled?: boolean;
  onChange: (value: string) => void;
}) {
  const id = useId();
  let values: Record<string, unknown> | undefined;
  try {
    values = parameterObject(parseParameterJson(value));
  } catch {
    /* retain repairable text */
  }
  const properties = parameterObject(schema?.properties);
  function field(
    name: string,
    spec: Record<string, unknown>,
    item: unknown,
    update: (next: unknown) => void,
    depth: number,
  ): React.ReactNode {
    const fieldId = `${id}-${name}`;
    const children = parameterObject(spec.properties);
    if (spec.type === "object" && children && depth < 4) {
      const defaults = Object.fromEntries(
        Object.entries(children).flatMap(([key, child]) => {
          const spec = parameterObject(child);
          return spec?.type === "object" && parameterObject(spec.default)
            ? [[key, spec.default]]
            : [];
        }),
      );
      const object = { ...defaults, ...parameterObject(item) };
      return (
        <fieldset key={name}>
          <legend>{name}</legend>
          {typeof spec.description === "string" && <p>{spec.description}</p>}
          {Object.entries(children).map(([key, child]) =>
            field(
              `${name}.${key}`,
              parameterObject(child) ?? {},
              object[key],
              (next) => update({ ...object, [key]: next }),
              depth + 1,
            ),
          )}
        </fieldset>
      );
    }
    const simple = ["string", "boolean", "integer", "number"].includes(
      String(spec.type),
    );
    return (
      <div key={name} className="parameter-field">
        <label htmlFor={fieldId}>{name}</label>
        {Array.isArray(spec.enum) ? (
          <select
            id={fieldId}
            disabled={disabled}
            value={item === undefined ? "" : JSON.stringify(item)}
            onChange={(event) =>
              update(
                event.target.value === ""
                  ? undefined
                  : JSON.parse(event.target.value),
              )
            }
          >
            <option value="">Choose a value</option>
            {spec.enum.map((choice, index) => (
              <option key={index} value={JSON.stringify(choice)}>
                {String(choice)}
              </option>
            ))}
          </select>
        ) : spec.type === "boolean" ? (
          <select
            id={fieldId}
            disabled={disabled}
            value={item === undefined ? "" : String(item)}
            onChange={(event) =>
              update(
                event.target.value === ""
                  ? undefined
                  : event.target.value === "true",
              )
            }
          >
            <option value="">Choose a value</option>
            <option value="true">True</option>
            <option value="false">False</option>
          </select>
        ) : spec.type === "integer" || spec.type === "number" ? (
          <NumericParameter
            id={fieldId}
            disabled={disabled}
            value={item}
            integer={spec.type === "integer"}
            onChange={update}
          />
        ) : simple ? (
          <input
            id={fieldId}
            disabled={disabled}
            type={spec.format === "date" ? "date" : "text"}
            inputMode={spec.inputMode === "decimal" ? "decimal" : undefined}
            value={item === undefined ? "" : String(item)}
            placeholder={
              Array.isArray(spec.examples)
                ? String(spec.examples[0] ?? "")
                : undefined
            }
            onChange={(event) => update(event.target.value)}
          />
        ) : (
          <textarea
            id={fieldId}
            disabled={disabled}
            value={
              typeof item === "string"
                ? item
                : item === undefined
                  ? ""
                  : JSON.stringify(item)
            }
            placeholder={spec.type === "array" ? "[]" : "{}"}
            onChange={(event) => {
              try {
                update(parseParameterJson(event.target.value));
              } catch {
                update(event.target.value);
              }
            }}
          />
        )}
        {typeof spec.description === "string" && (
          <small>{spec.description}</small>
        )}
      </div>
    );
  }
  return (
    <fieldset
      className="parameter-fields"
      disabled={disabled}
      aria-label={label}
    >
      <legend>{label}</legend>
      {properties && values ? (
        Object.entries(properties).map(([name, spec]) =>
          field(
            name,
            parameterObject(spec) ?? {},
            values![name],
            (next) => onChange(JSON.stringify({ ...values, [name]: next })),
            0,
          ),
        )
      ) : (
        <p>No named parameter fields are declared.</p>
      )}
      {properties && Object.keys(properties).length === 0 && (
        <p>No parameters are required.</p>
      )}
      <details>
        <summary>Advanced parameter object</summary>
        <textarea
          aria-label={advancedLabel}
          value={value}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
          rows={3}
        />
      </details>
    </fieldset>
  );
}
