import { useId, useRef, useState } from "react";
import { parameterObject } from "./ParameterFields";
import type { ApplicationCatalog } from "./types";
import "./function-reference.css";

const effectLabels: Record<string, string> = {
  read_or_preview_no_publication: "Read or preview",
  technical_certificate_no_business_revision: "Technical operation",
  durable_private_stage_before_publication: "Prepare work for review",
  durable_server_owned_effect: "Background effect",
  inline_atomic_effect: "Atomic effect",
};

function description(value: unknown) {
  return typeof value === "string" && value ? value : undefined;
}

function SchemaDisclosure({ label, value }: { label: string; value: unknown }) {
  const [open, setOpen] = useState(false);
  return (
    <details onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary>{label}</summary>
      {open && (
        <pre tabIndex={0} aria-label={label}>
          {JSON.stringify(value, null, 2)}
        </pre>
      )}
    </details>
  );
}

function ProgramExample({
  label,
  binding,
  program,
  diagnostic,
  authorizedRead,
  expectedError,
}: {
  label: string;
  binding?: string;
  program: Record<string, unknown>;
  diagnostic: boolean;
  authorizedRead: boolean;
  expectedError?: string;
}) {
  const [status, setStatus] = useState("");
  const text = JSON.stringify(program, null, 2);
  const copyLabel = diagnostic ? "Copy diagnostic request" : "Copy program";

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setStatus("Program copied.");
    } catch {
      setStatus("Clipboard unavailable. Select the example to copy it.");
    }
  }

  return (
    <div className="function-reference-example">
      <h4>{label}</h4>
      {binding && <p>{binding}</p>}
      {!diagnostic && (
        <p>
          {authorizedRead
            ? "Use with the currently selected authorized application."
            : "Fixture only. Bind the example in a disposable application."}
        </p>
      )}
      {diagnostic && (
        <p>
          <strong>
            {expectedError ? "Expected diagnostic" : "Diagnostic request"}
          </strong>
          {expectedError && (
            <>
              {" "}
              <code>{expectedError}</code>
            </>
          )}
        </p>
      )}
      <pre tabIndex={0} aria-label={label}>
        {text}
      </pre>
      <div className="function-example-actions">
        <button
          className="secondary"
          type="button"
          aria-label={`${copyLabel} for ${label}`}
          onClick={() => void copy()}
        >
          {copyLabel}
        </button>
        <span role="status">{status}</span>
      </div>
    </div>
  );
}

function ReplacementGuidance({
  replacement,
  catalog,
  referenceNames,
  inspect,
}: {
  replacement: Record<string, unknown>;
  catalog: ApplicationCatalog;
  referenceNames: ReadonlySet<string>;
  inspect: (functionName: string) => void;
}) {
  const owner = description(replacement.ownerKind);
  const identity = description(replacement.identity);
  const review = parameterObject(replacement.validationReview);
  const outcome = parameterObject(replacement.runOutcome);
  const phases = [
    {
      title: "Read the current inputs",
      discovery: replacement.bindingDiscovery,
      guidance: [replacement.environmentBinding, replacement.coordinateBinding],
    },
    {
      title: "Author and validate source",
      discovery: replacement.authoringDiscovery,
      guidance: [replacement.authoring, replacement.lifecycle],
      validation: true,
    },
    {
      title: "Inspect the current rule",
      discovery: replacement.inspectionDiscovery,
      guidance: [replacement.inspection],
    },
    {
      title: "Run the reviewed rule",
      discovery: [replacement.runDiscovery],
      guidance: [replacement.semantics],
    },
    {
      title: "Verify the rule outcome",
      discovery: [outcome?.discovery],
      guidance: [outcome?.guidance],
    },
  ];
  return (
    <section
      className="function-replacement"
      aria-label="Supported replacement"
    >
      <h4>Supported replacement</h4>
      {owner && (
        <p>
          Replacement owner <code>{owner}</code>
        </p>
      )}
      {identity && <p>{identity}</p>}
      {phases.map(({ title, discovery, guidance, validation }) => {
        const names = Array.isArray(discovery)
          ? discovery.flatMap((entry: unknown) => {
              const hint = parameterObject(entry);
              const name = description(hint?.function);
              return hint?.view === "functions" &&
                name &&
                Object.hasOwn(catalog.functions, name)
                ? [name]
                : [];
            })
          : [];
        if (!names.length) return null;
        return (
          <details
            key={title}
            open={title === "Inspect the current rule" || undefined}
          >
            <summary>{title}</summary>
            {guidance.map((value, index) => {
              const text = description(value);
              return text && <p key={index}>{text}</p>;
            })}
            <ul>
              {names.map((name) => (
                <li key={name}>
                  {referenceNames.has(name) ? (
                    <button
                      type="button"
                      className="secondary"
                      aria-label={`Inspect ${name}`}
                      onClick={() => inspect(name)}
                    >
                      Inspect <code>{name}</code>
                    </button>
                  ) : (
                    <code>{name}</code>
                  )}
                </li>
              ))}
            </ul>
            {validation &&
              description(review?.statusTool) &&
              description(review?.artifactTool) && (
                <p>
                  For MCP review, use{" "}
                  <code>{description(review?.statusTool)}</code> and{" "}
                  <code>{description(review?.artifactTool)}</code>.
                </p>
              )}
          </details>
        );
      })}
    </section>
  );
}

function FunctionContract({
  name,
  catalog,
  referenceNames,
  inspect,
}: {
  name: string;
  catalog: ApplicationCatalog;
  referenceNames: ReadonlySet<string>;
  inspect: (functionName: string) => void;
}) {
  const specification = parameterObject(catalog.functions[name]);
  const operation = parameterObject(catalog.operationContracts?.[name]);
  const contract = parameterObject(specification?.programContract);
  const execution = parameterObject(contract?.execution);
  const unavailable = execution?.newExecutionAvailable === false;
  const diagnosticCode = description(execution?.diagnostic);
  const replacement = parameterObject(contract?.replacement);
  const structures = parameterObject(operation?.structuralSchemas);
  const programSchema = parameterObject(
    structures?.programSchema ??
      specification?.programSchema ??
      contract?.programSchema,
  );
  const resultSchema = parameterObject(
    structures?.resultSchema ??
      specification?.resultSchema ??
      contract?.resultSchema,
  );
  const resultScope =
    structures?.resultSchemaScope ??
    specification?.resultSchemaScope ??
    contract?.resultSchemaScope;
  const required = Object.entries(
    parameterObject(specification?.arguments ?? operation?.argumentSchema) ??
      {},
  );
  const optional = Object.entries(
    parameterObject(
      specification?.optionalArguments ?? operation?.optionalArguments,
    ) ?? {},
  );
  const purpose = description(operation?.productPurpose);
  const result = description(specification?.result ?? operation?.resultSchema);
  const completeness = description(contract?.completeness);
  const scope = description(contract?.scope);
  const authority = description(
    operation?.permission ?? specification?.permission,
  );
  const effect = effectLabels[description(operation?.effectClass) ?? ""];
  const recovery = description(contract?.recovery);
  const replay = parameterObject(operation?.replay);
  const rules = contract?.semanticRules ?? specification?.semanticRules;
  const examples = Array.isArray(contract?.examples) ? contract.examples : [];
  const exampleUse = specification?.exampleUse;
  return (
    <div className="function-reference-contract">
      {purpose && <p>{purpose}</p>}
      {unavailable && (
        <p>
          <strong>Current execution unavailable.</strong>
          {diagnosticCode && (
            <>
              {" "}
              <code>{diagnosticCode}</code>
            </>
          )}
        </p>
      )}
      {unavailable && replacement && (
        <ReplacementGuidance
          replacement={replacement}
          catalog={catalog}
          referenceNames={referenceNames}
          inspect={inspect}
        />
      )}
      <dl>
        {!unavailable && effect && (
          <div>
            <dt>Operation</dt>
            <dd>{effect}</dd>
          </div>
        )}
        {!unavailable && authority && (
          <div>
            <dt>Required authority</dt>
            <dd>
              <code>{authority}</code>
            </dd>
          </div>
        )}
        {result && (
          <div>
            <dt>Result</dt>
            <dd>{result}</dd>
          </div>
        )}
        {scope && (
          <div>
            <dt>Scope</dt>
            <dd>{scope}</dd>
          </div>
        )}
        {completeness && (
          <div>
            <dt>Completeness</dt>
            <dd>{completeness}</dd>
          </div>
        )}
        {!unavailable && operation?.previewRequired === true && (
          <div>
            <dt>Preview</dt>
            <dd>Required for the exact program.</dd>
          </div>
        )}
        {!unavailable && operation?.idempotencyRequired === true && (
          <div>
            <dt>Operation identity</dt>
            <dd>Required for this request.</dd>
          </div>
        )}
      </dl>
      {(required.length > 0 || optional.length > 0) && (
        <details>
          <summary>Arguments</summary>
          <dl className="function-reference-arguments">
            {[
              ...required.map(([field, value]) => ({
                field,
                value,
                label: "Required",
              })),
              ...optional.map(([field, value]) => ({
                field,
                value,
                label: "Optional",
              })),
            ].map(({ field, value, label }) => (
              <div key={field}>
                <dt>
                  <code>{field}</code> <span>{label}</span>
                </dt>
                <dd>{description(value) ?? JSON.stringify(value)}</dd>
              </div>
            ))}
          </dl>
        </details>
      )}
      {examples.map((example: unknown, index: number) => {
        const entry = parameterObject(example);
        const expectedError =
          description(entry?.expectedError) ??
          (unavailable ? diagnosticCode : undefined);
        const program = parameterObject(entry?.program ?? entry);
        if (
          program?.function !== name ||
          typeof program.languageVersion !== "number" ||
          !parameterObject(program.arguments)
        )
          return null;
        return (
          <ProgramExample
            key={index}
            label={description(entry?.name) ?? `Example ${index + 1}`}
            binding={description(entry?.binding)}
            program={program}
            diagnostic={
              unavailable ||
              Boolean(expectedError) ||
              exampleUse === "diagnostic-only"
            }
            authorizedRead={exampleUse === "authorized-read"}
            expectedError={expectedError}
          />
        );
      })}
      {programSchema && (
        <SchemaDisclosure label="Program schema" value={programSchema} />
      )}
      {resultSchema && (
        <SchemaDisclosure
          label={
            resultScope === "envelope"
              ? "Result envelope schema"
              : "Result schema"
          }
          value={resultSchema}
        />
      )}
      {!programSchema && !resultSchema && (
        <p>Published guidance is descriptive.</p>
      )}
      {Array.isArray(rules) &&
        rules.some((rule) => typeof rule === "string") && (
          <details>
            <summary>Contract rules</summary>
            <ul>
              {rules.map(
                (rule: unknown, index: number) =>
                  typeof rule === "string" && <li key={index}>{rule}</li>,
              )}
            </ul>
          </details>
        )}
      {recovery && (
        <div>
          <h4>Recovery</h4>
          <p>{recovery}</p>
        </div>
      )}
      {replay && (
        <SchemaDisclosure
          label={
            unavailable ? "Historical recovery contract" : "Recovery contract"
          }
          value={replay}
        />
      )}
    </div>
  );
}

function FunctionEntry({
  name,
  group,
  catalog,
  referenceNames,
  inspect,
}: {
  name: string;
  group: string;
  catalog: ApplicationCatalog;
  referenceNames: ReadonlySet<string>;
  inspect: (functionName: string) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <li>
      <details
        name={group}
        data-function-reference={name}
        onToggle={(event) => setOpen(event.currentTarget.open)}
      >
        <summary>
          <code>{name}</code>
        </summary>
        {open && (
          <FunctionContract
            catalog={catalog}
            name={name}
            referenceNames={referenceNames}
            inspect={inspect}
          />
        )}
      </details>
    </li>
  );
}

export function FunctionReference({
  catalog,
  names,
}: {
  catalog: ApplicationCatalog;
  names: string[];
}) {
  const group = useId();
  const list = useRef<HTMLUListElement>(null);
  const visible = names.filter((name) =>
    Object.hasOwn(catalog.functions, name),
  );
  const referenceNames = new Set(visible);
  function inspect(functionName: string) {
    const entry = Array.from(
      list.current?.querySelectorAll<HTMLDetailsElement>(
        "details[data-function-reference]",
      ) ?? [],
    ).find((detail) => detail.dataset.functionReference === functionName);
    if (!entry) return;
    entry.open = true;
    entry.querySelector("summary")?.focus();
  }
  return visible.length ? (
    <ul className="function-reference-list" ref={list}>
      {visible.map((name) => (
        <FunctionEntry
          key={name}
          name={name}
          group={group}
          catalog={catalog}
          referenceNames={referenceNames}
          inspect={inspect}
        />
      ))}
    </ul>
  ) : (
    <p className="muted-copy">
      The current application catalogue lists no functions for this workspace.
    </p>
  );
}
