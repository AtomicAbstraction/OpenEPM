import { useEffect, useMemo, useRef, useState } from "react";
import { readProgram, request, previewAndSubmit } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";
import {
  ParameterFields,
  definitionParameterSchema,
  parameterInputError,
  parameterObject,
} from "./ParameterFields";
import { authoringContextKey } from "./python-authoring";
import "./rule-workspaces.css";

type SequenceSummary = {
  ruleId: string;
  stateToken: string;
  programDigest: string;
  statementCount: number;
  parameterDeclarations: Record<string, unknown>;
  metadataCurrent: boolean;
};

type SequenceDetail = {
  defined: boolean;
  ruleId: string;
  stateToken: string;
  status?: string;
  programDigest?: string;
  program?: { arguments?: Record<string, unknown> } & Record<string, unknown>;
  currentMetadataRevision?: number;
  policyRevision?: number;
};
type SequenceTarget = { ruleId: string; stateToken: string; digest: string };
const SEQUENCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const DIGEST = /^[0-9a-f]{64}$/;

export function exactApplicationSequence(
  value: unknown,
  target: SequenceTarget,
): SequenceDetail {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("INVALID_APPLICATION_SEQUENCE_RESPONSE");
  const item = value as Record<string, unknown>;
  const program = item.program as Record<string, unknown> | undefined;
  if (
    item.defined !== true ||
    item.ruleId !== target.ruleId ||
    item.stateToken !== target.stateToken ||
    item.status !== "Active" ||
    item.programDigest !== target.digest ||
    !SEQUENCE_ID.test(target.ruleId) ||
    !DIGEST.test(target.digest) ||
    !program ||
    program.function !== "rules.numeric_sequence.template" ||
    !program.arguments ||
    typeof program.arguments !== "object" ||
    Array.isArray(program.arguments)
  )
    throw new Error("INVALID_APPLICATION_SEQUENCE_RESPONSE");
  return value as SequenceDetail;
}
export function sequenceParameterSchema(value: unknown) {
  const declarations = parameterObject(value);
  if (!declarations) return undefined;
  const parameters = [];
  for (const [name, kind] of Object.entries(declarations)) {
    if (kind === "amount" || kind === "ratio")
      parameters.push({ name, type: kind === "amount" ? "Amount" : "Ratio" });
    else {
      const member = parameterObject(kind);
      if (member?.type !== "member" || typeof member.dimensionId !== "string")
        return undefined;
      parameters.push({
        name,
        type: "Member",
        dimensionId: member.dimensionId,
      });
    }
  }
  return definitionParameterSchema(parameters);
}

type SequenceListPage = {
  rows: SequenceSummary[];
  hasMore: boolean;
  nextAfterRuleId: string | null;
  metadataRevision: number;
  policyRevision: number;
};

function objectValue(value: string, label: string) {
  const parsed: unknown = JSON.parse(value);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object")
    throw new Error(`${label} must be a JSON object.`);
  return parsed as Record<string, unknown>;
}

export function sequenceListArguments(
  afterRuleId?: string | null,
  expectedMetadataRevision?: number,
  expectedPolicyRevision?: number,
) {
  return afterRuleId
    ? {
        limit: 100,
        afterRuleId,
        expectedMetadataRevision,
        expectedPolicyRevision,
      }
    : { limit: 100 };
}

export function sequenceReadArguments(ruleId: string) {
  return { ruleId };
}
export function collectNumericSequences(
  readPage: (
    arguments_: ReturnType<typeof sequenceListArguments>,
  ) => Promise<SequenceListPage>,
) {
  let metadata: number | undefined;
  let policy: number | undefined;
  return collectAllContinuations<SequenceListPage, SequenceSummary>({
    label: "Numeric sequences",
    readPage: async (cursor) => {
      const page = await readPage(
        sequenceListArguments(cursor, metadata, policy),
      );
      metadata = page.metadataRevision;
      policy = page.policyRevision;
      return page;
    },
    rows: (page) => page.rows,
    nextCursor: (page) => {
      if (typeof page.hasMore !== "boolean")
        throw new Error("Numeric sequences continuation status is invalid.");
      if (!page.hasMore && page.nextAfterRuleId !== null)
        throw new Error(
          "Numeric sequences continuation status is inconsistent.",
        );
      return page.hasMore ? page.nextAfterRuleId : null;
    },
    rowIdentity: (row) => `${row.ruleId}\u0000${row.stateToken}`,
    consistencyIdentity: (page) =>
      `${page.metadataRevision}\u0000${page.policyRevision}`,
  });
}

export function sequenceRunBody(
  app: ApplicationSummary,
  ruleId: string,
  bindings: Record<string, unknown>,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    program: {
      languageVersion: 2,
      function: "rules.numeric_sequence.run",
      arguments: {
        ruleId,
        ...(Object.keys(bindings).length ? { bindings } : {}),
      },
    },
    idempotencyKey,
    dependsOnJobIds: [],
    confirmed: true,
  };
}

export function BuildSequences({
  app,
  catalog,
  target,
  onRequestTransition = (action) => action(),
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  target?: SequenceTarget;
  onRequestTransition?: (action: () => void) => void;
}) {
  const activeRead = useRef<AbortController | null>(null);
  useEffect(
    () => () => activeRead.current?.abort(),
    [app?.workspaceId, app?.applicationId],
  );
  function beginRead() {
    activeRead.current?.abort();
    const controller = new AbortController();
    activeRead.current = controller;
    return controller;
  }
  const mutationIntentKey = useStableMutationIntentKey("sequence-ui");
  const [rows, setRows] = useState<SequenceSummary[]>([]);
  const [catalogueRead, setCatalogueRead] = useState(false);
  const [selected, setSelected] = useState<SequenceDetail | null>(null);
  const contextKey = app && catalog ? authoringContextKey(app, catalog) : "";
  const [selectedContextKey, setSelectedContextKey] = useState("");
  const parameterSchema =
    selectedContextKey === contextKey
      ? sequenceParameterSchema(selected?.program?.arguments?.parameters ?? {})
      : undefined;
  const editorHeading = useRef<HTMLHeadingElement>(null);
  const editorTrigger = useRef<HTMLElement | null>(null);
  const [metadataRevision, setMetadataRevision] = useState<number | null>(null);
  const [policyRevision, setPolicyRevision] = useState<number | null>(null);
  const [ruleId, setRuleId] = useState("");
  const [bindings, setBindings] = useState("{}");
  const [bindingsTouched, setBindingsTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<unknown>(null);
  useEffect(() => {
    if (selected) editorHeading.current?.focus();
  }, [selected?.ruleId, selected?.stateToken]);
  const functions = catalog?.functions || {};
  const available = Boolean(
    functions["rules.numeric_sequence.list"] &&
      functions["rules.numeric_sequence.read"],
  );
  const canRead = Boolean(functions["rules.numeric_sequence.read"]);
  const canRun = Boolean(functions["rules.numeric_sequence.run"]);
  const exactSelected = Boolean(selected && selected.ruleId === ruleId);
  const bindingsValid = useMemo(() => {
    try {
      const parsed = objectValue(bindings, "Bindings");
      return (
        Object.keys(parsed).length <= 8 &&
        !parameterInputError(bindings, parameterSchema)
      );
    } catch {
      return false;
    }
  }, [bindings, parameterSchema]);
  useUnsavedWork(
    `build-sequence:${app?.workspaceId || "none"}:${app?.applicationId || "none"}`,
    "Unsaved sequence execution bindings",
    bindingsTouched,
  );

  useEffect(() => {
    setRows([]);
    setCatalogueRead(false);
    setSelected(null);
    setMetadataRevision(null);
    setPolicyRevision(null);
    setRuleId("");
    setBindings("{}");
    setBindingsTouched(false);

    setResult(null);
    setError("");
  }, [app?.workspaceId, app?.applicationId]);

  function changeContext(action: () => void) {
    if (busy) return;
    const trigger = document.activeElement;
    if (
      trigger instanceof HTMLElement &&
      !trigger.closest(".rule-editor-frame")
    )
      editorTrigger.current = trigger;
    const change = () => {
      setSelected(null);
      setBindings("{}");
      setBindingsTouched(false);

      setResult(null);
      action();
    };
    if (bindingsTouched) onRequestTransition(change);
    else change();
  }

  async function loadSequences() {
    if (!app || !available) return;
    const controller = beginRead();
    setBusy(true);
    setError("");
    try {
      const collected = await collectNumericSequences((arguments_) =>
        readProgram(
          { workspaceId: app.workspaceId, applicationId: app.applicationId },
          "rules.numeric_sequence.list",
          arguments_,
          controller.signal,
        ),
      );
      if (controller.signal.aborted) return;
      setRows(collected.rows);
      setCatalogueRead(true);
      setSelected(null);
      setMetadataRevision(collected.finalPage.metadataRevision);
      setPolicyRevision(collected.finalPage.policyRevision);
    } catch (reason) {
      if (controller.signal.aborted) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to read sequences",
      );
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  async function readSequence(
    row: Pick<SequenceSummary, "ruleId" | "stateToken" | "programDigest">,
  ) {
    if (!app || !canRead) return;
    const controller = beginRead();
    setBusy(true);
    setError("");
    try {
      const value = await readProgram<unknown>(
        { workspaceId: app.workspaceId, applicationId: app.applicationId },
        "rules.numeric_sequence.read",
        sequenceReadArguments(row.ruleId),
        controller.signal,
      );
      if (controller.signal.aborted) return;
      const detail = exactApplicationSequence(value, {
        ruleId: row.ruleId,
        stateToken: row.stateToken,
        digest: row.programDigest,
      });
      setSelected(detail);
      setSelectedContextKey(contextKey);
      setRuleId(detail.ruleId);
      setBindings("{}");
      setBindingsTouched(false);
      setMetadataRevision(detail.currentMetadataRevision ?? metadataRevision);
      setPolicyRevision(detail.policyRevision ?? policyRevision);

      setResult(null);
    } catch (reason) {
      if (controller.signal.aborted) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to read sequence",
      );
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  useEffect(() => {
    if (target)
      void readSequence({
        ruleId: target.ruleId,
        stateToken: target.stateToken,
        programDigest: target.digest,
      });
  }, [
    app?.workspaceId,
    app?.applicationId,
    target?.ruleId,
    target?.stateToken,
    target?.digest,
    canRead,
  ]);

  async function runSequence() {
    if (
      !app ||
      !canRun ||
      !exactSelected ||
      !selected?.programDigest ||
      !bindingsValid ||
      busy
    )
      return;
    setBusy(true);
    setError("");
    try {
      const response = await previewAndSubmit(
        sequenceRunBody(
          app,
          ruleId,
          objectValue(bindings, "Bindings"),
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            functionName: "rules.numeric_sequence.run",
            ruleId,
            stateToken: selected.stateToken,
            programDigest: selected.programDigest,
            bindings: objectValue(bindings, "Bindings"),
          }),
        ),
        {
          ruleId: selected.ruleId,
          stateToken: selected.stateToken,
          programDigest: selected.programDigest,
        },
      );
      if (!response) return;
      setResult(response);
      setBindingsTouched(false);

      setSelected(null);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to run sequence",
      );
    } finally {
      setBusy(false);
    }
  }

  if (!canRead)
    return target ? (
      <p role="alert">Sequence inspection is not authorized.</p>
    ) : null;
  return (
    <section
      className="panel capability-activity"
      aria-labelledby="sequence-explorer-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>ORDERED REUSABLE BUSINESS LOGIC</small>
          <h2 id="sequence-explorer-heading" tabIndex={-1}>
            Calculation sequences
          </h2>
          <p>
            Inspect and run a published sequence of Set, Add and Clear steps.
            The steps run in order and commit together.
          </p>
        </div>
        <button
          disabled={busy || !available}
          onClick={() => changeContext(() => void loadSequences())}
        >
          {busy ? "Working…" : "Read sequences"}
        </button>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {rows.length ? (
        <div className="react-grid-scroll">
          <table className="react-cube-grid rule-grid">
            <thead>
              <tr>
                <th>Sequence</th>
                <th>Statements</th>
                <th>Parameters</th>
                <th>Metadata</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.ruleId}-${row.stateToken}`}>
                  <th>{row.ruleId}</th>
                  <td>{row.statementCount}</td>
                  <td>
                    <code>{JSON.stringify(row.parameterDeclarations)}</code>
                  </td>
                  <td>{row.metadataCurrent ? "Current" : "Stale"}</td>
                  <td>
                    <button
                      disabled={busy}
                      onClick={() =>
                        changeContext(() => void readSequence(row))
                      }
                    >
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted-copy">
          {catalogueRead
            ? "No published calculation sequences are defined for this application."
            : "No published-sequence catalogue read yet."}
        </p>
      )}
      {selected && (
        <fieldset
          id="calculation-sequence-inspector"
          className="rule-editor-frame"
          disabled={busy}
          aria-label="Sequence rule detail"
        >
          <div className="rule-editor-heading">
            <div>
              <small>SELECTED DEFINITION</small>
              <h3 ref={editorHeading} tabIndex={-1}>
                {selected.ruleId}
              </h3>
              <p>{selected.status || "Active current definition"}</p>
            </div>
            <button
              type="button"
              onClick={() =>
                changeContext(() => {
                  queueMicrotask(() =>
                    (
                      editorTrigger.current ||
                      document.getElementById("sequence-explorer-heading")
                    )?.focus(),
                  );
                })
              }
            >
              Close inspector
            </button>
          </div>
          <div className="governed-action-grid rule-authoring-grid">
            <article className="governed-action-card">
              <small>CURRENT DEFINITION</small>
              <h4>Ordered statements</h4>
              <p className="authority-note">
                Open an active sequence above to inspect its 1–500 ordered
                statements and typed parameters. Use a connected agent to author
                a new sequence.
              </p>
              <pre
                className="program-code"
                role="region"
                aria-label="Calculation sequence source"
                tabIndex={0}
              >
                {JSON.stringify(selected.program, null, 2)}
              </pre>
            </article>
            {canRun && (
              <article className="governed-action-card">
                <small>PREVIEWED DURABLE EXECUTION</small>
                <h4>Run published sequence</h4>
                <p>
                  {exactSelected
                    ? `${ruleId} is freshly read.`
                    : "Open a published sequence from the catalogue first."}
                </p>
                <ParameterFields
                  label="Sequence parameters"
                  advancedLabel="Sequence parameter bindings"
                  value={bindings}
                  schema={parameterSchema}
                  disabled={busy}
                  onChange={(value) => {
                    setBindings(value);
                    setBindingsTouched(true);
                    setResult(null);
                  }}
                />
                <button
                  disabled={busy || !canRun || !exactSelected || !bindingsValid}
                  onClick={() => void runSequence()}
                >
                  Run sequence
                </button>
                <p className="authority-note">
                  Run this exact active definition with the parameter values
                  shown above. Current model and access checks still apply.
                </p>
              </article>
            )}
          </div>
        </fieldset>
      )}
      {result !== null && (
        <details className="model-details">
          <summary>Latest authoritative outcome</summary>
          <pre
            className="program-code"
            role="region"
            aria-label="Calculation sequence result"
            tabIndex={0}
          >
            {JSON.stringify(result, null, 2)}
          </pre>
        </details>
      )}
      <footer className="grid-status" aria-live="polite">
        <span>
          {metadataRevision === null
            ? "No sequence snapshot read"
            : `${rows.length} sequences · current model`}
        </span>
      </footer>
    </section>
  );
}
