import { useEffect, useMemo, useState } from "react";
import { readProgram, request, reviewAndSubmit } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";

type SequenceSummary = {
  ruleId: string;
  version: number;
  programDigest: string;
  statementCount: number;
  parameterDeclarations: Record<string, unknown>;
  metadataCurrent: boolean;
};

type SequenceDetail = {
  defined: boolean;
  ruleId: string;
  version: number;
  status?: string;
  programDigest?: string;
  program?: { arguments?: Record<string, unknown> } & Record<string, unknown>;
  currentMetadataRevision?: number;
  policyRevision?: number;
};
type SequenceTarget = { ruleId: string; version: number; digest: string };
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
    item.version !== target.version ||
    item.status !== "Published" ||
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

export function sequenceReadArguments(ruleId: string, version: number) {
  return { ruleId, version };
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
    rowIdentity: (row) => `${row.ruleId}\u0000${row.version}`,
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
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  target?: SequenceTarget;
}) {
  const mutationIntentKey = useStableMutationIntentKey("sequence-ui");
  const [rows, setRows] = useState<SequenceSummary[]>([]);
  const [catalogueRead, setCatalogueRead] = useState(false);
  const [selected, setSelected] = useState<SequenceDetail | null>(null);
  const [metadataRevision, setMetadataRevision] = useState<number | null>(null);
  const [policyRevision, setPolicyRevision] = useState<number | null>(null);
  const [ruleId, setRuleId] = useState("");
  const [version, setVersion] = useState("1");
  const [bindings, setBindings] = useState("{}");
  const [bindingsTouched, setBindingsTouched] = useState(false);
  const [runReviewed, setRunReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const functions = catalog?.functions || {};
  const available = Boolean(
    functions["rules.numeric_sequence.version.list"] &&
      functions["rules.numeric_sequence.version.read"],
  );
  const canRead = Boolean(functions["rules.numeric_sequence.version.read"]);
  const canRun = Boolean(functions["rules.numeric_sequence.run"]);
  const numericVersion = Number(version);
  const exactSelected = Boolean(
    selected &&
      selected.ruleId === ruleId &&
      selected.version === numericVersion,
  );
  const bindingsValid = useMemo(() => {
    try {
      const parsed = objectValue(bindings, "Bindings");
      return Object.keys(parsed).length <= 8;
    } catch {
      return false;
    }
  }, [bindings]);
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
    setVersion("1");
    setBindings("{}");
    setBindingsTouched(false);
    setRunReviewed(false);
    setResult(null);
    setError("");
  }, [app?.workspaceId, app?.applicationId]);

  async function loadSequences() {
    if (!app || !available) return;
    setBusy(true);
    setError("");
    try {
      const collected = await collectNumericSequences((arguments_) =>
        readProgram(
          { workspaceId: app.workspaceId, applicationId: app.applicationId },
          "rules.numeric_sequence.version.list",
          arguments_,
        ),
      );
      setRows(collected.rows);
      setCatalogueRead(true);
      setSelected(null);
      setMetadataRevision(collected.finalPage.metadataRevision);
      setPolicyRevision(collected.finalPage.policyRevision);
      setRunReviewed(false);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read sequences",
      );
    } finally {
      setBusy(false);
    }
  }

  async function readSequence(
    row: Pick<SequenceSummary, "ruleId" | "version" | "programDigest">,
  ) {
    if (!app || !canRead) return;
    setBusy(true);
    setError("");
    try {
      const value = await readProgram<unknown>(
        { workspaceId: app.workspaceId, applicationId: app.applicationId },
        "rules.numeric_sequence.version.read",
        sequenceReadArguments(row.ruleId, row.version),
      );
      const detail = exactApplicationSequence(value, {
        ruleId: row.ruleId,
        version: row.version,
        digest: row.programDigest,
      });
      setSelected(detail);
      setRuleId(detail.ruleId);
      setVersion(String(detail.version));
      setBindings("{}");
      setBindingsTouched(false);
      setMetadataRevision(detail.currentMetadataRevision ?? metadataRevision);
      setPolicyRevision(detail.policyRevision ?? policyRevision);
      setRunReviewed(false);
      setResult(null);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read sequence",
      );
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (target)
      void readSequence({
        ruleId: target.ruleId,
        version: target.version,
        programDigest: target.digest,
      });
  }, [
    app?.workspaceId,
    app?.applicationId,
    target?.ruleId,
    target?.version,
    target?.digest,
    canRead,
  ]);

  async function runSequence() {
    if (!app || !canRun || !exactSelected || !runReviewed || !bindingsValid)
      return;
    setBusy(true);
    setError("");
    try {
      const response = await reviewAndSubmit(
        sequenceRunBody(
          app,
          ruleId,
          objectValue(bindings, "Bindings"),
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            functionName: "rules.numeric_sequence.run",
            ruleId,
            bindings: objectValue(bindings, "Bindings"),
          }),
        ),
        "Review the published ordered-sequence preview.",
      );
      if (!response) return;
      setResult(response);
      setBindingsTouched(false);
      setRunReviewed(false);
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
          <h2 id="sequence-explorer-heading">Calculation sequences</h2>
          <p>
            Inspect and execute published atomic ordered Set, Add and Clear
            programs through the existing fixed-core contracts.
          </p>
        </div>
        <button
          disabled={busy || !available}
          onClick={() => void loadSequences()}
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
                <th>Version</th>
                <th>Statements</th>
                <th>Parameters</th>
                <th>Metadata</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.ruleId}-${row.version}`}>
                  <th>{row.ruleId}</th>
                  <td>{row.version}</td>
                  <td>{row.statementCount}</td>
                  <td>
                    <code>{JSON.stringify(row.parameterDeclarations)}</code>
                  </td>
                  <td>{row.metadataCurrent ? "Current" : "Stale"}</td>
                  <td>
                    <button
                      disabled={busy}
                      onClick={() => void readSequence(row)}
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
      <div className="governed-action-grid rule-authoring-grid">
        <article className="governed-action-card">
          <small>IMMUTABLE DEFINITION</small>
          <h3>Inspect exact sequence</h3>
          <p className="authority-note">
            Open a published version above to inspect its 1–500 ordered
            statements and typed parameters. Authoring remains available to
            agents through the existing MCP/application-language contract; this
            UI does not widen the browser mutation API.
          </p>
          {selected ? (
            <pre>{JSON.stringify(selected.program, null, 2)}</pre>
          ) : (
            <p className="muted-copy">No exact sequence version is open.</p>
          )}
        </article>
        <article className="governed-action-card">
          <small>PREVIEWED DURABLE EXECUTION</small>
          <h3>Run published sequence</h3>
          <p>
            {exactSelected
              ? `${ruleId} v${version} is freshly read.`
              : "Open a published sequence from the catalogue first."}
          </p>
          <label>
            Typed parameter bindings
            <textarea
              aria-label="Sequence parameter bindings"
              rows={8}
              spellCheck={false}
              value={bindings}
              onChange={(event) => {
                setBindings(event.target.value);
                setBindingsTouched(true);
                setRunReviewed(false);
                setResult(null);
              }}
            />
          </label>
          <label className="review-check">
            <input
              type="checkbox"
              checked={runReviewed}
              disabled={!canRun || !exactSelected || !bindingsValid}
              onChange={(event) => setRunReviewed(event.target.checked)}
            />
            I reviewed this exact sequence execution and bindings.
          </label>
          <button
            disabled={
              busy ||
              !canRun ||
              !exactSelected ||
              !bindingsValid ||
              !runReviewed
            }
            onClick={() => void runSequence()}
          >
            Preview and submit
          </button>
          <p className="authority-note">
            The browser performs no arithmetic. Preview, authorization, current
            publication and atomic execution remain fixed-core responsibilities.
          </p>
        </article>
      </div>
      {selected && (
        <article
          className="program-inspector"
          aria-label="Sequence rule detail"
        >
          <h3>
            {selected.ruleId} v{selected.version}
          </h3>
          <p>{selected.status || "Published immutable version"}</p>
          <pre>{JSON.stringify(selected.program, null, 2)}</pre>
        </article>
      )}
      {result !== null && (
        <details className="model-details">
          <summary>Latest authoritative outcome</summary>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </details>
      )}
      <footer className="grid-status" aria-live="polite">
        <span>
          {metadataRevision === null
            ? "No sequence snapshot read"
            : `${rows.length} sequences · metadata revision ${metadataRevision} · policy revision ${policyRevision}`}
        </span>
      </footer>
    </section>
  );
}
