import { useEffect, useMemo, useRef, useState } from "react";
import { readProgram, requestAdmittedEffect } from "./api";
import { collectAllContinuations } from "./continuation";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import {
  ParameterFields,
  definitionParameterSchema,
  parameterInputError,
  parameterObject,
} from "./ParameterFields";
import { PythonDefinitionEditor } from "./PythonDefinitionEditor";
import type { PythonSourceBinding } from "./PythonDefinitionEditor";
import { pythonDefinitionTemplates } from "./python-definition-templates";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import "./rule-workspaces.css";

export type RuleSummary = {
  ruleId: string;
  stateToken: string;
  programDigest: string;
  metadataCurrent: boolean;
  status: "Active" | "Inactive" | "Unavailable";
  executable: boolean;
  reason: "ownership_unresolved" | "validation_required" | null;
};
type RuleDetail = RuleSummary & {
  defined: boolean;
  program: Record<string, unknown>;
  source?: PythonSourceBinding | null;
};
type RuleListPage = {
  rows: RuleSummary[];
  hasMore: boolean;
  nextAfterRuleId: string | null;
  metadataRevision: number;
  policyRevision: number;
};
export function ruleListArguments(
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
export function ruleReadArguments(ruleId: string) {
  return { ruleId };
}
export function ruleAvailabilityLabel(rule: RuleSummary) {
  if (rule.status === "Unavailable") return "Source ownership unresolved";
  if (rule.reason === "validation_required") return "Validation required";
  if (rule.status === "Inactive") return "Inactive by design";
  return "Executable";
}
export function collectApplicationRules(
  readPage: (
    arguments_: ReturnType<typeof ruleListArguments>,
  ) => Promise<RuleListPage>,
) {
  let metadata: number | undefined, policy: number | undefined;
  return collectAllContinuations<RuleListPage, RuleSummary>({
    label: "Application rules",
    readPage: async (cursor) => {
      const page = await readPage(ruleListArguments(cursor, metadata, policy));
      metadata = page.metadataRevision;
      policy = page.policyRevision;
      return page;
    },
    rows: (page) =>
      page.rows.map((row) => {
        if (
          !row ||
          typeof row.ruleId !== "string" ||
          !row.ruleId ||
          typeof row.stateToken !== "string" ||
          !/^[0-9a-f]{64}$/.test(row.stateToken) ||
          typeof row.programDigest !== "string" ||
          !/^[0-9a-f]{64}$/.test(row.programDigest) ||
          typeof row.metadataCurrent !== "boolean" ||
          !["Active", "Inactive", "Unavailable"].includes(row.status) ||
          typeof row.executable !== "boolean" ||
          ![null, "ownership_unresolved", "validation_required"].includes(
            row.reason,
          ) ||
          (row.status === "Unavailable" &&
            (row.reason !== "ownership_unresolved" || row.executable)) ||
          (row.reason === "ownership_unresolved" &&
            row.status !== "Unavailable") ||
          (row.reason === "validation_required" && row.executable) ||
          (row.status === "Active" && (!row.executable || row.reason !== null))
        )
          throw new Error("Application rule summary is invalid.");
        return row;
      }),
    nextCursor: (page) => {
      if (
        typeof page.hasMore !== "boolean" ||
        (!page.hasMore && page.nextAfterRuleId !== null)
      )
        throw new Error(
          "Application rules continuation status is inconsistent.",
        );
      return page.hasMore ? page.nextAfterRuleId : null;
    },
    rowIdentity: (row) => `${row.ruleId}:${row.stateToken}`,
    consistencyIdentity: (page) =>
      `${page.metadataRevision}:${page.policyRevision}`,
  });
}
export function ruleRunBody(
  app: ApplicationSummary,
  ruleId: string,
  bindings: Record<string, unknown>,
  idempotencyKey: string,
  expectedStateToken: string,
  expectedProgramDigest: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    program: {
      languageVersion: 2,
      function: "application.rule.run",
      arguments: {
        ruleId,
        bindings,
        expectedStateToken,
        expectedProgramDigest,
      },
    },
    idempotencyKey,
    confirmed: true,
  };
}
export function BuildRules({
  app,
  catalog,
  targetApplicationRule,
  onRequestTransition = (action) => action(),
  onRefreshCatalog,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  targetApplicationRule?: {
    ruleId: string;
    stateToken: string;
    digest: string;
  };
  onRequestTransition?: (action: () => void) => void;
  onRefreshCatalog?: () => Promise<ApplicationCatalog>;
}) {
  const [rows, setRows] = useState<RuleSummary[]>([]),
    [read, setRead] = useState(false),
    [page, setPage] = useState(0),
    [query, setQuery] = useState("");
  const [selected, setSelected] = useState<RuleDetail | null>(null),
    [creating, setCreating] = useState(false);
  const parameterSchema = definitionParameterSchema(
    parameterObject(selected?.program.arguments)?.parameters,
  );
  const [bindings, setBindings] = useState("{}"),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [sourceCurrentness, setSourceCurrentness] = useState<
    "checking" | "current" | "unavailable"
  >("unavailable");
  const [runIntent, setRunIntent] = useState(0);
  const activeRead = useRef<AbortController | null>(null);
  useUnsavedWork(
    "application-rule-parameters",
    "Unsubmitted rule parameters",
    bindings !== "{}" && result === null,
  );
  const mutationKey = useStableMutationIntentKey("application-rule-ui");
  const canRead = Boolean(
    catalog?.functions["application.rule.list"] &&
      catalog.functions["application.rule.read"],
  );
  const canCreate = Boolean(
    catalog?.functions["python.program.save"] &&
      catalog.functions["python.environment.list"],
  );
  const filtered = useMemo(
    () =>
      rows.filter((row) =>
        row.ruleId.toLowerCase().includes(query.toLowerCase()),
      ),
    [rows, query],
  );
  const start = Math.min(
    page * 50,
    Math.max(0, Math.floor((filtered.length - 1) / 50) * 50),
  );
  function begin() {
    activeRead.current?.abort();
    const controller = new AbortController();
    activeRead.current = controller;
    setBusy(true);
    setError("");
    return controller;
  }
  useEffect(() => {
    activeRead.current?.abort();
    setRows([]);
    setRead(false);
    setSelected(null);
    setCreating(false);
    setBindings("{}");
    setResult(null);
    setError("");
    setSourceCurrentness("unavailable");
    return () => activeRead.current?.abort();
  }, [app?.workspaceId, app?.applicationId]);
  async function loadRules() {
    if (!app || !canRead) return;
    const controller = begin();
    try {
      const result = await collectApplicationRules((args) =>
        readProgram<RuleListPage>(
          app,
          "application.rule.list",
          args,
          controller.signal,
        ),
      );
      if (!controller.signal.aborted) {
        setRows(result.rows);
        setRead(true);
        setPage(0);
        return result.rows;
      }
    } catch (reason) {
      if (!controller.signal.aborted)
        setError(
          reason instanceof Error ? reason.message : "Unable to read rules.",
        );
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  async function open(target: {
    ruleId: string;
    stateToken: string;
    digest: string;
  }) {
    if (!app || !catalog?.functions["application.rule.read"]) return;
    const controller = begin();
    setSelected(null);
    setSourceCurrentness("checking");
    setCreating(false);
    setResult(null);
    try {
      const detail = await readProgram<RuleDetail>(
        app,
        "application.rule.read",
        ruleReadArguments(target.ruleId),
        controller.signal,
      );
      if (controller.signal.aborted) return;
      if (
        !detail.defined ||
        detail.ruleId !== target.ruleId ||
        detail.stateToken !== target.stateToken ||
        detail.programDigest !== target.digest
      )
        throw new Error("The exact application rule is unavailable.");
      setSelected(detail);
      setSourceCurrentness(detail.source ? "checking" : "unavailable");
      setBindings("{}");
    } catch (reason) {
      if (!controller.signal.aborted)
        setError(
          reason instanceof Error ? reason.message : "Unable to open rule.",
        );
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  useEffect(() => {
    if (targetApplicationRule) void open(targetApplicationRule);
  }, [
    app?.workspaceId,
    app?.applicationId,
    targetApplicationRule?.ruleId,
    targetApplicationRule?.stateToken,
    targetApplicationRule?.digest,
  ]);
  async function run() {
    if (
      !app ||
      !selected ||
      selected.status !== "Active" ||
      selected.source?.active === false ||
      sourceCurrentness !== "current" ||
      result !== null ||
      busy
    )
      return;
    setBusy(true);
    setError("");
    try {
      const inputError = parameterInputError(bindings, parameterSchema);
      if (inputError) throw new Error(inputError);
      const values = JSON.parse(bindings);
      if (!values || typeof values !== "object" || Array.isArray(values))
        throw new Error("Rule parameters must be a JSON object.");
      const body = ruleRunBody(
        app,
        selected.ruleId,
        values,
        mutationKey({
          ruleId: selected.ruleId,
          stateToken: selected.stateToken,
          programDigest: selected.programDigest,
          bindings: values,
          runIntent,
        }),
        selected.stateToken,
        selected.programDigest,
      );
      const response = await requestAdmittedEffect<{ result: unknown }>(
        "/api/rule-action",
        body,
      );
      setResult(response.result);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to run rule.",
      );
    } finally {
      setBusy(false);
    }
  }
  if (!app || !catalog) return null;
  return (
    <section
      className="panel capability-activity"
      aria-label="Calculation rules"
    >
      <div className="section-heading-row">
        <div>
          <h2>Calculation rules</h2>
          <p>
            Author Python source, validate and activate the rule, then run its
            compiled definition.
          </p>
        </div>
        <div>
          <button
            disabled={busy || !canRead}
            onClick={() => onRequestTransition(() => void loadRules())}
          >
            Read rules
          </button>
          {canCreate && (
            <button
              disabled={busy}
              onClick={() =>
                onRequestTransition(() => {
                  setSelected(null);
                  setCreating(true);
                })
              }
            >
              New rule
            </button>
          )}
        </div>
      </div>
      {error && <p role="alert">{error}</p>}
      {busy && <p role="status">Working…</p>}
      {read && (
        <>
          <label>
            Find rule
            <input
              aria-label="Find calculation rule"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(0);
              }}
            />
          </label>
          <table className="react-cube-grid">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Status</th>
                <th>Availability</th>
                <th>Metadata</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(start, start + 50).map((row) => (
                <tr key={row.ruleId}>
                  <th>
                    <button
                      onClick={() =>
                        onRequestTransition(
                          () =>
                            void open({
                              ruleId: row.ruleId,
                              stateToken: row.stateToken,
                              digest: row.programDigest,
                            }),
                        )
                      }
                    >
                      {row.ruleId}
                    </button>
                  </th>
                  <td>{row.status}</td>
                  <td>{ruleAvailabilityLabel(row)}</td>
                  <td>{row.metadataCurrent ? "Current" : "Stale"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && (
            <p>No published rules. Create a Python rule to begin.</p>
          )}
          <button
            disabled={start === 0}
            onClick={() => setPage(start / 50 - 1)}
          >
            Previous rules
          </button>
          <button
            disabled={start + 50 >= filtered.length}
            onClick={() => setPage(start / 50 + 1)}
          >
            Next rules
          </button>
        </>
      )}
      {(creating || selected) && (
        <article
          className="program-inspector"
          aria-label="Application rule detail"
        >
          <h3>{selected ? selected.ruleId : "New rule"}</h3>
          <button
            onClick={() =>
              onRequestTransition(() => {
                setSelected(null);
                setCreating(false);
              })
            }
          >
            Close rule
          </button>
          {creating || selected?.source ? (
            <PythonDefinitionEditor
              key={
                selected ? `${selected.ruleId}:${selected.stateToken}` : "new"
              }
              app={app}
              catalog={catalog}
              kind="ApplicationRule"
              binding={selected?.source}
              definitionId={selected?.ruleId}
              template={pythonDefinitionTemplates.ApplicationRule}
              onRefreshCatalog={onRefreshCatalog}
              onSourceCurrentness={setSourceCurrentness}
              onChanged={async (definition) => {
                const rows = await loadRules();
                const row = rows?.find(
                  (row) =>
                    row.ruleId ===
                    (definition?.definitionId ?? selected?.ruleId),
                );
                if (row)
                  await open({
                    ruleId: row.ruleId,
                    stateToken: row.stateToken,
                    digest: row.programDigest,
                  });
              }}
            />
          ) : (
            <p>This compiled rule has no bound Python source.</p>
          )}
          {selected && (
            <>
              <details>
                <summary>Compiled rule inspection</summary>
                <pre role="region" aria-label="Compiled application rule">
                  {JSON.stringify(selected.program, null, 2)}
                </pre>
              </details>
              {Boolean(catalog.functions["application.rule.run"]) && (
                <section aria-label="Run compiled rule">
                  <ParameterFields
                    label="Rule parameters"
                    advancedLabel="Application rule parameters"
                    value={bindings}
                    schema={parameterSchema}
                    disabled={busy || result !== null}
                    onChange={setBindings}
                  />
                  <button
                    disabled={
                      busy ||
                      result !== null ||
                      selected.status !== "Active" ||
                      selected.source?.active === false ||
                      sourceCurrentness !== "current"
                    }
                    onClick={() => void run()}
                  >
                    Run rule
                  </button>
                  {selected.source && sourceCurrentness !== "current" && (
                    <p role="status">
                      {sourceCurrentness === "checking"
                        ? "Confirming the rule's current source before it can run."
                        : "The rule's bound source is unavailable or stale; refresh the exact current source before running."}
                    </p>
                  )}
                  {result !== null && (
                    <button
                      onClick={() => {
                        setResult(null);
                        setRunIntent((value) => value + 1);
                      }}
                    >
                      Prepare another run
                    </button>
                  )}
                </section>
              )}
            </>
          )}
        </article>
      )}
      {result !== null && (
        <>
          <p>
            Rule workflow accepted. Inspect its progress and receipts in
            Monitor.
          </p>
          <pre role="region" aria-label="Application rule run result">
            {JSON.stringify(result, null, 2)}
          </pre>
        </>
      )}
    </section>
  );
}
