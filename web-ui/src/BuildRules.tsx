import { useEffect, useMemo, useState } from "react";
import { readProgram, request, reviewAndSubmit } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";

type RuleSummary = {
  ruleId: string;
  version: number;
  resultKey: string;
  parameterDeclarations: Record<string, unknown>;
  metadataCurrent: boolean;
};
type RuleDetail = {
  defined: boolean;
  ruleId: string;
  version: number;
  status?: string;
  program?: { arguments?: Record<string, unknown> } & Record<string, unknown>;
  programDigest?: string;
  currentMetadataRevision?: number;
  policyRevision?: number;
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
export function ruleReadArguments(ruleId: string, version: number) {
  return { ruleId, version };
}
export function collectExpressionRules(
  readPage: (
    arguments_: ReturnType<typeof ruleListArguments>,
  ) => Promise<RuleListPage>,
) {
  let metadata: number | undefined;
  let policy: number | undefined;
  return collectAllContinuations<RuleListPage, RuleSummary>({
    label: "Expression rules",
    readPage: async (cursor) => {
      const page = await readPage(ruleListArguments(cursor, metadata, policy));
      metadata = page.metadataRevision;
      policy = page.policyRevision;
      return page;
    },
    rows: (page) => page.rows,
    nextCursor: (page) => {
      if (typeof page.hasMore !== "boolean")
        throw new Error("Expression rules continuation status is invalid.");
      if (!page.hasMore && page.nextAfterRuleId !== null)
        throw new Error(
          "Expression rules continuation status is inconsistent.",
        );
      return page.hasMore ? page.nextAfterRuleId : null;
    },
    rowIdentity: (row) => `${row.ruleId}\u0000${row.version}`,
    consistencyIdentity: (page) =>
      `${page.metadataRevision}\u0000${page.policyRevision}`,
  });
}
export function ruleActionBody(
  app: ApplicationSummary,
  functionName:
    | "rules.expression.version.save"
    | "rules.expression.version.publish",
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
export function ruleRunBody(
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
      function: "rules.expression.run",
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
function objectValue(value: string, label: string) {
  const parsed: unknown = JSON.parse(value);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object")
    throw new Error(`${label} must be a JSON object.`);
  return parsed as Record<string, unknown>;
}
function validRuleId(value: string) {
  return /^[A-Za-z0-9._-]{1,100}$/.test(value);
}

type SimpleFormula = "copy" | "add" | "subtract" | "multiply" | "divide";

export function simpleRuleDefinition(
  sourceMembers: Record<string, unknown>,
  targetMembers: Record<string, unknown>,
  formula: SimpleFormula,
  operand: string,
  resultKey: string,
) {
  if (!/^[A-Za-z0-9._-]{8,128}$/.test(resultKey))
    throw new Error(
      "Result key must be 8–128 letters, numbers, dots, underscores or hyphens.",
    );
  if (formula !== "copy" && !/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(operand))
    throw new Error("Enter an exact decimal amount or ratio.");
  if (formula === "divide" && /^-?0(?:\.0+)?$/.test(operand))
    throw new Error("Division ratio cannot be zero.");
  const operations = {
    add: "Add",
    subtract: "Subtract",
    multiply: "Multiply",
    divide: "Divide",
  } as const;
  const literal =
    formula === "add" || formula === "subtract"
      ? "AmountLiteral"
      : "RatioLiteral";
  const expression =
    formula === "copy"
      ? { op: "SourceAmount" }
      : {
          op: operations[formula],
          left: { op: "SourceAmount" },
          right: { op: literal, decimal: operand },
        };
  return {
    sourceMembers,
    expression,
    resultKey,
    ...(Object.keys(targetMembers).length ? { targetMembers } : {}),
  };
}

export function BuildRules({
  app,
  catalog,
  targetApplicationRule,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  targetApplicationRule?: { ruleId: string; version: number; digest: string };
}) {
  const mutationIntentKey = useStableMutationIntentKey("rule-ui");
  const [rules, setRules] = useState<RuleSummary[]>([]);
  const [selected, setSelected] = useState<RuleDetail | null>(null);
  const [metadataRevision, setMetadataRevision] = useState<number | null>(null);
  const [policyRevision, setPolicyRevision] = useState<number | null>(null);
  const [ruleId, setRuleId] = useState("");
  const [version, setVersion] = useState("1");
  const [calculation, setCalculation] = useState(`{
  "sourceMembers": {},
  "expression": { "op": "SourceAmount" },
  "resultKey": "cube.rule.result"
}`);
  const [bindings, setBindings] = useState("{}");
  const [sourceMembers, setSourceMembers] = useState("{}");
  const [targetMembers, setTargetMembers] = useState("{}");
  const [formula, setFormula] = useState<SimpleFormula>("copy");
  const [operand, setOperand] = useState("1");
  const [resultKey, setResultKey] = useState("cube.rule.result");
  const [draftTouched, setDraftTouched] = useState(false);
  const [saveReviewed, setSaveReviewed] = useState(false);
  const [publishReviewed, setPublishReviewed] = useState(false);
  const [runReviewed, setRunReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [applicationRule, setApplicationRule] = useState<RuleDetail | null>(
    null,
  );
  const [applicationRuleError, setApplicationRuleError] = useState("");
  const functions = catalog?.functions || {};
  const available = Boolean(
    functions["rules.expression.version.list"] &&
      functions["rules.expression.version.read"],
  );
  const canSave = Boolean(functions["rules.expression.version.save"]);
  const canPublish = Boolean(functions["rules.expression.version.publish"]);
  const canRun = Boolean(functions["rules.expression.run"]);
  const numericVersion = Number(version);
  const exactSelected = Boolean(
    selected &&
      selected.ruleId === ruleId &&
      selected.version === numericVersion,
  );
  useEffect(() => {
    if (!app || !targetApplicationRule) return;
    if (!catalog?.functions["application.rule.version.read"]) {
      setApplicationRuleError("APPLICATION_RULE_ARTIFACT_UNAUTHORIZED");
      return;
    }
    const controller = new AbortController();
    setApplicationRule(null);
    setApplicationRuleError("");
    readProgram<RuleDetail>(
      { workspaceId: app.workspaceId, applicationId: app.applicationId },
      "application.rule.version.read",
      {
        ruleId: targetApplicationRule.ruleId,
        version: targetApplicationRule.version,
      },
      controller.signal,
    )
      .then((detail) => {
        if (
          !detail.defined ||
          detail.ruleId !== targetApplicationRule.ruleId ||
          detail.version !== targetApplicationRule.version ||
          !detail.program ||
          detail.programDigest !== targetApplicationRule.digest
        )
          throw new Error("APPLICATION_RULE_ARTIFACT_MISMATCH");
        setApplicationRule(detail);
      })
      .catch((reason: Error) => {
        if (reason.name !== "AbortError")
          setApplicationRuleError(reason.message);
      });
    return () => controller.abort();
  }, [
    app?.workspaceId,
    app?.applicationId,
    catalog,
    targetApplicationRule?.ruleId,
    targetApplicationRule?.version,
    targetApplicationRule?.digest,
  ]);
  const draftValid = useMemo(() => {
    if (
      !validRuleId(ruleId) ||
      !Number.isInteger(numericVersion) ||
      numericVersion < 1
    )
      return false;
    try {
      const definition = objectValue(calculation, "Calculation");
      const source = definition.sourceMembers,
        expression = definition.expression,
        target = definition.targetMembers,
        parameters = definition.parameters;
      return Boolean(
        source &&
          !Array.isArray(source) &&
          typeof source === "object" &&
          expression &&
          !Array.isArray(expression) &&
          typeof expression === "object" &&
          typeof definition.resultKey === "string" &&
          /^[A-Za-z0-9._-]{8,128}$/.test(definition.resultKey) &&
          (target === undefined ||
            Boolean(
              target && !Array.isArray(target) && typeof target === "object",
            )) &&
          (parameters === undefined ||
            Boolean(
              parameters &&
                !Array.isArray(parameters) &&
                typeof parameters === "object",
            )),
      );
    } catch {
      return false;
    }
  }, [calculation, numericVersion, ruleId]);
  const bindingsValid = useMemo(() => {
    try {
      objectValue(bindings, "Bindings");
      return true;
    } catch {
      return false;
    }
  }, [bindings]);
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    "build-rule",
    "Unsaved calculation rule or execution bindings",
    draftTouched,
    {
      ruleId,
      version,
      calculation,
      bindings,
      sourceMembers,
      targetMembers,
      formula,
      operand,
      resultKey,
      draftTouched,
      saveReviewed,
      publishReviewed,
      runReviewed,
    },
    (draft) => {
      setRuleId(draft.ruleId);
      setVersion(draft.version);
      setCalculation(draft.calculation);
      setBindings(draft.bindings);
      setSourceMembers(draft.sourceMembers);
      setTargetMembers(draft.targetMembers);
      setFormula(draft.formula);
      setOperand(draft.operand);
      setResultKey(draft.resultKey);
      setDraftTouched(draft.draftTouched);
      setSaveReviewed(draft.saveReviewed);
      setPublishReviewed(draft.publishReviewed);
      setRunReviewed(draft.runReviewed);
    },
  );

  useEffect(() => {
    setRules([]);
    setSelected(null);
    setMetadataRevision(null);
    setPolicyRevision(null);
    setRuleId("");
    setVersion("1");
    setDraftTouched(false);
    setSaveReviewed(false);
    setPublishReviewed(false);
    setRunReviewed(false);
    setResult(null);
    setError("");
  }, [app?.workspaceId, app?.applicationId]);

  function invalidateExactIntent() {
    setSelected(null);
    setSaveReviewed(false);
    setPublishReviewed(false);
    setRunReviewed(false);
    setResult(null);
  }

  async function loadRules() {
    if (!app || !available) return;
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    setBusy(true);
    setError("");
    try {
      const collected = await collectExpressionRules((arguments_) =>
        readProgram(scope, "rules.expression.version.list", arguments_),
      );
      setRules(collected.rows);
      setSelected(null);
      setMetadataRevision(collected.finalPage.metadataRevision);
      setPolicyRevision(collected.finalPage.policyRevision);
      setSaveReviewed(false);
      setPublishReviewed(false);
      setRunReviewed(false);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read rules",
      );
    } finally {
      setBusy(false);
    }
  }

  async function readRule(rule: RuleSummary) {
    if (!app || !available) return;
    setBusy(true);
    setError("");
    try {
      const detail = await readProgram<RuleDetail>(
        { workspaceId: app.workspaceId, applicationId: app.applicationId },
        "rules.expression.version.read",
        ruleReadArguments(rule.ruleId, rule.version),
      );
      if (!detail.defined)
        throw new Error("That immutable rule version is unavailable.");
      setSelected(detail);
      setRuleId(detail.ruleId);
      setVersion(String(detail.version));
      if (detail.program?.arguments)
        setCalculation(JSON.stringify(detail.program.arguments, null, 2));
      if (detail.program?.arguments) {
        const definition = detail.program.arguments;
        setSourceMembers(
          JSON.stringify(definition.sourceMembers || {}, null, 2),
        );
        setTargetMembers(
          JSON.stringify(definition.targetMembers || {}, null, 2),
        );
        if (typeof definition.resultKey === "string")
          setResultKey(definition.resultKey);
        const expression = definition.expression as
          | {
              op?: string;
              left?: { op?: string };
              right?: { op?: string; decimal?: string };
            }
          | undefined;
        const names: Record<string, SimpleFormula> = {
          Add: "add",
          Subtract: "subtract",
          Multiply: "multiply",
          Divide: "divide",
        };
        if (expression?.op === "SourceAmount") setFormula("copy");
        else if (
          expression?.op &&
          names[expression.op] &&
          expression.left?.op === "SourceAmount" &&
          expression.right?.decimal
        ) {
          setFormula(names[expression.op]);
          setOperand(expression.right.decimal);
        }
      }
      setBindings("{}");
      setDraftTouched(false);
      setMetadataRevision(detail.currentMetadataRevision ?? metadataRevision);
      setPolicyRevision(detail.policyRevision ?? policyRevision);
      setSaveReviewed(false);
      setPublishReviewed(false);
      setRunReviewed(false);
      setResult(null);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read rule",
      );
    } finally {
      setBusy(false);
    }
  }

  async function applyRuleAction(action: "save" | "publish") {
    if (!app || metadataRevision === null || policyRevision === null) return;
    const save = action === "save";
    if (
      save ? !saveReviewed || !draftValid : !publishReviewed || !exactSelected
    )
      return;
    if (
      !window.confirm(
        save
          ? "Save this exact immutable calculation-rule version?"
          : "Publish this exact immutable calculation-rule version?",
      )
    )
      return;
    setBusy(true);
    setError("");
    try {
      const args: Record<string, unknown> = {
        ruleId,
        version: numericVersion,
        ...(save
          ? { calculation: objectValue(calculation, "Calculation") }
          : {}),
        expectedMetadataRevision: metadataRevision,
        expectedPolicyRevision: policyRevision,
      };
      const response = await request(
        "/api/rule-action",
        ruleActionBody(
          app,
          `rules.expression.version.${action}`,
          args,
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            functionName: `rules.expression.version.${action}`,
            args,
          }),
        ),
      );
      setResult(response);
      setDraftTouched(false);
      setSaveReviewed(false);
      setPublishReviewed(false);
      setRunReviewed(false);
      setSelected(null);
      await loadRules();
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : `Unable to ${action} rule`,
      );
    } finally {
      setBusy(false);
    }
  }

  function generateSimpleDefinition() {
    try {
      const definition = simpleRuleDefinition(
        objectValue(sourceMembers, "Source member filters"),
        objectValue(targetMembers, "Target member overrides"),
        formula,
        operand.trim(),
        resultKey.trim(),
      );
      setCalculation(JSON.stringify(definition, null, 2));
      setDraftTouched(true);
      setSelected(null);
      setSaveReviewed(false);
      setPublishReviewed(false);
      setRunReviewed(false);
      setResult(null);
      setError("");
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to generate typed definition",
      );
    }
  }

  async function runRule() {
    if (!app || !canRun || !exactSelected || !runReviewed || !bindingsValid)
      return;
    setBusy(true);
    setError("");
    try {
      const response = await reviewAndSubmit(
        ruleRunBody(
          app,
          ruleId,
          objectValue(bindings, "Bindings"),
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            functionName: "application.rule.run",
            ruleId,
            bindings: objectValue(bindings, "Bindings"),
          }),
        ),
        "Review the published rule-execution preview.",
      );
      if (!response) return;
      setResult(response);
      setDraftTouched(false);
      setRunReviewed(false);
      setSelected(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to run rule");
    } finally {
      setBusy(false);
    }
  }

  if (!available && !targetApplicationRule) return null;
  return (
    <section
      className="panel capability-activity"
      aria-labelledby="rule-explorer-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>REUSABLE BUSINESS LOGIC</small>
          <h2 id="rule-explorer-heading" tabIndex={-1}>
            Calculation rules
          </h2>
          <p>
            Inspect, author, publish and execute typed rules through the
            existing fixed-core contracts.
          </p>
        </div>
        <button disabled={busy} onClick={() => void loadRules()}>
          {busy ? "Working…" : "Read rules"}
        </button>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {targetApplicationRule && (
        <article
          className="program-inspector"
          aria-label="Application rule artifact"
        >
          <h3>
            Application rule {targetApplicationRule.ruleId} v
            {targetApplicationRule.version}
          </h3>
          {applicationRuleError ? (
            <p className="inline-error" role="alert">
              Exact artifact unavailable: {applicationRuleError}
            </p>
          ) : applicationRule ? (
            <>
              <p>
                {applicationRule.status || "Saved immutable version"} · digest{" "}
                <code>{applicationRule.programDigest}</code>
              </p>
              <pre>{JSON.stringify(applicationRule.program, null, 2)}</pre>
            </>
          ) : (
            <p role="status">Reading exact application rule…</p>
          )}
        </article>
      )}
      {rules.length ? (
        <div className="react-grid-scroll">
          <table className="react-cube-grid rule-grid">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Version</th>
                <th>Result</th>
                <th>Parameters</th>
                <th>Metadata</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={`${rule.ruleId}-${rule.version}`}>
                  <th>{rule.ruleId}</th>
                  <td>{rule.version}</td>
                  <td>
                    <code>{rule.resultKey}</code>
                  </td>
                  <td>
                    <code>{JSON.stringify(rule.parameterDeclarations)}</code>
                  </td>
                  <td>{rule.metadataCurrent ? "Current" : "Stale"}</td>
                  <td>
                    <button disabled={busy} onClick={() => void readRule(rule)}>
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted-copy">No published-rule catalogue read yet.</p>
      )}
      <div className="governed-action-grid rule-authoring-grid">
        <article className="governed-action-card">
          <small>REVIEWED IMMUTABLE DEFINITION</small>
          <h3>Author and publish</h3>
          <label>
            Rule stable ID
            <input
              aria-label="Rule stable ID"
              value={ruleId}
              maxLength={100}
              onChange={(event) => {
                setRuleId(event.target.value);
                setDraftTouched(true);
                invalidateExactIntent();
              }}
            />
          </label>
          <label>
            Version
            <input
              aria-label="Rule version"
              type="number"
              min="1"
              step="1"
              value={version}
              onChange={(event) => {
                setVersion(event.target.value);
                setDraftTouched(true);
                invalidateExactIntent();
              }}
            />
          </label>
          <fieldset className="formula-composer">
            <legend>Guided typed formula</legend>
            <label>
              Source member filters
              <textarea
                aria-label="Rule source member filters"
                rows={4}
                spellCheck={false}
                value={sourceMembers}
                onChange={(event) => {
                  setSourceMembers(event.target.value);
                  setDraftTouched(true);
                }}
              />
            </label>
            <label>
              Target member overrides
              <textarea
                aria-label="Rule target member overrides"
                rows={4}
                spellCheck={false}
                value={targetMembers}
                onChange={(event) => {
                  setTargetMembers(event.target.value);
                  setDraftTouched(true);
                }}
              />
            </label>
            <label>
              Formula
              <select
                aria-label="Rule formula"
                value={formula}
                onChange={(event) => {
                  setDraftTouched(true);
                  setFormula(event.target.value as SimpleFormula);
                }}
              >
                <option value="copy">Copy source</option>
                <option value="add">Source + exact amount</option>
                <option value="subtract">Source − exact amount</option>
                <option value="multiply">Source × exact ratio</option>
                <option value="divide">Source ÷ exact ratio</option>
              </select>
            </label>
            <label>
              Exact amount or ratio
              <input
                aria-label="Rule formula operand"
                inputMode="decimal"
                value={operand}
                disabled={formula === "copy"}
                onChange={(event) => {
                  setOperand(event.target.value);
                  setDraftTouched(true);
                }}
              />
            </label>
            <label>
              Result key
              <input
                aria-label="Rule result key"
                value={resultKey}
                maxLength={128}
                onChange={(event) => {
                  setResultKey(event.target.value);
                  setDraftTouched(true);
                }}
              />
            </label>
            <button
              type="button"
              className="secondary"
              onClick={generateSimpleDefinition}
            >
              Generate typed definition
            </button>
            <p className="authority-note">
              This composer only prepares approved typed JSON. The fixed core
              still validates and executes it.
            </p>
          </fieldset>
          <label>
            Typed calculation definition
            <textarea
              aria-label="Typed calculation definition"
              rows={12}
              spellCheck={false}
              value={calculation}
              onChange={(event) => {
                setCalculation(event.target.value);
                setDraftTouched(true);
                setSaveReviewed(false);
                setResult(null);
              }}
            />
          </label>
          <label className="review-check">
            <input
              type="checkbox"
              checked={saveReviewed}
              disabled={!canSave || !draftValid || metadataRevision === null}
              onChange={(event) => setSaveReviewed(event.target.checked)}
            />
            I reviewed this exact new immutable definition.
          </label>
          <button
            disabled={
              busy ||
              !canSave ||
              !draftValid ||
              !saveReviewed ||
              metadataRevision === null
            }
            onClick={() => void applyRuleAction("save")}
          >
            Save immutable version
          </button>
          <label className="review-check">
            <input
              type="checkbox"
              checked={publishReviewed}
              disabled={
                !canPublish || !exactSelected || metadataRevision === null
              }
              onChange={(event) => setPublishReviewed(event.target.checked)}
            />
            I freshly read and reviewed this exact version for publication.
          </label>
          <button
            className="secondary"
            disabled={
              busy ||
              !canPublish ||
              !exactSelected ||
              !publishReviewed ||
              metadataRevision === null
            }
            onClick={() => void applyRuleAction("publish")}
          >
            Publish exact version
          </button>
        </article>
        <article className="governed-action-card">
          <small>PREVIEWED DURABLE EXECUTION</small>
          <h3>Run published rule</h3>
          <p>
            {exactSelected
              ? `${ruleId} v${version} is freshly read.`
              : "Open a published rule from the catalogue first."}
          </p>
          <label>
            Parameter bindings
            <textarea
              aria-label="Rule parameter bindings"
              rows={6}
              spellCheck={false}
              value={bindings}
              onChange={(event) => {
                setBindings(event.target.value);
                setDraftTouched(true);
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
            I reviewed this exact rule execution and bindings.
          </label>
          <button
            disabled={
              busy ||
              !canRun ||
              !exactSelected ||
              !bindingsValid ||
              !runReviewed
            }
            onClick={() => void runRule()}
          >
            Preview and submit
          </button>
          <p className="authority-note">
            The fixed core validates the rule, bindings, authorization and
            publication. The browser performs no calculation.
          </p>
        </article>
      </div>
      {selected && (
        <article
          className="program-inspector"
          aria-label="Calculation rule detail"
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
            ? "No rule snapshot read"
            : `${rules.length} rules · metadata revision ${metadataRevision} · policy revision ${policyRevision}`}
        </span>
      </footer>
    </section>
  );
}
