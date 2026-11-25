import { useEffect, useRef, useState } from "react";
import { ApiError, readProgram } from "./api";
import { ExactScopeSelector } from "./ExactScopeSelector";
import { parseParameterJson } from "./exact-parameters";
import { useGovernedEffectRecovery } from "./governed-effect-recovery";
import { MetadataReceiptRecovery } from "./MetadataReceiptRecovery";
import { useStableMutationIntentKey } from "./mutation-intent";
import protocol, {
  authoredDefinition,
  newDefinition,
  newRule,
  policyFunctions as fn,
  policyPage,
  policyRecord,
  validDefinition,
  type Definition,
  type Policy,
  type PolicyAction,
  type PolicyPage,
  type Review,
  type Rule,
} from "./planning-policy";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";

type Props = { app: ApplicationSummary; catalog: ApplicationCatalog };
type Draft = {
  definition: Definition;
  expectedStateToken?: string;
  sourceId?: string;
};
function PolicySummary({ title, policy }: { title: string; policy: Policy }) {
  return (
    <section aria-label={title}>
      <h4>{title}</h4>
      <p>
        Effective from {policy.definition.effectiveFrom}{" "}
        {policy.definition.effectiveTo
          ? "through " + policy.definition.effectiveTo
          : "with no end date"}
        . Last changed by {policy.actor.subjectId} on {policy.updatedAt}.
      </p>
      <ul>
        {policy.definition.rules.map((rule) => (
          <li key={rule.ruleId}>
            <strong>{rule.ruleId}</strong> · {rule.effect}{" "}
            {rule.actions.join(", ")} for {rule.workflowRoles.join(", ")} ·
            priority {rule.priority}
            {Object.entries(rule.memberSelectors).map(([axis, members]) => (
              <span key={axis}>
                {" "}
                · {axis} = {members.join(", ")}
              </span>
            ))}
            {rule.levelSelector && (
              <span>
                {" "}
                · {rule.levelSelector.dimensionId} under{" "}
                {rule.levelSelector.rootMemberId} at depth{" "}
                {rule.levelSelector.depth}
              </span>
            )}
            {rule.scenarioBound && (
              <span>
                {" "}
                · {rule.scenarioBound.dimensionId} ={" "}
                {rule.scenarioBound.members.join(", ")}
              </span>
            )}
            {rule.periodBound && (
              <span>
                {" "}
                · {rule.periodBound.dimensionId} from{" "}
                {rule.periodBound.startMemberId} through{" "}
                {rule.periodBound.endMemberId}
              </span>
            )}
            {rule.effectiveFrom && <span> · starts {rule.effectiveFrom}</span>}
            {rule.effectiveTo && <span> · ends {rule.effectiveTo}</span>}
          </li>
        ))}
      </ul>
      <details>
        <summary>Exact definition and references</summary>
        <p>
          State token <code>{policy.stateToken}</code>
        </p>
        <p>
          Content digest <code>{policy.canonicalDigest}</code>
        </p>
        <pre>{JSON.stringify(policy.definition, null, 2)}</pre>
      </details>
    </section>
  );
}
export function PlanningPolicies(props: Props) {
  const { app, catalog } = props;
  const context = JSON.stringify([
    app.workspaceId,
    app.applicationId,
    catalog.accessContext,
    catalog.applicationAccess.issuer,
    catalog.applicationAccess.subjectId,
    catalog.applicationAccess.authorizationModel,
    catalog.revisions.policy,
    catalog.revisions.metadata,
    catalog.revisions.security,
    Object.values(fn).map((f) => Boolean(catalog.functions[f])),
  ]);
  return <PolicyWorkspace key={context} {...props} context={context} />;
}
function PolicyWorkspace({
  app,
  catalog,
  context,
}: Props & { context: string }) {
  const [page, setPage] = useState<PolicyPage | null>(null);
  const [selected, setSelected] = useState<Policy | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [advanced, setAdvanced] = useState<string | null>(null);
  const [review, setReview] = useState<Review | null>(null);
  const [stale, setStale] = useState(false);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const controller = useRef<AbortController | null>(null);
  const keyFor = useStableMutationIntentKey("planning-policy");
  const group =
    catalog.applicationAccess.authorizationModel === "group_assignments";
  const can = (a: keyof typeof fn) => Boolean(catalog.functions[fn[a]]);
  const identity = catalog.applicationAccess;
  const recovery = useGovernedEffectRecovery(
    app,
    catalog,
    context,
    {
      ...protocol,
      initialRefusal(reason) {
        if (
          reason instanceof ApiError &&
          [
            "PLANNING_POLICY_STATE_STALE",
            "PLANNING_POLICY_DIGEST_MISMATCH",
            "PLANNING_POLICY_EXPECTED_STATE_TOKEN_REQUIRED",
            "PLANNING_POLICY_HIERARCHY_STALE",
            "PLANNING_POLICY_ANOTHER_ACTIVE",
            "PLANNING_POLICY_ALREADY_ACTIVE",
            "PLANNING_POLICY_NOT_ACTIVE",
          ].includes(reason.code)
        )
          setStale(true);
        return protocol.initialRefusal(reason);
      },
    },
    (details) => {
      setReview(null);
      setDraft(null);
      setAdvanced(null);
      setSelected(null);
      setNotice(
        details.action === "save"
          ? "Draft saved. It is available for activation review."
          : details.action === "activate"
            ? "Policy activation recorded."
            : "Policy deactivation recorded.",
      );
      void load(details.policyId);
    },
  );
  const busy = working || recovery.busy || recovery.pending;
  useUnsavedWork(
    "planning-policy-definition",
    "Unsubmitted planning policy",
    Boolean(draft || review) && !recovery.pending,
  );
  function begin() {
    controller.current?.abort();
    const next = new AbortController();
    controller.current = next;
    setWorking(true);
    setError("");
    return next.signal;
  }
  async function load(id?: string, next?: PolicyPage) {
    if (!can("list")) return;
    const signal = begin();
    setReview(null);
    setSelected(null);
    setPage(null);
    setStale(false);
    try {
      const data = await readProgram<unknown>(
        app,
        fn.list,
        {
          limit: 25,
          ...(next && {
            afterPolicyId: next.nextAfterPolicyId,
            expectedCollectionToken: next.collectionToken,
          }),
        },
        signal,
      );
      if (signal.aborted) return;
      setPage(policyPage(data, app, next));
      if (id && can("read")) {
        const row = await readProgram<unknown>(
          app,
          fn.read,
          { policyId: id },
          signal,
        );
        if (!signal.aborted) setSelected(policyRecord(row, app, id));
      }
    } catch (e) {
      if (!signal.aborted)
        setError(
          e instanceof ApiError && e.code === "PLANNING_POLICY_LIST_STALE"
            ? "The policy collection changed. Refresh to return to its first page."
            : e instanceof Error
              ? e.message
              : "Unable to read policies.",
        );
    } finally {
      if (!signal.aborted) setWorking(false);
    }
  }
  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, []);
  async function open(id: string) {
    if (busy || draft || !can("read")) return;
    const signal = begin();
    setStale(false);
    setReview(null);
    setSelected(null);
    setNotice("");
    try {
      const data = await readProgram<unknown>(
        app,
        fn.read,
        { policyId: id },
        signal,
      );
      if (!signal.aborted) setSelected(policyRecord(data, app, id));
    } catch (e) {
      if (!signal.aborted)
        setError(
          e instanceof Error ? e.message : "Unable to read this policy.",
        );
    } finally {
      if (!signal.aborted) setWorking(false);
    }
  }
  function edit(row?: Policy) {
    if (busy || !can("save")) return;
    setReview(null);
    setAdvanced(null);
    setNotice("");
    setError("");
    if (!row) {
      setSelected(null);
      setDraft({ definition: newDefinition(app) });
      return;
    }
    const copy = authoredDefinition(row);
    if (!group && row.status === "Active") {
      copy.policyId = "";
      setDraft({ definition: copy, sourceId: row.policyId });
      return;
    }
    setDraft({ definition: copy, expectedStateToken: row.stateToken });
  }
  function update(definition: Definition) {
    if (!draft || busy) return;
    setDraft({ ...draft, definition });
    setReview(null);
    setError("");
  }
  function updateRule(index: number, fields: Partial<Rule>) {
    if (!draft) return;
    update({
      ...draft.definition,
      rules: draft.definition.rules.map((r, i) =>
        i === index ? { ...r, ...fields } : r,
      ),
    });
  }
  const candidate =
    selected?.pendingDraft ?? (selected?.status === "Saved" ? selected : null);
  function proposed(action: PolicyAction): Review | null {
    if (
      !can(action) ||
      !identity.subjectId ||
      !identity.issuer ||
      busy ||
      stale
    )
      return null;
    let args: Record<string, unknown>, id: string;
    if (action === "save") {
      if (
        !draft ||
        advanced !== null ||
        !validDefinition(draft.definition, app) ||
        draft.sourceId === draft.definition.policyId
      )
        return null;
      id = draft.definition.policyId;
      args = {
        definition: draft.definition,
        ...(draft.expectedStateToken && {
          expectedStateToken: draft.expectedStateToken,
        }),
      };
    } else {
      const row =
        action === "activate"
          ? candidate
          : selected?.status === "Active"
            ? selected
            : null;
      if (draft || !row) return null;
      id = row.policyId;
      args = {
        policyId: id,
        expectedStateToken: row.stateToken,
        canonicalDigest: row.canonicalDigest,
      };
    }
    return {
      action,
      policyId: id,
      args,
      issuer: identity.issuer,
      actorId: identity.subjectId,
      groupAssigned: group,
      previousCommit: catalog.revisions.commit,
    };
  }
  function prepare(action: PolicyAction) {
    const next = proposed(action);
    if (next) {
      setReview(next);
      setNotice("");
      setError("");
    }
  }
  async function submit() {
    if (
      !review ||
      JSON.stringify(proposed(review.action)) !== JSON.stringify(review)
    )
      return;
    const program = {
      languageVersion: 2,
      function: fn[review.action],
      arguments: review.args,
    };
    setReview(null);
    await recovery.submit(
      {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        program,
        confirmed: true,
        idempotencyKey: keyFor([context, program]),
      },
      review,
    );
  }
  const definition = draft?.definition;
  return (
    <section className="panel" aria-label="Planning policies">
      <h2>Planning policies</h2>
      <p>
        These policies govern cube writes by action, workflow duty and member
        selection.
      </p>
      <button disabled={busy || Boolean(draft)} onClick={() => void load()}>
        Refresh policies
      </button>
      {can("save") && !draft && (
        <button disabled={busy || !page} onClick={() => edit()}>
          New policy draft
        </button>
      )}
      {working && <p role="status">Reading policies…</p>}
      {error && <p role="alert">{error}</p>}
      {notice && <p role="status">{notice}</p>}
      {stale && (
        <section aria-label="Policy review expired">
          <p>
            The reviewed state changed. Read the current policy before preparing
            another change.
          </p>
          <button
            disabled={busy}
            onClick={() => {
              const id = selected?.policyId || draft?.definition.policyId;
              setDraft(null);
              setAdvanced(null);
              void load(id);
            }}
          >
            {draft ? "Discard local edits and reread policy" : "Reread policy"}
          </button>
        </section>
      )}
      <MetadataReceiptRecovery
        object="planning policy"
        recovery={recovery}
        onClose={() => {
          if (recovery.closeRecovery()) {
            setDraft(null);
            setAdvanced(null);
            void load();
          }
        }}
        copyReceiptCheck={() => recovery.copyReceiptCheck()}
      />
      {page && (
        <section aria-label="Policy list">
          {page.policies.length === 0 ? (
            <p>No policies were found.</p>
          ) : (
            <ul>
              {page.policies.map((p) => (
                <li key={p.policyId}>
                  <button
                    disabled={busy || Boolean(draft) || !can("read")}
                    onClick={() => void open(p.policyId)}
                  >
                    {p.policyId}
                  </button>
                  {" · "}
                  {p.status === "Active" ? "Active" : "Saved draft"}
                  {p.pendingDraft ? " · Pending draft" : ""}
                </li>
              ))}
            </ul>
          )}
          {page.nextAfterPolicyId && (
            <button
              disabled={busy || Boolean(draft)}
              onClick={() => void load(undefined, page)}
            >
              Next policy page
            </button>
          )}
        </section>
      )}
      {selected && (
        <section aria-label="Policy details">
          <h3>{selected.policyId}</h3>
          <PolicySummary
            policy={selected}
            title={
              selected.status === "Active" ? "Active policy" : "Saved draft"
            }
          />
          {selected.pendingDraft && (
            <PolicySummary
              policy={selected.pendingDraft}
              title="Pending draft"
            />
          )}
          {!draft && !review && (
            <>
              {can("save") && (
                <button
                  disabled={busy}
                  onClick={() => edit(selected.pendingDraft ?? selected)}
                >
                  {!group && selected.status === "Active"
                    ? "Copy to a new policy draft"
                    : candidate
                      ? "Edit draft"
                      : "Draft a revision"}
                </button>
              )}
              {candidate && can("activate") && (
                <button
                  disabled={!proposed("activate")}
                  onClick={() => prepare("activate")}
                >
                  Review activation
                </button>
              )}
              {selected.status === "Active" && can("deactivate") && (
                <button
                  disabled={!proposed("deactivate")}
                  onClick={() => prepare("deactivate")}
                >
                  Review deactivation
                </button>
              )}
            </>
          )}
        </section>
      )}
      {draft && definition && !recovery.pending && (
        <fieldset disabled={busy}>
          <legend>Draft policy</legend>
          {draft.sourceId && (
            <p>Choose a new policy ID. The source policy stays active.</p>
          )}
          <label className="form-field">
            Policy ID
            <input
              value={definition.policyId}
              readOnly={Boolean(draft.expectedStateToken)}
              onChange={(e) =>
                update({ ...definition, policyId: e.target.value })
              }
            />
          </label>
          <label className="form-field">
            Effective from
            <input
              type="date"
              value={definition.effectiveFrom}
              onChange={(e) =>
                update({ ...definition, effectiveFrom: e.target.value })
              }
            />
          </label>
          <label className="form-field">
            Effective through
            <input
              type="date"
              value={definition.effectiveTo ?? ""}
              onChange={(e) =>
                update({ ...definition, effectiveTo: e.target.value || null })
              }
            />
          </label>
          {advanced === null &&
            definition.rules.map((rule, index) => (
              <fieldset key={index}>
                <legend>Rule {index + 1}</legend>
                <label className="form-field">
                  Rule ID
                  <input
                    value={rule.ruleId}
                    onChange={(e) =>
                      updateRule(index, { ruleId: e.target.value })
                    }
                  />
                </label>
                <label className="form-field">
                  Priority
                  <input
                    type="number"
                    min={0}
                    max={10000}
                    value={rule.priority}
                    onChange={(e) =>
                      updateRule(index, { priority: e.target.valueAsNumber })
                    }
                  />
                </label>
                <label className="form-field">
                  Effect
                  <select
                    value={rule.effect}
                    onChange={(e) =>
                      updateRule(index, {
                        effect: e.target.value as Rule["effect"],
                      })
                    }
                  >
                    <option>Allow</option>
                    <option>Deny</option>
                  </select>
                </label>
                <label className="form-field">
                  Write actions (comma-separated)
                  <input
                    value={rule.actions.join(",")}
                    onChange={(e) =>
                      updateRule(index, {
                        actions: e.target.value.split(",").map((s) => s.trim()),
                      })
                    }
                  />
                </label>
                <label className="form-field">
                  Workflow duty IDs (comma-separated)
                  <input
                    value={rule.workflowRoles.join(",")}
                    onChange={(e) =>
                      updateRule(index, {
                        workflowRoles: e.target.value
                          .split(",")
                          .map((s) => s.trim()),
                      })
                    }
                  />
                </label>
                {can("save") &&
                Boolean(
                  catalog.functions["metadata.dimension.list"] &&
                    catalog.functions["metadata.member.list"],
                ) &&
                Object.values(rule.memberSelectors).every(
                  (ids) => ids.length === 1,
                ) ? (
                  <ExactScopeSelector
                    app={app}
                    catalog={catalog}
                    value={Object.fromEntries(
                      Object.entries(rule.memberSelectors).map(([k, v]) => [
                        k,
                        v[0],
                      ]),
                    )}
                    onChange={(scope) =>
                      updateRule(index, {
                        memberSelectors: Object.fromEntries(
                          Object.entries(scope).map(([k, v]) => [k, [v]]),
                        ),
                      })
                    }
                  />
                ) : null}
                <p>
                  {Object.keys(rule.memberSelectors).length === 0
                    ? "No exact member filter."
                    : JSON.stringify(rule.memberSelectors)}
                </p>
                {definition.rules.length > 1 && (
                  <button
                    onClick={() =>
                      update({
                        ...definition,
                        rules: definition.rules.filter((_, i) => i !== index),
                      })
                    }
                  >
                    Remove rule {index + 1}
                  </button>
                )}
              </fieldset>
            ))}
          {advanced === null ? (
            <>
              <button
                disabled={definition.rules.length >= 500}
                onClick={() =>
                  update({
                    ...definition,
                    rules: [
                      ...definition.rules,
                      {
                        ...newRule(),
                        ...(definition.format && { levelSelector: null }),
                      },
                    ],
                  })
                }
              >
                Add rule
              </button>
              <button
                onClick={() => {
                  setReview(null);
                  setAdvanced(JSON.stringify(definition.rules, null, 2));
                }}
              >
                Edit full rule definitions
              </button>
            </>
          ) : (
            <>
              <label className="form-field">
                Rules JSON
                <textarea
                  rows={12}
                  value={advanced}
                  onChange={(e) => {
                    setAdvanced(e.target.value);
                    setError("");
                  }}
                />
              </label>
              <p>
                Use memberSelectors for sets of members, scenarioBound or
                periodBound for ranges, and levelSelector for a hierarchy level.
              </p>
              <button
                onClick={() => {
                  try {
                    const rules: unknown = parseParameterJson(advanced);
                    if (!Array.isArray(rules)) throw new Error();
                    const v2 = rules.some(
                      (r) => r && Object.hasOwn(r, "levelSelector"),
                    );
                    const value = {
                      ...definition,
                      rules,
                      format: v2
                        ? ("openepm-planning-workflow-policy-v2" as const)
                        : undefined,
                    };
                    if (value.format === undefined) delete value.format;
                    if (!validDefinition(value, app)) throw new Error();
                    setAdvanced(null);
                    update(value);
                  } catch {
                    setError(
                      "Check policy ID, effective dates, rule IDs, actions, duties and selector definitions.",
                    );
                  }
                }}
              >
                Use edited rules
              </button>
              <button
                onClick={() => {
                  setAdvanced(null);
                  setError("");
                }}
              >
                Discard rule text edits
              </button>
            </>
          )}
          <button disabled={!proposed("save")} onClick={() => prepare("save")}>
            Review draft
          </button>
          <button
            onClick={() => {
              setDraft(null);
              setAdvanced(null);
              setReview(null);
              setError("");
            }}
          >
            Discard draft edits
          </button>
        </fieldset>
      )}
      {review && (
        <section
          className="metadata-changeset-review"
          aria-label="Policy change review"
        >
          <h3>
            {review.action === "save"
              ? "Review draft"
              : review.action === "activate"
                ? "Activate policy"
                : "Deactivate policy"}{" "}
            · {review.policyId}
          </h3>
          <p>
            {review.action === "save"
              ? "Saving records the draft for an activation review. Current enforcement continues."
              : review.action === "activate"
                ? "The reviewed saved rules will govern cube writes when activated."
                : "Deactivation removes this policy’s restrictions on cube writes. Other access controls still apply."}
          </p>
          {review.action === "deactivate" && selected?.pendingDraft && (
            <p>The pending draft will remain available as a saved policy.</p>
          )}
          <details open>
            <summary>Reviewed operation</summary>
            <pre>{JSON.stringify(review.args, null, 2)}</pre>
          </details>
          <button disabled={busy} onClick={() => void submit()}>
            {review.action === "save"
              ? "Save reviewed draft"
              : review.action === "activate"
                ? "Activate reviewed policy"
                : "Deactivate reviewed policy"}
          </button>
          <button disabled={busy} onClick={() => setReview(null)}>
            Cancel review
          </button>
        </section>
      )}
    </section>
  );
}
