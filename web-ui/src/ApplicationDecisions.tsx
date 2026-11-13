import { useEffect, useRef, useState } from "react";
import { readProgram, readSecurityProgram, requestAdmittedEffect } from "./api";
import type { ApplicationCatalog, Scope } from "./types";
import { usePreservedDraft } from "./unsaved-work";
import {
  collectSecuritySubjectOptions,
  type SecuritySubject,
} from "./security-directory";

export type ApplicationDecision = {
  decisionId: string;
  stateToken: string;
  title: string;
  text: string;
  rationale: string;
  sourceReference: string;
  provenance: "UserDecision" | "AgentInterpretation";
  status: "Active" | "Withdrawn";
  actor: { issuer: string; subjectId: string };
  updatedAt: string;
  operationId: string;
  contentDigest: string;
};
type Summary = Omit<
  ApplicationDecision,
  "text" | "rationale" | "sourceReference"
>;
type DecisionPage = {
  items: Summary[];
  collectionToken: string;
  nextAfterDecisionId: string | null;
};
type Program = {
  languageVersion: number;
  function: string;
  arguments: Record<string, unknown>;
};
type Draft = {
  decisionId: string;
  expectedStateToken?: string;
  title: string;
  text: string;
  rationale: string;
  sourceReference: string;
  provenance: ApplicationDecision["provenance"];
  intent?: { program: Program; key: string };
};
function content(record: ApplicationDecision): Draft {
  return {
    decisionId: record.decisionId,
    expectedStateToken: record.stateToken,
    title: record.title,
    text: record.text,
    rationale: record.rationale,
    sourceReference: record.sourceReference,
    provenance: record.provenance,
  };
}
function DecisionText({
  decision,
  actorName,
}: {
  decision: ApplicationDecision;
  actorName: string;
}) {
  return (
    <article>
      <h3>{decision.title}</h3>
      <p>
        {decision.status} ·{" "}
        {decision.provenance === "UserDecision"
          ? "User decision"
          : "Agent interpretation"}
      </p>
      <p style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
        {decision.text}
      </p>
      {decision.rationale && (
        <p style={{ whiteSpace: "pre-wrap" }}>
          <strong>Rationale: </strong>
          {decision.rationale}
        </p>
      )}
      {decision.sourceReference && (
        <p>
          <strong>Source: </strong>
          {decision.sourceReference}
        </p>
      )}
      <p className="data-scope-note">
        Recorded by {actorName} at{" "}
        {new Date(decision.updatedAt).toLocaleString()}
      </p>
    </article>
  );
}
export function ApplicationDecisions({
  scope,
  catalog,
  onRequestTransition,
}: {
  scope: Scope;
  catalog: ApplicationCatalog;
  onRequestTransition: (action: () => void) => void;
}) {
  const allowed = (action: string) =>
    Object.hasOwn(catalog.functions, `application.decision.${action}`);
  const canRead = allowed("list") && allowed("read");
  const [page, setPage] = useState<DecisionPage | null>(null);
  const [selected, setSelected] = useState<ApplicationDecision | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [comparison, setComparison] = useState<ApplicationDecision | null>(
    null,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [subjects, setSubjects] = useState<SecuritySubject[]>([]);
  const [directoryIssuer, setDirectoryIssuer] = useState("");
  const alive = useRef(true);
  const readSequence = useRef(0);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  usePreservedDraft(
    scope.workspaceId,
    scope.applicationId,
    "application-decisions",
    "Application decision",
    draft !== null,
    draft,
    setDraft,
  );
  async function loadPage(after?: string, pin?: string) {
    const result = await readProgram<DecisionPage>(
      scope,
      "application.decision.list",
      {
        limit: 25,
        ...(after
          ? { afterDecisionId: after, expectedCollectionToken: pin }
          : {}),
      },
    );
    if (alive.current) setPage(result);
  }
  useEffect(() => {
    if (!canRead) return;
    const controller = new AbortController();
    readProgram<DecisionPage>(
      scope,
      "application.decision.list",
      { limit: 25 },
      controller.signal,
    )
      .then(setPage)
      .catch((reason: Error) => {
        if (!controller.signal.aborted) setError(reason.message);
      });
    return () => controller.abort();
  }, [scope.workspaceId, scope.applicationId, canRead]);
  useEffect(() => {
    if (
      !Object.hasOwn(catalog.functions, "security.application.subject.list") ||
      !Object.hasOwn(catalog.functions, "security.identity.current.read")
    ) {
      setSubjects([]);
      setDirectoryIssuer("");
      return;
    }
    const controller = new AbortController();
    void Promise.all([
      collectSecuritySubjectOptions((arguments_) =>
        readSecurityProgram(
          scope,
          "security.application.subject.list",
          arguments_,
          controller.signal,
        ),
      ),
      readProgram<{ issuer: string; subjectId: string }>(
        scope,
        "security.identity.current.read",
        {},
        controller.signal,
      ),
    ])
      .then(([directory, identity]) => {
        if (controller.signal.aborted) return;
        setSubjects(directory.rows);
        setDirectoryIssuer(identity.issuer);
      })
      .catch(() => {
        if (controller.signal.aborted) return;
        setSubjects([]);
        setDirectoryIssuer("");
      });
    return () => controller.abort();
  }, [
    scope.workspaceId,
    scope.applicationId,
    Object.hasOwn(catalog.functions, "security.application.subject.list"),
    Object.hasOwn(catalog.functions, "security.identity.current.read"),
  ]);

  function actorName(decision: ApplicationDecision) {
    const subject =
      decision.actor.issuer === directoryIssuer
        ? subjects.find(
            (candidate) => candidate.selectionKey === decision.actor.subjectId,
          )
        : undefined;
    return subject
      ? `${subject.displayName} (${subject.username})`
      : "Directory identity unavailable";
  }
  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
    } catch (reason) {
      if (alive.current)
        setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function show(decisionId: string) {
    const sequence = ++readSequence.current;
    const result = await readProgram<ApplicationDecision>(
      scope,
      "application.decision.read",
      { decisionId },
    );
    if (alive.current && sequence === readSequence.current) {
      setSelected(result);
      setComparison(null);
    }
  }
  async function save() {
    if (!draft) return;
    const { intent: oldIntent, expectedStateToken, ...fields } = draft;
    const program: Program = {
      languageVersion: 2,
      function: `application.decision.${expectedStateToken === undefined ? "create" : "replace"}`,
      arguments: {
        ...fields,
        ...(expectedStateToken === undefined ? {} : { expectedStateToken }),
      },
    };
    const intent =
      oldIntent && JSON.stringify(oldIntent.program) === JSON.stringify(program)
        ? oldIntent
        : { program, key: `decision-ui-${crypto.randomUUID()}` };
    setDraft({ ...draft, intent });
    await requestAdmittedEffect("/api/application-decision", {
      ...scope,
      program,
      idempotencyKey: intent.key,
    });
    if (!alive.current) return;
    setDraft(null);
    setComparison(null);
    setNotice("Decision saved.");
    await show(draft.decisionId);
    await loadPage();
  }
  const withdrawIntent = useRef<{ program: Program; key: string } | null>(null);
  async function withdraw() {
    if (!selected) return;
    const program: Program = {
      languageVersion: 2,
      function: "application.decision.withdraw",
      arguments: {
        decisionId: selected.decisionId,
        expectedStateToken: selected.stateToken,
      },
    };
    if (
      JSON.stringify(withdrawIntent.current?.program) !==
      JSON.stringify(program)
    ) {
      withdrawIntent.current = {
        program,
        key: `decision-ui-${crypto.randomUUID()}`,
      };
    }
    await requestAdmittedEffect("/api/application-decision", {
      ...scope,
      program,
      idempotencyKey: withdrawIntent.current!.key,
    });
    if (!alive.current) return;
    setNotice("Decision withdrawn.");
    await show(selected.decisionId);
    await loadPage();
  }
  function change(field: keyof Draft, value: string) {
    setDraft((current) => (current ? { ...current, [field]: value } : null));
  }
  if (!canRead) return null;
  return (
    <section className="panel" aria-label="Application decisions">
      <div className="section-title">
        <div>
          <h2>Application decisions</h2>
          <p>
            Shared context for application administrators and their MCP clients.
          </p>
        </div>
        {allowed("create") && (
          <button
            disabled={busy}
            onClick={() =>
              onRequestTransition(() => {
                setDraft({
                  decisionId: `decision-${crypto.randomUUID()}`,
                  title: "",
                  text: "",
                  rationale: "",
                  sourceReference: "",
                  provenance: "UserDecision",
                });
                setComparison(null);
                setError("");
              })
            }
          >
            Add decision
          </button>
        )}
      </div>
      {error && (
        <div role="alert" className="alert">
          {error}
          {draft && (
            <p>
              Your draft is preserved. Retry the same request after a connection
              failure. For a state conflict, compare the current decision before
              saving again.
            </p>
          )}
        </div>
      )}
      {notice && <p role="status">{notice}</p>}
      {!page ? (
        <p>Loading decisions…</p>
      ) : page.items.length === 0 ? (
        <p>No decisions recorded.</p>
      ) : (
        <ul>
          {page.items.map((row) => (
            <li key={row.decisionId}>
              <button
                disabled={busy}
                onClick={() =>
                  onRequestTransition(() => {
                    setDraft(null);
                    void run(() => show(row.decisionId));
                  })
                }
              >
                {row.title}
              </button>{" "}
              {row.status} ·{" "}
              {row.provenance === "UserDecision"
                ? "User decision"
                : "Agent interpretation"}
            </li>
          ))}
        </ul>
      )}
      <div className="button-row">
        <button disabled={busy} onClick={() => void run(() => loadPage())}>
          Refresh decisions
        </button>
        {page?.nextAfterDecisionId && (
          <button
            disabled={busy}
            onClick={() =>
              void run(() =>
                loadPage(page.nextAfterDecisionId!, page.collectionToken),
              )
            }
          >
            Next decisions
          </button>
        )}
      </div>
      {selected && (
        <div>
          <DecisionText decision={selected} actorName={actorName(selected)} />
          <div className="button-row">
            {allowed("replace") && (
              <button
                disabled={busy}
                onClick={() =>
                  onRequestTransition(() => {
                    setDraft(content(selected));
                    setComparison(null);
                  })
                }
              >
                Edit decision
              </button>
            )}
            {allowed("withdraw") && selected.status === "Active" && (
              <button
                disabled={busy || draft !== null}
                onClick={() => void run(withdraw)}
              >
                Withdraw decision
              </button>
            )}
          </div>
        </div>
      )}
      {draft && (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void run(save);
          }}
        >
          <h3>
            {draft.expectedStateToken === undefined
              ? "New decision"
              : "Edit current decision"}
          </h3>
          <fieldset disabled={busy}>
            <label>
              Title
              <input
                value={draft.title}
                maxLength={200}
                required
                onChange={(event) => change("title", event.target.value)}
              />
            </label>
            <label>
              Provenance
              <select
                value={draft.provenance}
                onChange={(event) => change("provenance", event.target.value)}
              >
                <option value="UserDecision">User decision</option>
                <option value="AgentInterpretation">
                  Agent interpretation
                </option>
              </select>
            </label>
            <label>
              Decision
              <textarea
                value={draft.text}
                maxLength={8000}
                required
                rows={6}
                onChange={(event) => change("text", event.target.value)}
              />
            </label>
            <label>
              Rationale (optional)
              <textarea
                value={draft.rationale}
                maxLength={2000}
                rows={3}
                onChange={(event) => change("rationale", event.target.value)}
              />
            </label>
            <label>
              Source reference (optional)
              <input
                value={draft.sourceReference}
                maxLength={1000}
                onChange={(event) =>
                  change("sourceReference", event.target.value)
                }
              />
            </label>
            <p>
              Saving records context and the current actor. It does not change
              cube data or activate rules.
            </p>
            <div className="button-row">
              <button className="primary" type="submit">
                Save decision
              </button>
              <button
                type="button"
                onClick={() =>
                  onRequestTransition(() => {
                    setDraft(null);
                    setComparison(null);
                  })
                }
              >
                Discard draft
              </button>
              {draft.expectedStateToken !== undefined && (
                <button
                  type="button"
                  onClick={() =>
                    void run(async () => {
                      const value = await readProgram<ApplicationDecision>(
                        scope,
                        "application.decision.read",
                        { decisionId: draft.decisionId },
                      );
                      if (alive.current) setComparison(value);
                    })
                  }
                >
                  Compare current decision
                </button>
              )}
            </div>
          </fieldset>
          {comparison && (
            <div aria-label="Current saved decision">
              <h3>Current saved decision</h3>
              <DecisionText
                decision={comparison}
                actorName={actorName(comparison)}
              />
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  setDraft({
                    ...draft,
                    expectedStateToken: comparison.stateToken,
                    intent: undefined,
                  });
                  setError("");
                }}
              >
                Keep draft against current state
              </button>
            </div>
          )}
        </form>
      )}
    </section>
  );
}
