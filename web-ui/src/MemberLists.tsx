import { useEffect, useState } from "react";
import { readProgram, request } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";

type MemberListSummary = {
  listId: string;
  version: number;
  dimensionId: string;
  name: string;
  definition: Record<string, unknown>;
  canonicalDigest: string;
  status: "Saved" | "Published";
  stateRevision: number;
};

type MemberListPage = {
  memberLists: MemberListSummary[];
  nextAfterListId: string | null;
  metadataRevision: number;
  policyRevision: number;
};

type MemberListEvaluation = {
  listId: string;
  version: number;
  dimensionId: string;
  memberIds: string[];
  memberCount: number;
  canonicalDigest: string;
  metadataRevision: number;
  stateRevision: number;
  status: string;
};

type MemberListMutation = {
  result: {
    listId: string;
    version: number | null;
    status: string;
    canonicalDigest?: string;
    metadataRevision?: number;
    policyRevision: number;
    stateRevision?: number;
    committedRevision: number;
  };
};

export function memberListArguments(
  afterListId?: string | null,
  expectedMetadataRevision?: number,
  expectedPolicyRevision?: number,
) {
  return afterListId
    ? {
        limit: 100,
        afterListId,
        expectedMetadataRevision,
        expectedPolicyRevision,
      }
    : { limit: 100 };
}

export function collectMemberLists(
  readPage: (
    arguments_: ReturnType<typeof memberListArguments>,
  ) => Promise<MemberListPage>,
) {
  let metadata: number | undefined;
  let policy: number | undefined;
  return collectAllContinuations<MemberListPage, MemberListSummary>({
    label: "Member lists",
    readPage: async (cursor) => {
      const page = await readPage(
        memberListArguments(cursor, metadata, policy),
      );
      metadata = page.metadataRevision;
      policy = page.policyRevision;
      return page;
    },
    rows: (page) => page.memberLists,
    nextCursor: (page) => page.nextAfterListId,
    rowIdentity: (item) => `${item.listId}\u0000${item.version}`,
    consistencyIdentity: (page) =>
      `${page.metadataRevision}\u0000${page.policyRevision}`,
  });
}

export function parseMemberListJson(
  value: string,
  label: string,
  shape: "object" | "array",
): Record<string, unknown> | unknown[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${label} must be valid JSON.`);
  }
  if (
    (shape === "object" &&
      (typeof parsed !== "object" ||
        parsed === null ||
        Array.isArray(parsed))) ||
    (shape === "array" && !Array.isArray(parsed))
  )
    throw new Error(`${label} must be a JSON ${shape}.`);
  return parsed as Record<string, unknown> | unknown[];
}

export function memberListMutationBody(
  app: ApplicationSummary,
  functionName: string,
  args: Record<string, unknown>,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    program: {
      languageVersion: 2,
      function: functionName,
      arguments: args,
    },
    idempotencyKey,
    confirmed: true,
  };
}

export function MemberLists({
  app,
  catalog,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
}) {
  const [items, setItems] = useState<MemberListSummary[]>([]);
  const [selected, setSelected] = useState<MemberListSummary | null>(null);
  const [metadataRevision, setMetadataRevision] = useState(
    catalog?.revisions.metadata ?? 0,
  );
  const [policyRevision, setPolicyRevision] = useState(
    catalog?.revisions.policy ?? 0,
  );
  const [listId, setListId] = useState("");
  const [version, setVersion] = useState("1");
  const [dimensionId, setDimensionId] = useState("");
  const [name, setName] = useState("");
  const [parameters, setParameters] = useState("[]");
  const [expression, setExpression] = useState(
    '{\n  "kind": "explicit",\n  "memberIds": []\n}',
  );
  const [evaluationParameters, setEvaluationParameters] = useState("{}");
  const [evaluation, setEvaluation] = useState<MemberListEvaluation | null>(
    null,
  );
  const [reviewed, setReviewed] = useState(false);
  const [definitionTouched, setDefinitionTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const mutationIntentKey = useStableMutationIntentKey("member-list-ui");
  useUnsavedWork(
    `member-list:${app?.workspaceId || "none"}:${app?.applicationId || "none"}`,
    "Unsaved member-list definition",
    definitionTouched,
  );

  useEffect(() => {
    setMetadataRevision(catalog?.revisions.metadata ?? 0);
    setPolicyRevision(catalog?.revisions.policy ?? 0);
  }, [catalog?.revisions.metadata, catalog?.revisions.policy]);

  useEffect(() => {
    setItems([]);
    setSelected(null);
    setListId("");
    setVersion("1");
    setDimensionId("");
    setName("");
    setParameters("[]");
    setExpression('{\n  "kind": "explicit",\n  "memberIds": []\n}');
    setEvaluationParameters("{}");
    setEvaluation(null);
    setReviewed(false);
    setDefinitionTouched(false);
    setError("");
    setResult("");
  }, [app?.workspaceId, app?.applicationId]);

  function exactDefinition() {
    const nextVersion = Number(version);
    if (!listId.trim() || !dimensionId.trim() || !name.trim())
      throw new Error("List ID, version, dimension and name are required.");
    if (!Number.isInteger(nextVersion) || nextVersion < 1)
      throw new Error("Version must be a positive integer.");
    return {
      format: "openepm-member-list-v1",
      listId: listId.trim(),
      version: nextVersion,
      dimensionId: dimensionId.trim(),
      name: name.trim(),
      parameters: parseMemberListJson(parameters, "Parameters", "array"),
      expression: parseMemberListJson(expression, "Expression", "object"),
    };
  }

  function loadDraft(item: MemberListSummary) {
    setSelected(item);
    setListId(item.listId);
    setVersion(String(item.version));
    setDimensionId(item.dimensionId);
    setName(item.name);
    const definition = item.definition || {};
    setParameters(JSON.stringify(definition.parameters || [], null, 2));
    setExpression(JSON.stringify(definition.expression || {}, null, 2));
    setDefinitionTouched(false);
    setReviewed(false);
    setEvaluation(null);
    setResult("");
  }

  async function readLists() {
    if (!app) return;
    setBusy(true);
    setError("");
    try {
      const collected = await collectMemberLists((arguments_) =>
        readProgram<MemberListPage>(
          { workspaceId: app.workspaceId, applicationId: app.applicationId },
          "metadata.member_list.version.list",
          arguments_,
        ),
      );
      const found = collected.rows;
      setItems(found);
      setMetadataRevision(collected.finalPage.metadataRevision);
      setPolicyRevision(collected.finalPage.policyRevision);
      if (selected) {
        const current = found.find((item) => item.listId === selected.listId);
        if (current) loadDraft(current);
      }
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read member lists.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function mutate(
    functionName: string,
    args: Record<string, unknown>,
    confirmation: string,
  ) {
    if (!app || !reviewed || !window.confirm(confirmation)) return;
    setBusy(true);
    setError("");
    setResult("");
    try {
      const response = await request<MemberListMutation>(
        "/api/metadata-action",
        memberListMutationBody(
          app,
          functionName,
          args,
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            functionName,
            args,
          }),
        ),
      );
      setPolicyRevision(response.result.policyRevision);
      if (response.result.metadataRevision !== undefined)
        setMetadataRevision(response.result.metadataRevision);
      setResult(
        `${response.result.listId} v${response.result.version ?? "—"} is ${response.result.status}.`,
      );
      setReviewed(false);
      setDefinitionTouched(false);
      await readLists();
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Member-list action failed.",
      );
      setBusy(false);
    }
  }

  async function save() {
    let definition: Record<string, unknown>;
    try {
      definition = exactDefinition();
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Definition is invalid.",
      );
      return;
    }
    await mutate(
      "metadata.member_list.version.save",
      {
        definition,
        expectedMetadataRevision: metadataRevision,
        expectedPolicyRevision: policyRevision,
      },
      "Save this exact immutable member-list version?",
    );
  }

  async function publish() {
    if (!selected) return;
    await mutate(
      "metadata.member_list.publish",
      {
        listId: selected.listId,
        version: selected.version,
        expectedStateRevision: selected.stateRevision,
        expectedMetadataRevision: metadataRevision,
        expectedPolicyRevision: policyRevision,
      },
      "Publish this exact immutable member-list version?",
    );
  }

  async function deactivate() {
    if (!selected) return;
    await mutate(
      "metadata.member_list.deactivate",
      {
        listId: selected.listId,
        expectedStateRevision: selected.stateRevision,
        expectedMetadataRevision: metadataRevision,
        expectedPolicyRevision: policyRevision,
      },
      "Deactivate this published member list?",
    );
  }

  async function evaluate() {
    if (!app || !selected) return;
    let values: Record<string, unknown>;
    try {
      values = parseMemberListJson(
        evaluationParameters,
        "Evaluation parameters",
        "object",
      ) as Record<string, unknown>;
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Parameters are invalid.",
      );
      return;
    }
    setBusy(true);
    setError("");
    try {
      const value = await readProgram<MemberListEvaluation>(
        { workspaceId: app.workspaceId, applicationId: app.applicationId },
        "metadata.member_list.evaluate",
        {
          listId: selected.listId,
          version: selected.version,
          parameters: values,
          expectedMetadataRevision: metadataRevision,
        },
      );
      setEvaluation(value);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Evaluation failed.");
    } finally {
      setBusy(false);
    }
  }

  const canSave = Boolean(
    catalog?.functions["metadata.member_list.version.save"],
  );
  const canPublish = Boolean(
    catalog?.functions["metadata.member_list.publish"],
  );
  const canDeactivate = Boolean(
    catalog?.functions["metadata.member_list.deactivate"],
  );
  const canEvaluate = Boolean(
    catalog?.functions["metadata.member_list.evaluate"],
  );

  return (
    <section
      className="panel capability-activity"
      aria-labelledby="member-list-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>REUSABLE SELECTIONS</small>
          <h2 id="member-list-heading">Member-list versions</h2>
          <p>
            The browser constructs an inspectable definition. Fixed core
            validates, versions, evaluates and publishes it against
            authoritative metadata.
          </p>
        </div>
        <button disabled={busy || !app} onClick={() => void readLists()}>
          {busy ? "Working…" : "Read member lists"}
        </button>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {result && <p role="status">{result}</p>}
      <div className="snapshot-compare-controls">
        <label>
          Existing list
          <select
            aria-label="Existing member list"
            value={selected?.listId || ""}
            onChange={(event) => {
              if (
                definitionTouched &&
                !window.confirm("Discard the unsaved member-list definition?")
              )
                return;
              const item = items.find(
                (candidate) => candidate.listId === event.target.value,
              );
              if (item) loadDraft(item);
            }}
          >
            <option value="">New definition</option>
            {items.map((item) => (
              <option key={item.listId} value={item.listId}>
                {item.name} · v{item.version} · {item.status}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          onClick={() => {
            if (
              definitionTouched &&
              !window.confirm("Discard the unsaved member-list definition?")
            )
              return;
            setSelected(null);
            setListId("");
            setVersion("1");
            setDimensionId("");
            setName("");
            setParameters("[]");
            setExpression('{\n  "kind": "explicit",\n  "memberIds": []\n}');
            setDefinitionTouched(false);
            setReviewed(false);
            setEvaluation(null);
          }}
        >
          New version
        </button>
      </div>
      <div className="definition-grid">
        <label>
          List ID
          <input
            value={listId}
            onChange={(e) => {
              setListId(e.target.value);
              setDefinitionTouched(true);
              setReviewed(false);
            }}
          />
        </label>
        <label>
          Version
          <input
            type="number"
            min="1"
            value={version}
            onChange={(e) => {
              setVersion(e.target.value);
              setDefinitionTouched(true);
              setReviewed(false);
            }}
          />
        </label>
        <label>
          Dimension ID
          <input
            value={dimensionId}
            onChange={(e) => {
              setDimensionId(e.target.value);
              setDefinitionTouched(true);
              setReviewed(false);
            }}
          />
        </label>
        <label>
          Name
          <input
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              setDefinitionTouched(true);
              setReviewed(false);
            }}
          />
        </label>
      </div>
      <label>
        Typed parameters
        <textarea
          rows={5}
          value={parameters}
          onChange={(e) => {
            setParameters(e.target.value);
            setDefinitionTouched(true);
            setReviewed(false);
          }}
        />
      </label>
      <label>
        Member-list expression
        <textarea
          rows={12}
          value={expression}
          onChange={(e) => {
            setExpression(e.target.value);
            setDefinitionTouched(true);
            setReviewed(false);
          }}
        />
      </label>
      <label className="review-check">
        <input
          type="checkbox"
          checked={reviewed}
          onChange={(e) => setReviewed(e.target.checked)}
        />
        I reviewed the exact definition, revision and publication target.
      </label>
      <div className="reviewed-inline-actions">
        {canSave && (
          <button disabled={busy || !reviewed} onClick={() => void save()}>
            Save immutable version
          </button>
        )}
        {canPublish && selected && selected.status !== "Published" && (
          <button disabled={busy || !reviewed} onClick={() => void publish()}>
            Publish selected version
          </button>
        )}
        {canDeactivate && selected?.status === "Published" && (
          <button
            disabled={busy || !reviewed}
            onClick={() => void deactivate()}
          >
            Deactivate published list
          </button>
        )}
      </div>
      {selected && canEvaluate && (
        <article className="program-inspector">
          <h3>Evaluate exact version</h3>
          <label>
            Parameter bindings
            <textarea
              rows={4}
              value={evaluationParameters}
              onChange={(e) => setEvaluationParameters(e.target.value)}
            />
          </label>
          <button disabled={busy} onClick={() => void evaluate()}>
            Evaluate against metadata revision {metadataRevision}
          </button>
          {evaluation && (
            <div className="snapshot-compare-controls" aria-live="polite">
              <strong>{evaluation.memberCount} members</strong>
              <code>{evaluation.memberIds.join(", ") || "No members"}</code>
            </div>
          )}
        </article>
      )}
      <footer className="grid-status">
        <span>
          {items.length} lists · metadata revision {metadataRevision} · policy
          revision {policyRevision}
        </span>
      </footer>
    </section>
  );
}
