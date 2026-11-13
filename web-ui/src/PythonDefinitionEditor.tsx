import { useEffect, useRef, useState } from "react";
import { ApiError, readProgram, request, requestAdmittedEffect } from "./api";
import { collectAllContinuations } from "./continuation";
import { useStableMutationIntentKey } from "./mutation-intent";
import { usePreservedDraft } from "./unsaved-work";
import { PythonProgramTest } from "./PythonProgramTest";
import type { SealedPythonTest } from "./PythonProgramTest";
import { PythonRuleEditor } from "./PythonRuleEditor";
import type {
  PythonCompletionDescriptor,
  PythonDiagnostics,
} from "./PythonRuleEditor";
import {
  authoringCompletions,
  authoringContextKey,
  pythonDiagnostics,
} from "./python-authoring";
import type { PythonBuildStatus } from "./python-authoring";
import {
  pythonProgramActionBody,
  pythonProgramSaveBody,
} from "./python-source-contract";
import { usePythonBuildObserver } from "./usePythonBuildObserver";
import type { PythonBuildObservation } from "./usePythonBuildObserver";
import type { ApplicationCatalog, ApplicationSummary } from "./types";

export type PythonSourceBinding = {
  programId: string;
  sourceToken: string;
  sourceDigest: string;
  buildId: string;
  active: boolean;
};
export type PythonDefinitionKind =
  | "ApplicationRule"
  | "MemberList"
  | "CalculatedMember";
type Source = {
  defined: boolean;
  programId: string;
  stateToken: string;
  sourceToken: string;
  status: "Inactive" | "Active";
  sourceDigest: string;
  sourceText: string;
  entryPoint: string;
  environmentId: string;
  environmentStateToken: string;
  parameterSchema: Record<string, unknown>;
  validation?: PythonBuildStatus | null;
  latestImpactTest?: PythonBuildStatus | null;
};
type Environment = {
  environment_id: string;
  state_token: string;
  status: string;
};
type EnvironmentPage = {
  result: {
    environments: Environment[];
    nextAfterEnvironmentId: string | null;
  };
};

/** Definition views reopen the one current Python source registry. The fixed
 * compiled definition remains an inspection/execution artifact, never a second
 * editable copy of the authored rule. */
export function PythonDefinitionEditor({
  app,
  catalog,
  kind,
  binding,
  definitionId,
  template = "",
  onRefreshCatalog,
  onChanged,
  onSourceCurrentness,
}: {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
  kind: PythonDefinitionKind;
  binding?: PythonSourceBinding | null;
  definitionId?: string;
  template?: string;
  onRefreshCatalog?: () => Promise<ApplicationCatalog>;
  onChanged?: (definition?: PythonBuildStatus["definition"]) => void;
  onSourceCurrentness?: (state: "checking" | "current" | "unavailable") => void;
}) {
  const [sealedTest, setSealedTest] = useState<SealedPythonTest | null>(null);
  const [parameters, setParameters] = useState("{}");
  const [source, setSource] = useState<Source | null>(null);
  const [sourceContextKey, setSourceContextKey] = useState("");
  const [programId, setProgramId] = useState("");
  const [value, setValue] = useState(template);
  const [editing, setEditing] = useState(!binding);
  const [dirty, setDirty] = useState(false);
  const [environment, setEnvironment] = useState("");
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [entry, setEntry] = useState("build");
  const [schema, setSchema] = useState('{"type":"object"}');
  const [validation, setValidation] = useState<PythonBuildObservation | null>(
    null,
  );
  const [diagnostics, setDiagnostics] = useState<{
    contextKey: string;
    value: PythonDiagnostics;
  } | null>(null);
  const [metadata, setMetadata] = useState<{
    contextKey: string;
    values: PythonCompletionDescriptor[];
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reload, setReload] = useState(0);
  const [definitionRefresh, setDefinitionRefresh] = useState(0);
  const generation = useRef(0);
  const mutationKey = useStableMutationIntentKey("python-definition");
  const contextKey = authoringContextKey(app, catalog);
  const observer = usePythonBuildObserver(
    app,
    contextKey,
    validation,
    "Validation",
    setValidation,
  );
  const canWrite = Boolean(
    catalog.functions["python.program.save"] &&
      catalog.functions["python.environment.list"],
  );
  const approvedEnvironment = environments.find(
    (item) =>
      JSON.stringify([item.environment_id, item.state_token]) === environment,
  );
  const exactValidation =
    source &&
    validation &&
    observer.current &&
    validation.build.buildId === source.validation?.buildId
      ? validation.build
      : null;
  const definition = exactValidation?.definition;
  const validationReady =
    exactValidation?.status === "sealed" &&
    definition?.kind === kind &&
    (!definitionId || definition.definitionId === definitionId);
  const testReady =
    sealedTest?.contextKey === contextKey &&
    sealedTest.programId === source?.programId &&
    sealedTest.sourceToken === source?.sourceToken &&
    sealedTest.definition?.kind === kind &&
    (!definitionId || sealedTest.definition.definitionId === definitionId);
  const activationBuildId = testReady
    ? sealedTest.buildId
    : validationReady
      ? validation?.build.buildId
      : undefined;
  const activationDefinition = testReady
    ? sealedTest.definition
    : validationReady
      ? definition
      : undefined;
  const validated = Boolean(activationBuildId);
  const draftTarget = JSON.stringify([
    catalog.applicationAccess.issuer,
    catalog.applicationAccess.subjectId,
    app.workspaceId,
    app.applicationId,
    kind,
    definitionId ?? null,
    binding?.programId ?? null,
    binding?.sourceToken ?? null,
    binding?.sourceDigest ?? null,
  ]);
  const restoredTarget = useRef<string | null>(null);
  const openedTarget = useRef<string | null>(null);
  const acceptedSource = useRef<{ target: string; digest: string } | null>(
    null,
  );
  usePreservedDraft(
    app.workspaceId,
    app.applicationId,
    `python-definition-${draftTarget}`,
    `Unsaved ${kind} Python source`,
    dirty,
    { programId, value, environment, entry, schema },
    (draft) => {
      restoredTarget.current = draftTarget;
      setProgramId(draft.programId);
      setValue(draft.value);
      setEnvironment(draft.environment);
      setEntry(draft.entry);
      setSchema(draft.schema);
      setEditing(true);
      setDirty(true);
      setValidation(null);
      setDiagnostics(null);
      setSealedTest(null);
    },
  );

  function load(next: Source, key: string) {
    restoredTarget.current = null;
    acceptedSource.current = { target: draftTarget, digest: next.sourceDigest };
    setSource(next);
    setSourceContextKey(key);
    setProgramId(next.programId);
    setValue(next.sourceText);
    setEntry(next.entryPoint);
    setSchema(JSON.stringify(next.parameterSchema, null, 2));
    setEnvironment(
      JSON.stringify([next.environmentId, next.environmentStateToken]),
    );
    setEditing(false);
    setDirty(false);
    setDiagnostics(null);
    setSealedTest(null);
    setValidation(
      next.validation?.purpose === "Validation"
        ? { build: next.validation, contextKey: key }
        : null,
    );
  }
  async function readSource(program: string, signal?: AbortSignal) {
    const response = await request<{ result: Source }>(
      "/api/python-program",
      {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        program: {
          languageVersion: 2,
          function: "python.program.read",
          arguments: {
            programId: program,
          },
        },
      },
      signal,
    );
    if (
      !response.result.defined ||
      response.result.programId !== program ||
      !/^[a-f0-9]{64}$/.test(response.result.stateToken) ||
      !/^[a-f0-9]{64}$/.test(response.result.sourceToken) ||
      typeof response.result.sourceText !== "string" ||
      !/^[a-f0-9]{64}$/.test(response.result.sourceDigest)
    )
      throw new Error("The bound Python source is unavailable.");
    return response.result;
  }
  useEffect(() => {
    const controller = new AbortController();
    const revision = ++generation.current;
    // A changed authority invalidates every in-flight response and cached
    // source. Keep this identity's draft while current access is rechecked.
    const preserveDraft =
      restoredTarget.current === draftTarget ||
      (openedTarget.current === draftTarget && dirty);
    openedTarget.current = draftTarget;
    if (acceptedSource.current?.target !== draftTarget)
      acceptedSource.current = null;
    const expectedDigest =
      acceptedSource.current?.digest ?? binding?.sourceDigest;
    setBusy(Boolean(binding));
    setError("");
    setSource(null);
    setSourceContextKey("");
    setSealedTest(null);
    setValidation(null);
    setDiagnostics(null);
    onSourceCurrentness?.(binding ? "checking" : "unavailable");
    if (!preserveDraft) {
      setProgramId("");
      setValue(template);
      setEnvironment("");
      setEntry("build");
      setSchema('{"type":"object"}');
      setEditing(!binding);
      setDirty(false);
    }
    if (binding) {
      void readSource(binding.programId, controller.signal)
        .then((next) => {
          if (revision !== generation.current || controller.signal.aborted)
            return;
          if (next.sourceDigest !== expectedDigest)
            throw new Error(
              "The definition source digest does not match its immutable binding.",
            );
          if (preserveDraft || restoredTarget.current === draftTarget) {
            setSource(next);
            setSourceContextKey(contextKey);
          } else load(next, contextKey);
          onSourceCurrentness?.("current");
        })
        .catch((reason) => {
          if (!controller.signal.aborted && revision === generation.current) {
            onSourceCurrentness?.("unavailable");
            setError(
              reason instanceof Error
                ? reason.message
                : "Unable to reopen Python source.",
            );
          }
        })
        .finally(() => {
          if (!controller.signal.aborted && revision === generation.current)
            setBusy(false);
        });
    }
    return () => {
      generation.current += 1;
      controller.abort();
    };
  }, [draftTarget, contextKey, reload]);
  useEffect(() => {
    if (!catalog.functions["metadata.authoring.context"]) return;
    const controller = new AbortController();
    void readProgram<unknown>(
      app,
      "metadata.authoring.context",
      {},
      controller.signal,
    )
      .then((result) => {
        if (!controller.signal.aborted)
          setMetadata({
            contextKey,
            values: authoringCompletions(result, app, catalog),
          });
      })
      .catch(() => {
        if (!controller.signal.aborted) setMetadata(null);
      });
    return () => controller.abort();
  }, [contextKey, Boolean(catalog.functions["metadata.authoring.context"])]);
  useEffect(() => {
    setEnvironments([]);
    if (!canWrite || !editing) return;
    const controller = new AbortController();
    void collectAllContinuations<EnvironmentPage, Environment>({
      label: "Python environments",
      readPage: (after) =>
        request<EnvironmentPage>(
          "/api/python-environment",
          {
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            program: {
              languageVersion: 2,
              function: "python.environment.list",
              arguments: {
                limit: 50,
                ...(after ? { afterEnvironmentId: after } : {}),
              },
            },
          },
          controller.signal,
        ),
      rows: (page) => page.result.environments,
      nextCursor: (page) => page.result.nextAfterEnvironmentId,
      rowIdentity: (item) => `${item.environment_id}:${item.state_token}`,
    })
      .then((result) => {
        if (controller.signal.aborted) return;
        const active = result.rows.filter((item) => item.status === "Active");
        setEnvironments(active);
        setEnvironment(
          (current) =>
            current ||
            (active[0]
              ? JSON.stringify([
                  active[0].environment_id,
                  active[0].state_token,
                ])
              : ""),
        );
      })
      .catch((reason) => {
        if (!controller.signal.aborted)
          setError(
            reason instanceof Error
              ? reason.message
              : "Unable to read environments.",
          );
      });
    return () => controller.abort();
  }, [contextKey, editing, canWrite]);
  useEffect(() => {
    if (
      !source ||
      editing ||
      !observer.current ||
      validation?.build.status !== "sealed" ||
      definition
    )
      return;
    const controller = new AbortController();
    void readSource(source.programId, controller.signal)
      .then((next) => {
        if (controller.signal.aborted) return;
        if (next.sourceDigest !== source.sourceDigest)
          throw new Error("The saved source digest changed.");
        if (
          next.validation?.buildId !== validation.build.buildId ||
          next.validation.purpose !== "Validation" ||
          next.validation.status !== "sealed" ||
          next.validation.current !== true
        )
          throw new Error("The exact saved validation is unavailable.");
        if (!next.validation.definition)
          throw new Error(
            `Return a typed ${kind} definition from this source.`,
          );
        setSource((current) =>
          current?.programId === next.programId &&
          current.sourceToken === next.sourceToken &&
          current.sourceDigest === next.sourceDigest
            ? { ...current, validation: next.validation }
            : current,
        );
        setSourceContextKey(contextKey);
        setValidation({ build: next.validation, contextKey });
      })
      .catch((reason) => {
        if (!controller.signal.aborted)
          setError(
            reason instanceof Error
              ? reason.message
              : "Unable to read the compiled definition.",
          );
      });
    return () => controller.abort();
  }, [
    source?.programId,
    source?.sourceToken,
    validation?.build.buildId,
    validation?.build.status,
    observer.current,
    editing,
    definitionRefresh,
  ]);

  async function edit() {
    if (!source || busy || !canWrite) return;
    const revision = generation.current;
    setBusy(true);
    setError("");
    try {
      const latest = await readSource(source.programId);
      if (revision !== generation.current) return;
      load(latest, contextKey);
      setEditing(true);
      setDirty(true);
      setValidation(null);
      setDiagnostics(null);
      setNotice(
        "Edit the current Python source, then save and validate the replacement.",
      );
    } catch (reason) {
      if (revision === generation.current)
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to prepare the current source.",
        );
    } finally {
      if (revision === generation.current) setBusy(false);
    }
  }
  function draft() {
    const selected = approvedEnvironment;
    if (
      !selected ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(programId) ||
      !/^[A-Za-z_][A-Za-z0-9_]{0,99}$/.test(entry)
    )
      throw new Error(
        "Enter a source ID and entry point, and select an approved environment.",
      );
    const bytes = new TextEncoder().encode(value).length;
    if (!bytes || bytes > 1048576 || value.includes("\0"))
      throw new Error("Python source must contain 1 byte to 1 MiB of UTF-8.");
    const parameterSchema = JSON.parse(schema);
    if (
      !parameterSchema ||
      Array.isArray(parameterSchema) ||
      typeof parameterSchema !== "object"
    )
      throw new Error("Parameter schema must be a JSON object.");
    return {
      programId,
      entryPoint: entry,
      sourceText: value,
      parameterSchema,
      environmentId: selected.environment_id,
      environmentStateToken: selected.state_token,
      ...(source?.stateToken ? { expectedStateToken: source.stateToken } : {}),
    };
  }
  async function save() {
    if (busy || !editing || !canWrite) return;
    const revision = generation.current;
    setBusy(true);
    setError("");
    setDiagnostics(null);
    try {
      const sourceDraft = draft();
      const response = await requestAdmittedEffect<{
        result: {
          stateToken: string;
          sourceToken: string;
          status: "Inactive";
          sourceDigest: string;
          validation: PythonBuildStatus;
        };
      }>(
        "/api/python-program",
        pythonProgramSaveBody(
          app,
          catalog,
          sourceDraft,
          mutationKey({ operation: "save", draft: sourceDraft, contextKey }),
        ),
      );
      if (revision !== generation.current) return;
      if (
        !/^[a-f0-9]{64}$/.test(response.result.sourceDigest) ||
        response.result.validation?.purpose !== "Validation"
      )
        throw new Error("The saved source has no Validation task.");
      restoredTarget.current = null;
      acceptedSource.current = {
        target: draftTarget,
        digest: response.result.sourceDigest,
      };
      setSource({
        defined: true,
        ...sourceDraft,
        stateToken: response.result.stateToken,
        sourceToken: response.result.sourceToken,
        status: response.result.status,
        sourceDigest: response.result.sourceDigest,
        validation: response.result.validation,
      });
      setSourceContextKey(contextKey);
      setValidation({ build: response.result.validation, contextKey });
      setEditing(false);
      setDirty(false);
      setNotice(`Saved ${programId}; validating its typed definition.`);
    } catch (reason) {
      if (revision !== generation.current) return;
      const payload =
        reason instanceof ApiError
          ? pythonDiagnostics(reason.details)
          : undefined;
      if (payload) setDiagnostics({ contextKey, value: payload });
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to save Python source.",
      );
    } finally {
      if (revision === generation.current) setBusy(false);
    }
  }
  async function activate(action: "activate" | "deactivate") {
    if (!source || busy || editing || (action === "activate" && !validated))
      return;
    if (
      action === "deactivate" &&
      !window.confirm(
        "Deactivate this Python source and its compiled definition?",
      )
    )
      return;
    const revision = generation.current;
    setBusy(true);
    setError("");
    try {
      await requestAdmittedEffect(
        "/api/python-program",
        pythonProgramActionBody(
          app,
          catalog,
          source,
          action,
          mutationKey({
            operation: action,
            programId: source.programId,
            sourceToken: source.sourceToken,
            contextKey,
            validationBuildId:
              action === "activate" ? activationBuildId : undefined,
          }),
          action === "activate" ? activationBuildId : undefined,
        ),
      );
      if (revision !== generation.current) return;
      // Notify the owning view of the committed change before a catalog
      // refresh invalidates this request's old authority context.
      onChanged?.(activationDefinition ?? definition);
      const refreshed = await onRefreshCatalog?.();
      if (revision !== generation.current) return;
      const next = await readSource(source.programId);
      if (revision !== generation.current) return;
      load(next, refreshed ? authoringContextKey(app, refreshed) : contextKey);
      setNotice(
        action === "activate"
          ? "Python source activated; its compiled definition is ready."
          : "Python source deactivated.",
      );
    } catch (reason) {
      if (revision === generation.current)
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to change source activation.",
        );
    } finally {
      if (revision === generation.current) setBusy(false);
    }
  }
  return (
    <section aria-label={`${kind} Python source`}>
      <h4>Python source</h4>
      {busy && <p role="status">Working…</p>}
      {error && <p role="alert">{error}</p>}
      {notice && <p role="status">{notice}</p>}
      {binding && !source && !busy && (
        <button onClick={() => setReload((value) => value + 1)}>
          Retry bound source
        </button>
      )}
      {(source || !binding) && (
        <>
          <p>
            {programId || "New source"}
            {source?.status === "Active" ? " · Active" : ""}
          </p>
          {editing && (
            <fieldset disabled={busy}>
              <label>
                Source ID
                <input
                  aria-label={`${kind} source ID`}
                  value={programId}
                  readOnly={Boolean(binding)}
                  onChange={(event) => {
                    setProgramId(event.target.value);
                    setDirty(true);
                  }}
                />
              </label>
              <label>
                Approved environment
                <select
                  aria-label={`${kind} source environment`}
                  value={environment}
                  onChange={(event) => {
                    setEnvironment(event.target.value);
                    setDirty(true);
                  }}
                >
                  <option value="">Select an environment</option>
                  {environments.map((item) => (
                    <option
                      key={`${item.environment_id}:${item.state_token}`}
                      value={JSON.stringify([
                        item.environment_id,
                        item.state_token,
                      ])}
                    >
                      {item.environment_id}
                    </option>
                  ))}
                </select>
              </label>
              <details>
                <summary>Source settings</summary>
                <label>
                  Entry point
                  <input
                    value={entry}
                    onChange={(event) => {
                      setEntry(event.target.value);
                      setDirty(true);
                    }}
                  />
                </label>
                <label>
                  Parameter schema
                  <textarea
                    value={schema}
                    onChange={(event) => {
                      setSchema(event.target.value);
                      setDirty(true);
                    }}
                  />
                </label>
              </details>
            </fieldset>
          )}
          <PythonRuleEditor
            ariaLabel={`${kind} Python source editor`}
            value={value}
            onChange={(next) => {
              setValue(next);
              setDirty(true);
              setDiagnostics(null);
            }}
            readOnly={!editing || busy}
            diagnostics={
              diagnostics?.contextKey === contextKey
                ? diagnostics.value
                : observer.current
                  ? pythonDiagnostics(validation?.build.diagnostics)
                  : undefined
            }
            completions={
              metadata?.contextKey === contextKey ? metadata.values : []
            }
          />
          {editing ? (
            <button
              disabled={busy || !dirty || !approvedEnvironment || !canWrite}
              onClick={() => void save()}
            >
              Save and validate source
            </button>
          ) : (
            canWrite && (
              <button disabled={busy} onClick={() => void edit()}>
                Edit current source
              </button>
            )
          )}
          {validation && (
            <p role="status">
              Validation: {validation.build.status}
              {!observer.current ? " · stale context" : ""}
            </p>
          )}
          {definition && <p>Validated as {definition.kind}.</p>}
          {observer.error && (
            <p role="alert">
              {observer.error}{" "}
              <button onClick={observer.refresh}>
                Refresh source validation
              </button>
            </p>
          )}
          {validation?.build.status === "sealed" && !definition && (
            <button onClick={() => setDefinitionRefresh((value) => value + 1)}>
              Refresh compiled definition
            </button>
          )}
          {source &&
            !editing &&
            Boolean(catalog.functions["python.program.test"]) && (
              <PythonProgramTest
                key={`${source.programId}:${source.sourceToken}:${source.latestImpactTest?.buildId}:${source.latestImpactTest?.status}`}
                app={app}
                catalog={catalog}
                program={{
                  ...source,
                  validation: exactValidation,
                }}
                definitionKind={kind}
                definitionContextKey={
                  sourceContextKey === contextKey ? sourceContextKey : undefined
                }
                parameters={parameters}
                onParametersChange={setParameters}
                onSealedTest={setSealedTest}
              />
            )}
          {Boolean(catalog.functions["python.program.activate"]) && (
            <button
              disabled={
                busy || editing || !validated || source?.status === "Active"
              }
              onClick={() => void activate("activate")}
            >
              Activate source
            </button>
          )}
          {Boolean(catalog.functions["python.program.deactivate"]) &&
            source &&
            source.status === "Active" && (
              <button
                disabled={busy || editing}
                onClick={() => void activate("deactivate")}
              >
                Deactivate source
              </button>
            )}
        </>
      )}
    </section>
  );
}
