import { useEffect, useRef, useState } from "react";
import { request, requestAdmittedEffect } from "./api";
import {
  ParameterFields,
  definitionParameterSchema,
  parameterInputError,
  parameterObject,
} from "./ParameterFields";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import {
  authoringContextKey,
  buildIsPending,
  pythonDiagnostics,
} from "./python-authoring";
import type { PythonBuildStatus } from "./python-authoring";
import { PythonRuleEditor } from "./PythonRuleEditor";
import { PythonImpactView } from "./PythonImpactView";
import { usePythonBuildObserver } from "./usePythonBuildObserver";
import type { PythonBuildObservation } from "./usePythonBuildObserver";
import type { ApplicationCatalog, ApplicationSummary } from "./types";

export type SealedPythonTest = {
  programId: string;
  sourceToken: string;
  contextKey: string;
  buildId: string;
  definition?: PythonBuildStatus["definition"];
};

export function PythonProgramTest({
  app,
  catalog,
  program,
  parameters,
  onParametersChange,
  onSealedTest,
  definitionKind,
  definitionContextKey,
}: {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
  program: {
    programId: string;
    sourceToken: string;
    sourceText: string;
    sourceDigest: string;
    parameterSchema?: unknown;
    validation?: PythonBuildStatus | null;
    latestImpactTest?: PythonBuildStatus | null;
  };
  parameters: string;
  onParametersChange: (value: string) => void;
  onSealedTest?: (value: SealedPythonTest | null) => void;
  definitionKind?: NonNullable<PythonBuildStatus["definition"]>["kind"];
  definitionContextKey?: string;
}) {
  const contextKey = authoringContextKey(app, catalog);
  const sourceSchema = parameterObject(program.parameterSchema);
  const typedKind =
    definitionKind ??
    program.validation?.definition?.kind ??
    program.latestImpactTest?.definition?.kind;
  const [definitionParameters, setDefinitionParameters] = useState("{}");
  const compiled =
    definitionContextKey === contextKey
      ? [program.validation, program.latestImpactTest].find(
          (build) =>
            build?.status === "sealed" &&
            build.current === true &&
            build.definition,
        )?.definition
      : undefined;
  const definitionSchema = definitionParameterSchema(compiled?.parameters);
  const parameterKey = JSON.stringify([parameters, definitionParameters]);
  const [sealedDefinition, setSealedDefinition] = useState<{
    buildId: string;
    definition: PythonBuildStatus["definition"];
  } | null>(null);
  const [parametersEdited, setParametersEdited] = useState(false);
  const [testedParameters, setTestedParameters] = useState<string | null>(null);
  const [testedDataRevision, setTestedDataRevision] = useState<number | null>(
    null,
  );
  const [observation, setObservation] = useState<PythonBuildObservation | null>(
    program.latestImpactTest?.purpose === "ImpactTest"
      ? { build: program.latestImpactTest, contextKey }
      : null,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [impact, setImpact] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const decoder = useRef<TextDecoder | null>(null);
  const seenCursors = useRef(new Set<string>());
  const bytesRead = useRef(0);
  const generation = useRef(0);
  const mutationKey = useStableMutationIntentKey("python-test");
  const observer = usePythonBuildObserver(
    app,
    contextKey,
    observation,
    "ImpactTest",
    setObservation,
  );
  const current =
    observer.current &&
    (testedParameters === null
      ? !parametersEdited
      : testedParameters === parameterKey);
  useUnsavedWork(
    "python-test-parameters",
    "Unsubmitted Python test parameters",
    parametersEdited &&
      parameterKey !== (testedParameters ?? JSON.stringify(["{}", "{}"])),
  );
  useEffect(() => {
    generation.current += 1;
    setBusy(false);
    return () => {
      generation.current += 1;
    };
  }, [contextKey]);
  useEffect(() => {
    setSealedDefinition(null);
    if (!typedKind || !current || observation?.build.status !== "sealed")
      return;
    const controller = new AbortController();
    const buildId = observation.build.buildId;
    void request<{
      result: {
        programId: string;
        sourceToken: string;
        sourceDigest: string;
        latestImpactTest?: PythonBuildStatus;
      };
    }>(
      "/api/python-program",
      {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        program: {
          languageVersion: 2,
          function: "python.program.read",
          arguments: { programId: program.programId },
        },
      },
      controller.signal,
    )
      .then((response) => {
        if (controller.signal.aborted) return;
        const test = response.result.latestImpactTest;
        if (
          response.result.programId !== program.programId ||
          response.result.sourceToken !== program.sourceToken ||
          response.result.sourceDigest !== program.sourceDigest ||
          test?.buildId !== buildId ||
          test.purpose !== "ImpactTest" ||
          test.status !== "sealed" ||
          test.current !== true ||
          !test.definition ||
          test.definition.kind !== typedKind
        )
          throw new Error(
            "The exact tested definition is unavailable; refresh the saved source before activation.",
          );
        setSealedDefinition({ buildId, definition: test.definition });
      })
      .catch((reason) => {
        if (!controller.signal.aborted)
          setError(
            reason instanceof Error
              ? reason.message
              : "Unable to read tested definition.",
          );
      });
    return () => controller.abort();
  }, [
    contextKey,
    current,
    observation?.build.status,
    observation?.build.buildId,
    program.programId,
    program.sourceToken,
    typedKind,
  ]);
  useEffect(() => {
    const definition =
      sealedDefinition?.buildId === observation?.build.buildId
        ? sealedDefinition?.definition
        : undefined;
    onSealedTest?.(
      current &&
        observation?.build.status === "sealed" &&
        (!typedKind || definition)
        ? {
            programId: program.programId,
            sourceToken: program.sourceToken,
            contextKey,
            buildId: observation.build.buildId,
            definition,
          }
        : null,
    );
    return () => onSealedTest?.(null);
  }, [
    current,
    observation?.build.status,
    observation?.build.buildId,
    contextKey,
    program.programId,
    program.sourceToken,
    onSealedTest,
    sealedDefinition,
    typedKind,
  ]);

  async function test() {
    if (
      busy ||
      !catalog.functions["python.program.test"] ||
      catalog.revisions.schemaEpoch === undefined
    )
      return;
    // Source inputs can change a typed definition. The server validates the
    // actual Test bindings; the earlier Validation fields are authoring help.
    const inputError =
      parameterInputError(parameters, sourceSchema) ??
      (typedKind ? parameterInputError(definitionParameters) : null);
    if (inputError) {
      setError(inputError);
      return;
    }
    let values: unknown;
    let ruleValues: unknown = {};
    try {
      values = JSON.parse(parameters);
      if (!values || typeof values !== "object" || Array.isArray(values))
        throw new Error();
      ruleValues = JSON.parse(definitionParameters);
      if (
        !ruleValues ||
        typeof ruleValues !== "object" ||
        Array.isArray(ruleValues)
      )
        throw new Error();
    } catch {
      setError(
        "Test parameters must be a JSON object matching the saved parameter schema.",
      );
      return;
    }
    const requestGeneration = ++generation.current;
    const arguments_ = {
      programId: program.programId,
      programSourceToken: program.sourceToken,
      parameters: values,
      ...(typedKind ? { definitionParameters: ruleValues } : {}),
      expectedMetadataRevision: catalog.revisions.metadata,
      expectedPolicyRevision: catalog.revisions.policy,
      expectedSchemaEpoch: catalog.revisions.schemaEpoch,
    };
    setBusy(true);
    setError("");
    setImpact("");
    setCursor(null);
    decoder.current = null;
    seenCursors.current.clear();
    bytesRead.current = 0;
    try {
      const response = await requestAdmittedEffect<{
        result: PythonBuildStatus;
      }>("/api/python-build", {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        action: "request",
        confirmed: true,
        idempotencyKey: mutationKey({
          arguments: arguments_,
          dataRevision: catalog.revisions.data,
          expiredBuildId:
            observation?.build.status === "expired"
              ? observation.build.buildId
              : null,
        }),
        program: {
          languageVersion: 2,
          function: "python.program.test",
          arguments: arguments_,
        },
      });
      if (requestGeneration !== generation.current) return;
      if (response.result.purpose !== "ImpactTest")
        throw new Error("Test returned a different build purpose.");
      setTestedParameters(parameterKey);
      setParametersEdited(false);
      setTestedDataRevision(catalog.revisions.data);
      setObservation({ build: response.result, contextKey });
    } catch (reason) {
      if (requestGeneration === generation.current)
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to test this version.",
        );
    } finally {
      if (requestGeneration === generation.current) setBusy(false);
    }
  }

  async function readImpact(next: boolean) {
    if (
      !observation ||
      !current ||
      observation.build.status !== "sealed" ||
      busy ||
      (next && !cursor)
    )
      return;
    const requestGeneration = ++generation.current;
    setBusy(true);
    setError("");
    try {
      const response = await request<{
        result: { chunkBase64: string; nextCursor: string | null };
      }>("/api/python-build", {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        action: "artifact",
        buildId: observation.build.buildId,
        section: "Impact",
        cursor: next ? cursor : null,
      });
      if (requestGeneration !== generation.current) return;
      const page = response.result;
      if (
        typeof page.chunkBase64 !== "string" ||
        page.chunkBase64.length > 2_000_000 ||
        (page.nextCursor !== null && typeof page.nextCursor !== "string")
      )
        throw new Error("Invalid impact page.");
      if (!next) {
        decoder.current = new TextDecoder("utf-8", { fatal: true });
        seenCursors.current.clear();
        bytesRead.current = 0;
      }
      if (page.nextCursor && seenCursors.current.has(page.nextCursor))
        throw new Error("Impact paging repeated a cursor.");
      const bytes = Uint8Array.from(atob(page.chunkBase64), (value) =>
        value.charCodeAt(0),
      );
      // The browser is a bounded reader, not an unbounded artifact accumulator.
      if (bytesRead.current + bytes.length > 16 * 1024 * 1024)
        throw new Error(
          "Impact exceeds the 16 MiB impact review limit. Read the artifact through the application API.",
        );
      const text = decoder.current!.decode(bytes, {
        stream: page.nextCursor !== null,
      });
      bytesRead.current += bytes.length;
      if (page.nextCursor) seenCursors.current.add(page.nextCursor);
      setImpact((value) => (next ? value + text : text));
      setCursor(page.nextCursor);
    } catch (reason) {
      if (requestGeneration === generation.current) {
        setCursor(null);
        decoder.current = null;
        setError(
          reason instanceof Error ? reason.message : "Unable to read impact.",
        );
      }
    } finally {
      if (requestGeneration === generation.current) setBusy(false);
    }
  }

  return (
    <section
      aria-label="Test saved Python source"
      className="python-program-test"
    >
      <h4>Test this source</h4>
      <p>
        Run the saved source in isolation and inspect its private effects before
        activation.
      </p>
      <ParameterFields
        label="Source parameters"
        advancedLabel="Python test parameters"
        value={parameters}
        schema={sourceSchema}
        disabled={busy}
        onChange={(value) => {
          onParametersChange(value);
          setParametersEdited(true);
        }}
      />
      {typedKind && (
        <ParameterFields
          label="Rule parameters"
          advancedLabel="Python rule test parameters"
          value={definitionParameters}
          schema={definitionSchema}
          disabled={busy}
          onChange={(value) => {
            setDefinitionParameters(value);
            setParametersEdited(true);
          }}
        />
      )}
      <button
        disabled={
          busy ||
          Boolean(
            observer.current &&
              observation &&
              buildIsPending(observation.build),
          ) ||
          catalog.revisions.schemaEpoch === undefined
        }
        onClick={() => void test()}
      >
        Test source
      </button>
      {error && <p role="alert">{error}</p>}
      {observation && (
        <p role="status">
          Test: {observation.build.status}
          {!current ? " · source context or parameters changed" : ""}
          {observation.build.errorCode
            ? ` · ${observation.build.errorCode}`
            : ""}
        </p>
      )}
      {observation?.build.status === "expired" && (
        <p role="status">Test result expired; test again.</p>
      )}
      {observation && testedParameters === null && (
        <p>
          Latest saved test. Its parameters and data baseline are included in
          the impact.
        </p>
      )}
      {observation &&
        testedDataRevision !== null &&
        testedDataRevision !== catalog.revisions.data && (
          <p role="status">
            Application data changed since this test. The impact describes the
            earlier data snapshot.
          </p>
        )}
      {observer.error && (
        <p role="alert">
          {observer.error}{" "}
          <button onClick={observer.refresh}>Refresh test status</button>
        </p>
      )}
      {current && pythonDiagnostics(observation?.build.diagnostics) && (
        <PythonRuleEditor
          ariaLabel="Tested Python source"
          value={program.sourceText}
          onChange={() => undefined}
          readOnly
          diagnostics={pythonDiagnostics(observation?.build.diagnostics)}
        />
      )}
      {current && observation?.build.status === "sealed" && (
        <div>
          <button disabled={busy} onClick={() => void readImpact(false)}>
            Read test impact
          </button>
          <button
            disabled={busy || !cursor}
            onClick={() => void readImpact(true)}
          >
            Next impact page
          </button>
          {impact && (
            <PythonImpactView
              text={impact}
              complete={cursor === null}
              sourceDigest={program.sourceDigest}
            />
          )}
        </div>
      )}
    </section>
  );
}
