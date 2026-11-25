import { useState } from "react";
import {
  ParameterFields,
  parameterInputError,
  parameterObject,
} from "./ParameterFields";
import { useStableMutationIntentKey } from "./mutation-intent";
import { buildIsPending, type PythonBuildStatus } from "./python-authoring";
import { usePythonEvidenceBuildRequest } from "./python-evidence-build-request";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";

type PythonSourceValidationProps = {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
  source: {
    programId: string;
    sourceToken: string;
    parameterSchema: unknown;
    validation?: PythonBuildStatus | null;
  };
  contextKey: string;
  suspended: boolean;
  onAccepted: (build: PythonBuildStatus) => void;
};

export function PythonSourceValidation(props: PythonSourceValidationProps) {
  const { app, catalog, source } = props;
  const { issuer, subjectId } = catalog.applicationAccess;
  const draftScope = JSON.stringify([
    issuer,
    subjectId,
    source.programId,
    source.sourceToken,
  ]);
  return (
    <ValidationSamples
      key={JSON.stringify([app.workspaceId, app.applicationId, draftScope])}
      draftScope={draftScope}
      {...props}
    />
  );
}

function ValidationSamples({
  app,
  catalog,
  source,
  contextKey,
  suspended,
  onAccepted,
  draftScope,
}: PythonSourceValidationProps & { draftScope: string }) {
  const [values, setValues] = useState("{}");
  const [submittedValues, setSubmittedValues] = useState("{}");
  const [inputError, setInputError] = useState("");
  usePreservedDraft(
    app.workspaceId,
    app.applicationId,
    `python-validation-samples:${draftScope}`,
    "Unsubmitted Python validation samples",
    values !== submittedValues,
    values,
    setValues,
  );
  const mutationKey = useStableMutationIntentKey("python-source-validation");
  const requestContext = JSON.stringify([contextKey, source.sourceToken]);
  const submission = usePythonEvidenceBuildRequest(
    app,
    catalog,
    source.programId,
    requestContext,
    "Validation",
    (build, baseline) => {
      if (baseline.contextKey !== requestContext) return;
      setSubmittedValues(baseline.parameterKey);
      onAccepted({ ...build, ownedByCaller: true });
    },
  );
  const canValidate = Boolean(catalog.functions["python.program.validate"]);
  const pending =
    source.validation?.ownedByCaller === true &&
    source.validation.current !== false &&
    buildIsPending(source.validation);
  const busy = suspended || submission.busy;
  const schema = parameterObject(source.parameterSchema);

  async function validate() {
    const error = parameterInputError(values, schema);
    if (error) {
      setInputError(error);
      return;
    }
    const parameters = parameterObject(JSON.parse(values));
    if (!parameters) return;
    const args = {
      programId: source.programId,
      programSourceToken: source.sourceToken,
      parameters,
      expectedMetadataRevision: catalog.revisions.metadata,
      expectedPolicyRevision: catalog.revisions.policy,
      expectedSchemaEpoch: catalog.revisions.schemaEpoch,
    };
    await submission.submit(
      args,
      mutationKey({ args, previousBuildId: source.validation?.buildId }),
      values,
    );
  }

  if (!canValidate && !submission.canRecover) return null;
  return (
    <section aria-label="Validate saved source">
      {canValidate && (
        <>
          <ParameterFields
            label="Validation samples"
            advancedLabel="Validation sample parameters"
            schema={schema}
            value={values}
            disabled={busy || pending || submission.pending}
            onChange={(value) => {
              setValues(value);
              setInputError("");
            }}
          />
          <button
            disabled={
              busy ||
              pending ||
              submission.pending ||
              catalog.revisions.schemaEpoch === undefined
            }
            onClick={() => void validate()}
          >
            Validate saved source
          </button>
        </>
      )}
      {(inputError || submission.error) && (
        <p role="alert">{inputError || submission.error}</p>
      )}
      {(submission.status || submission.canRecover) && (
        <p role="status">
          {submission.status ||
            "The original validation request has an unconfirmed outcome."}
        </p>
      )}
      {submission.canRecover && (
        <div className="reviewed-inline-actions">
          <button
            disabled={busy}
            onClick={() => void submission.recover("read")}
          >
            Check original validation
          </button>
          {submission.canRetry && (
            <button
              disabled={busy}
              onClick={() => void submission.recover("retry")}
            >
              Retry original validation
            </button>
          )}
          {submission.missing === "expired" && (
            <button disabled={busy} onClick={submission.closeExpired}>
              Close expired validation request
            </button>
          )}
        </div>
      )}
    </section>
  );
}
