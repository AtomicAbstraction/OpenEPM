import { useState } from "react";
import { ApiError, request } from "./api";

const PREFIX = "workspace.application.purge.";
type Manifest = {
  workspaceId: string;
  applicationId: string;
  name: string;
  createdAt: string;
  schemaEpoch: number;
  status: string;
  activeLeases: Record<string, number>;
  rowCounts: Record<string, number>;
};
type Prepared = { manifest: Manifest; manifestDigest: string };
type Intent = {
  workspaceId: string;
  idempotencyKey: string;
  program: {
    languageVersion: 2;
    function: string;
    arguments: {
      applicationId: string;
      createdAt: string;
      manifestDigest?: string;
    };
  };
};
const operationKey = () => `purge-ui-${crypto.randomUUID()}`;
function retainedIntent(key: string, workspaceId: string): Intent | null {
  try {
    const raw = localStorage.getItem(key);
    if (!raw || raw.length > 8192) return null;
    const value = JSON.parse(raw) as Intent | null;
    const exactKeys = (value: unknown, allowed: string[]) =>
      Boolean(
        value &&
          typeof value === "object" &&
          !Array.isArray(value) &&
          Object.keys(value).every((key) => allowed.includes(key)),
      );
    if (
      !exactKeys(value, ["workspaceId", "idempotencyKey", "program"]) ||
      value?.workspaceId !== workspaceId ||
      !exactKeys(value.program, ["languageVersion", "function", "arguments"]) ||
      value.program.languageVersion !== 2 ||
      ![PREFIX + "quiesce", PREFIX + "apply"].includes(
        value.program.function,
      ) ||
      !exactKeys(value.program.arguments, [
        "applicationId",
        "createdAt",
        "manifestDigest",
      ])
    )
      return null;
    const args = value.program.arguments;
    if (
      typeof args.applicationId !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(args.applicationId) ||
      typeof args.createdAt !== "string" ||
      args.createdAt.length > 100 ||
      !Number.isFinite(Date.parse(args.createdAt)) ||
      typeof value.idempotencyKey !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(value.idempotencyKey) ||
      (args.manifestDigest !== undefined &&
        !/^[a-f0-9]{64}$/.test(args.manifestDigest)) ||
      (value.program.function === PREFIX + "quiesce" && !args.manifestDigest)
    )
      return null;
    // Reconstruct the exact bounded retry identity. Browser persistence grants
    // no authority and never carries an inventory or application payload.
    return {
      workspaceId,
      idempotencyKey: value.idempotencyKey,
      program: {
        languageVersion: 2,
        function: value.program.function,
        arguments: {
          applicationId: args.applicationId,
          createdAt: args.createdAt,
          ...(args.manifestDigest
            ? { manifestDigest: args.manifestDigest }
            : {}),
        },
      },
    };
  } catch {
    /* An invalid local retry record grants no server authority. */
  }
  return null;
}

export function ApplicationPurge({
  workspaceId,
  applicationId,
  subject,
  deleted,
}: {
  workspaceId: string;
  applicationId: string;
  subject: string;
  deleted: (workspaceId: string, applicationId: string) => Promise<void>;
}) {
  const storageKey = `openepm:application-purge:${subject}:${workspaceId}`;
  const [pending, setPending] = useState(() =>
    retainedIntent(storageKey, workspaceId),
  );
  const [target, setTarget] = useState(
    pending?.program.arguments.applicationId || applicationId,
  );
  const [prepared, setPrepared] = useState<Prepared | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [completed, setCompleted] = useState<string | null>(null);
  const manifest = prepared?.manifest;
  const leases = Object.values(manifest?.activeLeases || {}).reduce(
    (sum, value) => sum + value,
    0,
  );
  const applying = pending?.program.function === PREFIX + "apply";

  function retain(intent: Intent | null) {
    if (intent) localStorage.setItem(storageKey, JSON.stringify(intent));
    else localStorage.removeItem(storageKey);
    setPending(intent);
  }
  async function inspect() {
    const inspected = await request<Prepared>("/api/application-purge", {
      workspaceId,
      idempotencyKey: null,
      program: {
        languageVersion: 2,
        function: PREFIX + "prepare",
        arguments: { applicationId: target },
      },
    });
    if (
      pending &&
      inspected.manifest.createdAt !== pending.program.arguments.createdAt
    ) {
      setPrepared(null);
      throw new Error(
        "This ID now belongs to a different application. Retry the saved request to reconcile its original target; it cannot delete the replacement.",
      );
    }
    setPrepared(inspected);
    return inspected;
  }
  async function inspectTarget() {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await inspect();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to inspect the application.",
      );
    } finally {
      setBusy(false);
    }
  }
  async function execute(intent: Intent) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      // Retain only the exact request identity, never application data or an inventory snapshot.
      retain(intent);
      const result = await request<{ status: string }>(
        "/api/application-purge",
        intent,
      );
      if (result.status === "Deleted") {
        retain(null);
        setPrepared(null);
        setCompleted(intent.program.arguments.applicationId);
        setMessage(`${intent.program.arguments.applicationId} was deleted.`);
        await deleted(workspaceId, intent.program.arguments.applicationId);
      } else if (result.status === "Deleting") {
        const next: Intent = {
          workspaceId,
          idempotencyKey: operationKey(),
          program: {
            languageVersion: 2,
            function: PREFIX + "apply",
            arguments: {
              applicationId: intent.program.arguments.applicationId,
              createdAt: intent.program.arguments.createdAt,
            },
          },
        };
        retain(next);
        setMessage(
          "The application is stopped for deletion. Refresh worker status, then delete its contents.",
        );
        await inspect();
      } else
        throw new Error(
          "Unexpected deletion result. Retry the same request to reconcile its outcome.",
        );
    } catch (reason) {
      if (
        reason instanceof ApiError &&
        [
          "APPLICATION_PURGE_MANIFEST_STALE",
          "APPLICATION_PURGE_INCARNATION_CHANGED",
          "APPLICATION_PURGE_TARGET_NOT_FOUND",
          "IDEMPOTENCY_KEY_REUSED",
        ].includes(reason.code)
      ) {
        retain(null);
        setPrepared(null);
      }
      setError(
        reason instanceof Error
          ? reason.message
          : "The request was interrupted. Retry the same request.",
      );
    } finally {
      setBusy(false);
    }
  }
  function begin() {
    if (!prepared) return;
    const { applicationId: id, createdAt, status } = prepared.manifest;
    void execute({
      workspaceId,
      idempotencyKey: operationKey(),
      program: {
        languageVersion: 2,
        function: PREFIX + (status === "Deleting" ? "apply" : "quiesce"),
        arguments: {
          applicationId: id,
          createdAt,
          ...(status === "Deleting"
            ? {}
            : { manifestDigest: prepared.manifestDigest }),
        },
      },
    });
  }
  return (
    <details className="create-application-panel" open={Boolean(pending)}>
      <summary>Delete an application</summary>
      <p>
        Delete one application and all its data, rules, decisions and history.
        This is permanent. The workspace and its other applications remain
        available. Only a minimal actor record is retained.
      </p>
      <p>
        Workspace: <code>{workspaceId}</code>
      </p>
      <label>
        Application ID to delete
        <input
          value={target}
          disabled={busy || Boolean(pending)}
          onChange={(event) => {
            setTarget(event.target.value);
            setPrepared(null);
            setCompleted(null);
            setMessage("");
          }}
        />
      </label>
      <p>
        Enter the exact ID to resume an application already stopped for
        deletion.
      </p>
      <button
        type="button"
        disabled={busy || !target.trim()}
        onClick={() => void inspectTarget()}
      >
        {manifest ? "Refresh worker status" : "Inspect application"}
      </button>
      {pending && (
        <p>
          Saved request targets{" "}
          <code>{pending.program.arguments.applicationId}</code>, created{" "}
          {pending.program.arguments.createdAt}. Retry preserves this exact
          target and request.
        </p>
      )}
      {manifest && (
        <div>
          <h3>
            {manifest.name} ({manifest.applicationId})
          </h3>
          <p>
            Created {manifest.createdAt}. Status: {manifest.status}.
          </p>
          <p>
            {leases
              ? `${leases} worker leases are still active. Deletion waits until they drain.`
              : "No active worker leases."}
          </p>
          <details>
            <summary>Stored application records</summary>
            <table>
              <thead>
                <tr>
                  <th>Record type</th>
                  <th>Count</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(manifest.rowCounts)
                  .filter(([, count]) => count > 0)
                  .sort(([a], [b]) => a.localeCompare(b))
                  .map(([name, count]) => (
                    <tr key={name}>
                      <td>{name}</td>
                      <td>{count}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </details>
        </div>
      )}
      {!completed &&
        (pending ? (
          <button
            type="button"
            className="danger"
            disabled={busy || Boolean(applying && manifest && leases > 0)}
            onClick={() => void execute(pending)}
          >
            {applying
              ? `Delete ${pending.program.arguments.applicationId} permanently`
              : "Retry stop request"}
          </button>
        ) : (
          manifest && (
            <button
              type="button"
              className="danger"
              disabled={busy || (manifest.status === "Deleting" && leases > 0)}
              onClick={begin}
            >
              {manifest.status === "Deleting"
                ? `Delete ${manifest.applicationId} permanently`
                : "Stop application for deletion"}
            </button>
          )
        ))}
      {completed && (
        <button
          type="button"
          disabled={busy}
          onClick={() =>
            void deleted(workspaceId, completed).catch((reason) =>
              setError(String(reason)),
            )
          }
        >
          Refresh applications
        </button>
      )}
      {message && <p role="status">{message}</p>}
      {error && <p role="alert">{error}</p>}
    </details>
  );
}
