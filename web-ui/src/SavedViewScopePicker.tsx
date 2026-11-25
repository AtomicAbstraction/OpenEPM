import { useEffect, useRef, useState } from "react";
import { readSecurityProgram } from "./api";
import type { ApplicationSummary } from "./types";

export const OBJECT_CATALOG = "security.application.authorization.objects.list";
type Key = { objectType: "saved_view"; objectId: string };
type Choice = Key & { objectName: string };
type Continuation = { after: Key; expectedSnapshot: string };
type Page = {
  workspaceId: string;
  applicationId: string;
  objects: Choice[];
  snapshotToken: string;
  nextAfter: Key | null;
};

export function SavedViewScopePicker({
  app,
  available,
  selector,
  onSelect,
}: {
  app: ApplicationSummary;
  available: boolean;
  selector: Record<string, unknown>;
  onSelect: (key: Key) => void;
}) {
  const [choices, setChoices] = useState<Choice[]>([]);
  const [next, setNext] = useState<Continuation | null>(null);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);
  async function load(continuation: Continuation | null) {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    setMessage("");
    setPending(true);
    try {
      const page = await readSecurityProgram<Page>(
        app,
        OBJECT_CATALOG,
        { limit: 50, ...continuation },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      const valid =
        page.workspaceId === app.workspaceId &&
        page.applicationId === app.applicationId &&
        typeof page.snapshotToken === "string" &&
        Boolean(page.snapshotToken) &&
        (!continuation ||
          page.snapshotToken === continuation.expectedSnapshot) &&
        Array.isArray(page.objects) &&
        page.objects.length <= 50 &&
        page.objects.every(
          (v, index, rows) =>
            v?.objectType === "saved_view" &&
            typeof v.objectId === "string" &&
            /^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/.test(v.objectId) &&
            typeof v.objectName === "string" &&
            v.objectName.length > 0 &&
            v.objectId >
              (index
                ? rows[index - 1].objectId
                : continuation?.after.objectId || ""),
        ) &&
        (page.nextAfter === null ||
          (page.nextAfter?.objectType === "saved_view" &&
            page.nextAfter.objectId === page.objects.at(-1)?.objectId));
      if (!valid) throw new Error("Invalid saved-view choices");
      setChoices(page.objects);
      setNext(
        page.nextAfter
          ? { after: page.nextAfter, expectedSnapshot: page.snapshotToken }
          : null,
      );
      if (!page.objects.length)
        setMessage("No saved views available for this scope.");
    } catch {
      if (!controller.signal.aborted) {
        setChoices([]);
        setNext(null);
        setMessage(
          "Saved-view choices are unavailable or have changed. Read them again.",
        );
      }
    } finally {
      if (!controller.signal.aborted) setPending(false);
    }
  }
  const selected =
    typeof selector.objectId === "string" ? selector.objectId : "";
  return (
    <>
      {available && (
        <button
          type="button"
          disabled={pending}
          onClick={() => void load(null)}
        >
          Read eligible saved views
        </button>
      )}
      {pending && <p role="status">Reading saved views…</p>}
      {message && <p role="status">{message}</p>}
      <label className="form-field">
        Saved view
        <select
          value={selected}
          disabled={!choices.length}
          onChange={(event) => {
            const choice = choices.find(
              (item) => item.objectId === event.target.value,
            );
            if (choice)
              onSelect({
                objectType: choice.objectType,
                objectId: choice.objectId,
              });
          }}
        >
          <option value="">Select a saved view</option>
          {selected && !choices.some((row) => row.objectId === selected) && (
            <option value={selected}>{selected}</option>
          )}
          {choices.map((row) => (
            <option key={row.objectId} value={row.objectId}>
              {row.objectName} · {row.objectId}
            </option>
          ))}
        </select>
      </label>
      {next && (
        <button
          type="button"
          disabled={pending}
          onClick={() => void load(next)}
        >
          Next eligible saved views
        </button>
      )}
    </>
  );
}
