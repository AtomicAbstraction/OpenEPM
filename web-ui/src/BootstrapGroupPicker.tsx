import { useEffect, useRef, useState } from "react";
import { bootstrapGroups, workspaceAccessRead } from "./workspace-access";
import type { BootstrapGroup } from "./workspace-access";

export function BootstrapGroupPicker({
  workspaceId,
  selected,
  choose,
  disabled,
}: {
  workspaceId: string;
  selected: BootstrapGroup | null;
  choose: (value: BootstrapGroup | null) => void;
  disabled: boolean;
}) {
  const [draft, setDraft] = useState("");
  const [filter, setFilter] = useState("");
  const [groups, setGroups] = useState<BootstrapGroup[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);
  async function search(continuePage = false) {
    const term = continuePage ? filter : draft.trim();
    if (continuePage && !next) return;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setStatus("");
    choose(null);
    setGroups([]);
    setNext(null);
    try {
      const page = await workspaceAccessRead(
        workspaceId,
        bootstrapGroups,
        {
          limit: 25,
          ...(term ? { query: term } : {}),
          ...(continuePage ? { cursor: next } : {}),
        },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      setFilter(term);
      setGroups(page.groups);
      setNext(page.nextCursor);
      if (page.coverage === "partial")
        setStatus("The available group list has partial directory coverage.");
      else if (!page.groups.length)
        setStatus("No eligible administrator groups matched.");
    } catch {
      if (!controller.signal.aborted)
        setStatus("Eligible administrator groups are unavailable. Read again.");
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  return (
    <fieldset disabled={disabled}>
      <legend>Initial application administrator group</legend>
      <label>
        Group name
        <input
          type="search"
          maxLength={128}
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
        />
      </label>
      <button type="button" disabled={busy} onClick={() => void search()}>
        {draft.trim() ? "Find eligible groups" : "List eligible groups"}
      </button>
      {busy && <p role="status">Reading eligible groups…</p>}
      {status && <p role="status">{status}</p>}
      {groups.length > 0 && (
        <label>
          Administrator group
          <select
            value={selected?.groupId || ""}
            onChange={(event) =>
              choose(
                groups.find((group) => group.groupId === event.target.value) ||
                  null,
              )
            }
          >
            <option value="">Choose an eligible group</option>
            {groups.map((group) => (
              <option key={group.groupId} value={group.groupId}>
                {group.displayName || group.groupName || group.groupId} ·{" "}
                {group.groupId}
              </option>
            ))}
          </select>
        </label>
      )}
      {next && (
        <button type="button" disabled={busy} onClick={() => void search(true)}>
          Next eligible groups
        </button>
      )}
      {selected && (
        <p>
          {selected.actorMember
            ? "Your verified membership can open the new application."
            : "The selected group will administer this application. Your account will stay in this workspace."}
        </p>
      )}
    </fieldset>
  );
}
