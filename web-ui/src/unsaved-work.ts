import { useEffect, useRef, useState } from "react";

export type UnsavedWorkItem = {
  id: string;
  label: string;
};

type Listener = (items: UnsavedWorkItem[]) => void;

const items = new Map<string, UnsavedWorkItem>();
const listeners = new Set<Listener>();
const discardSources = new Set<() => void>();
type DraftRecord = {
  item: UnsavedWorkItem;
  value: unknown;
  bytes: number;
  touched: number;
};
const drafts = new Map<string, DraftRecord>();
const MAX_DRAFTS = 24;
const MAX_DRAFT_BYTES = 280 * 1024 * 1024;
const MAX_DRAFT_ENTRY_BYTES = 140 * 1024 * 1024;
let draftClock = 0;
let draftIdentity = "anonymous";
let discardGeneration = 0;

export function setDraftIdentity(identity: string) {
  draftIdentity = identity || "anonymous";
}

function draftKey(workspaceId: string, applicationId: string, editor: string) {
  return [draftIdentity, workspaceId || "none", applicationId || "none", editor]
    .map(encodeURIComponent)
    .join(":");
}

function evictDrafts() {
  let changed = false;
  const total = () =>
    [...drafts.values()].reduce((sum, draft) => sum + draft.bytes, 0);
  while (drafts.size > MAX_DRAFTS || total() > MAX_DRAFT_BYTES) {
    const oldest = [...drafts.entries()].sort(
      ([leftKey, left], [rightKey, right]) =>
        left.touched - right.touched || leftKey.localeCompare(rightKey),
    )[0];
    if (!oldest) break;
    drafts.delete(oldest[0]);
    changed = items.delete(oldest[0]) || changed;
  }
  return changed;
}

type DraftSession = {
  key: string;
  ready: boolean;
  restoring: boolean;
  initial: { serialized: string | undefined; dirty: boolean };
  previous?: { serialized: string | undefined; dirty: boolean; label: string };
  inherited?: { serialized: string | undefined };
};

export function usePreservedDraft<T>(
  workspaceId: string,
  applicationId: string,
  editor: string,
  label: string,
  dirty: boolean,
  value: T,
  restore: (value: T) => void,
) {
  const key = draftKey(workspaceId, applicationId, editor);
  const sessionRef = useRef<DraftSession | null>(null);
  const latest = useRef({ key, value, dirty });
  latest.current = { key, value, dirty };
  const discarded = useRef<{ serialized: string | undefined } | null>(null);
  const [settled, setSettled] = useState(0);
  const restoreRef = useRef(restore);
  restoreRef.current = restore;

  useEffect(() => {
    const fence = () => {
      // Capture the value at the explicit discard, not at the next render:
      // a subsequent genuine edit must still be registered.
      discarded.current = { serialized: JSON.stringify(latest.current.value) };
    };
    discardSources.add(fence);
    return () => {
      discardSources.delete(fence);
    };
  }, []);

  useEffect(() => {
    const previous = sessionRef.current;
    const saved = drafts.get(key);
    const initial = {
      serialized: JSON.stringify(latest.current.value),
      dirty: latest.current.dirty,
    };
    const session: DraftSession = {
      key,
      ready: false,
      restoring: Boolean(saved),
      initial,
      // On an in-place source switch, the render still contains the old
      // editor's state until its own initialization effect has run.
      ...(previous && previous.key !== key
        ? { inherited: { serialized: initial.serialized } }
        : {}),
    };
    sessionRef.current = session;
    const generation = discardGeneration;
    let active = true;
    // Settle after the editor's reset effects. Store effects must not erase a
    // saved target draft or copy the previous target's state while restoring.
    queueMicrotask(() => {
      if (!active || latest.current.key !== key) return;
      session.ready = true;
      if (
        generation === discardGeneration &&
        saved &&
        drafts.get(key) === saved
      ) {
        saved.touched = ++draftClock;
        session.inherited = undefined;
        restoreRef.current(structuredClone(saved.value) as T);
      }
      setSettled((current) => current + 1);
    });
    return () => {
      active = false;
    };
  }, [key]);

  useEffect(() => {
    const session = sessionRef.current;
    if (!session || session.key !== key) return;
    const serialized = JSON.stringify(value);
    if (
      !session.ready &&
      (session.restoring ||
        (serialized === session.initial.serialized &&
          dirty === session.initial.dirty))
    )
      return;
    if (discarded.current) {
      if (dirty && discarded.current.serialized === serialized) return;
      discarded.current = null;
    }
    if (session.inherited) {
      if (dirty && session.inherited.serialized === serialized) return;
      session.inherited = undefined;
    }
    if (
      session.previous?.serialized === serialized &&
      session.previous.dirty === dirty &&
      session.previous.label === label
    )
      return;
    session.previous = { serialized, dirty, label };
    if (!dirty) {
      drafts.delete(key);
      setUnsavedWork(key, label, false);
      return;
    }
    const bytes = new TextEncoder().encode(serialized).length;
    if (bytes > MAX_DRAFT_ENTRY_BYTES)
      throw new Error("DRAFT_ENTRY_CAPACITY_EXCEEDED");
    drafts.set(key, {
      item: { id: key, label },
      value: structuredClone(value),
      bytes,
      touched: ++draftClock,
    });
    const changed = updateItem(key, label, true);
    const evicted = evictDrafts();
    if (changed || evicted) notify();
  }, [dirty, key, label, value, settled]);
}

function currentItems() {
  return [...items.values()].sort((left, right) =>
    left.id.localeCompare(right.id),
  );
}

function notify() {
  const snapshot = currentItems();
  for (const listener of listeners) listener(snapshot);
}

/** Same-tab navigation is safe only when every dirty editor already has its
 * exact identity-scoped in-memory recovery record. Reload/logout still warn. */
export function canPreserveUnsavedWork() {
  return [...items.keys()].every((key) => drafts.has(key));
}

export function unsavedWorkSnapshot() {
  return currentItems();
}

export function subscribeUnsavedWork(listener: Listener) {
  listeners.add(listener);
  listener(currentItems());
  return () => {
    listeners.delete(listener);
  };
}

function updateItem(id: string, label: string, dirty: boolean) {
  if (!id) throw new Error("UNSAVED_WORK_ID_REQUIRED");
  const before = items.get(id);
  if (dirty) {
    if (before?.label === label) return false;
    items.set(id, { id, label });
  } else {
    if (!before) return false;
    items.delete(id);
  }
  return true;
}

export function setUnsavedWork(id: string, label: string, dirty: boolean) {
  if (updateItem(id, label, dirty)) notify();
}

export function discardUnsavedWork() {
  discardGeneration += 1;
  for (const fence of discardSources) fence();
  drafts.clear();
  if (items.size === 0) return;
  items.clear();
  notify();
}

export function useUnsavedWork(id: string, label: string, dirty: boolean) {
  useEffect(() => {
    setUnsavedWork(id, label, dirty);
    return () => setUnsavedWork(id, label, false);
  }, [dirty, id, label]);
}

export function resetUnsavedWorkForTests() {
  items.clear();
  drafts.clear();
  draftClock = 0;
  draftIdentity = "anonymous";
  discardGeneration = 0;
  discardSources.clear();
  listeners.clear();
}
