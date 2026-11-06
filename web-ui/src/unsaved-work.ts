import { useEffect, useRef } from "react";

export type UnsavedWorkItem = {
  id: string;
  label: string;
};

type Listener = (items: UnsavedWorkItem[]) => void;

const items = new Map<string, UnsavedWorkItem>();
const listeners = new Set<Listener>();
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

export function setDraftIdentity(identity: string) {
  draftIdentity = identity || "anonymous";
}

function draftKey(workspaceId: string, applicationId: string, editor: string) {
  return [draftIdentity, workspaceId || "none", applicationId || "none", editor]
    .map(encodeURIComponent)
    .join(":");
}

function draftBytes(value: unknown) {
  return new TextEncoder().encode(JSON.stringify(value)).length;
}

function evictDrafts() {
  const total = () =>
    [...drafts.values()].reduce((sum, draft) => sum + draft.bytes, 0);
  while (drafts.size > MAX_DRAFTS || total() > MAX_DRAFT_BYTES) {
    const oldest = [...drafts.entries()].sort(
      ([leftKey, left], [rightKey, right]) =>
        left.touched - right.touched || leftKey.localeCompare(rightKey),
    )[0];
    if (!oldest) break;
    drafts.delete(oldest[0]);
    items.delete(oldest[0]);
  }
}

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
  const firstStore = useRef(true);
  const restoreRef = useRef(restore);
  restoreRef.current = restore;
  useEffect(() => {
    const saved = drafts.get(key);
    if (saved) {
      saved.touched = ++draftClock;
      let active = true;
      queueMicrotask(() => {
        if (active) restoreRef.current(structuredClone(saved.value) as T);
      });
      return () => {
        active = false;
      };
    }
  }, [key]);
  useEffect(() => {
    if (firstStore.current) {
      firstStore.current = false;
      return;
    }
    if (!dirty) {
      drafts.delete(key);
      setUnsavedWork(key, label, false);
      return;
    }
    const copy = structuredClone(value);
    const bytes = draftBytes(copy);
    if (bytes > MAX_DRAFT_ENTRY_BYTES)
      throw new Error("DRAFT_ENTRY_CAPACITY_EXCEEDED");
    drafts.set(key, {
      item: { id: key, label },
      value: copy,
      bytes,
      touched: ++draftClock,
    });
    setUnsavedWork(key, label, true);
    evictDrafts();
    notify();
  }, [dirty, key, label, value]);
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

export function setUnsavedWork(id: string, label: string, dirty: boolean) {
  if (!id) throw new Error("UNSAVED_WORK_ID_REQUIRED");
  const before = items.get(id);
  if (dirty) {
    if (before?.label === label) return;
    items.set(id, { id, label });
  } else {
    if (!before) return;
    items.delete(id);
  }
  notify();
}

export function discardUnsavedWork() {
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
  listeners.clear();
}
