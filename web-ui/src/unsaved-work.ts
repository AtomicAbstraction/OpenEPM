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
  lease: DraftRecoveryLease | null;
};
export type DraftRecoveryLease = {
  readonly key: string;
  readonly epoch: number;
  readonly token: number;
};
export type DraftRecovery<T> = {
  /** Available after this exact identity/key has hydrated. */
  lease: DraftRecoveryLease | null;
  /** Atomically replaces the expected record and returns its new lease.
   * Capture every return value: earlier callbacks cannot overwrite or release
   * a later recovery state, even when both belong to the same intent. */
  retain: (
    value: T,
    expectedLease?: DraftRecoveryLease | null,
  ) => DraftRecoveryLease;
  release: (lease: DraftRecoveryLease, nextValue: T, dirty?: boolean) => void;
};
const drafts = new Map<string, DraftRecord>();
const MAX_DRAFTS = 24;
const MAX_DRAFT_BYTES = 280 * 1024 * 1024;
const MAX_DRAFT_ENTRY_BYTES = 140 * 1024 * 1024;
let draftClock = 0;
let draftIdentity = "anonymous";
let discardGeneration = 0;
let recoveryEpoch = 0;
let leaseClock = 0;

export function setDraftIdentity(identity: string) {
  const next = identity || "anonymous";
  if (next !== draftIdentity) recoveryEpoch += 1;
  draftIdentity = next;
}

function draftKey(workspaceId: string, applicationId: string, editor: string) {
  return [draftIdentity, workspaceId || "none", applicationId || "none", editor]
    .map(encodeURIComponent)
    .join(":");
}

function capacityEvictions(key: string, bytes: number) {
  if (bytes > MAX_DRAFT_ENTRY_BYTES)
    throw new Error(
      "This recovery record is too large to retain in this tab. Existing retained recovery is unchanged.",
    );
  const remaining = [...drafts.entries()].filter(([id]) => id !== key);
  let count = remaining.length + 1;
  let total = remaining.reduce((sum, [, draft]) => sum + draft.bytes, bytes);
  const candidates = remaining
    .filter(([, draft]) => !draft.lease)
    .sort(
      ([leftKey, left], [rightKey, right]) =>
        left.touched - right.touched || leftKey.localeCompare(rightKey),
    );
  const evictions: string[] = [];
  while (count > MAX_DRAFTS || total > MAX_DRAFT_BYTES) {
    const candidate = candidates.shift();
    if (!candidate)
      throw new Error(
        "This tab cannot retain another recovery record. Reconcile existing operations before submitting more work.",
      );
    evictions.push(candidate[0]);
    count -= 1;
    total -= candidate[1].bytes;
  }
  return evictions;
}

function capturedDraft(value: unknown) {
  const cloned = structuredClone(value);
  const serialized = JSON.stringify(cloned);
  if (serialized === undefined) throw new Error("DRAFT_VALUE_INVALID");
  return { value: cloned, bytes: new TextEncoder().encode(serialized).length };
}

function storeDraft(
  key: string,
  label: string,
  value: unknown,
  lease: DraftRecoveryLease | null,
) {
  const captured = capturedDraft(value);
  // Plan admission before changing anything; failed reservation leaves old pins intact.
  const evictions = capacityEvictions(key, captured.bytes);
  for (const id of evictions) drafts.delete(id); // Keep dirty warnings for forgotten ordinary drafts.
  drafts.set(key, {
    item: { id: key, label },
    ...captured,
    touched: ++draftClock,
    lease,
  });
  const changed = updateItem(key, label, true);
  if (changed || evictions.length) notify();
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
): DraftRecovery<T> {
  const key = draftKey(workspaceId, applicationId, editor);
  const identity = draftIdentity;
  const handleEpoch = recoveryEpoch;
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
      if (
        !active ||
        latest.current.key !== key ||
        draftIdentity !== identity ||
        recoveryEpoch !== handleEpoch
      )
        return;
      session.ready = true;
      const newerLocalEdit =
        latest.current.dirty &&
        JSON.stringify(latest.current.value) !== session.initial.serialized;
      if (
        (generation === discardGeneration || saved?.lease) &&
        saved &&
        drafts.get(key) === saved &&
        (saved.lease || !newerLocalEdit)
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
  }, [key, identity, handleEpoch]);

  useEffect(() => {
    const session = sessionRef.current;
    if (!session || session.key !== key) return;
    const serialized = JSON.stringify(value);
    if (
      !session.ready &&
      ((session.restoring &&
        (!dirty ||
          serialized === session.initial.serialized ||
          Boolean(drafts.get(key)?.lease))) ||
        (serialized === session.initial.serialized &&
          dirty === session.initial.dirty))
    )
      return;
    // Only the explicit lease API can replace or release unresolved recovery.
    if (drafts.get(key)?.lease) {
      if (updateItem(key, label, true)) notify();
      return;
    }
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
    try {
      storeDraft(key, label, value, null);
    } catch {
      // Do not crash after a user types, or pretend an older value is current.
      drafts.delete(key);
      updateItem(key, label, true);
      notify();
    }
  }, [dirty, key, label, value, settled]);

  function currentHandle() {
    if (draftIdentity !== identity || recoveryEpoch !== handleEpoch)
      throw new Error("This recovery context is no longer current.");
  }
  function matches(lease: DraftRecoveryLease) {
    const current = drafts.get(key)?.lease;
    return (
      current &&
      lease.key === key &&
      lease.epoch === current.epoch &&
      lease.token === current.token
    );
  }
  // Owner integration: admit -> current-context fence -> retain(exactPacket)
  // -> dispatch. Updates/retries use lease = retain(nextValue, lease), rotating
  // the compare-and-swap token at each successful replacement. Terminal native
  // evidence releases(lease, clearedValue). Never release a prior unknown on a
  // later denial. Capture this handle/lease before awaits; its key is immutable.
  return {
    lease:
      sessionRef.current?.key === key && sessionRef.current.ready
        ? (drafts.get(key)?.lease ?? null)
        : null,
    retain(nextValue, expectedLease) {
      currentHandle();
      if (
        expectedLease
          ? !matches(expectedLease)
          : Boolean(drafts.get(key)?.lease)
      )
        throw new Error(
          "An existing recovery record must be reconciled before starting another operation.",
        );
      const lease = {
        key,
        epoch: handleEpoch,
        token: ++leaseClock,
      };
      storeDraft(key, label, nextValue, lease);
      setSettled((current) => current + 1);
      return lease;
    },
    release(lease, nextValue, dirty = false) {
      currentHandle();
      if (!matches(lease))
        throw new Error("This recovery record has already changed or settled.");
      // Fence effects from the old pending render before any caller setState.
      if (latest.current.key === key)
        discarded.current = {
          serialized: JSON.stringify(latest.current.value),
        };
      if (dirty) storeDraft(key, label, nextValue, null);
      else {
        drafts.delete(key);
        setUnsavedWork(key, label, false);
      }
      setSettled((current) => current + 1);
    },
  };
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

export function discardUnsavedWork(
  options: { abandonRecovery?: boolean } = {},
) {
  discardGeneration += 1;
  for (const fence of discardSources) fence();
  if (options.abandonRecovery) recoveryEpoch += 1;
  let changed = false;
  for (const id of items.keys()) {
    if (drafts.get(id)?.lease && !options.abandonRecovery) continue;
    drafts.delete(id);
    items.delete(id);
    changed = true;
  }
  if (changed) notify();
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
  recoveryEpoch = 0;
  leaseClock = 0;
  discardSources.clear();
  listeners.clear();
}
