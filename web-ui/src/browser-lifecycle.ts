export type BrowserLifecycleState =
  | "bootstrapping"
  | "authenticated"
  | "revalidating"
  | "expired"
  | "unavailable"
  | "offline";

export type BrowserLifecycleSnapshot = {
  state: BrowserLifecycleState;
  changedAt: number;
  reason?: string;
};

type Listener = (snapshot: BrowserLifecycleSnapshot) => void;

const CHANNEL = "openepm-browser-lifecycle-v1";
const listeners = new Set<Listener>();
let snapshot: BrowserLifecycleSnapshot = {
  state: "bootstrapping",
  changedAt: Date.now(),
};
let channel: BroadcastChannel | null = null;

function notify() {
  for (const listener of listeners) listener(snapshot);
}

function receive(value: unknown) {
  if (
    typeof value !== "object" ||
    value === null ||
    !("state" in value) ||
    !["expired", "authenticated"].includes(String(value.state))
  )
    return;
  snapshot = {
    state: String(value.state) as "expired" | "authenticated",
    changedAt: Date.now(),
    reason: "another-tab",
  };
  notify();
}

function ensureChannel() {
  if (channel || typeof BroadcastChannel === "undefined") return;
  channel = new BroadcastChannel(CHANNEL);
  channel.addEventListener("message", (event) => receive(event.data));
}

export function browserLifecycleSnapshot() {
  return snapshot;
}

export function subscribeBrowserLifecycle(listener: Listener) {
  ensureChannel();
  listeners.add(listener);
  listener(snapshot);
  return () => {
    listeners.delete(listener);
  };
}

export function setBrowserLifecycle(
  state: BrowserLifecycleState,
  reason?: string,
  broadcast = false,
) {
  if (snapshot.state === "expired" && state !== "authenticated") return;
  snapshot = { state, changedAt: Date.now(), reason };
  notify();
  if (broadcast && (state === "expired" || state === "authenticated")) {
    ensureChannel();
    channel?.postMessage({ state });
  }
}

export function classifyBrowserFailure(error: unknown) {
  if (error instanceof DOMException && error.name === "AbortError") return;
  const online = typeof navigator === "undefined" || navigator.onLine;
  setBrowserLifecycle(
    online ? "unavailable" : "offline",
    error instanceof Error ? error.name : "NETWORK_FAILURE",
  );
}

export function installConnectivityLifecycle(revalidate: () => void) {
  if (typeof window === "undefined") return () => undefined;
  const online = () => {
    setBrowserLifecycle("revalidating", "online");
    revalidate();
  };
  const offline = () => setBrowserLifecycle("offline", "offline");
  const visible = () => {
    if (document.visibilityState === "visible") {
      setBrowserLifecycle("revalidating", "visibility");
      revalidate();
    }
  };
  window.addEventListener("online", online);
  window.addEventListener("offline", offline);
  document.addEventListener("visibilitychange", visible);
  return () => {
    window.removeEventListener("online", online);
    window.removeEventListener("offline", offline);
    document.removeEventListener("visibilitychange", visible);
  };
}

export function resetBrowserLifecycleForTests() {
  snapshot = { state: "bootstrapping", changedAt: Date.now() };
  channel?.close();
  channel = null;
  listeners.clear();
}
