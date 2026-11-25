import { afterEach, describe, expect, it, vi } from "vitest";
import {
  browserLifecycleSnapshot,
  classifyBrowserFailure,
  installConnectivityLifecycle,
  resetBrowserLifecycleForTests,
  setBrowserLifecycle,
  subscribeBrowserLifecycle,
} from "./browser-lifecycle";

afterEach(() => {
  resetBrowserLifecycleForTests();
  vi.unstubAllGlobals();
});

describe("application-wide browser lifecycle", () => {
  it("publishes one authoritative expiry state to every subscriber", () => {
    const states: string[] = [];
    const unsubscribe = subscribeBrowserLifecycle((value) =>
      states.push(value.state),
    );
    setBrowserLifecycle("authenticated");
    setBrowserLifecycle("expired", "ACCESS_TOKEN_EXPIRED");
    setBrowserLifecycle("revalidating");
    expect(states).toEqual(["bootstrapping", "authenticated", "expired"]);
    expect(browserLifecycleSnapshot().reason).toBe("ACCESS_TOKEN_EXPIRED");
    unsubscribe();
  });

  it("revalidates locally when another tab authenticates", () => {
    const channel = Object.assign(new EventTarget(), {
      close: vi.fn(),
      postMessage: vi.fn(),
    });
    vi.stubGlobal(
      "BroadcastChannel",
      class {
        constructor() {
          return channel;
        }
      },
    );
    const unsubscribe = subscribeBrowserLifecycle(() => undefined);
    const revalidate = vi.fn();
    const uninstall = installConnectivityLifecycle(revalidate);
    setBrowserLifecycle("offline");
    channel.dispatchEvent(
      new MessageEvent("message", {
        data: { state: "authenticated" },
      }),
    );
    expect(browserLifecycleSnapshot()).toMatchObject({
      state: "revalidating",
      reason: "another-tab",
    });
    expect(revalidate).toHaveBeenCalledExactlyOnceWith(false);
    setBrowserLifecycle("authenticated", undefined, false);
    expect(channel.postMessage).not.toHaveBeenCalled();
    uninstall();
    unsubscribe();
  });

  it("does not mistake an intentional aborted request for an outage", () => {
    classifyBrowserFailure(new DOMException("cancelled", "AbortError"));
    expect(browserLifecycleSnapshot().state).toBe("bootstrapping");
  });

  it("distinguishes offline state from an available-network failure", () => {
    vi.stubGlobal("navigator", { onLine: false });
    classifyBrowserFailure(new TypeError("fetch failed"));
    expect(browserLifecycleSnapshot().state).toBe("offline");
  });
});
