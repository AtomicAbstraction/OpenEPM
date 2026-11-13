import { afterEach, describe, expect, it, vi } from "vitest";
import {
  browserLifecycleSnapshot,
  classifyBrowserFailure,
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
