import { useState } from "react";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { usePythonBuildObserver } from "./usePythonBuildObserver";
import type { PythonBuildObservation } from "./usePythonBuildObserver";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
const initial: PythonBuildObservation = {
  contextKey: "current",
  build: { buildId: "validation-1", purpose: "Validation", status: "accepted" },
};
function useObserver(contextKey = "current") {
  const [observation, setObservation] = useState<PythonBuildObservation | null>(
    initial,
  );
  const observer = usePythonBuildObserver(
    { workspaceId: "ws", applicationId: "app" },
    contextKey,
    observation,
    "Validation",
    setObservation,
  );
  return { observation, ...observer };
}

it("rejects mismatched build identity and can retry without replacing the saved source build", async () => {
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          result: { ...initial.build, buildId: "other", status: "sealed" },
        }),
      ),
    )
    .mockResolvedValueOnce(
      new Response(
        JSON.stringify({ result: { ...initial.build, status: "sealed" } }),
      ),
    );
  vi.stubGlobal("fetch", fetch);
  const { result } = renderHook(() => useObserver());
  await waitFor(() =>
    expect(result.current.error).toMatch(/different build identity/),
  );
  expect(result.current.observation?.build.status).toBe("accepted");
  act(() => result.current.refresh());
  await waitFor(() =>
    expect(result.current.observation?.build.status).toBe("sealed"),
  );
  expect(result.current.observation?.build.buildId).toBe("validation-1");
});

it("aborts the old scope request and ignores its late result after context drift", async () => {
  let finish: (response: Response) => void = () => undefined;
  let signal: AbortSignal | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn((_input, init) => {
      signal = init.signal;
      return new Promise<Response>((resolve) => {
        finish = resolve;
      });
    }),
  );
  const { result, rerender } = renderHook(
    ({ contextKey }) => useObserver(contextKey),
    { initialProps: { contextKey: "current" } },
  );
  rerender({ contextKey: "changed" });
  expect(signal?.aborted).toBe(true);
  await act(async () =>
    finish(
      new Response(
        JSON.stringify({ result: { ...initial.build, status: "sealed" } }),
      ),
    ),
  );
  expect(result.current.current).toBe(false);
  expect(result.current.observation?.build.status).toBe("accepted");
});

it("bounds automatic polling and releases every timer on unmount", async () => {
  vi.useFakeTimers();
  const fetch = vi.fn(
    async () =>
      new Response(
        JSON.stringify({ result: { ...initial.build, status: "running" } }),
      ),
  );
  vi.stubGlobal("fetch", fetch);
  const { result, unmount } = renderHook(() => useObserver());
  await act(async () => {
    await vi.advanceTimersByTimeAsync(120_000);
  });
  expect(fetch).toHaveBeenCalledTimes(60);
  expect(result.current.error).toMatch(/Refresh its status/);
  unmount();
  expect(vi.getTimerCount()).toBe(0);
});
