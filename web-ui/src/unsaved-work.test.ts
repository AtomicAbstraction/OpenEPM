import {
  createElement,
  StrictMode,
  useEffect,
  useState,
  type ChangeEvent,
} from "react";
import {
  act,
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  canPreserveUnsavedWork,
  discardUnsavedWork,
  resetUnsavedWorkForTests,
  setDraftIdentity,
  setUnsavedWork,
  subscribeUnsavedWork,
  unsavedWorkSnapshot,
  usePreservedDraft,
  type UnsavedWorkItem,
  type DraftRecoveryLease,
} from "./unsaved-work";

afterEach(resetUnsavedWorkForTests);

it("maintains one application-wide dirty registry without exposing draft values", () => {
  const listener = vi.fn();
  const unsubscribe = subscribeUnsavedWork(listener);
  setUnsavedWork("metadata/member", "Member attribute value", true);
  setUnsavedWork("metadata/member", "Member attribute value", true);
  setUnsavedWork("rules/editor", "Rule source", true);
  expect(unsavedWorkSnapshot()).toEqual([
    { id: "metadata/member", label: "Member attribute value" },
    { id: "rules/editor", label: "Rule source" },
  ]);
  expect(JSON.stringify(unsavedWorkSnapshot())).not.toContain("draft value");
  setUnsavedWork("metadata/member", "Member attribute value", false);
  expect(unsavedWorkSnapshot()).toEqual([
    { id: "rules/editor", label: "Rule source" },
  ]);
  expect(listener).toHaveBeenCalledTimes(4);
  unsubscribe();
});

function DraftHarness({
  workspace = "ws",
  application = "app",
  editor = "editor",
  label = "Unsaved editor",
  resetOnSourceChange = false,
}) {
  const [value, setValue] = useState("");
  usePreservedDraft(
    workspace,
    application,
    editor,
    label,
    Boolean(value),
    { value },
    (saved) => setValue(saved.value),
  );
  useEffect(() => {
    if (resetOnSourceChange) setValue("");
  }, [workspace, application, editor, resetOnSourceChange]);
  return createElement("input", {
    "aria-label": "Draft value",
    value,
    onChange: (event: ChangeEvent<HTMLInputElement>) =>
      setValue(event.target.value),
  });
}

it("hydrates an exact in-memory draft and isolates identity and application", async () => {
  setDraftIdentity("owner-a");
  const first = render(createElement(DraftHarness));
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "private draft" },
  });
  await waitFor(() => expect(unsavedWorkSnapshot()).toHaveLength(1));
  first.unmount();

  const restored = render(createElement(DraftHarness));
  await waitFor(() =>
    expect(screen.getByLabelText("Draft value")).toHaveValue("private draft"),
  );
  restored.unmount();

  setDraftIdentity("owner-b");
  const otherIdentity = render(createElement(DraftHarness));
  expect(screen.getByLabelText("Draft value")).toHaveValue("");
  otherIdentity.unmount();

  setDraftIdentity("owner-a");
  const otherApplication = render(
    createElement(DraftHarness, { application: "other" }),
  );
  expect(screen.getByLabelText("Draft value")).toHaveValue("");
  otherApplication.unmount();

  discardUnsavedWork();
  const discarded = render(createElement(DraftHarness));
  expect(screen.getByLabelText("Draft value")).toHaveValue("");
  discarded.unmount();
});

it("retains the warning when an ordinary oldest draft exceeds the entry bound", async () => {
  setDraftIdentity("bounded-owner");
  for (let index = 0; index < 25; index += 1) {
    const rendered = render(
      createElement(DraftHarness, { application: `app-${index}` }),
    );
    fireEvent.change(screen.getByLabelText("Draft value"), {
      target: { value: `draft-${index}` },
    });
    await waitFor(() =>
      expect(
        unsavedWorkSnapshot().some((item) =>
          item.id.includes(encodeURIComponent(`app-${index}`)),
        ),
      ).toBe(true),
    );
    rendered.unmount();
  }
  expect(unsavedWorkSnapshot()).toHaveLength(25);
  expect(canPreserveUnsavedWork()).toBe(false);
  expect(unsavedWorkSnapshot().some((item) => item.id.includes("app-0"))).toBe(
    true,
  );
  expect(unsavedWorkSnapshot().some((item) => item.id.includes("app-24"))).toBe(
    true,
  );
});

it("rejects an anonymous dirty source", () => {
  expect(() => setUnsavedWork("", "Unknown", true)).toThrow(
    "UNSAVED_WORK_ID_REQUIRED",
  );
});

it("atomically discards every registered browser draft without retaining values", () => {
  const listener = vi.fn();
  subscribeUnsavedWork(listener);
  setUnsavedWork("app-a/grid", "Unsaved grid value", true);
  setUnsavedWork("app-a/rule", "Unsaved rule", true);
  discardUnsavedWork();
  expect(unsavedWorkSnapshot()).toEqual([]);
  expect(listener).toHaveBeenLastCalledWith([]);
  discardUnsavedWork();
  expect(listener).toHaveBeenCalledTimes(4);
});

it("settles a subscribed parent and only notifies when the visible dirty registry changes", async () => {
  const notified = vi.fn();
  const cloned = vi.spyOn(globalThis, "structuredClone");
  let renders = 0;
  function SubscribedParent({ label = "Unsaved editor" }) {
    const [pending, setPending] = useState<UnsavedWorkItem[]>([]);
    if (++renders > 30) throw new Error("Dirty registry render loop");
    useEffect(
      () =>
        subscribeUnsavedWork((items) => {
          notified(items);
          setPending(items);
        }),
      [],
    );
    return createElement(
      "div",
      null,
      createElement(
        "output",
        { "aria-label": "Unsaved count" },
        pending.length,
      ),
      createElement(DraftHarness, { label }),
    );
  }
  const view = render(createElement(SubscribedParent));
  await act(async () => undefined);
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "first edit" },
  });
  expect(screen.getByLabelText("Unsaved count")).toHaveTextContent("1");
  expect(notified).toHaveBeenCalledTimes(2);
  const clonesAfterEdit = cloned.mock.calls.length;
  for (let count = 0; count < 5; count += 1)
    view.rerender(createElement(SubscribedParent));
  expect(notified).toHaveBeenCalledTimes(2);
  expect(cloned).toHaveBeenCalledTimes(clonesAfterEdit);
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "latest exact edit" },
  });
  expect(notified).toHaveBeenCalledTimes(2);
  view.rerender(createElement(SubscribedParent, { label: "Renamed draft" }));
  expect(notified).toHaveBeenCalledTimes(3);
  expect(unsavedWorkSnapshot()).toEqual([
    { id: "anonymous:ws:app:editor", label: "Renamed draft" },
  ]);
  view.unmount();
  render(createElement(DraftHarness));
  await waitFor(() =>
    expect(screen.getByLabelText("Draft value")).toHaveValue(
      "latest exact edit",
    ),
  );
  cloned.mockRestore();
});

it("fences a discarded value before navigation and still registers a later genuine edit", async () => {
  const notified = vi.fn();
  function NavigationHarness({ leaving = false }) {
    const [, setPending] = useState<UnsavedWorkItem[]>([]);
    useEffect(
      () =>
        subscribeUnsavedWork((items) => {
          notified(items);
          setPending(items);
        }),
      [],
    );
    return createElement(
      "div",
      null,
      createElement(
        "button",
        { onClick: discardUnsavedWork },
        "Discard and continue",
      ),
      leaving
        ? createElement("p", null, "Next workspace")
        : createElement(DraftHarness),
    );
  }
  const view = render(createElement(NavigationHarness));
  await act(async () => undefined);
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "discard this" },
  });
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  fireEvent.click(screen.getByRole("button", { name: "Discard and continue" }));
  // The old editor can render again while the transition is still pending.
  view.rerender(createElement(NavigationHarness));
  expect(unsavedWorkSnapshot()).toEqual([]);
  expect(notified).toHaveBeenLastCalledWith([]);
  view.rerender(createElement(NavigationHarness, { leaving: true }));
  view.rerender(createElement(NavigationHarness));
  await act(async () => undefined);
  expect(screen.getByLabelText("Draft value")).toHaveValue("");
  expect(unsavedWorkSnapshot()).toEqual([]);
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "a new edit" },
  });
  expect(unsavedWorkSnapshot()).toHaveLength(1);

  // Staying mounted after discard must still allow a subsequent genuine edit.
  act(discardUnsavedWork);
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "new edit after discard" },
  });
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  view.unmount();
  render(createElement(DraftHarness));
  await waitFor(() =>
    expect(screen.getByLabelText("Draft value")).toHaveValue(
      "new edit after discard",
    ),
  );
});

it("does not restore a queued draft after an explicit discard", async () => {
  const original = render(createElement(DraftHarness));
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "queued draft" },
  });
  await waitFor(() => expect(unsavedWorkSnapshot()).toHaveLength(1));
  original.unmount();
  render(createElement(DraftHarness));
  act(discardUnsavedWork);
  await act(async () => undefined);
  expect(screen.getByLabelText("Draft value")).toHaveValue("");
  expect(unsavedWorkSnapshot()).toEqual([]);
});

it("isolates in-place source keys and restores each draft after the editor reset effect", async () => {
  const view = render(
    createElement(DraftHarness, {
      editor: "members:Account",
      resetOnSourceChange: true,
    }),
  );
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "account draft" },
  });
  await waitFor(() => expect(unsavedWorkSnapshot()).toHaveLength(1));
  view.rerender(
    createElement(DraftHarness, {
      editor: "members:Entity",
      resetOnSourceChange: true,
    }),
  );
  await act(async () => undefined);
  expect(screen.getByLabelText("Draft value")).toHaveValue("");
  expect(unsavedWorkSnapshot()).toEqual([
    { id: "anonymous:ws:app:members%3AAccount", label: "Unsaved editor" },
  ]);
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "entity draft" },
  });
  expect(unsavedWorkSnapshot()).toHaveLength(2);
  view.rerender(
    createElement(DraftHarness, {
      editor: "members:Account",
      resetOnSourceChange: true,
    }),
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Draft value")).toHaveValue("account draft"),
  );
  view.rerender(
    createElement(DraftHarness, {
      editor: "members:Entity",
      resetOnSourceChange: true,
    }),
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Draft value")).toHaveValue("entity draft"),
  );
  expect(unsavedWorkSnapshot()).toHaveLength(2);
});

it("never copies a previous application's unchanged editor state into a new draft key", async () => {
  const view = render(createElement(DraftHarness));
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "old application value" },
  });
  await waitFor(() => expect(unsavedWorkSnapshot()).toHaveLength(1));
  view.rerender(createElement(DraftHarness, { application: "other" }));
  await act(async () => undefined);
  view.rerender(createElement(DraftHarness, { application: "other" }));
  expect(unsavedWorkSnapshot()).toEqual([
    { id: "anonymous:ws:app:editor", label: "Unsaved editor" },
  ]);
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "other application draft" },
  });
  expect(unsavedWorkSnapshot()).toHaveLength(2);
  view.rerender(createElement(DraftHarness));
  await waitFor(() =>
    expect(screen.getByLabelText("Draft value")).toHaveValue(
      "old application value",
    ),
  );
  act(discardUnsavedWork);
  view.rerender(createElement(DraftHarness, { application: "other" }));
  await act(async () => undefined);
  expect(unsavedWorkSnapshot()).toEqual([]);
});

it("stores a synchronous edit before immediate unmount without waiting for initialization", async () => {
  const view = render(createElement(DraftHarness));
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "retain on immediate navigation" },
  });
  view.unmount();
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  render(createElement(DraftHarness));
  await waitFor(() =>
    expect(screen.getByLabelText("Draft value")).toHaveValue(
      "retain on immediate navigation",
    ),
  );
});

it("allows a new edit after discard without requiring any subscriber or intervening render", async () => {
  const view = render(createElement(DraftHarness));
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "discarded" },
  });
  await waitFor(() => expect(unsavedWorkSnapshot()).toHaveLength(1));
  act(discardUnsavedWork);
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "retain the first new edit" },
  });
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  view.unmount();
  render(createElement(DraftHarness));
  await waitFor(() =>
    expect(screen.getByLabelText("Draft value")).toHaveValue(
      "retain the first new edit",
    ),
  );
});

it("preserves and restores exact values through StrictMode effect replay", async () => {
  const first = render(
    createElement(StrictMode, null, createElement(DraftHarness)),
  );
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "strict draft" },
  });
  await waitFor(() => expect(unsavedWorkSnapshot()).toHaveLength(1));
  first.unmount();
  render(createElement(StrictMode, null, createElement(DraftHarness)));
  await waitFor(() =>
    expect(screen.getByLabelText("Draft value")).toHaveValue("strict draft"),
  );
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  act(discardUnsavedWork);
  await act(async () => undefined);
  expect(unsavedWorkSnapshot()).toEqual([]);
});

it("allows safe same-tab navigation only when every dirty editor is retained", async () => {
  const view = render(createElement(DraftHarness));
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "retain on navigation" },
  });
  await waitFor(() => expect(canPreserveUnsavedWork()).toBe(true));
  setUnsavedWork("unretained", "Unsaved external editor", true);
  expect(canPreserveUnsavedWork()).toBe(false);
  setUnsavedWork("unretained", "Unsaved external editor", false);
  view.unmount();
  expect(canPreserveUnsavedWork()).toBe(true);
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});

function recoveryHook(editor = "operation", restore = vi.fn()) {
  return renderHook(() =>
    usePreservedDraft(
      "ws",
      "app",
      editor,
      "Unconfirmed operation",
      false,
      { value: "" },
      restore,
    ),
  );
}

it("reserves an exact cloned packet synchronously and preserves it through clean renders, discard and remount", async () => {
  const first = recoveryHook();
  const input = { value: "original signed packet" };
  let lease!: DraftRecoveryLease;
  act(() => {
    lease = first.result.current.retain(input);
  });
  input.value = "mutated caller value";
  expect(canPreserveUnsavedWork()).toBe(true);
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  first.rerender();
  act(discardUnsavedWork);
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  first.unmount();
  const restore = vi.fn();
  const second = recoveryHook("operation", restore);
  await waitFor(() =>
    expect(restore).toHaveBeenCalledWith({ value: "original signed packet" }),
  );
  expect(second.result.current.lease).toEqual(lease);
  act(() => second.result.current.release(lease, { value: "" }));
  expect(unsavedWorkSnapshot()).toEqual([]);
});

it("protects all existing pins at the count limit and rejects before a caller can dispatch", async () => {
  for (let index = 0; index < 24; index += 1) {
    const hook = recoveryHook(`pending-${index}`);
    act(() => {
      hook.result.current.retain({ value: `packet-${index}` });
    });
    hook.unmount();
  }
  const next = recoveryHook("pending-new");
  const dispatch = vi.fn();
  expect(() => {
    next.result.current.retain({ value: "new packet" });
    dispatch();
  }).toThrow("cannot retain another recovery record");
  expect(dispatch).not.toHaveBeenCalled();
  expect(unsavedWorkSnapshot()).toHaveLength(24);
  expect(canPreserveUnsavedWork()).toBe(true);
  next.unmount();
  const restore = vi.fn();
  recoveryHook("pending-0", restore);
  await waitFor(() =>
    expect(restore).toHaveBeenCalledWith({ value: "packet-0" }),
  );
});

it("evicts ordinary drafts before pins and keeps their loss visible", async () => {
  const pin = recoveryHook();
  act(() => {
    pin.result.current.retain({ value: "oldest unresolved packet" });
  });
  pin.unmount();
  for (let index = 0; index < 24; index += 1) {
    const ordinary = render(
      createElement(DraftHarness, { editor: `ordinary-${index}` }),
    );
    fireEvent.change(screen.getByLabelText("Draft value"), {
      target: { value: `draft-${index}` },
    });
    ordinary.unmount();
  }
  expect(unsavedWorkSnapshot()).toHaveLength(25);
  expect(canPreserveUnsavedWork()).toBe(false);
  const restore = vi.fn();
  recoveryHook("operation", restore);
  await waitFor(() =>
    expect(restore).toHaveBeenCalledWith({ value: "oldest unresolved packet" }),
  );
});

it("rotates the expected lease on every replacement and rejects stale updates and settlement", async () => {
  const hook = recoveryHook();
  let lease!: DraftRecoveryLease;
  act(() => {
    lease = hook.result.current.retain({ value: "packet one" });
  });
  expect(() => hook.result.current.retain({ value: "double click" })).toThrow(
    "existing recovery record",
  );
  expect(() =>
    hook.result.current.retain(
      { value: "forged" },
      { ...lease, token: lease.token + 1 },
    ),
  ).toThrow("existing recovery record");
  const previous = lease;
  act(() => {
    lease = hook.result.current.retain({ value: "known accepted task" }, lease);
  });
  expect(lease).not.toEqual(previous);
  expect(() =>
    hook.result.current.retain({ value: "late packet" }, previous),
  ).toThrow("existing recovery record");
  expect(() => hook.result.current.release(previous, { value: "" })).toThrow(
    "already changed or settled",
  );
  act(() => hook.result.current.release(lease, { value: "" }));
  expect(() =>
    hook.result.current.retain({ value: "late packet" }, lease),
  ).toThrow("existing recovery record");
  expect(() => hook.result.current.release(lease, { value: "" })).toThrow(
    "already changed or settled",
  );
  expect(unsavedWorkSnapshot()).toEqual([]);
});

it("invalidates captured handles on explicit abandonment and identity changes", () => {
  setDraftIdentity("owner-a");
  const hook = recoveryHook();
  const captured = hook.result.current;
  let lease!: DraftRecoveryLease;
  act(() => {
    lease = captured.retain({ value: "private packet" });
  });
  act(() => discardUnsavedWork({ abandonRecovery: true }));
  expect(() => captured.retain({ value: "late response" }, lease)).toThrow(
    "no longer current",
  );
  expect(() => captured.release(lease, { value: "" })).toThrow(
    "no longer current",
  );
  expect(unsavedWorkSnapshot()).toEqual([]);
  hook.rerender();
  const newHandle = hook.result.current;
  act(() => {
    lease = newHandle.retain({ value: "second private packet" });
  });
  setDraftIdentity("owner-b");
  expect(() =>
    newHandle.retain({ value: "late identity response" }, lease),
  ).toThrow("no longer current");
  act(() => discardUnsavedWork({ abandonRecovery: true }));
  hook.unmount();
  const restore = vi.fn();
  recoveryHook("operation", restore);
  expect(restore).not.toHaveBeenCalled();
  expect(unsavedWorkSnapshot()).toEqual([]);
});

it("atomically refuses oversized replacement and aggregate byte admission without losing prior recovery", async () => {
  // Exercise exact production byte thresholds without allocating hundreds of MiB.
  const original = TextEncoder.prototype.encode;
  vi.spyOn(TextEncoder.prototype, "encode").mockImplementation(function (
    this: TextEncoder,
    value,
  ) {
    const sizes: Record<string, number> = {
      large: 100 * 1024 * 1024,
      oversized: 141 * 1024 * 1024,
    };
    const size = sizes[JSON.parse(String(value)).value];
    return size
      ? ({ length: size } as Uint8Array<ArrayBuffer>)
      : original.call(this, value);
  });
  try {
    const first = recoveryHook("first");
    let lease!: DraftRecoveryLease;
    act(() => {
      lease = first.result.current.retain({ value: "large" });
    });
    expect(() =>
      first.result.current.retain({ value: "oversized" }, lease),
    ).toThrow("too large");
    // Failed replacement must not invalidate the previous compare-and-swap token.
    const retainedLease = lease;
    act(() => {
      lease = first.result.current.retain({ value: "large" }, retainedLease);
    });
    expect(lease.token).not.toBe(retainedLease.token);
    first.unmount();
    const second = recoveryHook("second");
    act(() => {
      second.result.current.retain({ value: "large" });
    });
    second.unmount();
    const third = recoveryHook("third");
    expect(() => third.result.current.retain({ value: "large" })).toThrow(
      "cannot retain another",
    );
    third.unmount();
    const restore = vi.fn();
    recoveryHook("first", restore);
    await waitFor(() =>
      expect(restore).toHaveBeenCalledWith({ value: "large" }),
    );
    expect(unsavedWorkSnapshot()).toHaveLength(2);
  } finally {
    vi.restoreAllMocks();
  }
});

it("does not replace a new local edit with a queued ordinary restored value", async () => {
  const first = render(createElement(DraftHarness));
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "older saved draft" },
  });
  first.unmount();
  const second = render(createElement(DraftHarness));
  fireEvent.change(screen.getByLabelText("Draft value"), {
    target: { value: "newer local edit" },
  });
  await act(async () => undefined);
  expect(screen.getByLabelText("Draft value")).toHaveValue("newer local edit");
  second.unmount();
  render(createElement(DraftHarness));
  await waitFor(() =>
    expect(screen.getByLabelText("Draft value")).toHaveValue(
      "newer local edit",
    ),
  );
});

it("restores a queued pinned record through ordinary discard but refuses restoration after identity change", async () => {
  const original = recoveryHook();
  act(() => {
    original.result.current.retain({ value: "original packet" });
  });
  original.unmount();
  const restore = vi.fn();
  const next = recoveryHook("operation", restore);
  act(discardUnsavedWork);
  await waitFor(() =>
    expect(restore).toHaveBeenCalledWith({ value: "original packet" }),
  );
  next.unmount();
  const privateRestore = vi.fn();
  recoveryHook("operation", privateRestore);
  setDraftIdentity("another-person");
  await act(async () => undefined);
  expect(privateRestore).not.toHaveBeenCalled();
});

it("keeps an ordinary oversized edit visible as unpreserved without throwing from its effect", async () => {
  const original = TextEncoder.prototype.encode;
  const encoded = vi
    .spyOn(TextEncoder.prototype, "encode")
    .mockImplementation(function (this: TextEncoder, value) {
      return String(value).includes("oversized edit")
        ? ({ length: 141 * 1024 * 1024 } as Uint8Array<ArrayBuffer>)
        : original.call(this, value);
    });
  try {
    render(createElement(DraftHarness));
    fireEvent.change(screen.getByLabelText("Draft value"), {
      target: { value: "oversized edit" },
    });
    await act(async () => undefined);
    expect(screen.getByLabelText("Draft value")).toHaveValue("oversized edit");
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    expect(canPreserveUnsavedWork()).toBe(false);
  } finally {
    encoded.mockRestore();
  }
});

it("keeps a remounted owner's newer recovery when the old owner later updates or releases", async () => {
  const first = recoveryHook();
  const oldHandle = first.result.current;
  let original!: DraftRecoveryLease;
  act(() => {
    original = oldHandle.retain({ value: "original request" });
  });
  first.unmount();
  const second = recoveryHook();
  await waitFor(() => expect(second.result.current.lease).toEqual(original));
  let next!: DraftRecoveryLease;
  act(() => {
    next = second.result.current.retain(
      { value: "newer phase packet" },
      original,
    );
  });
  expect(() =>
    oldHandle.retain({ value: "late original response" }, original),
  ).toThrow("existing recovery record");
  expect(() => oldHandle.release(original, { value: "" })).toThrow(
    "already changed or settled",
  );
  second.unmount();
  const restore = vi.fn();
  const third = recoveryHook("operation", restore);
  await waitFor(() =>
    expect(restore).toHaveBeenCalledWith({ value: "newer phase packet" }),
  );
  expect(third.result.current.lease).toEqual(next);
  act(() => third.result.current.release(next, { value: "" }));
  expect(unsavedWorkSnapshot()).toEqual([]);
});
