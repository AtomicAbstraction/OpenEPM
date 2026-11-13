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

it("evicts the oldest scoped draft deterministically at the entry bound", async () => {
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
  expect(unsavedWorkSnapshot()).toHaveLength(24);
  expect(unsavedWorkSnapshot().some((item) => item.id.includes("app-0"))).toBe(
    false,
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
