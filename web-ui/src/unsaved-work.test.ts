import { createElement, useState, type ChangeEvent } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  discardUnsavedWork,
  resetUnsavedWorkForTests,
  setDraftIdentity,
  setUnsavedWork,
  subscribeUnsavedWork,
  unsavedWorkSnapshot,
  usePreservedDraft,
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

function DraftHarness({ workspace = "ws", application = "app" }) {
  const [value, setValue] = useState("");
  usePreservedDraft(
    workspace,
    application,
    "editor",
    "Unsaved editor",
    Boolean(value),
    { value },
    (saved) => setValue(saved.value),
  );
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
