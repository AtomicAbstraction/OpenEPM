import { browserIdentityFixture } from "./test-setup";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { useState } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "./App";
import {
  resetUnsavedWorkForTests,
  usePreservedDraft,
  unsavedWorkSnapshot,
  type DraftRecovery,
  type DraftRecoveryLease,
} from "./unsaved-work";
let currentRecovery: DraftRecovery<{ source: string }> | null = null;
let retainedOperation: {
  recovery: DraftRecovery<{ source: string }>;
  lease: DraftRecoveryLease;
} | null = null;
import {
  resetBrowserLifecycleForTests,
  setBrowserLifecycle,
} from "./browser-lifecycle";
import type { ApplicationSummary } from "./types";

// Exercise the real shell and existing draft store. Exact source/version
// restoration is separately exercised with both real source editor components.
vi.mock("./CapabilityArea", () => ({
  CapabilityArea: ({ app }: { app: ApplicationSummary }) => {
    const [source, setSource] = useState("");
    const recovery = usePreservedDraft(
      app.workspaceId,
      app.applicationId,
      "python-source-v3",
      "Unsaved Python source",
      Boolean(source),
      { source },
      (draft) => setSource(draft.source),
    );
    currentRecovery = recovery;
    return (
      <>
        <button
          onClick={() => {
            // Dispatch callers capture the synchronous reservation token.
            // The rendered lease is exposed only after hydration has settled.
            const lease = recovery.retain({ source });
            retainedOperation = { recovery, lease };
          }}
        >
          Retain original source operation
        </button>
        <textarea
          aria-label="Shell Python draft"
          value={source}
          onChange={(event) => setSource(event.target.value)}
        />
      </>
    );
  },
}));
afterEach(() => {
  currentRecovery = null;
  retainedOperation = null;
  vi.unstubAllGlobals();
  resetUnsavedWorkForTests();
  resetBrowserLifecycleForTests();
  window.history.replaceState(null, "", "/");
});
function fixture() {
  let subject = "designer";
  let issuer = "https://identity.example";
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input) => {
      const url = String(input);
      const result = (value: unknown) => new Response(JSON.stringify(value));
      if (url.startsWith("/api/applications"))
        return result({
          applications: [
            {
              workspaceId: "ws",
              applicationId: "app",
              name: "App",
              status: "Active",
            },
          ],
          nextAfter: null,
        });
      if (url === "/api/session-identity")
        return result(browserIdentityFixture(subject, issuer));
      if (url === "/api/runtime")
        return result({
          build: { sourceCommit: "a".repeat(40), packagedSchema: 294 },
        });
      if (url === "/api/catalog")
        return result({
          applicationAccess: {
            issuer,
            subjectId: subject,
            role: "Editor",
            workspaceAdministrator: false,
          },
          enabledCapabilities: [],
          functions: { "python.program.save": {}, "python.program.list": {} },
          revisions: {
            metadata: 1,
            policy: 1,
            data: 1,
            security: 1,
            commit: 1,
            schemaEpoch: 1,
          },
        });
      if (url === "/api/platform/browser/catalog")
        return new Response("{}", { status: 403 });
      return result({});
    }),
  );
  window.history.replaceState(
    null,
    "",
    "#/rules/0?workspace=ws&application=app&section=python",
  );
  return {
    setSubject: (value: string) => {
      subject = value;
    },
    setIssuer: (value: string) => {
      issuer = value;
    },
  };
}
function sourceRoute() {
  act(() => {
    window.history.replaceState(
      null,
      "",
      "#/rules/0?workspace=ws&application=app&section=python",
    );
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  });
}
async function retainOriginalSource() {
  fireEvent.click(
    screen.getByRole("button", { name: "Retain original source operation" }),
  );
  expect(retainedOperation).not.toBeNull();
  const captured = retainedOperation!;
  expect(captured.lease).not.toBeNull();
  await waitFor(() => expect(currentRecovery?.lease).toEqual(captured.lease));
  return captured;
}
it("keeps a draft through same-tab navigation and expiry recovery while guarding logout", async () => {
  fixture();
  render(<App />);
  fireEvent.change(await screen.findByLabelText("Shell Python draft"), {
    target: { value: "recover this exact draft" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Home" }));
  expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  sourceRoute();
  await waitFor(() =>
    expect(screen.getByLabelText("Shell Python draft")).toHaveValue(
      "recover this exact draft",
    ),
  );
  act(() => setBrowserLifecycle("expired", "qualification"));
  expect(screen.getByText("Your session has timed out")).toBeInTheDocument();
  act(() => setBrowserLifecycle("authenticated", "qualification-recovered"));
  await waitFor(() =>
    expect(
      screen.queryByText("Your session has timed out"),
    ).not.toBeInTheDocument(),
  );
  expect(screen.getByLabelText("Shell Python draft")).toHaveValue(
    "recover this exact draft",
  );
  fireEvent.click(screen.getByRole("button", { name: "Account" }));
  fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
  expect(
    screen.getByRole("alertdialog", { name: "Discard unsaved changes?" }),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(screen.getByLabelText("Shell Python draft")).toHaveValue(
    "recover this exact draft",
  );
  const unload = new Event("beforeunload", { cancelable: true });
  window.dispatchEvent(unload);
  expect(unload.defaultPrevented).toBe(true);
});
it.each(["subject", "issuer"] as const)(
  "never transfers the retained draft to another authenticated %s",
  async (changed) => {
    const session = fixture();
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Shell Python draft"), {
      target: { value: "designer private source" },
    });
    const { recovery: captured, lease } = await retainOriginalSource();
    if (changed === "subject") session.setSubject("other-designer");
    else session.setIssuer("https://other-identity.example");
    fireEvent(document, new Event("visibilitychange"));
    await waitFor(() =>
      expect(screen.getByText("Identity changed")).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/Unconfirmed requests may already have completed/),
    ).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Discard drafts and continue" }),
    );
    await waitFor(() =>
      expect(screen.getByLabelText("Shell Python draft")).toHaveValue(""),
    );
    expect(unsavedWorkSnapshot()).toEqual([]);
    expect(() =>
      captured.retain({ source: "late private packet" }, lease),
    ).toThrow("no longer current");
    expect(() => captured.release(lease, { source: "" })).toThrow(
      "no longer current",
    );
  },
);

it("keeps pinned recovery through same-tab navigation and explicitly abandons it only after confirmed sign out", async () => {
  fixture();
  render(<App />);
  fireEvent.change(await screen.findByLabelText("Shell Python draft"), {
    target: { value: "original exact packet" },
  });
  const { recovery: captured, lease } = await retainOriginalSource();
  fireEvent.click(screen.getByRole("button", { name: "Home" }));
  expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  sourceRoute();
  await waitFor(() =>
    expect(screen.getByLabelText("Shell Python draft")).toHaveValue(
      "original exact packet",
    ),
  );
  expect(currentRecovery?.lease).toEqual(lease);
  fireEvent.click(screen.getByRole("button", { name: "Account" }));
  fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
  expect(screen.getByRole("alertdialog")).toHaveTextContent(
    "Unconfirmed requests may already have completed",
  );
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
  fireEvent.click(screen.getByRole("button", { name: "Discard and continue" }));
  expect(unsavedWorkSnapshot()).toEqual([]);
  expect(() =>
    captured.retain({ source: "late private packet" }, lease),
  ).toThrow("no longer current");
});
