import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "./App";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { resetBrowserLifecycleForTests } from "./browser-lifecycle";
import { resetUnsavedWorkForTests } from "./unsaved-work";

vi.mock("./CapabilityArea", () => ({
  CapabilityArea: ({
    app,
    catalog,
    onRefreshCatalog,
  }: {
    app?: ApplicationSummary;
    catalog: ApplicationCatalog | null;
    onRefreshCatalog: () => Promise<ApplicationCatalog>;
  }) => (
    <section>
      <p>
        Context: {app?.applicationId} policy {catalog?.revisions.policy}
      </p>
      <button onClick={() => void onRefreshCatalog().catch(() => undefined)}>
        Refresh shared context
      </button>
    </section>
  ),
}));
function catalog(policy: number) {
  return new Response(
    JSON.stringify({
      applicationAccess: { role: "Editor", workspaceAdministrator: false },
      enabledCapabilities: [],
      functions: { "python.program.list": {}, "python.program.read": {} },
      revisions: {
        metadata: 1,
        policy,
        data: 1,
        security: 1,
        commit: 1,
        schemaEpoch: 1,
      },
    }),
  );
}
function fixture() {
  let refresh: (value: Response) => void = () => undefined;
  let alphaReads = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const url = String(input);
      if (url.startsWith("/api/applications"))
        return new Response(
          JSON.stringify({
            applications: ["alpha", "beta"].map((applicationId) => ({
              workspaceId: "ws",
              applicationId,
              name: applicationId,
              status: "Active",
            })),
            nextAfter: null,
          }),
        );
      if (url === "/api/session-identity")
        return new Response(JSON.stringify({ subject: "designer" }));
      if (url === "/api/runtime")
        return new Response(
          JSON.stringify({
            build: { sourceCommit: "a".repeat(40), packagedSchema: 281 },
          }),
        );
      if (url === "/api/platform/browser/catalog")
        return new Response("{}", { status: 403 });
      if (url === "/api/catalog") {
        const scope = JSON.parse(init.body);
        if (scope.applicationId === "beta") return catalog(3);
        if (++alphaReads === 1) return catalog(1);
        return new Promise<Response>((resolve) => {
          refresh = resolve;
        });
      }
      return new Response("{}", { status: 404 });
    }),
  );
  window.history.replaceState(
    null,
    "",
    "#/rules/0?workspace=ws&application=alpha&section=python",
  );
  return {
    finish: (value: Response) => refresh(value),
    reads: () => alphaReads,
  };
}
afterEach(() => {
  vi.unstubAllGlobals();
  resetBrowserLifecycleForTests();
  resetUnsavedWorkForTests();
  window.history.replaceState(null, "", "/");
});

it("refreshes the single application catalog after a lifecycle mutation", async () => {
  const pending = fixture();
  render(<App />);
  await screen.findByText("Context: alpha policy 1");
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh shared context" }),
  );
  await waitFor(() => expect(pending.reads()).toBe(2));
  await act(async () => pending.finish(catalog(2)));
  await screen.findByText("Context: alpha policy 2");
});

it("cannot apply a late refresh to another application scope", async () => {
  const pending = fixture();
  render(<App />);
  await screen.findByText("Context: alpha policy 1");
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh shared context" }),
  );
  await waitFor(() => expect(pending.reads()).toBe(2));
  act(() => {
    window.history.replaceState(
      null,
      "",
      "#/rules/0?workspace=ws&application=beta&section=python",
    );
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  });
  await screen.findByText("Context: beta policy 3");
  await act(async () => pending.finish(catalog(99)));
  expect(screen.getByText("Context: beta policy 3")).toBeInTheDocument();
  expect(screen.queryByText(/policy 99/)).not.toBeInTheDocument();
});
