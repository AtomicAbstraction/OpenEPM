import { browserIdentityFixture } from "./test-setup";
import { useState } from "react";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "./App";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { resetBrowserLifecycleForTests } from "./browser-lifecycle";
import { resetUnsavedWorkForTests, setUnsavedWork } from "./unsaved-work";

vi.mock("./CapabilityArea", () => ({
  CapabilityArea: ({
    app,
    catalog,
    onRefreshCatalog,
  }: {
    app?: ApplicationSummary;
    catalog: ApplicationCatalog | null;
    onRefreshCatalog: () => Promise<ApplicationCatalog>;
  }) => {
    const [draft, setDraft] = useState("");
    return (
      <section>
        <p>
          Context: {app?.applicationId} policy {catalog?.revisions.policy}
        </p>
        <label>
          Draft text
          <input
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
          />
        </label>
        <button onClick={() => void onRefreshCatalog().catch(() => undefined)}>
          Refresh shared context
        </button>
      </section>
    );
  },
}));
vi.mock("./ServerAdministration", () => ({
  ServerAdministration: () => <h1>Server directory fixture</h1>,
}));

function platformAccess(authorized: boolean) {
  return new Response(
    JSON.stringify({ languageVersion: 2, authorized, functions: {} }),
  );
}

function catalog(policy: number, role: "Editor" | "Reader" = "Editor") {
  return new Response(
    JSON.stringify({
      applicationAccess: { role, workspaceAdministrator: false },
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
  const refreshes: {
    finish: (value: Response) => void;
    signal?: AbortSignal;
  }[] = [];
  let alphaReads = 0;
  let betaReads = 0;
  let holdBetaCatalog = false;
  let finishBetaCatalog: (value: Response) => void = () => undefined;
  let applicationReads = 0;
  let holdApplicationList = false;
  let refreshApplications: (value: Response) => void = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const url = String(input);
      if (url.startsWith("/api/applications")) {
        applicationReads++;
        if (holdApplicationList)
          return new Promise<Response>((resolve) => {
            refreshApplications = resolve;
          });
        return applicationList("alpha", "beta");
      }
      if (url === "/api/session-identity")
        return new Response(JSON.stringify(browserIdentityFixture("designer")));
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
        if (scope.applicationId === "beta") {
          betaReads++;
          if (holdBetaCatalog)
            return new Promise<Response>((resolve) => {
              finishBetaCatalog = resolve;
            });
          return catalog(3);
        }
        if (++alphaReads === 1) return catalog(1);
        return new Promise<Response>((resolve) => {
          refreshes.push({ finish: resolve, signal: init.signal });
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
    finish: (value: Response) => refreshes.at(-1)!.finish(value),
    earlier: () => refreshes.at(-2)!,
    reads: () => alphaReads,
    pauseBetaCatalog: () => (holdBetaCatalog = true),
    betaReads: () => betaReads,
    finishBetaCatalog: (value: Response) => finishBetaCatalog(value),
    pauseDiscovery: () => (holdApplicationList = true),
    discoveryReads: () => applicationReads,
    finishDiscovery: (value: Response) => refreshApplications(value),
  };
}

function applicationList(...ids: string[]) {
  return new Response(
    JSON.stringify({
      applications: ids.map((applicationId) => ({
        workspaceId: "ws",
        applicationId,
        name: applicationId,
        status: "Active",
      })),
      nextAfter: null,
    }),
  );
}
afterEach(() => {
  vi.unstubAllGlobals();
  resetBrowserLifecycleForTests();
  resetUnsavedWorkForTests();
  window.history.replaceState(null, "", "/");
});

it("pauses an open workspace until a same-application check confirms current access", async () => {
  const pending = fixture();
  render(<App />);
  await screen.findByText("Context: alpha policy 1");
  const draft = screen.getByRole("textbox", { name: "Draft text" });
  fireEvent.change(draft, { target: { value: "Unsaved business input" } });
  const refresh = screen.getByRole("button", {
    name: "Refresh shared context",
  });
  refresh.focus();
  fireEvent.click(refresh);
  await waitFor(() => expect(pending.reads()).toBe(2));
  expect(
    screen.getByRole("heading", { name: "Checking the application context…" }),
  ).toBeVisible();
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  expect(draft).toHaveValue("Unsaved business input");
  expect(screen.queryByRole("textbox", { name: "Draft text" })).toBeNull();
  // jsdom does not implement the focus loss caused by an inert ancestor.
  refresh.blur();
  await act(async () => pending.finish(catalog(2)));
  expect(await screen.findByText("Context: alpha policy 2")).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Draft text" })).toBe(draft);
  expect(draft).toHaveValue("Unsaved business input");
  expect(refresh).toHaveFocus();
});

it("renders the new workspace availability after the current role changes", async () => {
  const pending = fixture();
  render(<App />);
  await screen.findByText("Context: alpha policy 1");
  const refresh = screen.getByRole("button", {
    name: "Refresh shared context",
  });
  refresh.focus();
  const route = window.location.hash;
  fireEvent.click(refresh);
  await screen.findByRole("heading", {
    name: "Checking the application context…",
  });
  expect(
    screen.queryByRole("heading", { name: "Rules unavailable" }),
  ).toBeNull();
  refresh.blur();
  await act(async () => pending.finish(catalog(2, "Reader")));
  expect(
    await screen.findByRole("heading", { name: "Rules unavailable" }),
  ).toBeVisible();
  expect(
    screen.queryByRole("heading", { name: "Application unavailable" }),
  ).toBeNull();
  expect(screen.queryByText("Context: alpha policy 1")).toBeNull();
  expect(screen.getByRole("main")).toHaveFocus();
  expect(window.location.hash).toBe(route);
});

it.each([
  ["gateway failure", 503, "WEB_OPERATION_OUTCOME_UNKNOWN"],
  ["authentication failure", 401, "IDENTITY_SESSION_REVOKED"],
] as const)(
  "ignores an older %s after a newer refresh of the same application succeeds",
  async (_, status, code) => {
    const pending = fixture();
    render(<App />);
    await screen.findByText("Context: alpha policy 1");
    const refresh = screen.getByRole("button", {
      name: "Refresh shared context",
    });
    fireEvent.click(refresh);
    await waitFor(() => expect(pending.reads()).toBe(2));
    fireEvent.click(refresh);
    await waitFor(() => expect(pending.reads()).toBe(3));
    await act(async () => pending.finish(catalog(3)));
    await screen.findByText("Context: alpha policy 3");
    const earlier = pending.earlier();
    await act(async () =>
      earlier.finish(new Response(JSON.stringify({ code }), { status })),
    );
    expect(document.querySelector(".shell")).not.toHaveAttribute("inert");
    expect(
      screen.getByRole("button", { name: "Refresh shared context" }),
    ).toBeVisible();
    expect(screen.getByText("Context: alpha policy 3")).toBeVisible();
    expect(earlier.signal?.aborted).toBe(true);
  },
);

it("keeps the workspace paused when an overtaken check settles before the current one", async () => {
  const pending = fixture();
  render(<App />);
  await screen.findByText("Context: alpha policy 1");
  const refresh = screen.getByRole("button", {
    name: "Refresh shared context",
  });
  fireEvent.click(refresh);
  await waitFor(() => expect(pending.reads()).toBe(2));
  // Another in-flight operation can request a check while the shell is inert.
  fireEvent.click(refresh);
  await waitFor(() => expect(pending.reads()).toBe(3));
  const earlier = pending.earlier();
  await act(async () => earlier.finish(revokedCatalog()));
  expect(earlier.signal?.aborted).toBe(true);
  expect(
    screen.getByRole("heading", { name: "Checking the application context…" }),
  ).toBeVisible();
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  await act(async () => pending.finish(catalog(3)));
  expect(await screen.findByText("Context: alpha policy 3")).toBeVisible();
  expect(document.querySelector(".shell")).not.toHaveAttribute("inert");
});

it("waits for a newer same-application refresh that overtakes reconnect", async () => {
  const pending = fixture();
  render(<App />);
  await screen.findByText("Context: alpha policy 1");
  const refresh = screen.getByRole("button", {
    name: "Refresh shared context",
  });
  fireEvent(window, new Event("online"));
  await waitFor(() => expect(pending.reads()).toBe(2));
  // A callback from work already in flight can request a refreshed catalogue
  // after reconnect begins, even though the user-facing shell is inert.
  fireEvent.click(refresh);
  await waitFor(() => expect(pending.reads()).toBe(3));
  const earlier = pending.earlier();
  await act(async () =>
    earlier.finish(
      new Response(JSON.stringify({ code: "WEB_OPERATION_OUTCOME_UNKNOWN" }), {
        status: 503,
      }),
    ),
  );
  expect(
    screen.getByRole("heading", { name: "Revalidating your session" }),
  ).toBeVisible();
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  expect(earlier.signal?.aborted).toBe(true);
  expect(pending.discoveryReads()).toBe(1);
  await act(async () => pending.finish(catalog(3)));
  await screen.findByText("Context: alpha policy 3");
  await waitFor(() =>
    expect(document.querySelector(".shell")).not.toHaveAttribute("inert"),
  );
  expect(pending.discoveryReads()).toBe(2);
  expect(pending.reads()).toBe(3);
});

it("pauses the mounted workspace after a failed refresh until the exact context is confirmed", async () => {
  const pending = fixture();
  render(<App />);
  await screen.findByText("Context: alpha policy 1");
  const draft = screen.getByRole("textbox", { name: "Draft text" });
  fireEvent.change(draft, { target: { value: "retain the current draft" } });
  const route = window.location.hash;
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh shared context" }),
  );
  await waitFor(() => expect(pending.reads()).toBe(2));
  const unavailable = () =>
    new Response(JSON.stringify({ code: "ADMISSION_CAPACITY_EXCEEDED" }), {
      status: 429,
    });
  await act(async () => pending.finish(unavailable()));
  await screen.findByRole("heading", {
    name: "Application context unavailable",
  });
  expect(draft).toHaveValue("retain the current draft");
  expect(screen.queryByRole("textbox", { name: "Draft text" })).toBeNull();
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  expect(
    screen.queryByRole("heading", { name: "Application unavailable" }),
  ).toBeNull();

  const recheck = screen.getByRole("button", { name: "Retry context check" });
  expect(recheck).toHaveFocus();
  fireEvent.keyDown(recheck, { key: "k", ctrlKey: true });
  fireEvent.click(recheck);
  await waitFor(() => expect(pending.reads()).toBe(3));
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  await act(async () => pending.finish(unavailable()));
  await screen.findByRole("heading", {
    name: "Application context unavailable",
  });
  expect(document.querySelector(".shell")).toHaveAttribute("inert");

  fireEvent.click(screen.getByRole("button", { name: "Retry context check" }));
  await waitFor(() => expect(pending.reads()).toBe(4));
  expect(screen.queryByRole("textbox", { name: "Draft text" })).toBeNull();
  await act(async () => pending.finish(catalog(2)));
  await screen.findByText("Context: alpha policy 2");
  expect(screen.getByRole("textbox", { name: "Draft text" })).toBe(draft);
  expect(draft).toHaveValue("retain the current draft");
  expect(screen.queryByRole("dialog", { name: /search/i })).toBeNull();
  expect(screen.getByRole("main")).toHaveFocus();
  expect(window.location.hash).toBe(route);
  expect(pending.betaReads()).toBe(0);
});

it.each([
  ["success", () => catalog(99)],
  ["denial", revokedCatalog],
  [
    "capacity failure",
    () =>
      new Response(JSON.stringify({ code: "ADMISSION_CAPACITY_EXCEEDED" }), {
        status: 429,
      }),
  ],
  [
    "gateway failure",
    () =>
      new Response(JSON.stringify({ code: "WEB_OPERATION_OUTCOME_UNKNOWN" }), {
        status: 503,
      }),
  ],
] as const)(
  "ignores a late refresh %s after switching application",
  async (_, response) => {
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
    await act(async () => pending.finish(response()));
    expect(screen.getByText("Context: beta policy 3")).toBeInTheDocument();
    expect(document.querySelector(".shell")).not.toHaveAttribute("inert");
    expect(screen.queryByText(/policy 99/)).not.toBeInTheDocument();
    expect(
      screen.queryByText("Application grant required"),
    ).not.toBeInTheDocument();
  },
);

it.each(["granted", "denied"] as const)(
  "waits for fresh access when returning to an application last seen as %s",
  async (previousAccess) => {
    const pending = fixture();
    render(<App />);
    await screen.findByText("Context: alpha policy 1");
    if (previousAccess === "denied") {
      fireEvent.click(
        screen.getByRole("button", { name: "Refresh shared context" }),
      );
      await waitFor(() => expect(pending.reads()).toBe(2));
      await act(async () => pending.finish(revokedCatalog()));
      await screen.findByRole("heading", { name: "Application unavailable" });
    }
    function navigate(applicationId: string) {
      act(() => {
        window.history.replaceState(
          null,
          "",
          `#/rules/0?workspace=ws&application=${applicationId}&section=python`,
        );
        window.dispatchEvent(new HashChangeEvent("hashchange"));
      });
    }

    pending.pauseBetaCatalog();
    navigate("beta");
    await waitFor(() => expect(pending.betaReads()).toBe(1));
    await screen.findByText("Checking the application context…");
    navigate("alpha");
    await waitFor(() =>
      expect(pending.reads()).toBe(previousAccess === "denied" ? 3 : 2),
    );
    expect(screen.getByText("Checking the application context…")).toBeVisible();
    expect(screen.queryByText("Context: alpha policy 1")).toBeNull();
    expect(
      screen.queryByRole("heading", { name: "Application unavailable" }),
    ).toBeNull();

    await act(async () => pending.finishBetaCatalog(catalog(3)));
    expect(screen.getByText("Checking the application context…")).toBeVisible();
    await act(async () =>
      pending.finish(
        previousAccess === "granted" ? revokedCatalog() : catalog(4),
      ),
    );
    if (previousAccess === "granted") {
      expect(
        await screen.findByRole("heading", { name: "Application unavailable" }),
      ).toBeVisible();
    } else {
      expect(await screen.findByText("Context: alpha policy 4")).toBeVisible();
    }
    expect(screen.queryByText("Context: beta policy 3")).toBeNull();
  },
);

function revokedCatalog() {
  return new Response(
    JSON.stringify({
      code: "APPLICATION_GRANT_REQUIRED",
      message: "Application grant required",
    }),
    { status: 403 },
  );
}

it.each(["granted", "denied", "unconfirmed"] as const)(
  "rechecks the same denied application and renders the %s outcome",
  async (outcome) => {
    const pending = fixture();
    render(<App />);
    await screen.findByText("Context: alpha policy 1");
    fireEvent.click(
      screen.getByRole("button", { name: "Refresh shared context" }),
    );
    await waitFor(() => expect(pending.reads()).toBe(2));
    await act(async () => pending.finish(revokedCatalog()));
    await screen.findByRole("heading", { name: "Application unavailable" });
    const route = window.location.hash;
    const recheck = screen.getByRole("button", {
      name: "Recheck application access",
    });
    recheck.focus();
    fireEvent.click(recheck);
    await waitFor(() => expect(pending.reads()).toBe(3));
    expect(screen.getByText("Checking the application context…")).toBeVisible();
    expect(screen.getByRole("main")).toHaveFocus();
    expect(
      screen.queryByRole("heading", { name: "Application unavailable" }),
    ).toBeNull();
    expect(screen.queryByText("Context: alpha policy 1")).toBeNull();
    await act(async () =>
      pending.finish(
        outcome === "granted"
          ? catalog(4)
          : outcome === "denied"
            ? revokedCatalog()
            : new Response(
                JSON.stringify({ code: "ADMISSION_CAPACITY_EXCEEDED" }),
                { status: 429 },
              ),
      ),
    );
    if (outcome === "granted")
      expect(await screen.findByText("Context: alpha policy 4")).toBeVisible();
    else if (outcome === "denied")
      expect(
        await screen.findByRole("heading", { name: "Application unavailable" }),
      ).toBeVisible();
    else {
      expect(
        await screen.findByRole("heading", {
          name: "Application context unavailable",
        }),
      ).toBeVisible();
      expect(screen.queryByText("Application grant required")).toBeNull();
    }
    expect(window.location.hash).toBe(route);
    expect(pending.betaReads()).toBe(0);
    expect(pending.discoveryReads()).toBe(1);
  },
);

it("rechecks discovery for an exact link with a newly granted application", async () => {
  const pending = fixture();
  pending.pauseDiscovery();
  render(<App />);
  await waitFor(() => expect(pending.discoveryReads()).toBe(1));
  await act(async () => pending.finishDiscovery(applicationList("beta")));
  await screen.findByRole("heading", { name: "Application unavailable" });
  expect(pending.reads()).toBe(0);
  const route = window.location.hash;
  fireEvent.click(
    screen.getByRole("button", { name: "Recheck application access" }),
  );
  await waitFor(() => expect(pending.discoveryReads()).toBe(2));
  expect(
    screen.getByRole("heading", { name: "Revalidating your session" }),
  ).toBeVisible();
  expect(pending.betaReads()).toBe(0);
  await act(async () =>
    pending.finishDiscovery(applicationList("beta", "alpha")),
  );
  expect(await screen.findByText("Context: alpha policy 1")).toBeVisible();
  expect(screen.getByRole("main")).toHaveFocus();
  expect(window.location.hash).toBe(route.replace("#/rules/0?", "#/rules/1?"));
  expect(pending.betaReads()).toBe(0);
  expect(pending.reads()).toBe(1);
});

it("keeps an exact link unverified when a later page of its initial application directory fails", async () => {
  const pending = fixture();
  pending.pauseDiscovery();
  render(<App />);
  await waitFor(() => expect(pending.discoveryReads()).toBe(1));
  expect(screen.getByText("Loading your workspace…")).toBeVisible();
  const firstPage = await applicationList("beta").json();
  await act(async () =>
    pending.finishDiscovery(
      new Response(
        JSON.stringify({
          ...firstPage,
          nextAfter: { workspaceId: "ws", applicationId: "beta" },
        }),
      ),
    ),
  );
  await waitFor(() => expect(pending.discoveryReads()).toBe(2));
  expect(screen.getByText("Loading your workspace…")).toBeVisible();
  await act(async () =>
    pending.finishDiscovery(
      new Response(JSON.stringify({ code: "ADMISSION_CAPACITY_EXCEEDED" }), {
        status: 429,
      }),
    ),
  );

  await screen.findByRole("heading", {
    name: "Open EPM is temporarily unavailable",
  });
  expect(screen.queryByText(/linked application is unavailable/)).toBeNull();
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  expect(pending.reads()).toBe(0);
  expect(window.location.hash).toContain("application=alpha");
  fireEvent.click(screen.getByRole("button", { name: "Retry connection" }));
  await waitFor(() => expect(pending.discoveryReads()).toBe(3));
  await act(async () =>
    pending.finishDiscovery(applicationList("alpha", "beta")),
  );
  expect(await screen.findByText("Context: alpha policy 1")).toBeVisible();
  expect(document.querySelector(".shell")).not.toHaveAttribute("inert");
});

it("shows confirmed unavailability only after the initial directory successfully establishes absence", async () => {
  const pending = fixture();
  pending.pauseDiscovery();
  render(<App />);
  await waitFor(() => expect(pending.discoveryReads()).toBe(1));
  expect(screen.getByText("Loading your workspace…")).toBeVisible();
  expect(screen.queryByText(/linked application is unavailable/)).toBeNull();
  await act(async () => pending.finishDiscovery(applicationList("beta")));
  expect(
    await screen.findByRole("heading", { name: "Application unavailable" }),
  ).toBeVisible();
  expect(pending.reads()).toBe(0);
});

it("waits for a usable session identity before opening the application directory", async () => {
  const pending = fixture();
  const fetchImplementation = vi.mocked(fetch).getMockImplementation()!;
  let identityReads = 0;
  vi.mocked(fetch).mockImplementation((input, init) =>
    String(input) === "/api/session-identity" && ++identityReads === 1
      ? Promise.resolve(new Response("{}"))
      : fetchImplementation(input, init),
  );
  render(<App />);
  await screen.findByRole("heading", {
    name: "Open EPM is temporarily unavailable",
  });
  expect(screen.queryByText(/linked application is unavailable/)).toBeNull();
  expect(pending.discoveryReads()).toBe(0);
  fireEvent.click(screen.getByRole("button", { name: "Retry connection" }));
  expect(await screen.findByText("Context: alpha policy 1")).toBeVisible();
  expect(identityReads).toBe(2);
  expect(pending.discoveryReads()).toBe(1);
});

it("keeps a paged directory bound to the signed-in account that started discovery", async () => {
  const former = browserIdentityFixture("former");
  const current = browserIdentityFixture("current");
  let actor = former;
  const checks: Array<{ path: string; binding: string | null }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const path = String(input);
      const binding = new Headers(init?.headers).get(
        "x-openepm-browser-identity",
      );
      checks.push({ path, binding });
      if (path === "/api/session-identity")
        return new Response(JSON.stringify(actor));
      if (path === "/api/runtime")
        return new Response(JSON.stringify({ build: {} }));
      if (path.startsWith("/api/applications?")) actor = current;
      if (binding !== actor.identityBinding)
        return new Response(
          JSON.stringify({ code: "BROWSER_IDENTITY_CHANGED" }),
          {
            status: 409,
          },
        );
      if (path === "/api/platform/browser/catalog")
        return platformAccess(false);
      if (path === "/api/catalog") return catalog(1);
      if (path === "/api/applications" && actor === former) {
        const first = await applicationList("former-private").json();
        return new Response(
          JSON.stringify({
            ...first,
            nextAfter: { workspaceId: "ws", applicationId: "former-private" },
          }),
        );
      }
      if (path === "/api/applications")
        return applicationList("current-private");
      return new Response("{}", { status: 404 });
    }),
  );
  window.history.replaceState(null, "", "#/applications/0");
  render(<App />);
  await screen.findByRole("heading", { name: "Check the signed-in account" });
  expect(screen.queryByText("former-private")).toBeNull();
  expect(screen.queryByText("current-private")).toBeNull();
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  expect(
    checks.find(({ path }) => path.startsWith("/api/applications?"))?.binding,
  ).toBe(former.identityBinding);
  expect(checks.filter(({ path }) => path === "/api/catalog")).toEqual([]);
  fireEvent.click(screen.getByRole("button", { name: "Retry connection" }));
  expect(
    await screen.findByRole("button", { name: "Open current-private" }),
  ).toBeVisible();
  expect(screen.queryByText("former-private")).toBeNull();
  expect(
    checks
      .filter(({ path }) => path === "/api/session-identity")
      .map(({ binding }) => binding),
  ).toEqual([null, null]);
  expect(
    checks
      .filter(({ path }) => path === "/api/platform/browser/catalog")
      .map(({ binding }) => binding),
  ).toEqual([former.identityBinding, current.identityBinding]);
});

it("clears the selected catalogue when a current explicit refresh is denied", async () => {
  const pending = fixture();
  render(<App />);
  await screen.findByText("Context: alpha policy 1");
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh shared context" }),
  );
  await waitFor(() => expect(pending.reads()).toBe(2));
  await act(async () => pending.finish(revokedCatalog()));
  expect(await screen.findByText("Application grant required")).toBeVisible();
  expect(
    screen.getByRole("heading", { name: "Application unavailable" }),
  ).toBeVisible();
  expect(
    screen.getByRole("button", { name: "Choose application" }),
  ).toBeVisible();
  expect(screen.queryByText("Context: alpha policy 1")).not.toBeInTheDocument();
});

it("rechecks the selected catalogue before enabling the same session after reconnect", async () => {
  const pending = fixture();
  render(<App />);
  await screen.findByText("Context: alpha policy 1");
  fireEvent(window, new Event("online"));
  await waitFor(() => expect(pending.reads()).toBe(2));
  expect(screen.getByText("Revalidating your session")).toBeVisible();
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  await act(async () => pending.finish(revokedCatalog()));
  expect(await screen.findByText("Application grant required")).toBeVisible();
  expect(
    screen.getByRole("heading", { name: "Application unavailable" }),
  ).toBeVisible();
  expect(
    screen.getByRole("button", { name: "Choose application" }),
  ).toBeVisible();
  expect(
    screen.queryByText("Revalidating your session"),
  ).not.toBeInTheDocument();
  expect(screen.queryByText("Context: alpha policy 1")).not.toBeInTheDocument();
});

it("resumes after reconnect with the newer catalogue for the same application", async () => {
  const pending = fixture();
  render(<App />);
  await screen.findByText("Context: alpha policy 1");
  fireEvent(window, new Event("online"));
  await waitFor(() => expect(pending.reads()).toBe(2));
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  await act(async () => pending.finish(catalog(2)));
  expect(await screen.findByText("Context: alpha policy 2")).toBeVisible();
  expect(screen.queryByText("Context: alpha policy 1")).not.toBeInTheDocument();
  expect(document.querySelector(".shell")).not.toHaveAttribute("inert");
});

it("keeps the revoked route unavailable and reopens the picker with only current grants", async () => {
  const pending = fixture();
  render(<App />);
  await screen.findByText("Context: alpha policy 1");
  pending.pauseDiscovery();
  fireEvent(window, new Event("online"));
  await waitFor(() => expect(pending.reads()).toBe(2));
  await act(async () => pending.finish(revokedCatalog()));
  await waitFor(() => expect(pending.discoveryReads()).toBe(2));
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  await act(async () =>
    pending.finishDiscovery(applicationList("beta", "gamma")),
  );
  await screen.findByRole("heading", { name: "Application unavailable" });
  expect(window.location.hash).toContain("application=alpha");
  fireEvent.click(
    within(screen.getByRole("main")).getByRole("button", {
      name: "Choose application",
    }),
  );
  await screen.findByRole("heading", { name: "Applications" });
  expect(screen.getByRole("button", { name: "Open gamma" })).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Open alpha" }),
  ).not.toBeInTheDocument();
});

it("keeps the old roster inert when the current application directory is invalid", async () => {
  const pending = fixture();
  render(<App />);
  await screen.findByText("Context: alpha policy 1");
  pending.pauseDiscovery();
  fireEvent(window, new Event("online"));
  await waitFor(() => expect(pending.reads()).toBe(2));
  await act(async () => pending.finish(catalog(2)));
  await waitFor(() => expect(pending.discoveryReads()).toBe(2));
  await act(async () => pending.finishDiscovery(new Response("{}")));
  await screen.findByRole("heading", {
    name: "Open EPM is temporarily unavailable",
  });
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
});

it("preserves the selected application by scope when reconnect changes its list position", async () => {
  const pending = fixture();
  window.history.replaceState(null, "", "#/home/1");
  render(<App />);
  const selection = {
    name: "Choose application; current beta",
  };
  await screen.findByRole("button", selection);
  pending.pauseDiscovery();
  fireEvent(window, new Event("online"));
  await waitFor(() => expect(pending.discoveryReads()).toBe(2));
  await act(async () =>
    pending.finishDiscovery(applicationList("beta", "gamma")),
  );
  expect(await screen.findByRole("button", selection)).toBeVisible();
  expect(window.location.hash).toBe("#/home/0");
});

it.each([
  [503, "WEB_OPERATION_OUTCOME_UNKNOWN"],
  [403, "WEB_ORIGIN_REQUIRED"],
] as const)(
  "keeps the shell blocked when the catalogue check fails on reconnect with %s",
  async (status, code) => {
    const pending = fixture();
    render(<App />);
    await screen.findByText("Context: alpha policy 1");
    fireEvent(window, new Event("online"));
    await waitFor(() => expect(pending.reads()).toBe(2));
    await act(async () =>
      pending.finish(new Response(JSON.stringify({ code }), { status })),
    );
    expect(
      await screen.findByRole("heading", {
        name: "Application context unavailable",
      }),
    ).toBeVisible();
    expect(document.querySelector(".shell")).toHaveAttribute("inert");
    expect(
      screen.queryByRole("heading", { name: "Application unavailable" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Application unavailable")).toBeNull();
  },
);

function identityDiscoveryFixture(holdPlatformRefresh = false) {
  let subject = "first-identity";
  let discoveryCount = 0;
  const platformRefreshes: Array<(response: Response) => void> = [];
  let release: (response: Response) => void = () => undefined;
  function visibleApplication(applicationId: string, name: string) {
    return new Response(
      JSON.stringify({
        applications: [
          { workspaceId: "ws", applicationId, name, status: "Active" },
        ],
        nextAfter: null,
      }),
    );
  }
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/api/session-identity")
        return new Response(JSON.stringify(browserIdentityFixture(subject)));
      if (url.startsWith("/api/applications")) {
        discoveryCount++;
        if (subject === "first-identity")
          return visibleApplication("first", "Prior private application");
        return new Promise<Response>((resolve) => {
          release = resolve;
        });
      }
      if (url === "/api/platform/browser/catalog") {
        if (holdPlatformRefresh && discoveryCount > 1)
          return new Promise<Response>((resolve) => {
            platformRefreshes.push(resolve);
          });
        return platformAccess(subject === "first-identity");
      }
      if (url === "/api/catalog") return catalog(1);
      if (url === "/api/runtime")
        return new Response(
          JSON.stringify({
            build: { sourceCommit: "a".repeat(40), packagedSchema: 386 },
          }),
        );
      return new Response("{}", { status: 404 });
    }),
  );
  window.history.replaceState(null, "", "#/applications/0");
  return {
    discoveryCount: () => discoveryCount,
    platformRefreshes,
    switchIdentity: (target = "second-identity") => {
      subject = target;
      fireEvent(window, new Event("online"));
    },
    finish: () =>
      release(visibleApplication("second", "Current private application")),
  };
}

it.each([false, true])(
  "fences application discovery and platform access during an identity switch with local drafts %s",
  async (withDraft) => {
    const context = identityDiscoveryFixture();
    render(<App />);
    await screen.findAllByText("Prior private application");
    await screen.findByRole("button", { name: "Server Administration" });
    if (withDraft)
      act(() => setUnsavedWork("old/identity", "Prior identity draft", true));
    context.switchIdentity();
    if (withDraft) {
      await screen.findByRole("heading", { name: "Identity changed" });
      expect(context.discoveryCount()).toBe(1);
      expect(document.querySelector(".shell")).toHaveAttribute("inert");
      fireEvent.click(
        screen.getByRole("button", { name: "Discard drafts and continue" }),
      );
    }
    await waitFor(() => expect(context.discoveryCount()).toBe(2));
    expect(document.querySelector(".shell")).toHaveAttribute("inert");
    await act(async () => context.finish());
    expect(
      (await screen.findAllByText("Current private application")).length,
    ).toBeGreaterThan(0);
    expect(screen.queryAllByText("Prior private application")).toHaveLength(0);
    expect(
      screen.queryByRole("button", { name: "Server Administration" }),
    ).not.toBeInTheDocument();
    expect(document.querySelector(".shell")).not.toHaveAttribute("inert");
  },
);

it("does not reuse an earlier platform grant when the first identity returns", async () => {
  const context = identityDiscoveryFixture(true);
  render(<App />);
  await screen.findByRole("button", { name: "Server Administration" });
  context.switchIdentity();
  await waitFor(() => expect(context.discoveryCount()).toBe(2));
  await act(async () => context.finish());
  await waitFor(() => expect(context.platformRefreshes).toHaveLength(1));
  context.switchIdentity("first-identity");
  await waitFor(() => expect(context.platformRefreshes).toHaveLength(2));
  await act(async () => context.platformRefreshes[0](platformAccess(true)));
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  expect(
    screen.queryByRole("button", { name: "Server Administration" }),
  ).not.toBeInTheDocument();
  await act(async () => context.platformRefreshes[1](platformAccess(false)));
  await screen.findAllByText("Prior private application");
  expect(
    screen.queryByRole("button", { name: "Server Administration" }),
  ).not.toBeInTheDocument();
});

it("checks current server administration authority on reconnect to the same account", async () => {
  const context = identityDiscoveryFixture(true);
  window.history.replaceState(null, "", "#/server/0?section=groups");
  render(<App />);
  await screen.findByRole("heading", { name: "Server directory fixture" });
  context.switchIdentity("first-identity");
  await waitFor(() => expect(context.platformRefreshes).toHaveLength(1));
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
  expect(
    screen.queryByRole("heading", { name: "Server directory fixture" }),
  ).not.toBeInTheDocument();
  await act(async () => context.platformRefreshes[0](platformAccess(false)));
  await screen.findByRole("heading", {
    name: "Server administration unavailable",
  });
  expect(window.location.hash).toBe("#/server/0?section=groups");
  expect(
    screen.queryByRole("button", { name: "Server Administration" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("heading", { name: "Server directory fixture" }),
  ).not.toBeInTheDocument();

  context.switchIdentity("first-identity");
  await waitFor(() => expect(context.platformRefreshes).toHaveLength(2));
  await act(async () => context.platformRefreshes[1](platformAccess(true)));
  await screen.findByRole("heading", { name: "Server directory fixture" });
  expect(
    screen.getByRole("button", { name: "Server Administration" }),
  ).toBeVisible();
});

it.each(["IDENTITY_INACTIVE", "IDENTITY_SESSION_REVOKED"])(
  "offers sign-in recovery when the platform check returns %s",
  async (code) => {
    const context = identityDiscoveryFixture(true);
    window.history.replaceState(null, "", "#/server/0?section=groups");
    render(<App />);
    await screen.findByRole("heading", { name: "Server directory fixture" });
    context.switchIdentity("first-identity");
    await waitFor(() => expect(context.platformRefreshes).toHaveLength(1));
    await act(async () =>
      context.platformRefreshes[0](
        new Response(JSON.stringify({ error: code }), { status: 401 }),
      ),
    );
    await screen.findByRole("heading", {
      name: "Your sign-in is no longer valid",
    });
    expect(screen.getByRole("button", { name: "Sign in again" })).toBeVisible();
    expect(document.querySelector(".shell")).toHaveAttribute("inert");
    expect(
      screen.queryByRole("heading", { name: "Server directory fixture" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("heading", {
        name: "Server administration unavailable",
      }),
    ).not.toBeInTheDocument();
    expect(window.location.hash).toBe("#/server/0?section=groups");
  },
);

it("keeps a newly offline tab blocked when an older platform check completes", async () => {
  const context = identityDiscoveryFixture(true);
  render(<App />);
  await screen.findByRole("button", { name: "Server Administration" });
  context.switchIdentity("first-identity");
  await waitFor(() => expect(context.platformRefreshes).toHaveLength(1));
  fireEvent(window, new Event("offline"));
  await act(async () => context.platformRefreshes[0](platformAccess(true)));
  await screen.findByRole("heading", { name: "You are offline" });
  expect(document.querySelector(".shell")).toHaveAttribute("inert");
});

it.each([
  ["a malformed platform catalogue", () => new Response("{}")],
  [
    "a refused browser origin",
    () => Response.json({ error: "WEB_ORIGIN_REQUIRED" }, { status: 403 }),
  ],
  [
    "an opaque platform refusal",
    () => new Response("Forbidden", { status: 403 }),
  ],
] as const)(
  "shows retryable server authority uncertainty after %s",
  async (_, failedRead) => {
    const context = identityDiscoveryFixture(true);
    window.history.replaceState(null, "", "#/server/0?section=groups");
    render(<App />);
    await screen.findByRole("heading", { name: "Server directory fixture" });
    context.switchIdentity("first-identity");
    await waitFor(() => expect(context.platformRefreshes).toHaveLength(1));
    await act(async () => context.platformRefreshes[0](failedRead()));
    expect(
      await screen.findByText(
        "Open EPM could not confirm server administration access.",
      ),
    ).toBeVisible();
    expect(
      screen.queryByText(
        "Your current account does not have server administration access.",
      ),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Server Administration" }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry access check" }));
    await waitFor(() => expect(context.platformRefreshes).toHaveLength(2));
    expect(
      screen.getByRole("heading", { name: "Revalidating your session" }),
    ).toBeVisible();
    expect(document.querySelector(".shell")).toHaveAttribute("inert");
    expect(
      screen.queryByRole("button", { name: "Retry access check" }),
    ).not.toBeInTheDocument();
    await act(async () => context.platformRefreshes[1](platformAccess(true)));
    await screen.findByRole("heading", { name: "Server directory fixture" });
    expect(window.location.hash).toBe("#/server/0?section=groups");
  },
);
