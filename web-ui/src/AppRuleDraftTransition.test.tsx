import { browserIdentityFixture } from "./test-setup";
import {
  act,
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "./App";
import { resetBrowserLifecycleForTests } from "./browser-lifecycle";
import {
  unsavedWorkSnapshot,
  usePreservedDraft,
  useUnsavedWork,
} from "./unsaved-work";

// Keep the shell, transitions and both draft owners real; replace only Monaco's
// visual editor because it requires a browser layout engine.
vi.mock("./PythonRuleEditor", () => ({
  PythonRuleEditor: ({
    value,
    onChange,
    readOnly,
    ariaLabel,
  }: {
    value: string;
    onChange: (value: string) => void;
    readOnly?: boolean;
    ariaLabel?: string;
  }) => (
    <textarea
      aria-label={ariaLabel}
      value={value}
      readOnly={readOnly}
      onChange={(event) => onChange(event.target.value)}
    />
  ),
}));

afterEach(() => {
  vi.unstubAllGlobals();
  resetBrowserLifecycleForTests();
  window.history.replaceState(null, "", "/");
});

function fixture() {
  const unexpected: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const url = String(input);
      const response = (value: unknown) => new Response(JSON.stringify(value));
      if (url.startsWith("/api/applications"))
        return response({
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
        return response({
          ...browserIdentityFixture("designer"),
        });
      if (url === "/api/runtime")
        return response({
          build: { sourceCommit: "a".repeat(40), packagedSchema: 381 },
        });
      if (url === "/api/platform/browser/catalog")
        return new Response("{}", { status: 403 });
      if (url === "/api/catalog")
        return response({
          applicationAccess: {
            issuer: "https://identity.example",
            subjectId: "designer",
            role: "Editor",
            workspaceAdministrator: false,
          },
          enabledCapabilities: [],
          functions: Object.fromEntries(
            [
              "python.program.list",
              "python.program.read",
              "python.program.save",
              "python.environment.list",
              "application.rule.list",
              "application.rule.read",
            ].map((name) => [name, {}]),
          ),
          revisions: {
            metadata: 1,
            policy: 1,
            data: 1,
            security: 1,
            commit: 1,
            schemaEpoch: 1,
          },
        });
      const body = init?.body ? JSON.parse(String(init.body)) : null;
      if (
        url === "/api/python-program" &&
        body?.program?.function === "python.program.list"
      )
        return response({ result: { programs: [], nextAfterProgramId: null } });
      if (
        url === "/api/python-environment" &&
        body?.program?.function === "python.environment.list"
      )
        return response({
          result: { environments: [], nextAfterEnvironmentId: null },
        });
      if (
        url === "/api/read" &&
        body?.program?.function === "application.rule.list"
      )
        return response({
          result: {
            rows: [],
            nextAfterRuleId: null,
            hasMore: false,
            metadataRevision: 1,
            policyRevision: 1,
          },
        });
      unexpected.push(`${url}:${body?.program?.function || "none"}`);
      throw new Error("Unexpected request in draft-only journey");
    }),
  );
  window.history.replaceState(
    null,
    "",
    "#/rules/0?workspace=ws&application=app&section=python",
  );
  return unexpected;
}

function section(name: "python" | "rules") {
  fireEvent.click(
    screen.getByRole("button", {
      name: name === "python" ? "Python programs" : "Calculation rules",
    }),
  );
}

async function pythonField() {
  const summary = await screen.findByText("Create a program");
  const disclosure = summary.closest("details")!;
  if (!disclosure.open) fireEvent.click(summary);
  const field = await screen.findByLabelText("Python rule key");
  await waitFor(() => expect(field).toBeEnabled());
  return field;
}

async function newRule() {
  section("rules");
  const button = await screen.findByRole("button", { name: "New rule" });
  await waitFor(() => expect(button).toBeEnabled());
  fireEvent.click(button);
}

it("opens and reopens an independent new rule while preserving both real source drafts", async () => {
  const unexpected = fixture();
  render(<App />);
  fireEvent.change(await pythonField(), {
    target: { value: "unsaved-python-source" },
  });
  await waitFor(() => expect(unsavedWorkSnapshot()).toHaveLength(1));
  await newRule();
  expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  const rule = await screen.findByLabelText("ApplicationRule source ID");
  expect(rule).toHaveValue("");
  fireEvent.change(rule, { target: { value: "unsaved-rule-source" } });
  await waitFor(() => expect(unsavedWorkSnapshot()).toHaveLength(2));
  // Starting over in this already-open editor remains a replacement transition.
  fireEvent.click(screen.getByRole("button", { name: "New rule" }));
  expect(await screen.findByRole("alertdialog")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(rule).toHaveValue("unsaved-rule-source");
  section("python");
  await waitFor(async () =>
    expect(await pythonField()).toHaveValue("unsaved-python-source"),
  );
  await newRule();
  expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  await waitFor(() =>
    expect(screen.getByLabelText("ApplicationRule source ID")).toHaveValue(
      "unsaved-rule-source",
    ),
  );
  section("python");
  await waitFor(async () =>
    expect(await pythonField()).toHaveValue("unsaved-python-source"),
  );
  expect(unsavedWorkSnapshot()).toHaveLength(2);
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(unexpected).toEqual([]);
});

it("keeps the global guard when unrelated work cannot be preserved", async () => {
  const unexpected = fixture();
  render(<App />);
  await pythonField();
  const warning = renderHook(() =>
    useUnsavedWork("unpreserved-editor", "Unpreserved editor work", true),
  );
  section("rules");
  expect(await screen.findByRole("alertdialog")).toBeInTheDocument();
  expect(
    screen.getByRole("heading", { name: "Python programs" }),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  warning.unmount();
  section("rules");
  const button = await screen.findByRole("button", { name: "New rule" });
  await waitFor(() => expect(button).toBeEnabled());
  renderHook(() =>
    useUnsavedWork("unpreserved-editor", "Unpreserved editor work", true),
  );
  fireEvent.click(button);
  expect(await screen.findByRole("alertdialog")).toBeInTheDocument();
  expect(
    screen.queryByLabelText("ApplicationRule source ID"),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  expect(unexpected).toEqual([]);
});

it("guards section navigation when pinned recovery fills capacity and the typed draft cannot be retained", async () => {
  const unexpected = fixture();
  render(<App />);
  const field = await pythonField();
  for (let i = 0; i < 24; i++) {
    const slot = renderHook(() =>
      usePreservedDraft(
        "ws",
        "app",
        `capacity-${i}`,
        "Original pending operation",
        false,
        { packet: "" },
        () => undefined,
      ),
    );
    act(() => {
      slot.result.current.retain({ packet: `original-${i}` });
    });
    slot.unmount();
  }
  fireEvent.change(field, {
    target: { value: "still-visible-unretained-draft" },
  });
  await waitFor(() => expect(unsavedWorkSnapshot()).toHaveLength(25));
  section("rules");
  expect(await screen.findByRole("alertdialog")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(field).toHaveValue("still-visible-unretained-draft");
  expect(
    screen.queryByRole("button", { name: "New rule" }),
  ).not.toBeInTheDocument();
  expect(
    unsavedWorkSnapshot().filter(
      (item) => item.label === "Original pending operation",
    ),
  ).toHaveLength(24);
  expect(unexpected).toEqual([]);
});
