import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { CapabilityArea } from "./CapabilityArea";
import { PythonDefinitionEditor } from "./PythonDefinitionEditor";
import { authoringContextKey } from "./python-authoring";
import { installOperationAdmissionFixture } from "./test-setup";
import { resetUnsavedWorkForTests } from "./unsaved-work";
import type { ApplicationCatalog } from "./types";

vi.mock("./PythonRuleEditor", () => ({
  PythonRuleEditor: ({
    value,
    ariaLabel,
  }: {
    value: string;
    ariaLabel: string;
  }) => <textarea aria-label={ariaLabel} value={value} readOnly />,
}));
// Observe the exact parent-to-Test contract independently of the Test renderer.
vi.mock("./PythonProgramTest", () => ({
  PythonProgramTest: (props: {
    program: unknown;
    definitionContextKey?: string;
  }) => (
    <output aria-label="Forwarded Test contract">
      {JSON.stringify(props)}
    </output>
  ),
}));
afterEach(() => {
  vi.unstubAllGlobals();
  resetUnsavedWorkForTests();
});
const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "App",
  status: "Active",
};
const catalog: ApplicationCatalog = {
  applicationAccess: {
    issuer: "issuer",
    subjectId: "author",
    role: "Designer",
    workspaceAdministrator: false,
  },
  functions: {
    "python.program.read": {},
    "python.program.list": {},
    "python.program.test": {},
    "python.program.activate": {},
  },
  enabledCapabilities: [],
  revisions: {
    metadata: 1,
    policy: 1,
    security: 1,
    data: 1,
    commit: 1,
    schemaEpoch: 1,
  },
};
const queued = {
  buildId: "validation-two",
  purpose: "Validation",
  status: "accepted",
  current: true,
};
const sealed = {
  ...queued,
  status: "sealed",
  definition: {
    kind: "ApplicationRule",
    definitionId: "rule",
    parameters: [{ name: "rate", type: "Ratio" }],
  },
};
const source = {
  programId: "source",
  stateToken: "b".repeat(64),
  sourceToken: "c".repeat(64),
  status: "Inactive",
  sourceDigest: "a".repeat(64),
  sourceText: "def build(context, parameters):\n    return rule",
  entryPoint: "build",
  environmentId: "approved",
  environmentStateToken: "d".repeat(64),
  parameterSchema: { type: "object" },
  validation: queued,
  declaredOutput: {
    kind: "ApplicationRule",
    definitionId: "rule",
  },
  defined: true,
  valid: false,
  active: false,
  sourceCurrent: true,
  executable: false,
  reason: "validation_required",
};
const binding = {
  programId: source.programId,
  sourceToken: "c".repeat(64),
  sourceDigest: source.sourceDigest,
  buildId: queued.buildId,
  active: false,
};
const response = (result: unknown) => new Response(JSON.stringify({ result }));
const contract = () =>
  JSON.parse(screen.getByLabelText("Forwarded Test contract").textContent!);

it.each(["definition", "program"] as const)(
  "forwards %s's exact authorized Validation declarations before activation and fences context drift",
  async (surface) => {
    let reads = 0;
    let drifted = false;
    let finishRecheck: ((value: Response) => void) | undefined;
    const fetch = vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.program?.function === "python.program.list")
        return response({ programs: [source], nextAfterProgramId: null });
      if (body.program?.function === "python.program.read") {
        if (drifted)
          return new Promise<Response>((resolve) => {
            finishRecheck = resolve;
          });
        return response({
          ...source,
          validation: ++reads === 1 ? queued : sealed,
        });
      }
      if (body.action === "read")
        return response({ ...queued, status: "sealed" });
      throw new Error(`Unexpected ${JSON.stringify(body)}`);
    });
    vi.stubGlobal("fetch", fetch);
    const element = (context = catalog) =>
      surface === "definition" ? (
        <PythonDefinitionEditor
          app={app}
          catalog={context}
          kind="ApplicationRule"
          binding={binding}
          definitionId="rule"
        />
      ) : (
        <CapabilityArea
          app={app}
          catalog={context}
          area="rules"
          section="python"
          index={0}
        />
      );
    const view = render(element());
    if (surface === "program") {
      fireEvent.click(await screen.findByRole("button", { name: "Open" }));
    }
    await waitFor(() =>
      expect(contract().program.validation?.definition).toEqual(
        sealed.definition,
      ),
    );
    expect(contract().definitionContextKey).toBe(
      authoringContextKey(app, catalog),
    );
    expect(
      fetch.mock.calls.some(
        ([, init]) =>
          JSON.parse(init.body).program?.function === "python.program.activate",
      ),
    ).toBe(false);
    drifted = true;
    const changedCatalog = {
      ...catalog,
      revisions: { ...catalog.revisions, security: 2 },
    };
    view.rerender(element(changedCatalog));
    if (surface === "definition") {
      // The bound editor hides its old source while current access is read.
      expect(
        screen.queryByLabelText("Forwarded Test contract"),
      ).not.toBeInTheDocument();
      await waitFor(() => expect(finishRecheck).toBeDefined());
      await act(async () =>
        finishRecheck!(
          response({ ...source, validation: { ...sealed, current: false } }),
        ),
      );
      expect(contract().definitionContextKey).toBe(
        authoringContextKey(app, changedCatalog),
      );
    } else {
      await waitFor(() =>
        expect(contract().definitionContextKey).toBeUndefined(),
      );
    }
    expect(contract().program.validation).toBeNull();
  },
);

it.each(["definition", "program"] as const)(
  "rejects a %s descriptor from a different Validation build",
  async (surface) => {
    let reads = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url, init) => {
        const body = JSON.parse(init.body);
        if (body.program?.function === "python.program.list")
          return response({ programs: [source], nextAfterProgramId: null });
        if (body.program?.function === "python.program.read")
          return response({
            ...source,
            validation:
              ++reads === 1 ? queued : { ...sealed, buildId: "foreign-build" },
          });
        if (body.action === "read")
          return response({ ...queued, status: "sealed" });
        throw new Error(`Unexpected ${JSON.stringify(body)}`);
      }),
    );
    render(
      surface === "definition" ? (
        <PythonDefinitionEditor
          app={app}
          catalog={catalog}
          kind="ApplicationRule"
          binding={binding}
          definitionId="rule"
        />
      ) : (
        <CapabilityArea
          app={app}
          catalog={catalog}
          area="rules"
          section="python"
          index={0}
        />
      ),
    );
    if (surface === "program") {
      fireEvent.click(await screen.findByRole("button", { name: "Open" }));
    }
    await screen.findByText("The exact saved validation is unavailable.");
    expect(contract().program.validation?.definition).toBeUndefined();
  },
);

it("forwards a newly saved inactive source's automatic Validation without a compiled registry read", async () => {
  const freshSource = { ...source, validation: sealed };
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      const fn = body.program?.function;
      if (fn) calls.push(fn);
      if (fn === "python.environment.list")
        return response({
          environments: [
            {
              environment_id: "approved",
              state_token: "d".repeat(64),
              status: "Active",
            },
          ],
          nextAfterEnvironmentId: null,
        });
      if (fn === "python.program.save")
        return response({
          stateToken: source.stateToken,
          sourceToken: source.sourceToken,
          status: "Inactive",
          sourceDigest: source.sourceDigest,
          validation: queued,
        });
      if (fn === "python.program.read") return response(freshSource);
      if (body.action === "read")
        return response({ ...queued, status: "sealed" });
      throw new Error(`Unexpected ${JSON.stringify(body)}`);
    }),
  );
  installOperationAdmissionFixture("6");
  render(
    <PythonDefinitionEditor
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "python.program.save": {},
          "python.environment.list": {},
        },
      }}
      kind="ApplicationRule"
      template={source.sourceText}
    />,
  );
  fireEvent.change(screen.getByLabelText("ApplicationRule source ID"), {
    target: { value: "source" },
  });
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Save and validate source" }),
    ).toBeEnabled(),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Save and validate source" }),
  );
  await waitFor(() =>
    expect(contract().program.validation?.definition).toEqual(
      sealed.definition,
    ),
  );
  expect(contract().program.sourceToken).toBe(source.sourceToken);
  expect(contract().program.status).toBe("Inactive");
  expect(contract().definitionContextKey).toBe(
    authoringContextKey(app, catalog),
  );
  expect(calls).toContain("python.program.save");
  expect(calls).toContain("python.program.read");
  expect(calls.every((fn) => fn.startsWith("python."))).toBe(true);
});
