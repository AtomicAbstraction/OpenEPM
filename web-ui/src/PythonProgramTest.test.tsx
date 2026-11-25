import { useState } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { PythonProgramTest } from "./PythonProgramTest";
import { authoringContextKey } from "./python-authoring";
import {
  installOperationAdmissionFixture,
  operationAdmissionResponse,
} from "./test-setup";
import type { ComponentProps } from "react";
function TestFixture(
  props: Omit<
    ComponentProps<typeof PythonProgramTest>,
    "parameters" | "onParametersChange"
  >,
) {
  const [parameters, setParameters] = useState("{}");
  return (
    <PythonProgramTest
      {...props}
      parameters={parameters}
      onParametersChange={setParameters}
    />
  );
}
import type { ApplicationCatalog, ApplicationSummary } from "./types";

const app: ApplicationSummary = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "Active",
};
const catalog: ApplicationCatalog = {
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: { "python.program.test": {} },
  revisions: {
    metadata: 4,
    policy: 2,
    schemaEpoch: 1,
    data: 0,
    commit: 0,
    security: 0,
  },
};
const program = {
  programId: "forecast",
  sourceToken: "c".repeat(64),
  sourceDigest: "a".repeat(64),
  sourceText: "def build(context, parameters):\n    return Program()",
};
afterEach(() => vi.unstubAllGlobals());

it("uses pre-activation validated parameter declarations and sends separate typed source and rule bindings", async () => {
  const requests: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      requests.push(body);
      return new Response(
        JSON.stringify({
          result: {
            buildId: "1".repeat(32),
            status: "failed",
            purpose: "ImpactTest",
          },
        }),
      );
    }),
  );
  installOperationAdmissionFixture("1");
  render(
    <TestFixture
      app={app}
      definitionContextKey={authoringContextKey(app, catalog)}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "application.rule.read": {},
        },
      }}
      program={{
        ...program,
        parameterSchema: {
          type: "object",
          properties: { label: { type: "string" } },
          required: ["label"],
        },
        validation: {
          buildId: "valid",
          status: "sealed",
          current: true,
          purpose: "Validation",
          definition: {
            kind: "ApplicationRule",
            definitionId: "double",
            parameters: [
              { name: "rate", type: "Ratio" },
              { name: "enabled", type: "Boolean" },
            ],
          },
        },
      }}
    />,
  );
  await screen.findByLabelText("rate");
  fireEvent.click(screen.getByRole("button", { name: "Test source" }));
  expect(requests).toHaveLength(0);
  fireEvent.change(screen.getByLabelText("label"), {
    target: { value: "Europe" },
  });
  fireEvent.change(screen.getByLabelText("rate"), {
    target: { value: "1.123456789012" },
  });
  fireEvent.change(screen.getByLabelText("enabled"), {
    target: { value: "false" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Test source" }));
  await waitFor(() => expect(requests).toHaveLength(1));
  expect(requests[0]).toMatchObject({
    program: {
      arguments: {
        parameters: { label: "Europe" },
        definitionParameters: { rate: "1.123456789012", enabled: false },
        programId: program.programId,
        programSourceToken: program.sourceToken,
      },
    },
  });
});

it("tests an exact current source without delegation and reads private impact with UTF-8 paging", async () => {
  const requests: Record<string, unknown>[] = [];
  let pages = 0;
  const content = new TextEncoder().encode(
    JSON.stringify({
      format: "openepm-python-impact-v1",
      status: "complete",
      sourceDigest: program.sourceDigest,
      businessDataChanged: false,
      baseline: {},
      counts: { selected: 1, changed: 1, created: 1, cleared: 0 },
      rows: [
        {
          seriesKey: "one",
          members: { Account: "Narrative" },
          before: { present: false },
          after: { present: true, kind: "text", text: "€" },
          delta: null,
        },
      ],
    }),
  );
  const split = content.indexOf(0xe2) + 1;
  const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const body = JSON.parse(init.body);
      requests.push(body);
      if (body.action === "artifact") {
        pages += 1;
        return new Response(
          JSON.stringify({
            result:
              pages === 1
                ? {
                    chunkBase64: base64(content.slice(0, split)),
                    nextCursor: "cursor-2",
                  }
                : {
                    chunkBase64: base64(content.slice(split)),
                    nextCursor: null,
                  },
          }),
        );
      }
      return new Response(
        JSON.stringify({
          result: {
            buildId: "2".repeat(32),
            status: body.action === "read" ? "sealed" : "accepted",
            purpose: "ImpactTest",
          },
        }),
      );
    }),
  );
  installOperationAdmissionFixture("2");
  render(<TestFixture app={app} catalog={catalog} program={program} />);
  fireEvent.change(screen.getByLabelText("Python test parameters"), {
    target: { value: '{"ratio":"2"}' },
  });
  fireEvent.click(screen.getByRole("button", { name: "Test source" }));
  await screen.findByText("Test: sealed");
  expect(requests[0]).toMatchObject({
    workspaceId: "ws",
    applicationId: "app",
    action: "request",
    confirmed: true,
    program: {
      languageVersion: 2,
      function: "python.program.test",
      arguments: {
        programId: "forecast",
        programSourceToken: "c".repeat(64),
        parameters: { ratio: "2" },
        expectedMetadataRevision: 4,
        expectedPolicyRevision: 2,
        expectedSchemaEpoch: 1,
      },
    },
  });
  expect(
    (requests[0].program as { arguments: unknown }).arguments,
  ).not.toHaveProperty("delegationId");
  fireEvent.click(screen.getByRole("button", { name: "Read test impact" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Next impact page" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Next impact page" }));
  expect(await screen.findByText("€")).toBeVisible();
  expect(
    screen.queryByText("Technical impact artifact"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("region", { name: "Python impact artifact" }),
  ).not.toBeInTheDocument();
  expect(requests.at(-1)).toMatchObject({
    action: "artifact",
    buildId: "2".repeat(32),
    section: "Impact",
    cursor: "cursor-2",
  });
  expect(screen.queryByRole("button", { name: /Run/ })).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Python test parameters"), {
    target: { value: "{}" },
  });
  expect(screen.queryByText("€")).not.toBeInTheDocument();
});

it("rejects another build purpose and invalid parameters before sending", async () => {
  const fetch = vi.fn(
    async () =>
      new Response(
        JSON.stringify({
          result: { buildId: "plan-1", status: "sealed", purpose: "Plan" },
        }),
      ),
  );
  vi.stubGlobal("fetch", fetch);
  installOperationAdmissionFixture("3");
  render(<TestFixture app={app} catalog={catalog} program={program} />);
  fireEvent.change(screen.getByLabelText("Python test parameters"), {
    target: { value: "[]" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Test source" }));
  expect(fetch).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText("Python test parameters"), {
    target: { value: "{}" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Test source" }));
  await screen.findByText("Test returned a different build purpose.");
  expect(
    screen.queryByRole("button", { name: "Read test impact" }),
  ).not.toBeInTheDocument();
});

it("withholds a late acknowledgement after context change and retains its original lookup", async () => {
  let finish: (value: Response) => void = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          finish = resolve;
        }),
    ),
  );
  installOperationAdmissionFixture("4");
  const { rerender } = render(
    <TestFixture app={app} catalog={catalog} program={program} />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Test source" }));
  await screen.findByRole("region", { name: "Original Python impact test" });
  rerender(
    <TestFixture
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, policy: 3 } }}
      program={program}
    />,
  );
  finish(
    new Response(
      JSON.stringify({
        result: {
          buildId: "2".repeat(32),
          status: "sealed",
          purpose: "ImpactTest",
        },
      }),
    ),
  );
  expect(screen.getByRole("button", { name: "Test source" })).toBeDisabled();
  expect(screen.queryByText("Test: sealed")).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Check original test" }),
  ).toBeEnabled();
});

it("allows an expired result to be tested again and keeps that fresh intent stable after response loss", async () => {
  const mutationKeys: string[] = [];
  let first = true;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const body = JSON.parse(init.body);
      if (body.action === "read")
        return Response.json(
          { code: "PYTHON_BUILD_UNAVAILABLE" },
          { status: 400 },
        );
      mutationKeys.push(body.idempotencyKey);
      if (first) {
        first = false;
        throw new TypeError("Response lost");
      }
      return new Response(
        JSON.stringify({
          result: {
            buildId: "3".repeat(32),
            purpose: "ImpactTest",
            status: "sealed",
          },
        }),
      );
    }),
  );
  installOperationAdmissionFixture("5");
  const onSealedTest = vi.fn();
  render(
    <TestFixture
      app={app}
      catalog={catalog}
      program={{
        ...program,
        latestImpactTest: {
          buildId: "expired-test",
          purpose: "ImpactTest",
          status: "expired",
          current: false,
        },
      }}
      onSealedTest={onSealedTest}
    />,
  );
  expect(
    screen.getByText("Test result expired; test again."),
  ).toBeInTheDocument();
  expect(onSealedTest).not.toHaveBeenCalledWith(
    expect.objectContaining({ buildId: "expired-test" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Test source" }));
  await screen.findByText("Response lost");
  expect(screen.getByRole("button", { name: "Test source" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Check original test" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Retry original test" }),
  );
  await screen.findByText("Test: sealed");
  expect(mutationKeys).toHaveLength(2);
  expect(mutationKeys[0]).toBe(mutationKeys[1]);
  await waitFor(() =>
    expect(onSealedTest).toHaveBeenCalledWith(
      expect.objectContaining({
        buildId: "3".repeat(32),
        programId: "forecast",
        sourceToken: "c".repeat(64),
      }),
    ),
  );
});

it("recovers a committed test by read under current authority through a same-tab remount", async () => {
  const effects: string[] = [];
  const lookups: Array<Record<string, unknown>> = [];
  const copy = vi.fn(async () => {});
  const onSealedTest = vi.fn();
  vi.stubGlobal("navigator", { clipboard: { writeText: copy } });
  const admission = vi.fn(() => operationAdmissionResponse("a"));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      if (path === "/api/operation-admission") return admission();
      const body = JSON.parse(String(init.body));
      if (body.action === "request") {
        effects.push(String(init.body));
        return Response.json(
          { code: "WEB_OPERATION_OUTCOME_UNKNOWN" },
          { status: 503 },
        );
      }
      lookups.push(body);
      return Response.json({
        result: {
          buildId: "e".repeat(32),
          purpose: "ImpactTest",
          status: "sealed",
        },
      });
    }),
  );
  const editor = {
    ...catalog,
    applicationAccess: {
      ...catalog.applicationAccess,
      issuer: "issuer",
      subjectId: "owner",
    },
    functions: { ...catalog.functions, "python.program.read": {} },
  };
  const { unmount } = render(
    <TestFixture app={app} catalog={editor} program={program} />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Test source" }));
  await screen.findByText("WEB_OPERATION_OUTCOME_UNKNOWN");
  expect(
    screen.queryByRole("button", { name: "Retry original test" }),
  ).toBeNull();
  unmount();
  const reader = {
    ...editor,
    revisions: { ...editor.revisions, security: 1 },
    applicationAccess: { ...editor.applicationAccess, role: "Reader" },
    functions: { "python.program.read": {} },
  };
  const fixture = (
    target: ApplicationSummary,
    authority: ApplicationCatalog,
  ) => (
    <TestFixture
      app={target}
      catalog={authority}
      program={program}
      onSealedTest={onSealedTest}
    />
  );
  const view = render(fixture({ ...app, applicationId: "other" }, reader));
  await waitFor(() =>
    expect(
      screen.queryByRole("button", { name: "Check original test" }),
    ).toBeNull(),
  );
  view.rerender(
    fixture(app, {
      ...reader,
      applicationAccess: {
        ...reader.applicationAccess,
        subjectId: "different",
      },
    }),
  );
  expect(
    screen.queryByRole("button", { name: "Check original test" }),
  ).toBeNull();
  view.rerender(fixture(app, reader));
  const check = await screen.findByRole("button", {
    name: "Check original test",
  });
  expect(screen.queryByRole("button", { name: "Test source" })).toBeNull();
  expect(lookups).toHaveLength(0);
  fireEvent.click(
    screen.getByRole("button", { name: "Copy original test lookup for MCP" }),
  );
  await waitFor(() => expect(copy).toHaveBeenCalledTimes(1));
  check.focus();
  fireEvent.click(check);
  await screen.findByText(
    "Test: sealed · source context or parameters changed",
  );
  expect(
    screen.getByRole("heading", { name: "Test this source" }),
  ).toHaveFocus();
  expect(admission).toHaveBeenCalledTimes(1);
  expect(effects).toHaveLength(1);
  const { program: requestProgram, idempotencyKey } = JSON.parse(effects[0]);
  const originalRequest = { program: requestProgram, idempotencyKey };
  expect(lookups).toEqual([
    {
      workspaceId: "ws",
      applicationId: "app",
      action: "read",
      originalRequest,
    },
  ]);
  expect(copy).toHaveBeenCalledWith(
    JSON.stringify({
      tool: "read_v2_python_program_build",
      arguments: {
        workspace_id: "ws",
        application_id: "app",
        original_request: originalRequest,
      },
    }),
  );
  expect(onSealedTest.mock.calls.every(([value]) => value === null)).toBe(true);
});

it("never offers an effect after a denied check and closes only a confirmed missing expired original", async () => {
  const effects: string[] = [];
  let readCount = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      const body = JSON.parse(String(init.body));
      if (body.action === "read") {
        readCount += 1;
        return readCount === 1
          ? Response.json({ code: "PYTHON_BUILD_UNAVAILABLE" }, { status: 403 })
          : Response.json(
              { code: "PYTHON_BUILD_UNAVAILABLE" },
              { status: 400 },
            );
      }
      effects.push(String(init.body));
      return effects.length === 1
        ? Response.json(
            { code: "WEB_OPERATION_OUTCOME_UNKNOWN" },
            { status: 503 },
          )
        : Response.json(
            { code: "OPERATION_ADMISSION_EXPIRED" },
            { status: 400 },
          );
    }),
  );
  installOperationAdmissionFixture("b");
  render(<TestFixture app={app} catalog={catalog} program={program} />);
  fireEvent.click(screen.getByRole("button", { name: "Test source" }));
  await screen.findByText("WEB_OPERATION_OUTCOME_UNKNOWN");
  fireEvent.click(screen.getByRole("button", { name: "Check original test" }));
  await screen.findByText("PYTHON_BUILD_UNAVAILABLE");
  expect(
    screen.queryByRole("button", { name: "Retry original test" }),
  ).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Check original test" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Retry original test" }),
  );
  expect(effects).toHaveLength(2);
  expect(effects[0]).toBe(effects[1]);
  const close = await screen.findByRole("button", {
    name: "Close expired request",
  });
  expect(screen.getByRole("button", { name: "Test source" })).toBeDisabled();
  fireEvent.click(close);
  await screen.findByText(
    "Original request closed. Review the current inputs before testing again.",
  );
  expect(screen.getByRole("button", { name: "Test source" })).toBeEnabled();
  expect(effects).toHaveLength(2);
});
it("keeps source and rule parameters separate and binds activation eligibility to the exact tested definition", async () => {
  const calls: any[] = [],
    onSealedTest = vi.fn();
  const definition = {
    kind: "ApplicationRule" as const,
    definitionId: "rule",
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      calls.push(body);
      const result =
        body.program?.function === "python.program.read"
          ? {
              ...program,
              latestImpactTest: {
                buildId: "1".repeat(32),
                purpose: "ImpactTest",
                status: "sealed",
                current: true,
                definition,
              },
            }
          : {
              buildId: "1".repeat(32),
              purpose: "ImpactTest",
              status: "sealed",
            };
      return new Response(JSON.stringify({ result }));
    }),
  );
  installOperationAdmissionFixture("6");
  render(
    <TestFixture
      app={app}
      catalog={catalog}
      program={{
        ...program,
        validation: {
          buildId: "valid",
          purpose: "Validation",
          status: "sealed",
          current: true,
          definition: {
            ...definition,
            parameters: [{ name: "factor", type: "Amount" }],
          },
        },
      }}
      definitionKind="ApplicationRule"
      definitionContextKey={authoringContextKey(app, catalog)}
      onSealedTest={onSealedTest}
    />,
  );
  fireEvent.change(screen.getByLabelText("Python test parameters"), {
    target: { value: '{"definitionVersion":2}' },
  });
  fireEvent.change(screen.getByLabelText("factor"), {
    target: { value: "2.00000001" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Test source" }));
  await waitFor(() =>
    expect(onSealedTest).toHaveBeenCalledWith(
      expect.objectContaining({ buildId: "1".repeat(32), definition }),
    ),
  );
  expect(calls[0].program.arguments).toMatchObject({
    parameters: { definitionVersion: 2 },
    definitionParameters: { factor: "2.00000001" },
  });
  fireEvent.change(screen.getByLabelText("factor"), {
    target: { value: "3" },
  });
  await waitFor(() => expect(onSealedTest).toHaveBeenLastCalledWith(null));
});
it.each(["build", "program", "source", "purpose", "status", "current"])(
  "rejects a mismatched or stale %s when reading the displayed test identity",
  async (mismatch) => {
    const onSealedTest = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url, init) => {
        const body = JSON.parse(init.body);
        return new Response(
          JSON.stringify({
            result:
              body.program?.function === "python.program.read"
                ? {
                    ...program,
                    ...(mismatch === "program" ? { programId: "other" } : {}),
                    ...(mismatch === "source"
                      ? { sourceToken: "d".repeat(64) }
                      : {}),
                    latestImpactTest: {
                      buildId:
                        mismatch === "build"
                          ? "different-test"
                          : "4".repeat(32),
                      purpose: mismatch === "purpose" ? "Plan" : "ImpactTest",
                      status: mismatch === "status" ? "expired" : "sealed",
                      current: mismatch !== "current",
                      definition: {
                        kind: "MemberList",
                        definitionId: "list",
                      },
                    },
                  }
                : {
                    buildId: "4".repeat(32),
                    purpose: "ImpactTest",
                    status: "sealed",
                  },
          }),
        );
      }),
    );
    installOperationAdmissionFixture("7");
    render(
      <TestFixture
        app={app}
        catalog={catalog}
        program={program}
        definitionKind="MemberList"
        onSealedTest={onSealedTest}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Test source" }));
    await screen.findByText(/The exact tested definition is unavailable/);
    expect(onSealedTest.mock.calls.every(([value]) => value === null)).toBe(
      true,
    );
  },
);
