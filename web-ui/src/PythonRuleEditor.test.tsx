import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PythonRuleEditor } from "./PythonRuleEditor";
import { loadPythonEditor } from "./python-editor-loader";
import * as contract from "./python-editor-contract";
import type { PythonDiagnostics } from "./python-editor-contract";
import type { languages } from "monaco-editor/editor/editor.api.js";

vi.mock("./python-editor-loader", () => ({ loadPythonEditor: vi.fn() }));
type Loaded = Awaited<ReturnType<typeof loadPythonEditor>>;

function runtime() {
  const models: ReturnType<typeof model>[] = [];
  const providers: languages.CompletionItemProvider[] = [];
  const providerDisposals: ReturnType<typeof vi.fn>[] = [];
  function model(initial: string) {
    let value = initial;
    let changed = () => {};
    const result = {
      getValue: () => value,
      setValue: vi.fn((next: string) => {
        value = next;
        changed();
      }),
      type(next: string) {
        value = next;
        changed();
      },
      dispose: vi.fn(),
      contentDispose: vi.fn(),
      onDidChangeContent(callback: () => void) {
        changed = callback;
        return { dispose: result.contentDispose };
      },
      getWordUntilPosition: () => ({ word: "", startColumn: 1, endColumn: 1 }),
    };
    return result;
  }
  const view = {
    updateOptions: vi.fn(),
    dispose: vi.fn(),
    setSelection: vi.fn(),
    revealRangeInCenter: vi.fn(),
    focus: vi.fn(),
  };
  const monaco = {
    Uri: { parse: (uri: string) => uri },
    MarkerSeverity: { Error: 8, Warning: 4, Info: 2 },
    editor: {
      createModel: vi.fn((source: string) => {
        const next = model(source);
        models.push(next);
        return next;
      }),
      create: vi.fn(() => view),
      setModelMarkers: vi.fn(),
    },
    languages: {
      CompletionItemKind: {
        Function: 1,
        Variable: 2,
        Field: 3,
        Class: 4,
        Value: 5,
      },
      registerCompletionItemProvider: vi.fn(
        (_language: string, provider: languages.CompletionItemProvider) => {
          providers.push(provider);
          const dispose = vi.fn();
          providerDisposals.push(dispose);
          return { dispose };
        },
      ),
    },
  };
  return {
    loaded: { monaco } as unknown as Loaded,
    monaco,
    models,
    providers,
    providerDisposals,
    view,
  };
}
async function diagnostics(source: string): Promise<PythonDiagnostics> {
  return {
    format: "openepm-diagnostics-v1",
    positionEncoding: "utf-16",
    truncated: false,
    sourceDigest: await contract.pythonSourceDigest(source),
    diagnostics: [
      {
        code: "RULE_INVALID",
        severity: "error",
        stage: "lowering",
        message: "Use a declared field",
        span: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 2 },
      },
    ],
  };
}
function suggestions(fake: ReturnType<typeof runtime>, model = fake.models[0]) {
  const provider = fake.providers[0];
  return provider.provideCompletionItems(
    model as never,
    { lineNumber: 1, column: 1 } as never,
    {} as never,
    {} as never,
  );
}

beforeEach(() => {
  vi.stubGlobal("crypto", {
    subtle: {
      digest: vi.fn(async (_algorithm: string, bytes: Uint8Array) => {
        const result = new Uint8Array(32);
        for (let index = 0; index < bytes.length; index++)
          result[index % 32] ^= bytes[index];
        return result.buffer;
      }),
    },
  });
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.mocked(loadPythonEditor).mockReset();
});

describe("PythonRuleEditor", () => {
  it("binds UTF-16 markers to the exact source and immediately clears stale diagnostics on editing", async () => {
    const fake = runtime();
    vi.mocked(loadPythonEditor).mockResolvedValue(fake.loaded);
    const onChange = vi.fn();
    const value = "x = 1";
    render(
      <PythonRuleEditor
        value={value}
        onChange={onChange}
        diagnostics={await diagnostics(value)}
      />,
    );
    await screen.findByRole("button", { name: /Use a declared field/ });
    expect(fake.monaco.editor.create).toHaveBeenCalledWith(
      expect.any(HTMLElement),
      expect.objectContaining({ editContext: false, domReadOnly: false }),
    );
    await waitFor(() =>
      expect(fake.monaco.editor.setModelMarkers).toHaveBeenLastCalledWith(
        fake.models[0],
        "openepm-python-validation",
        [
          expect.objectContaining({
            startLineNumber: 1,
            endColumn: 2,
            severity: 8,
          }),
        ],
      ),
    );
    fireEvent.click(
      screen.getByRole("button", { name: /Use a declared field/ }),
    );
    expect(fake.view.focus).toHaveBeenCalledOnce();
    act(() => fake.models[0].type("x = 2"));
    expect(onChange).toHaveBeenCalledWith("x = 2");
    expect(fake.monaco.editor.setModelMarkers).toHaveBeenLastCalledWith(
      fake.models[0],
      "openepm-python-validation",
      [],
    );
    expect(
      screen.queryByRole("button", { name: /Use a declared field/ }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Validate to refresh/)).toBeInTheDocument();
  });

  it("keeps source echoes out of undo history and scopes metadata completions to this model", async () => {
    const fake = runtime();
    vi.mocked(loadPythonEditor).mockResolvedValue(fake.loaded);
    const { rerender } = render(
      <PythonRuleEditor
        value="x"
        onChange={vi.fn()}
        completions={[
          {
            label: "Revenue",
            insertText: '"Revenue"',
            documentation: "Plain metadata text",
            kind: "field",
          },
        ]}
      />,
    );
    await waitFor(() =>
      expect(fake.monaco.editor.create).toHaveBeenCalledOnce(),
    );
    await waitFor(() =>
      expect(screen.queryByRole("status")).not.toBeInTheDocument(),
    );
    act(() => fake.models[0].type("xy"));
    rerender(
      <PythonRuleEditor
        value="xy"
        onChange={vi.fn()}
        completions={[
          { label: "Expense", insertText: '"Expense"', kind: "field" },
        ]}
      />,
    );
    expect(fake.models[0].setValue).not.toHaveBeenCalled();
    expect(suggestions(fake)).toMatchObject({
      suggestions: [{ label: "Expense", insertText: '"Expense"' }],
    });
    expect(suggestions(fake, {} as never)).toEqual({ suggestions: [] });
    rerender(<PythonRuleEditor value="xy" onChange={vi.fn()} readOnly />);
    expect(suggestions(fake)).toEqual({ suggestions: [] });
    expect(fake.view.updateOptions).toHaveBeenLastCalledWith(
      expect.objectContaining({ readOnly: true, domReadOnly: true }),
    );
  });

  it("shows source-bound diagnostics without spans as plain text, including path and hint", async () => {
    const fake = runtime();
    vi.mocked(loadPythonEditor).mockResolvedValue(fake.loaded);
    const details = await diagnostics("x");
    details.diagnostics = [
      {
        code: "UNKNOWN_FIELD",
        severity: "error",
        stage: "metadata",
        message: "Unknown field",
        path: "arguments.fieldId",
        hint: '<img src="https://example.invalid/tracker">',
      },
    ];
    const { container } = render(
      <PythonRuleEditor value="x" onChange={vi.fn()} diagnostics={details} />,
    );
    expect(await screen.findByText("arguments.fieldId")).toBeInTheDocument();
    expect(screen.getByText(details.diagnostics[0].hint!)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    expect(fake.monaco.editor.setModelMarkers).toHaveBeenLastCalledWith(
      fake.models[0],
      "openepm-python-validation",
      [],
    );
  });

  it("ignores out-of-order source hashing and never revives markers from an older source", async () => {
    const fake = runtime();
    vi.mocked(loadPythonEditor).mockResolvedValue(fake.loaded);
    const pending = new Map<string, (digest: string) => void>();
    vi.spyOn(contract, "pythonSourceDigest").mockImplementation(
      (source) =>
        new Promise((resolve) => {
          pending.set(source, resolve);
        }),
    );
    const details: PythonDiagnostics = {
      format: "openepm-diagnostics-v1",
      positionEncoding: "utf-16",
      sourceDigest: "b".repeat(64),
      truncated: false,
      diagnostics: [],
    };
    const { rerender } = render(
      <PythonRuleEditor value="a" onChange={vi.fn()} diagnostics={details} />,
    );
    await waitFor(() => expect(fake.models).toHaveLength(1));
    rerender(
      <PythonRuleEditor value="b" onChange={vi.fn()} diagnostics={details} />,
    );
    await act(async () => {
      pending.get("b")!("b".repeat(64));
    });
    expect(
      screen.getByText("No diagnostics for this source."),
    ).toBeInTheDocument();
    await act(async () => {
      pending.get("a")!("a".repeat(64));
    });
    expect(
      screen.getByText("No diagnostics for this source."),
    ).toBeInTheDocument();
  });

  it("disposes model, editor, completion provider and change subscription on unmount", async () => {
    const fake = runtime();
    vi.mocked(loadPythonEditor).mockResolvedValue(fake.loaded);
    const { unmount } = render(
      <PythonRuleEditor value="x" onChange={vi.fn()} />,
    );
    await waitFor(() => expect(fake.models).toHaveLength(1));
    unmount();
    expect(fake.models[0].dispose).toHaveBeenCalledOnce();
    expect(fake.models[0].contentDispose).toHaveBeenCalledOnce();
    expect(fake.view.dispose).toHaveBeenCalledOnce();
    expect(fake.providerDisposals[0]).toHaveBeenCalledOnce();
  });

  it("does not create an editor after unmount while its module is loading", async () => {
    const fake = runtime();
    let resolve!: (value: Loaded) => void;
    vi.mocked(loadPythonEditor).mockReturnValue(
      new Promise((done) => {
        resolve = done;
      }),
    );
    const { unmount } = render(
      <PythonRuleEditor value="x" onChange={vi.fn()} />,
    );
    unmount();
    await act(async () => resolve(fake.loaded));
    expect(fake.monaco.editor.createModel).not.toHaveBeenCalled();
  });

  it("keeps source accessible after load failure and retries without losing controlled source", async () => {
    const fake = runtime();
    fake.monaco.editor.create.mockImplementationOnce(() => {
      throw new Error("failed");
    });
    vi.mocked(loadPythonEditor).mockResolvedValue(fake.loaded);
    render(<PythonRuleEditor value="saved source" onChange={vi.fn()} />);
    expect(
      await screen.findByRole("textbox", {
        name: "Python rule source",
      }),
    ).toHaveValue("saved source");
    expect(screen.getByRole("alert")).toHaveTextContent(
      "source remains available below",
    );
    expect(fake.models[0].dispose).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole("button", { name: "Retry editor" }));
    await waitFor(() =>
      expect(fake.monaco.editor.create).toHaveBeenCalledTimes(2),
    );
    expect(fake.models[1].getValue()).toBe("saved source");
  });
});

describe("Python diagnostic positions", () => {
  it("uses UTF-16 columns and rejects reversed or out-of-source ranges", () => {
    expect(
      contract.diagnosticSpan("😀x", {
        startLine: 1,
        startColumn: 3,
        endLine: 1,
        endColumn: 4,
      }),
    ).toEqual({
      startLineNumber: 1,
      startColumn: 3,
      endLineNumber: 1,
      endColumn: 4,
    });
    for (const span of [
      { startLine: 0, startColumn: 1, endLine: 1, endColumn: 2 },
      { startLine: 1, startColumn: 3, endLine: 1, endColumn: 2 },
      { startLine: 1, startColumn: 1, endLine: 2, endColumn: 1 },
      { startLine: 1, startColumn: 1, endLine: 1, endColumn: 5 },
    ])
      expect(contract.diagnosticSpan("😀x", span)).toBeUndefined();
  });
});
