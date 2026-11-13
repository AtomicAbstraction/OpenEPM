import { useEffect, useId, useRef, useState } from "react";
import type { editor, languages } from "monaco-editor/editor/editor.api.js";
import { loadPythonEditor } from "./python-editor-loader";
import { diagnosticSpan, pythonSourceDigest } from "./python-editor-contract";
import type {
  PythonCompletionDescriptor,
  PythonDiagnostics,
} from "./python-editor-contract";
import "./python-rule-editor.css";

export type {
  PythonCompletionDescriptor,
  PythonDiagnostic,
  PythonDiagnostics,
  PythonDiagnosticSpan,
} from "./python-editor-contract";
export type PythonRuleEditorProps = {
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
  diagnostics?: PythonDiagnostics | null;
  completions?: readonly PythonCompletionDescriptor[];
  ariaLabel?: string;
  height?: number;
};
type Runtime = Awaited<ReturnType<typeof loadPythonEditor>>["monaco"];
type ActiveEditor = {
  monaco: Runtime;
  model: editor.ITextModel;
  view: editor.IStandaloneCodeEditor;
};
const MARKER_OWNER = "openepm-python-validation";
const NO_COMPLETIONS: readonly PythonCompletionDescriptor[] = [];

/** Presentation only. Validation and publication remain server operations. */
export function PythonRuleEditor({
  value,
  onChange,
  readOnly = false,
  diagnostics,
  completions = NO_COMPLETIONS,
  ariaLabel = "Python rule source",
  height = 400,
}: PythonRuleEditorProps) {
  const id = useId();
  const host = useRef<HTMLDivElement>(null);
  const active = useRef<ActiveEditor | null>(null);
  const current = useRef({ value, onChange, readOnly, completions, ariaLabel });
  current.current = { value, onChange, readOnly, completions, ariaLabel };
  const [source, setSource] = useState(value);
  const [digest, setDigest] = useState<{
    source: string;
    sha256: string;
  } | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "failed">("loading");
  const [attempt, setAttempt] = useState(0);
  const matched =
    diagnostics?.format === "openepm-diagnostics-v1" &&
    diagnostics.positionEncoding === "utf-16" &&
    digest?.source === source &&
    digest.sha256 === diagnostics.sourceDigest;

  useEffect(() => {
    let cancelled = false;
    const disposals: Array<() => void> = [];
    const dispose = () => {
      for (const release of disposals.splice(0).reverse()) release();
    };
    setState("loading");
    void loadPythonEditor()
      .then(({ monaco }) => {
        if (cancelled || !host.current) return;
        const model = monaco.editor.createModel(
          current.current.value,
          "python",
          monaco.Uri.parse(
            `inmemory://openepm-python/${encodeURIComponent(id)}.py`,
          ),
        );
        disposals.push(() => model.dispose());
        const view = monaco.editor.create(host.current, {
          model,
          ariaLabel: current.current.ariaLabel,
          readOnly: current.current.readOnly,
          domReadOnly: current.current.readOnly,
          // Native EditContext omits read-only semantics from Chrome's AX tree.
          // Monaco's supported textarea path exposes the native readonly state.
          editContext: false,
          automaticLayout: true,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          tabSize: 4,
          insertSpaces: true,
          fontSize: 13,
          lineNumbers: "on",
          wordWrap: "off",
          links: false,
          renderRichScreenReaderContent: false,
          stickyScroll: { enabled: false },
          wordBasedSuggestions: "currentDocument",
          quickSuggestions: { other: true, comments: false, strings: false },
        });
        disposals.push(() => view.dispose());
        active.current = { monaco, model, view };
        disposals.push(() => {
          monaco.editor.setModelMarkers(model, MARKER_OWNER, []);
          active.current = null;
        });
        setSource(model.getValue());
        const edits = model.onDidChangeContent(() => {
          monaco.editor.setModelMarkers(model, MARKER_OWNER, []);
          const next = model.getValue();
          setSource(next);
          if (next !== current.current.value) current.current.onChange(next);
        });
        disposals.push(() => edits.dispose());
        const provider = monaco.languages.registerCompletionItemProvider(
          "python",
          {
            provideCompletionItems(candidate, position) {
              // Monaco providers are global; each editor owns only its own model.
              if (candidate !== model || current.current.readOnly)
                return { suggestions: [] };
              const word = model.getWordUntilPosition(position);
              const prefix = word.word.toLowerCase();
              const descriptors = current.current.completions.filter((item) =>
                item.label.toLowerCase().startsWith(prefix),
              );
              const kinds: Record<
                NonNullable<PythonCompletionDescriptor["kind"]>,
                languages.CompletionItemKind
              > = {
                function: monaco.languages.CompletionItemKind.Function,
                variable: monaco.languages.CompletionItemKind.Variable,
                field: monaco.languages.CompletionItemKind.Field,
                class: monaco.languages.CompletionItemKind.Class,
                value: monaco.languages.CompletionItemKind.Value,
              };
              return {
                incomplete: descriptors.length > 200,
                suggestions: descriptors.slice(0, 200).map((item) => ({
                  label: item.label,
                  insertText: item.insertText,
                  detail: item.detail,
                  documentation: item.referenceUrl
                    ? {
                        value: `${item.documentation || item.detail || item.label}\n\n[Open reference](${item.referenceUrl})`,
                        isTrusted: false,
                      }
                    : item.documentation,
                  kind: kinds[item.kind ?? "value"],
                  range: {
                    startLineNumber: position.lineNumber,
                    endLineNumber: position.lineNumber,
                    startColumn: word.startColumn,
                    endColumn: word.endColumn,
                  },
                })),
              };
            },
          },
        );
        disposals.push(() => provider.dispose());
        setState("ready");
      })
      .catch(() => {
        dispose();
        if (!cancelled) setState("failed");
      });
    return () => {
      cancelled = true;
      dispose();
    };
  }, [id, attempt]);

  useEffect(() => {
    const currentEditor = active.current;
    if (!currentEditor) return;
    const externalValue = current.current.value;
    // Parent echoes must not reset the model, selection, or undo history.
    // Read the latest prop through the ref: an older passive-effect closure
    // may run after Monaco has accepted a user edit and a newer parent echo.
    if (currentEditor.model.getValue() !== externalValue) {
      currentEditor.monaco.editor.setModelMarkers(
        currentEditor.model,
        MARKER_OWNER,
        [],
      );
      currentEditor.model.setValue(externalValue);
    }
    setSource(currentEditor.model.getValue());
  }, [value, state]);
  useEffect(() => {
    active.current?.view.updateOptions({
      readOnly,
      domReadOnly: readOnly,
      ariaLabel,
    });
  }, [readOnly, ariaLabel, state]);
  useEffect(() => {
    let cancelled = false;
    setDigest(null);
    void pythonSourceDigest(source)
      .then((sha256) => {
        if (!cancelled) setDigest({ source, sha256 });
      })
      .catch(() => {
        if (!cancelled) setDigest(null);
      });
    return () => {
      cancelled = true;
    };
  }, [source]);
  useEffect(() => {
    const currentEditor = active.current;
    if (!currentEditor) return;
    const { monaco, model } = currentEditor;
    const markers: editor.IMarkerData[] = [];
    if (matched && diagnostics && model.getValue() === source) {
      for (const diagnostic of diagnostics.diagnostics) {
        const range = diagnosticSpan(source, diagnostic.span);
        if (range)
          markers.push({
            ...range,
            code: diagnostic.code,
            message:
              diagnostic.message +
              (diagnostic.hint ? `\n${diagnostic.hint}` : ""),
            source: diagnostic.stage,
            severity:
              diagnostic.severity === "error"
                ? monaco.MarkerSeverity.Error
                : diagnostic.severity === "warning"
                  ? monaco.MarkerSeverity.Warning
                  : monaco.MarkerSeverity.Info,
          });
      }
    }
    monaco.editor.setModelMarkers(model, MARKER_OWNER, markers);
  }, [diagnostics, matched, source, state]);

  return (
    <div className="python-rule-editor">
      <div
        ref={host}
        className="python-rule-editor__canvas"
        hidden={state === "failed"}
        style={{ height }}
      />
      {state === "loading" && <p role="status">Loading Python editor…</p>}
      {state === "failed" && (
        <div className="python-rule-editor__fallback">
          <div role="alert">
            The enhanced Python editor could not load. The source remains
            available below.
            <button
              type="button"
              onClick={() => setAttempt((number) => number + 1)}
            >
              Retry editor
            </button>
          </div>
          <textarea
            aria-label={ariaLabel}
            readOnly={readOnly}
            spellCheck={false}
            value={value}
            onChange={(event) => onChange(event.currentTarget.value)}
            style={{ minHeight: height }}
          />
        </div>
      )}
      {diagnostics && (
        <section
          aria-label="Python diagnostics"
          className="python-rule-editor__diagnostics"
        >
          {!matched ? (
            <p role="status">
              Diagnostics do not match the current source. Validate to refresh.
            </p>
          ) : (
            <>
              <p>
                {diagnostics.diagnostics.length === 0
                  ? "No diagnostics for this source."
                  : `${diagnostics.diagnostics.length} diagnostic${diagnostics.diagnostics.length === 1 ? "" : "s"}`}
                {diagnostics.truncated &&
                  " — More diagnostics were omitted by the validator."}
              </p>
              {diagnostics.diagnostics.length > 0 && (
                <ul>
                  {diagnostics.diagnostics.map((diagnostic, index) => {
                    const range = diagnosticSpan(source, diagnostic.span);
                    const text = `${diagnostic.severity}: ${diagnostic.message} (${diagnostic.code})`;
                    return (
                      <li key={`${diagnostic.code}-${index}`}>
                        {range ? (
                          <button
                            type="button"
                            disabled={state !== "ready"}
                            onClick={() => {
                              active.current?.view.setSelection(range);
                              active.current?.view.revealRangeInCenter(range);
                              active.current?.view.focus();
                            }}
                          >
                            {text} · Line {range.startLineNumber}, column{" "}
                            {range.startColumn}
                          </button>
                        ) : (
                          <span>{text}</span>
                        )}
                        {diagnostic.path && (
                          <div>
                            Path: <code>{diagnostic.path}</code>
                          </div>
                        )}
                        {diagnostic.hint && <div>{diagnostic.hint}</div>}
                      </li>
                    );
                  })}
                </ul>
              )}
            </>
          )}
        </section>
      )}
    </div>
  );
}
