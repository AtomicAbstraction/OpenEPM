export type PythonDiagnosticSpan = {
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
};
export type PythonDiagnostic = {
  code: string;
  severity: "error" | "warning" | "info";
  stage: string;
  message: string;
  span?: PythonDiagnosticSpan;
  path?: string;
  hint?: string;
};
export type PythonDiagnostics = {
  format: "openepm-diagnostics-v1";
  sourceDigest: string;
  positionEncoding: "utf-16";
  truncated: boolean;
  diagnostics: PythonDiagnostic[];
};
export type PythonCompletionDescriptor = {
  label: string;
  insertText: string;
  detail?: string;
  documentation?: string;
  referenceUrl?: string;
  kind?: "function" | "variable" | "field" | "class" | "value";
};

export async function pythonSourceDigest(source: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(source),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

/** Positions are one-based UTF-16 code units, with an exclusive end. */
export function diagnosticSpan(source: string, span?: PythonDiagnosticSpan) {
  if (
    !span ||
    !Object.values(span).every(
      (value) => Number.isSafeInteger(value) && value > 0,
    )
  )
    return undefined;
  const lines = source.split(/\r\n|\r|\n/);
  if (
    span.startLine > lines.length ||
    span.endLine > lines.length ||
    span.endLine < span.startLine ||
    (span.endLine === span.startLine && span.endColumn <= span.startColumn) ||
    span.startColumn > lines[span.startLine - 1].length + 1 ||
    span.endColumn > lines[span.endLine - 1].length + 1
  )
    return undefined;
  return {
    startLineNumber: span.startLine,
    startColumn: span.startColumn,
    endLineNumber: span.endLine,
    endColumn: span.endColumn,
  };
}
