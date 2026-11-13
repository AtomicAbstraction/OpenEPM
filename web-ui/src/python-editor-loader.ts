let loading: Promise<typeof import("./python-editor-runtime")> | undefined;

export function loadPythonEditor() {
  loading ??= import("./python-editor-runtime").catch((error: unknown) => {
    loading = undefined;
    throw error;
  });
  return loading;
}
