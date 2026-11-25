import { useEffect, useMemo, useRef, useState } from "react";
import { request } from "./api";
import { mergeTaskListPage, taskListBody } from "./task-list";
import type { TaskListPage, TaskListRow } from "./task-list";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";

export type NavigationTarget = {
  id: string;
  label: string;
};

const focusableSelector = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function usePanelKeyboard(
  open: boolean,
  close: () => void,
  panel: React.RefObject<HTMLElement | null>,
  trapFocus: boolean,
) {
  const trigger = useRef<HTMLElement | null>(null);
  const closeRef = useRef(close);
  closeRef.current = close;
  if (
    open &&
    trigger.current === null &&
    document.activeElement instanceof HTMLElement
  )
    trigger.current = document.activeElement;
  useEffect(() => {
    if (!open) return;
    const keyboard = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeRef.current();
        return;
      }
      if (event.key !== "Tab" || !trapFocus || !panel.current) return;
      const controls = Array.from(
        panel.current.querySelectorAll<HTMLElement>(focusableSelector),
      ).filter((control) => !control.hidden);
      if (!controls.length) return;
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", keyboard);
    return () => {
      window.removeEventListener("keydown", keyboard);
      if (document.activeElement === document.body) trigger.current?.focus();
      trigger.current = null;
    };
  }, [open, panel, trapFocus]);
}

export function GlobalSearch({
  open,
  close,
  applications,
  selectedApplication,
  targets,
  catalog,
  go,
  chooseApplication,
}: {
  open: boolean;
  close: () => void;
  applications: ApplicationSummary[];
  selectedApplication?: ApplicationSummary;
  targets: NavigationTarget[];
  catalog: ApplicationCatalog | null;
  go: (id: string) => void;
  chooseApplication: (index: number) => void;
}) {
  const [query, setQuery] = useState("");
  const panel = useRef<HTMLElement>(null);
  usePanelKeyboard(open, close, panel, true);
  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  const normalized = query.trim().toLocaleLowerCase();
  const applicationResults = applications
    .map((app, index) => ({ app, index }))
    .filter(({ app }) =>
      [app.name, app.workspaceId, app.applicationId].some((value) =>
        value.toLocaleLowerCase().includes(normalized),
      ),
    );
  const navigationResults = targets.filter((item) =>
    item.label.toLocaleLowerCase().includes(normalized),
  );
  const functionResults = Object.keys(catalog?.functions || {})
    .filter((name) => name.toLocaleLowerCase().includes(normalized))
    .slice(0, 12);
  const noMatches =
    normalized.length > 0 &&
    !applicationResults.length &&
    !navigationResults.length &&
    !functionResults.length;

  if (!open) return null;
  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={close}>
      <section
        ref={panel}
        id="global-search-panel"
        className="global-panel search-panel"
        role="dialog"
        aria-modal="true"
        aria-label="Search Open EPM"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header>
          <div>
            <small>GLOBAL SEARCH</small>
            <h2>Find applications and work</h2>
          </div>
          <button aria-label="Close search" onClick={close}>
            ×
          </button>
        </header>
        <label className="search-input">
          <span aria-hidden="true">⌕</span>
          <input
            aria-label="Search applications, pages or authorized functions"
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search applications, pages or authorized functions"
          />
        </label>
        <div role="status" className={noMatches ? "empty-state" : undefined}>
          {noMatches ? "No accessible result matches your search." : ""}
        </div>
        {!normalized ? (
          <p className="panel-hint">
            Type to search within your accessible applications and current
            authorized catalogue.
          </p>
        ) : !noMatches ? (
          <div className="search-results">
            {applicationResults.length > 0 && (
              <ResultGroup title="Applications">
                {applicationResults.map(({ app, index }) => (
                  <button
                    key={`${app.workspaceId}/${app.applicationId}`}
                    onClick={() => {
                      chooseApplication(index);
                      close();
                    }}
                  >
                    <span className="result-icon">{app.name.slice(0, 1)}</span>
                    <span>
                      <strong>{app.name}</strong>
                      <small>{app.status}</small>
                    </span>
                  </button>
                ))}
              </ResultGroup>
            )}
            {navigationResults.length > 0 && (
              <ResultGroup title="Destinations">
                {navigationResults.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => {
                      go(item.id);
                      close();
                    }}
                  >
                    <span className="result-icon">→</span>
                    <span>
                      <strong>{item.label}</strong>
                      <small>{selectedApplication?.name || "Workspace"}</small>
                    </span>
                  </button>
                ))}
              </ResultGroup>
            )}
            {functionResults.length > 0 && (
              <ResultGroup title="Authorized functions">
                {functionResults.map((name) => (
                  <div className="function-result" key={name}>
                    <span className="result-icon">ƒ</span>
                    <code>{name}</code>
                  </div>
                ))}
              </ResultGroup>
            )}
          </div>
        ) : null}
      </section>
    </div>
  );
}

function ResultGroup({
  title,
  children,
}: React.PropsWithChildren<{ title: string }>) {
  return (
    <section className="result-group">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

type TaskNotice = TaskListRow & { sourceFamily: string };
type NotificationResult =
  | { scope: Scope; state: "ready"; notices: TaskNotice[] }
  | { scope: Scope; state: "error" };

export function Notifications({
  open,
  close,
  app,
  goMonitor,
}: {
  open: boolean;
  close: () => void;
  app?: ApplicationSummary;
  goMonitor: () => void;
}) {
  const workspaceId = app?.workspaceId;
  const applicationId = app?.applicationId;
  const scope = useMemo(
    () =>
      open && workspaceId && applicationId
        ? { workspaceId, applicationId }
        : null,
    [open, workspaceId, applicationId],
  );
  const [result, setResult] = useState<NotificationResult | null>(null);
  const panel = useRef<HTMLElement>(null);
  usePanelKeyboard(open, close, panel, false);
  useEffect(() => {
    if (!scope) return;
    const controller = new AbortController();
    const { signal } = controller;
    request<TaskListPage<TaskNotice>>(
      "/api/tasks",
      taskListBody(scope, 0, true),
      signal,
    )
      .then((value) => {
        if (signal.aborted) return;
        const { tasks } = mergeTaskListPage([], value, 0, false);
        if (tasks.some((task) => task.progressState !== "attention"))
          throw new Error("Task attention response is invalid.");
        setResult({ scope, state: "ready", notices: tasks.slice(0, 12) });
      })
      .catch(() => {
        if (!signal.aborted) setResult({ scope, state: "error" });
      });
    return () => controller.abort();
  }, [scope]);
  const current = result?.scope === scope ? result : null;
  if (!open) return null;
  return (
    <section
      ref={panel}
      id="notification-panel"
      className="global-panel notification-panel"
      role="dialog"
      aria-modal="false"
      aria-label="Notifications"
    >
      <header>
        <div>
          <small>NOTIFICATIONS</small>
          <h2>Work needing attention</h2>
        </div>
        <button aria-label="Close notifications" onClick={close}>
          ×
        </button>
      </header>
      {!scope && (
        <p className="panel-hint">
          Choose an application to see its notifications.
        </p>
      )}
      {scope && !current && (
        <p className="panel-hint" role="status">
          Reading task status…
        </p>
      )}
      {current?.state === "error" && (
        <div className="inline-error" role="alert">
          Notifications could not be loaded. Reopen this panel to try again.
        </div>
      )}
      {current?.state === "ready" && !current.notices.length && (
        <div className="empty-state">
          <strong>No task currently needs attention</strong>
        </div>
      )}
      {current?.state === "ready" && current.notices.length > 0 && (
        <div className="notice-list">
          {current.notices.map((task) => (
            <article key={task.taskId}>
              <span className="task-state attention">{task.status}</span>
              <strong>{task.function}</strong>
              <small>{task.sourceFamily}</small>
            </article>
          ))}
        </div>
      )}
      {scope && (
        <button
          className="primary-link panel-action"
          onClick={() => {
            goMonitor();
            close();
          }}
        >
          Open Monitor →
        </button>
      )}
    </section>
  );
}

export function HelpPanel({
  open,
  close,
}: {
  open: boolean;
  close: () => void;
}) {
  const panel = useRef<HTMLElement>(null);
  usePanelKeyboard(open, close, panel, true);
  if (!open) return null;
  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={close}>
      <section
        ref={panel}
        id="keyboard-help-panel"
        className="global-panel help-panel"
        role="dialog"
        aria-modal="true"
        aria-label="Keyboard help"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header>
          <div>
            <small>KEYBOARD HELP</small>
            <h2>Move through Open EPM efficiently</h2>
          </div>
          <button autoFocus aria-label="Close keyboard help" onClick={close}>
            ×
          </button>
        </header>
        <div className="shortcut-groups">
          <section>
            <h3>Anywhere</h3>
            <dl>
              <div>
                <dt>Search applications and authorized work</dt>
                <dd>
                  <kbd>Ctrl</kbd>/<kbd>⌘</kbd> + <kbd>K</kbd>
                </dd>
              </div>
              <div>
                <dt>Open this keyboard help</dt>
                <dd>
                  <kbd>?</kbd>
                </dd>
              </div>
              <div>
                <dt>Close the active panel or drawer</dt>
                <dd>
                  <kbd>Esc</kbd>
                </dd>
              </div>
              <div>
                <dt>Move through controls</dt>
                <dd>
                  <kbd>Tab</kbd> / <kbd>Shift</kbd> + <kbd>Tab</kbd>
                </dd>
              </div>
            </dl>
          </section>
          <section>
            <h3>Analyze grid</h3>
            <dl>
              <div>
                <dt>Move between visible cells</dt>
                <dd>
                  <kbd>↑</kbd> <kbd>↓</kbd> <kbd>←</kbd> <kbd>→</kbd>
                </dd>
              </div>
              <div>
                <dt>First or last cell in the row</dt>
                <dd>
                  <kbd>Home</kbd> / <kbd>End</kbd>
                </dd>
              </div>
              <div>
                <dt>Open the selected cell</dt>
                <dd>
                  <kbd>Enter</kbd>
                </dd>
              </div>
            </dl>
          </section>
        </div>
        <p className="panel-hint">
          Shortcuts never bypass review, authorization, validation or durable
          publication. When focus is inside a text field, typing remains with
          that field.
        </p>
      </section>
    </div>
  );
}
