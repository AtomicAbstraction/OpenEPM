import { useEffect, useLayoutEffect, useRef, useState } from "react";

export function gridCoordinateKey(members: Record<string, string>, kind = "") {
  return JSON.stringify([Object.entries(members).sort(), kind]);
}

// Native focus scrolling does not account for the sticky row/column headers.
function exposeCell(cell: HTMLButtonElement) {
  const scroll = cell.closest<HTMLElement>(".analytical-grid-scroll");
  const table = cell.closest("table");
  if (!scroll || !table) return;
  const viewport = scroll.getBoundingClientRect();
  const bounds = cell.getBoundingClientRect();
  const rowHeader = cell.closest("tr")?.querySelector("th:first-child");
  const stickyWidth =
    rowHeader && getComputedStyle(rowHeader).position === "sticky"
      ? rowHeader.getBoundingClientRect().width
      : 0;
  const header = table.tHead?.querySelector("th");
  const stickyHeight =
    header && getComputedStyle(header).top !== "auto"
      ? table.tHead?.getBoundingClientRect().height || 0
      : 0;
  const left = viewport.left + stickyWidth + 3;
  const right = viewport.right - 3;
  const top = viewport.top + stickyHeight + 3;
  const bottom = viewport.bottom - 3;
  if (bounds.left < left) scroll.scrollLeft += bounds.left - left;
  else if (bounds.right > right)
    scroll.scrollLeft += Math.min(bounds.right - right, bounds.left - left);
  if (bounds.top < top) scroll.scrollTop += bounds.top - top;
  else if (bounds.bottom > bottom)
    scroll.scrollTop += Math.min(bounds.bottom - bottom, bounds.top - top);
}

type FocusRequest = {
  context: string;
  trigger: HTMLElement;
  kind: "read" | "mutation";
  ready: boolean;
};

/** Presentation focus only. Coordinates, read authority and mutation outcomes
 * remain owned by Analyze and the existing exact mutation controller. */
export function useGridFocus(
  context: string,
  keys: string[][],
  busy: boolean,
  hasRecovery: boolean,
  blocked: boolean,
) {
  const root = useRef<HTMLDivElement>(null);
  const currentContext = useRef(context);
  currentContext.current = context;
  const interactionBlocked = useRef(blocked);
  interactionBlocked.current = blocked;
  const pending = useRef<FocusRequest | null>(null);
  const interacted = useRef(false);
  const recoveryPresented = useRef(false);
  const [completion, setCompletion] = useState(0);
  const [announcement, setAnnouncement] = useState<{
    context: string;
    label: string;
  } | null>(null);
  const [active, setActive] = useState<{
    context: string;
    key: string;
    row: number;
    column: number;
  } | null>(null);
  let row = 0;
  let column = 0;
  if (active?.context === context && keys.length) {
    row = keys.findIndex((line) => line.includes(active.key));
    if (row >= 0) column = keys[row].indexOf(active.key);
    else {
      row = Math.min(active.row, keys.length - 1);
      column = Math.min(active.column, keys[row].length - 1);
    }
  }
  const key = keys[row]?.[column];

  useEffect(() => {
    if (blocked || busy) setAnnouncement(null);
  }, [blocked, busy]);

  useEffect(() => {
    // Ignore focus dropped onto BODY by disabled/removed controls. Deliberate
    // navigation or a pointer action cancels restoration, including blank space.
    const focus = (event: FocusEvent) => {
      if (interactionBlocked.current) return;
      if (event.target !== document.body) interacted.current = true;
      if (
        pending.current &&
        event.target !== document.body &&
        event.target !== pending.current.trigger
      )
        pending.current = null;
    };
    const pointer = () => {
      if (interactionBlocked.current) return;
      interacted.current = true;
      pending.current = null;
    };
    const keyboard = (event: globalThis.KeyboardEvent) => {
      if (interactionBlocked.current) return;
      interacted.current = true;
      if (
        [
          "Tab",
          "Escape",
          "ArrowUp",
          "ArrowDown",
          "ArrowLeft",
          "ArrowRight",
          "Home",
          "End",
        ].includes(event.key)
      )
        pending.current = null;
    };
    document.addEventListener("focusin", focus);
    document.addEventListener("pointerdown", pointer);
    document.addEventListener("keydown", keyboard);
    return () => {
      pending.current = null;
      document.removeEventListener("focusin", focus);
      document.removeEventListener("pointerdown", pointer);
      document.removeEventListener("keydown", keyboard);
    };
  }, []);

  useLayoutEffect(() => {
    if (blocked) {
      pending.current = null;
      interacted.current = false;
      recoveryPresented.current = false;
      return;
    }
    if (!busy && key && (active?.key !== key || active.context !== context))
      setActive({ context, key, row, column });
    const request = pending.current;
    if (!request) {
      // Current-owner hydration or removal of the App's inert connection guard
      // may expose recovery. Offer it only when nothing else has taken focus.
      if (hasRecovery && !busy && !recoveryPresented.current) {
        recoveryPresented.current = true;
        if (!interacted.current && document.activeElement === document.body)
          root.current
            ?.querySelector<HTMLElement>("[data-grid-focus-outcome]")
            ?.focus();
      }
      return;
    }
    if (request.context !== context) {
      pending.current = null;
      return;
    }
    if (busy || !request.ready) return;
    pending.current = null;
    if (
      document.activeElement !== document.body &&
      document.activeElement !== request.trigger
    )
      return;
    const error = root.current?.querySelector<HTMLElement>(
      `[data-grid-focus-error="${request.kind}"]`,
    );
    const outcome =
      request.kind === "mutation"
        ? root.current?.querySelector<HTMLElement>("[data-grid-focus-outcome]")
        : null;
    const cell = root.current?.querySelector<HTMLButtonElement>(
      `[data-grid-row="${row}"][data-grid-column="${column}"]`,
    );
    const triggerUsable =
      request.trigger.isConnected &&
      !request.trigger.matches(":disabled") &&
      !request.trigger.hasAttribute("data-grid-row");
    const target =
      error ||
      outcome ||
      (cell && triggerUsable ? request.trigger : cell) ||
      root.current?.querySelector<HTMLElement>("[data-grid-focus-status]");
    target?.focus();
  }, [
    context,
    key,
    row,
    column,
    busy,
    completion,
    active,
    hasRecovery,
    blocked,
  ]);

  return {
    root,
    keyboardAnnouncement:
      !blocked && !busy && announcement?.context === context
        ? announcement.label
        : "",
    announceKeyboardPosition: (label: string) =>
      setAnnouncement({ context, label }),
    tabIndex: (atRow: number, atColumn: number) =>
      row === atRow && column === atColumn ? 0 : -1,
    onCellFocus: (cell: HTMLButtonElement, atRow: number, atColumn: number) => {
      const next = keys[atRow]?.[atColumn];
      if (next) setActive({ context, key: next, row: atRow, column: atColumn });
      setAnnouncement(null);
      exposeCell(cell);
    },
    begin: (kind: FocusRequest["kind"] = "read") => {
      if (interactionBlocked.current) return null;
      const trigger = document.activeElement;
      if (!(trigger instanceof HTMLElement) || !root.current?.contains(trigger))
        return null;
      const request = { context, trigger, kind, ready: false };
      pending.current = request;
      return request;
    },
    finish: (request: FocusRequest | null) => {
      if (
        request &&
        pending.current === request &&
        request.context === currentContext.current
      ) {
        request.ready = true;
        setCompletion((value) => value + 1);
      }
    },
  };
}
