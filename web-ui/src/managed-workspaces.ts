import { useCallback, useEffect, useState } from "react";
import { request } from "./api";
import type { ApplicationCatalog } from "./types";

type Workspace = { workspaceId: string; workspaceName: string };
type Management = {
  workspaceId: string;
  functions: string[];
  applicationBlueprint?: ApplicationCatalog["applicationBlueprint"];
};
export function useManagedWorkspaces(
  owner: string,
  discover: boolean,
  preferred: string,
  applicationWorkspace: string,
) {
  const [requested, setRequested] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [listing, setListing] = useState<{
    owner: string;
    workspaces: Workspace[];
  } | null>(null);
  const [catalog, setCatalog] = useState<{
    owner: string;
    value: Management;
  } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [catalogBusy, setCatalogBusy] = useState(false);
  const workspaces = listing?.owner === owner ? listing.workspaces : [];
  const id =
    preferred || applicationWorkspace || workspaces[0]?.workspaceId || "";
  const needsSeparate = Boolean(
    id && (id !== applicationWorkspace || !applicationWorkspace),
  );
  const chosen = workspaces.some((w) => w.workspaceId === id);
  const current =
    catalog?.owner === owner && catalog.value.workspaceId === id
      ? catalog.value
      : null;
  const refresh = useCallback(() => {
    setRequested(true);
    setAttempt((n) => n + 1);
  }, []);
  useEffect(() => {
    if (!discover && !requested && !preferred) return;
    const c = new AbortController();
    setListing(null);
    setCatalog(null);
    setError("");
    setBusy(true);
    async function load() {
      const all: Workspace[] = [];
      const seen = new Set<string>();
      const cursors = new Set<string>();
      let after: string | null = null;
      do {
        const suffix = after ? "&after=" + encodeURIComponent(after) : "";
        const p: { workspaces: Workspace[]; nextAfter: string | null } =
          await request(
            "/api/applications?view=managedWorkspaces" + suffix,
            undefined,
            c.signal,
          );
        if (
          !p ||
          !Array.isArray(p.workspaces) ||
          p.workspaces.length > 100 ||
          !p.workspaces.every(
            (w) =>
              w &&
              typeof w.workspaceId === "string" &&
              w.workspaceId.length > 0 &&
              typeof w.workspaceName === "string",
          ) ||
          (p.nextAfter !== null &&
            (!p.workspaces.length ||
              typeof p.nextAfter !== "string" ||
              !p.nextAfter.length ||
              p.nextAfter.length > 8192 ||
              cursors.has(p.nextAfter)))
        )
          throw new Error("Invalid workspace page");
        for (const w of p.workspaces) {
          if (seen.has(w.workspaceId)) throw new Error("Repeated workspace");
          seen.add(w.workspaceId);
          all.push(w);
        }
        if (all.length > 10000) throw new Error("Workspace capacity exceeded");
        after = p.nextAfter;
        if (after) cursors.add(after);
      } while (after);
      if (!c.signal.aborted) {
        setListing({ owner, workspaces: all });
        setBusy(false);
      }
    }
    void load().catch(() => {
      if (!c.signal.aborted) {
        setError("Managed workspaces are unavailable. Refresh to retry.");
        setBusy(false);
      }
    });
    return () => c.abort();
  }, [owner, discover, requested, preferred, attempt]);
  useEffect(() => {
    setCatalog(null);
    setCatalogBusy(false);
    if (!needsSeparate || !chosen) return;
    const c = new AbortController();
    setCatalogBusy(true);
    void request<Management>(
      "/api/workspace-catalog",
      { workspaceId: id },
      c.signal,
    )
      .then((p) => {
        if (c.signal.aborted) return;
        if (
          !p ||
          p.workspaceId !== id ||
          !Array.isArray(p.functions) ||
          !p.functions.every((f) => typeof f === "string") ||
          (p.applicationBlueprint != null &&
            (!Array.isArray(p.applicationBlueprint.dimensions) ||
              !p.applicationBlueprint.dimensions.every(
                (d) =>
                  d &&
                  typeof d.name === "string" &&
                  typeof d.dimensionId === "string",
              )))
        )
          throw new Error("Invalid workspace authority");
        setCatalog({ owner, value: p });
        setError("");
        setCatalogBusy(false);
      })
      .catch(() => {
        if (!c.signal.aborted) {
          setError(
            "Workspace management is unavailable. Refresh to recheck access.",
          );
          setCatalogBusy(false);
        }
      });
    return () => c.abort();
  }, [owner, chosen, id, needsSeparate, attempt]);
  return {
    workspaces,
    id,
    management: current,
    refresh,
    busy: busy || catalogBusy,
    error,
    missing: Boolean(
      preferred &&
        listing?.owner === owner &&
        !chosen &&
        preferred !== applicationWorkspace,
    ),
  };
}
