import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  ApplicationPurge,
  applicationPurgeRecoveryKey,
} from "./ApplicationPurge";
import { ApiError, request } from "./api";
vi.mock("./api", async (original) => ({
  ...(await original<typeof import("./api")>()),
  request: vi.fn(),
}));
const manifest = {
  workspaceId: "w",
  applicationId: "a",
  name: "Forecast",
  createdAt: "2026-11-08T11:00:00+00:00",
  schemaEpoch: 2,
  status: "Active",
  activeLeases: {},
  rowCounts: { numeric_cell_projection: 42 },
};
const prepared = { manifest, manifestDigest: "d".repeat(64) };
const issuer = "https://identity.example/realm";
const storageKey = applicationPurgeRecoveryKey(issuer, "owner", "w")!;
const deleted = vi.fn().mockResolvedValue(undefined);
function display() {
  return render(
    <ApplicationPurge
      workspaceId="w"
      applicationId="a"
      issuer={issuer}
      subject="owner"
      deleted={deleted}
    />,
  );
}
function open() {
  fireEvent.click(screen.getByText("Delete an application"));
}
beforeEach(() => {
  localStorage.clear();
  deleted.mockClear();
  vi.mocked(request).mockReset();
});
afterEach(() => {
  localStorage.clear();
});

it("shows the exact target and inventory and requires distinct stop and delete actions", async () => {
  vi.mocked(request)
    .mockResolvedValueOnce(prepared)
    .mockResolvedValueOnce({ status: "Deleting" })
    .mockResolvedValueOnce({
      ...prepared,
      manifest: { ...manifest, status: "Deleting" },
    })
    .mockResolvedValueOnce({ status: "Deleted" });
  display();
  open();
  fireEvent.click(screen.getByRole("button", { name: "Inspect application" }));
  expect(await screen.findByText("Forecast (a)")).toBeVisible();
  expect(screen.getByText(/Created 2026-11-08T11:00:00/)).toBeVisible();
  fireEvent.click(
    screen.getByRole("button", { name: "Stop application for deletion" }),
  );
  await waitFor(() => expect(request).toHaveBeenCalledTimes(3));
  expect(deleted).not.toHaveBeenCalled();
  const stored = JSON.parse(localStorage.getItem(storageKey)!);
  expect(stored.program.function).toBe("workspace.application.purge.apply");
  expect(JSON.stringify(stored)).not.toContain("rowCounts");
  expect(JSON.stringify(stored)).not.toContain("Forecast");
  fireEvent.click(screen.getByRole("button", { name: "Delete a permanently" }));
  await waitFor(() => expect(deleted).toHaveBeenCalledWith("w", "a"));
  expect(vi.mocked(request).mock.calls[3][1]).toEqual(stored);
  expect(localStorage.getItem(storageKey)).toBeNull();
  expect(screen.queryByRole("checkbox")).toBeNull();
});

it("retains the same request after interruption and refuses to retarget a replacement", async () => {
  vi.mocked(request)
    .mockResolvedValueOnce(prepared)
    .mockRejectedValueOnce(new Error("Lost response"));
  const first = display();
  open();
  fireEvent.click(screen.getByRole("button", { name: "Inspect application" }));
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Stop application for deletion",
    }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent("Lost response");
  const exact = vi.mocked(request).mock.calls[1][1];
  first.unmount();
  display();
  expect(screen.getByLabelText("Application ID to delete")).toBeDisabled();
  vi.mocked(request).mockResolvedValueOnce({
    ...prepared,
    manifest: { ...manifest, createdAt: "2026-11-09T11:00:00Z" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Inspect application" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "different application",
  );
  vi.mocked(request).mockRejectedValueOnce(
    new Error("Original target unavailable"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Retry stop request" }));
  await waitFor(() => expect(request).toHaveBeenCalledTimes(4));
  expect(vi.mocked(request).mock.calls[3][1]).toEqual(exact);
});

it("shows worker drain and prevents deletion until a fresh inspection reports no leases", async () => {
  vi.mocked(request).mockResolvedValueOnce({
    ...prepared,
    manifest: {
      ...manifest,
      status: "Deleting",
      activeLeases: { "job.lease_until": 2 },
    },
  });
  display();
  open();
  fireEvent.click(screen.getByRole("button", { name: "Inspect application" }));
  expect(
    await screen.findByText(/2 worker leases are still active/),
  ).toBeVisible();
  expect(
    screen.getByRole("button", { name: "Delete a permanently" }),
  ).toBeDisabled();
  vi.mocked(request).mockResolvedValueOnce({
    ...prepared,
    manifest: { ...manifest, status: "Deleting" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh worker status" }),
  );
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Delete a permanently" }),
    ).toBeEnabled(),
  );
  expect(request).toHaveBeenCalledTimes(2);
});

it("reconciles a lost deletion response with the exact persisted request without needing the old app", async () => {
  const exact = {
    workspaceId: "w",
    idempotencyKey: "purge-original-request",
    program: {
      languageVersion: 2,
      function: "workspace.application.purge.apply",
      arguments: { applicationId: "a", createdAt: manifest.createdAt },
    },
  };
  localStorage.setItem(storageKey, JSON.stringify(exact));
  vi.mocked(request).mockResolvedValueOnce({ status: "Deleted" });
  display();
  fireEvent.click(screen.getByRole("button", { name: "Delete a permanently" }));
  await waitFor(() => expect(deleted).toHaveBeenCalledWith("w", "a"));
  expect(vi.mocked(request).mock.calls[0][1]).toEqual(exact);
});

it("clears a provably rejected stale manifest so the owner can inspect again", async () => {
  vi.mocked(request)
    .mockResolvedValueOnce(prepared)
    .mockRejectedValueOnce(
      new ApiError(409, "APPLICATION_PURGE_MANIFEST_STALE"),
    );
  display();
  open();
  fireEvent.click(screen.getByRole("button", { name: "Inspect application" }));
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Stop application for deletion",
    }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "APPLICATION_PURGE_MANIFEST_STALE",
  );
  expect(
    screen.getByRole("button", { name: "Inspect application" }),
  ).toBeEnabled();
  expect(localStorage.getItem(storageKey)).toBeNull();
});
it.each([
  { extra: { inventory: { facts: [1] } } },
  { extra: { workspaceId: "foreign" } },
  { programExtra: { source: "unreplaced source" } },
  { argumentsExtra: { rowCounts: { business: 1 } } },
  { argumentsExtra: { manifestDigest: "invalid" } },
  { argumentsExtra: { createdAt: "not-a-date" } },
])("rejects malformed or foreign persisted retry metadata: %j", (value) => {
  localStorage.setItem(
    storageKey,
    JSON.stringify({
      workspaceId: "w",
      idempotencyKey: "purge-key",
      ...value.extra,
      program: {
        languageVersion: 2,
        function: "workspace.application.purge.apply",
        ...value.programExtra,
        arguments: {
          applicationId: "old-target",
          createdAt: manifest.createdAt,
          ...value.argumentsExtra,
        },
      },
    }),
  );
  display();
  open();
  expect(screen.getByLabelText("Application ID to delete")).toBeEnabled();
  expect(screen.getByLabelText("Application ID to delete")).toHaveValue("a");
  expect(request).not.toHaveBeenCalled();
});

function savedIntent(target: string, key = "purge-original-request") {
  return JSON.stringify({
    workspaceId: "w",
    idempotencyKey: key,
    program: {
      languageVersion: 2,
      function: "workspace.application.purge.apply",
      arguments: { applicationId: target, createdAt: manifest.createdAt },
    },
  });
}

it.each([
  { issuer: "https://other.example/realm", subject: "owner", workspaceId: "w" },
  { issuer, subject: "another-owner", workspaceId: "w" },
  { issuer, subject: "owner", workspaceId: "another-workspace" },
])(
  "never restores another authority, account or workspace intent: %j",
  (identity) => {
    const original = savedIntent("original-secret-target");
    localStorage.setItem(storageKey, original);
    const view = display();
    expect(screen.getByLabelText("Application ID to delete")).toHaveValue(
      "original-secret-target",
    );
    view.rerender(
      <ApplicationPurge
        {...identity}
        applicationId="current"
        deleted={deleted}
      />,
    );
    expect(screen.getByLabelText("Application ID to delete")).toHaveValue(
      "current",
    );
    expect(screen.getByLabelText("Application ID to delete")).toBeEnabled();
    expect(
      screen.queryByText(/original-secret-target/),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /permanently/ }),
    ).not.toBeInTheDocument();
    expect(localStorage.getItem(storageKey)).toBe(original);
    expect(request).not.toHaveBeenCalled();
  },
);

it("keeps each issuer's same-subject retry exact when switching back", () => {
  const otherIssuer = "https://other.example/realm";
  const otherKey = applicationPurgeRecoveryKey(otherIssuer, "owner", "w")!;
  const original = savedIntent("first-authority-target");
  const other = savedIntent("second-authority-target", "second-operation");
  localStorage.setItem(storageKey, original);
  localStorage.setItem(otherKey, other);
  const view = display();
  view.rerender(
    <ApplicationPurge
      workspaceId="w"
      applicationId="a"
      issuer={otherIssuer}
      subject="owner"
      deleted={deleted}
    />,
  );
  expect(screen.getByLabelText("Application ID to delete")).toHaveValue(
    "second-authority-target",
  );
  view.rerender(
    <ApplicationPurge
      workspaceId="w"
      applicationId="a"
      issuer={issuer}
      subject="owner"
      deleted={deleted}
    />,
  );
  expect(screen.getByLabelText("Application ID to delete")).toHaveValue(
    "first-authority-target",
  );
  expect(localStorage.getItem(storageKey)).toBe(original);
  expect(localStorage.getItem(otherKey)).toBe(other);
  expect(request).not.toHaveBeenCalled();
});

it("preserves an unbound legacy witness without disclosing or adopting its contents", () => {
  const key = "openepm:application-purge:owner:w";
  const legacy = savedIntent("legacy-secret-target", "legacy-secret-operation");
  localStorage.setItem(key, legacy);
  display();
  open();
  expect(screen.getByRole("status")).toHaveTextContent(
    "preserved but cannot be restored",
  );
  expect(screen.getByRole("status")).toHaveTextContent(
    "current-authorized application status inspection",
  );
  expect(document.body.textContent).not.toContain("legacy-secret");
  expect(screen.getByLabelText("Application ID to delete")).toHaveValue("a");
  expect(screen.getByLabelText("Application ID to delete")).toBeEnabled();
  expect(localStorage.getItem(key)).toBe(legacy);
  expect(localStorage.getItem(storageKey)).toBeNull();
  expect(request).not.toHaveBeenCalled();
});

it("requires a verified issuer and account before reading recovery or offering deletion", () => {
  localStorage.setItem(storageKey, savedIntent("secret-target"));
  const read = vi.spyOn(Storage.prototype, "getItem");
  const view = render(
    <ApplicationPurge
      workspaceId="w"
      applicationId="a"
      issuer=""
      subject="owner"
      deleted={deleted}
    />,
  );
  expect(
    screen.getByText(/requires a verified sign-in authority and account/),
  ).toBeVisible();
  expect(
    screen.queryByLabelText("Application ID to delete"),
  ).not.toBeInTheDocument();
  view.rerender(
    <ApplicationPurge
      workspaceId="w"
      applicationId="a"
      issuer={issuer}
      subject=""
      deleted={deleted}
    />,
  );
  expect(read).not.toHaveBeenCalled();
  expect(request).not.toHaveBeenCalled();
  read.mockRestore();
});

it("discloses reload/sign-out persistence and the definite reconciliation lifetime", () => {
  display();
  open();
  expect(
    screen.getByText(/This browser stores the exact deletion retry request/),
  ).toHaveTextContent(
    "survives reload and sign-out until the request is reconciled as deleted or definitively rejected",
  );
});

it("ignores a late previous-identity reply without clearing its witness or reading as the new identity", async () => {
  const original = savedIntent("original-target");
  localStorage.setItem(storageKey, original);
  let finish!: (value: { status: string }) => void;
  vi.mocked(request).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const view = display();
  fireEvent.click(
    screen.getByRole("button", { name: "Delete original-target permanently" }),
  );
  expect(request).toHaveBeenCalledOnce();
  view.rerender(
    <ApplicationPurge
      workspaceId="w"
      applicationId="a"
      issuer="https://other.example"
      subject="owner"
      deleted={deleted}
    />,
  );
  await act(async () => finish({ status: "Deleting" }));
  expect(request).toHaveBeenCalledOnce();
  expect(deleted).not.toHaveBeenCalled();
  expect(localStorage.getItem(storageKey)).toBe(original);
  expect(screen.getByLabelText("Application ID to delete")).toHaveValue("a");
});

it("cannot let an unmounted reply delete a newer same-identity retry witness", async () => {
  localStorage.setItem(storageKey, savedIntent("original-target"));
  let finish!: (value: { status: string }) => void;
  vi.mocked(request).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const first = display();
  fireEvent.click(
    screen.getByRole("button", { name: "Delete original-target permanently" }),
  );
  first.unmount();
  const newer = savedIntent("newer-target", "newer-operation");
  localStorage.setItem(storageKey, newer);
  display();
  await act(async () => finish({ status: "Deleted" }));
  expect(localStorage.getItem(storageKey)).toBe(newer);
  expect(screen.getByLabelText("Application ID to delete")).toHaveValue(
    "newer-target",
  );
  expect(deleted).not.toHaveBeenCalled();
  expect(request).toHaveBeenCalledOnce();
});

it("encodes tuple boundaries without colon or percent aliases", () => {
  expect(applicationPurgeRecoveryKey("issuer:a", "b", "w")).not.toBe(
    applicationPurgeRecoveryKey("issuer", "a:b", "w"),
  );
  expect(applicationPurgeRecoveryKey("issuer%3Aa", "b", "w")).not.toBe(
    applicationPurgeRecoveryKey("issuer:a", "b", "w"),
  );
});
