import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApplicationPurge } from "./ApplicationPurge";
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
const deleted = vi.fn().mockResolvedValue(undefined);
function display() {
  return render(
    <ApplicationPurge
      workspaceId="w"
      applicationId="a"
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
  const stored = JSON.parse(
    localStorage.getItem("openepm:application-purge:owner:w")!,
  );
  expect(stored.program.function).toBe("workspace.application.purge.apply");
  expect(JSON.stringify(stored)).not.toContain("rowCounts");
  expect(JSON.stringify(stored)).not.toContain("Forecast");
  fireEvent.click(screen.getByRole("button", { name: "Delete a permanently" }));
  await waitFor(() => expect(deleted).toHaveBeenCalledWith("w", "a"));
  expect(vi.mocked(request).mock.calls[3][1]).toEqual(stored);
  expect(localStorage.getItem("openepm:application-purge:owner:w")).toBeNull();
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
  localStorage.setItem(
    "openepm:application-purge:owner:w",
    JSON.stringify(exact),
  );
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
  expect(localStorage.getItem("openepm:application-purge:owner:w")).toBeNull();
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
    "openepm:application-purge:owner:w",
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
