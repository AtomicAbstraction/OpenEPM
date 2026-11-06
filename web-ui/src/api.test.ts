import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  listApplications,
  readPlatformProgram,
  request,
  reviewAndSubmit,
  writePlatformProgram,
} from "./api";
import {
  browserLifecycleSnapshot,
  resetBrowserLifecycleForTests,
} from "./browser-lifecycle";
import serverContracts from "./server-contract-fixtures.json";

afterEach(() => {
  vi.unstubAllGlobals();
  resetBrowserLifecycleForTests();
});

describe("presentation API adapter", () => {
  it("uses the existing endpoint without changing a request body", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const body = { workspaceId: "ws", applicationId: "app" };
    await request("/api/catalog", body);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/catalog",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(body),
        credentials: "same-origin",
      }),
    );
  });

  it("submits only the exact server preview after explicit review", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            previewToken: "sealed-preview-token",
            programDigest: "a".repeat(64),
            revisionVector: { metadata: 3, data: 4 },
          }),
        ),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify({ jobId: "job-1" })));
    vi.stubGlobal("fetch", fetchMock);
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const body = {
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "facts.numeric.batch",
        arguments: { mutations: [] },
      },
      idempotencyKey: "intent-1",
      dependsOnJobIds: [],
      confirmed: true,
    };
    await expect(reviewAndSubmit(body, "Review writeback.")).resolves.toEqual({
      jobId: "job-1",
    });
    expect(fetchMock.mock.calls[0][0]).toBe("/api/preview");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      workspaceId: "ws",
      applicationId: "app",
      program: body.program,
    });
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({
      ...body,
      previewToken: "sealed-preview-token",
    });
    expect(confirm.mock.calls[0][0]).toContain("a".repeat(64));
    expect(confirm.mock.calls[0][0]).toContain(
      'Dependency revisions: {"metadata":3,"data":4}',
    );
  });

  it("never submits a rejected or malformed server preview", async () => {
    const body = {
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "facts.numeric.batch",
        arguments: {},
      },
      idempotencyKey: "intent-2",
      dependsOnJobIds: [],
      confirmed: true,
    };
    const rejectedFetch = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ previewToken: "sealed-preview-token" })),
      );
    vi.stubGlobal("fetch", rejectedFetch);
    vi.spyOn(window, "confirm").mockReturnValue(false);
    await expect(reviewAndSubmit(body, "Review.")).resolves.toBeNull();
    expect(rejectedFetch).toHaveBeenCalledTimes(1);

    const malformedFetch = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ previewToken: "short" })),
      );
    vi.stubGlobal("fetch", malformedFetch);
    await expect(reviewAndSubmit(body, "Review.")).rejects.toMatchObject({
      code: "INVALID_SERVER_PREVIEW",
    });
    expect(malformedFetch).toHaveBeenCalledTimes(1);
  });

  it("retains server error codes", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ error: "ACCESS_DENIED" }), {
          status: 403,
          headers: { "content-type": "application/json" },
        }),
      ),
    );
    await expect(request("/api/catalog", {})).rejects.toEqual(
      new ApiError(403, "ACCESS_DENIED"),
    );
  });

  it("retains correlation, retryability and safe field details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: "CAPACITY_REJECTED",
            code: "CAPACITY_REJECTED",
            message: "Capacity rejected",
            correlationId: "a".repeat(32),
            retryable: true,
            details: { field: "rows" },
          }),
          { status: 429 },
        ),
      ),
    );
    await expect(request("/api/source-load", {})).rejects.toMatchObject({
      kind: "capacity",
      code: "CAPACITY_REJECTED",
      correlationId: "a".repeat(32),
      retryable: true,
      details: { field: "rows" },
    });
  });

  it("makes an expired session an application-wide state", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ error: "ACCESS_TOKEN_EXPIRED" }), {
          status: 401,
          headers: { "content-type": "application/json" },
        }),
      ),
    );
    await expect(request("/api/session-identity")).rejects.toMatchObject({
      kind: "authentication",
    });
    expect(browserLifecycleSnapshot()).toMatchObject({
      state: "expired",
      reason: "ACCESS_TOKEN_EXPIRED",
    });
  });

  it("keeps authorization denial separate from session expiry", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ error: "ACCESS_DENIED" }), {
          status: 403,
          headers: { "content-type": "application/json" },
        }),
      ),
    );
    await expect(request("/api/catalog", {})).rejects.toMatchObject({
      kind: "authorization",
    });
    expect(browserLifecycleSnapshot().state).toBe("bootstrapping");
  });

  it("rejects redirected API responses as application-wide expiry", async () => {
    const response = new Response("<html>sign in</html>", { status: 200 });
    Object.defineProperty(response, "redirected", { value: true });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
    await expect(request("/api/session-identity")).rejects.toMatchObject({
      kind: "authentication",
      code: "AUTHENTICATION_REDIRECTED",
    });
    expect(browserLifecycleSnapshot()).toMatchObject({
      state: "expired",
      reason: "AUTHENTICATION_REDIRECTED",
    });
  });

  it("rejects successful non-JSON responses as unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("<html>upstream error</html>", { status: 200 }),
        ),
    );
    await expect(request("/api/session-identity")).rejects.toMatchObject({
      kind: "unavailable",
      code: "INVALID_RESPONSE_CONTENT",
    });
    expect(browserLifecycleSnapshot()).toMatchObject({
      state: "unavailable",
      reason: "INVALID_RESPONSE_CONTENT",
    });
  });

  it("follows the existing bounded application pagination contract", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ...serverContracts.applicationPage,
            nextAfter: { workspaceId: "ws", applicationId: "app" },
          }),
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            applications: [
              {
                workspaceId: "b",
                applicationId: "2",
                name: "Two",
                status: "active",
              },
            ],
            nextAfter: null,
          }),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    expect(await listApplications()).toHaveLength(2);
    expect(fetchMock.mock.calls[1][0]).toContain("afterWorkspaceId=ws");
  });

  it("rejects incomplete or substituted application continuations", async () => {
    const invalidCursor = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          ...serverContracts.applicationPage,
          nextAfter: { workspaceId: "other", applicationId: "cursor" },
        }),
      ),
    );
    vi.stubGlobal("fetch", invalidCursor);
    await expect(listApplications()).rejects.toMatchObject({
      code: "INVALID_APPLICATION_CATALOG_CONTINUATION",
    });

    const repeated = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ...serverContracts.applicationPage,
            nextAfter: { workspaceId: "ws", applicationId: "app" },
          }),
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify(serverContracts.applicationPage)),
      );
    vi.stubGlobal("fetch", repeated);
    await expect(listApplications()).rejects.toMatchObject({
      code: "APPLICATION_CATALOG_REPEATED_APPLICATION",
    });
  });

  it("keeps server directory reads and writes inside the platform browser boundary", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        async () =>
          new Response(JSON.stringify({ items: [] }), { status: 200 }),
      );
    vi.stubGlobal("fetch", fetchMock);
    await readPlatformProgram("identity.group.list", { offset: 0, limit: 100 });
    await writePlatformProgram(
      "identity.group.membership.set",
      { subjectId: "user-1", groupId: "finance", action: "add" },
      "request-1",
    );
    expect(fetchMock.mock.calls[0][0]).toBe("/api/platform/browser/read");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      program: {
        languageVersion: 2,
        function: "identity.group.list",
        arguments: { offset: 0, limit: 100 },
      },
    });
    expect(fetchMock.mock.calls[1][0]).toBe("/api/platform/browser/write");
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({
      program: {
        languageVersion: 2,
        function: "identity.group.membership.set",
        arguments: {
          subjectId: "user-1",
          groupId: "finance",
          action: "add",
        },
      },
      idempotencyKey: "request-1",
      confirmed: true,
    });
  });
});
