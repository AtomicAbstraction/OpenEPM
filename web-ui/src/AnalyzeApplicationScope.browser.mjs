import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const output = process.argv[2];
assert.ok(output, "Pass an output JSON path");
const web = resolve("web-ui");
const require = createRequire(resolve(web, "package.json"));
const globalModules = execFileSync("npm", ["root", "--global"], {
  encoding: "utf8",
}).trim();
const { chromium } = require(resolve(globalModules, "playwright"));
const { createServer } = await import(
  resolve(web, "node_modules/vite/dist/node/index.js")
);
const cacheDir = await mkdtemp(resolve(tmpdir(), "openepm-grid-scope-"));
const report = {
  scenarios: [],
  applicationChoices: [],
  pageErrors: [],
  unexpectedRequests: [],
};
const readFunction = "facts.cube.resolved.read";
const dimensions = ["Account", "Period"];
const source = { kind: "raw", resultKey: null };
const readPolicy = { semantics: "own" };
const viewFormat = "openepm-cube-view-read-v1";
const first = application(
  "first",
  "First application",
  "FirstMargin",
  93217,
  71,
);
const second = application(
  "second",
  "Second application",
  "SecondMargin",
  21438,
  82,
);
const alternative = application(
  "alternative",
  "Another application",
  "OtherMargin",
  402,
  91,
);

function application(workspaceId, name, member, value, revision) {
  return {
    summary: {
      workspaceId,
      applicationId: "planning",
      name,
      status: "Active",
      kind: "blank",
    },
    coordinates: { Account: member, Period: "Jan" },
    amount: `${value}.00000000`,
    revision,
  };
}

function definition(app) {
  return {
    format: "openepm-cube-view-v1",
    viewId: "shared-view",
    name: "Operating plan",
    selection: {
      format: "openepm-cube-selection-v1",
      metadataRevision: 2,
      dimensions: dimensions.map((dimensionId) => ({
        dimensionId,
        include: { kind: "members", memberIds: [app.coordinates[dimensionId]] },
        exclude: null,
      })),
    },
    layout: { pages: [], rows: ["Account"], columns: ["Period"], filters: [] },
    dataSource: source,
    suppression: { missing: false, zero: false },
    pageSize: 100,
  };
}

function result(app) {
  return {
    format: viewFormat,
    dataSource: source,
    readPolicy,
    complete: true,
    snapshot: { commitRevision: app.revision },
    presentation: { pageSize: 100, rowCount: 1 },
    rows: [
      {
        members: app.coordinates,
        values: {
          raw: [
            {
              present: true,
              value: app.amount,
              unit: "CHF",
              origin: "input",
              currentness: "current",
              resultStateToken: null,
            },
          ],
        },
      },
    ],
  };
}

async function checkScope(browser, base, width, settleAt) {
  const firstStatus = settleAt === "second-loaded" ? 400 : 200;
  const throughUnavailable = settleAt !== "second-loaded";
  const context = await browser.newContext({
    viewport: { width, height: 1000 },
  });
  const pending = new Map();
  const requests = [];
  let applications = [first, second];
  let listingGate;
  const catalogue = {
    applicationAccess: {
      role: settleAt === "second-loaded" ? "Editor" : "Reader",
      workspaceAdministrator: false,
      issuer: "fixture",
      subjectId: "reader",
    },
    enabledCapabilities: [],
    functions: {
      "metadata.dimension.list": {},
      "metadata.member.list": {},
      "grid.definition.list": {},
      ...(settleAt === "second-loaded" ? { "grid.definition.save": {} } : {}),
      [readFunction]: { canonicalViewRead: viewFormat },
    },
    revisions: { metadata: 2, data: 2, policy: 1, security: 1, commit: 2 },
  };
  try {
    const page = await context.newPage();
    page.setDefaultTimeout(12000);
    page.on("pageerror", (error) => report.pageErrors.push(error.message));
    // Hold the first response body after the client has accepted its headers.
    // This forces the parse to complete even after the caller cancels the read.
    await page.addInitScript((readFunction) => {
      const fetchOriginal = window.fetch.bind(window);
      window.scopeProbe = { aborted: false, parsedStatus: null, leaks: [] };
      window.fetch = async (input, options) => {
        const body =
          typeof options?.body === "string" ? JSON.parse(options.body) : null;
        if (
          body?.workspaceId !== "first" ||
          body.program?.function !== readFunction
        )
          return fetchOriginal(input, options);
        options.signal.addEventListener(
          "abort",
          () => {
            window.scopeProbe.aborted = true;
          },
          { once: true },
        );
        const response = await fetchOriginal(input, {
          ...options,
          signal: undefined,
        });
        const parse = response.json.bind(response);
        response.json = async () => {
          await new Promise((resolve) => {
            window.releaseObsoleteBody = resolve;
          });
          const value = await parse();
          window.scopeProbe.parsedStatus = response.status;
          return value;
        };
        return response;
      };
      window.observeScope = () => {
        const protectedText =
          /FirstMargin|93[,.]?217|Snapshot 71|OLD_SCOPE_READ_FAILED/;
        const observe = () => {
          const match = document
            .querySelector("main")
            ?.textContent.match(protectedText);
          if (match) window.scopeProbe.leaks.push(match[0]);
        };
        const observer = new MutationObserver(observe);
        observer.observe(document.querySelector("main"), {
          subtree: true,
          childList: true,
          characterData: true,
        });
        observe();
      };
    }, readFunction);
    async function serveFixture(route) {
      const request = route.request();
      const url = new URL(request.url());
      if (url.origin !== base) return route.abort();
      if (!url.pathname.startsWith("/api/")) return route.continue();
      const body = request.postDataJSON();
      const { pathname } = url;
      const reply = (json, status = 200) => route.fulfill({ status, json });
      if (pathname === "/api/applications") {
        if (listingGate) await listingGate.promise;
        return reply({
          applications: applications.map(({ summary }) => summary),
          nextAfter: null,
        });
      }
      if (pathname === "/api/session-identity")
        return reply({
          issuer: "fixture",
          subject: "reader",
          identityBinding: "a".repeat(64),
          displayIdentity: "Scope fixture reader",
        });
      if (pathname === "/api/runtime")
        return reply({
          readOnlyReview: false,
          build: { sourceCommit: "a".repeat(40), packagedSchema: 393 },
        });
      if (pathname === "/api/platform/browser/catalog")
        return reply({ languageVersion: 2, functions: {} });
      const fn = body?.program?.function;
      requests.push({
        path: pathname,
        scope: [body?.workspaceId, body?.applicationId],
        function: fn,
      });
      const app = [first, second, alternative].find(
        ({ summary }) =>
          summary.workspaceId === body?.workspaceId &&
          summary.applicationId === body?.applicationId,
      );
      if (app && pathname === "/api/catalog") return reply(catalogue);
      if (app && pathname === "/api/tasks")
        return reply({ tasks: [], nextSequence: 0, hasMore: false });
      if (app && pathname === "/api/read") {
        const args = body.program.arguments;
        if (fn === "metadata.dimension.list")
          return reply({
            result: {
              rows: dimensions.map((id) => ({
                dimension_id: id,
                name: id,
                model_role: id,
                status: "Active",
              })),
              nextAfterDimensionId: null,
              metadataRevision: 2,
            },
          });
        if (fn === "metadata.member.list") {
          const member = app.coordinates[args.dimensionId ?? args.dimension];
          assert.ok(member);
          return reply({
            result: {
              rows: [{ member_id: member, name: member, status: "Active" }],
              nextAfterMemberId: null,
              metadataRevision: 2,
            },
          });
        }
        if (fn === "grid.definition.list")
          return reply({
            result: {
              grids: [
                {
                  gridId: "shared-view",
                  name: "Operating plan",
                  definition: definition(app),
                  stateToken: "c".repeat(64),
                  metadataRevision: 2,
                  canonicalDigest: "fixture-view-digest",
                  creator: { issuer: "fixture", subjectId: "reader" },
                },
              ],
              nextAfterGridId: null,
              collectionToken: "d".repeat(64),
            },
          });
        if (fn === readFunction) {
          assert.equal(args.format, viewFormat);
          assert.deepEqual(args.view, definition(app));
          assert.deepEqual(args.readPolicy, readPolicy);
          if (app === first)
            return firstStatus === 400
              ? reply({ code: "OLD_SCOPE_READ_FAILED" }, firstStatus)
              : reply({ result: result(app) });
          assert.ok(!pending.has(app));
          const gate = Promise.withResolvers();
          const settled = Promise.withResolvers();
          pending.set(app, {
            release: gate.resolve,
            delivered: settled.promise,
          });
          await gate.promise;
          await reply({ result: result(app) });
          settled.resolve();
          return;
        }
      }
      report.unexpectedRequests.push({ path: pathname, fn });
      return reply({ code: "UNEXPECTED_FIXTURE_API" }, 400);
    }
    await page.route("**/*", async (route) => {
      try {
        await serveFixture(route);
      } catch (error) {
        report.pageErrors.push(error.message);
        await route.abort();
      }
    });

    const hash = (workspace) =>
      `#/grid/0?workspace=${workspace}&application=planning`;
    const navigate = (workspace) =>
      page.evaluate((target) => {
        location.hash = target;
      }, hash(workspace));
    const main = page.getByRole("main");
    const status = page.getByLabel("Grid snapshot status", { exact: true });
    const loaded = page.getByLabel("Loaded grid read", { exact: true });
    const focusText = () =>
      page.evaluate(() => document.activeElement?.textContent.trim());
    async function settleObsoleteResponse() {
      await page.evaluate(() => window.releaseObsoleteBody());
      await page.waitForFunction(
        (code) => window.scopeProbe.parsedStatus === code,
        firstStatus,
      );
    }
    async function begin(app) {
      await main
        .locator(".analyze-page .page-heading")
        .getByText(app.summary.name, { exact: true })
        .waitFor();
      await main
        .getByRole("button", { name: "Open view", exact: true })
        .click();
      const read = main.getByRole("button", { name: "Read grid", exact: true });
      await read.focus();
      await Promise.all([
        page.waitForRequest((request) => {
          const packet = request.postDataJSON();
          return (
            packet?.workspaceId === app.summary.workspaceId &&
            packet.program?.function === readFunction
          );
        }),
        page.keyboard.press("Enter"),
      ]);
      await status.getByText("Reading grid…", { exact: true }).waitFor();
      if (app === first)
        await page.waitForFunction(() => Boolean(window.releaseObsoleteBody));
      else assert.ok(pending.has(app));
      assert.equal(await loaded.count(), 0);
    }

    await page.goto(base + hash("first"));
    await begin(first);
    if (throughUnavailable) {
      const offset = requests.length;
      await navigate("unavailable");
      await main
        .getByRole("heading", { name: "Application unavailable" })
        .waitFor();
      assert.equal(new URL(page.url()).hash, hash("unavailable"));
      assert.equal(
        await main.getByRole("heading", { name: "Grid" }).count(),
        0,
      );
      await page.evaluate(() => window.observeScope());
      if (settleAt === "unavailable") {
        const recheck = main.getByRole("button", {
          name: "Recheck application access",
        });
        await recheck.focus();
        await settleObsoleteResponse();
        assert.equal(await focusText(), "Recheck application access");
        assert.equal(new URL(page.url()).hash, hash("unavailable"));
        assert.equal(await loaded.count(), 0);
      }
      assert.deepEqual(
        requests.slice(offset),
        [],
        "An unavailable link must not read another application",
      );
    }
    await navigate("second");
    await begin(second);
    if (!throughUnavailable) await page.evaluate(() => window.observeScope());

    const configure = main.getByRole("button", {
      name: "Configure layout",
      exact: true,
    });
    const release = async (app) => {
      const read = pending.get(app);
      read.release();
      await read.delivered;
    };
    if (firstStatus === 400) {
      await release(second);
      await loaded.waitFor();
      assert.equal(await loaded.innerText(), "Own input at each member");
    }
    await configure.focus();
    if (settleAt !== "unavailable") await settleObsoleteResponse();
    assert.equal(await focusText(), "Configure layout");
    if (firstStatus === 200) {
      assert.equal(await loaded.count(), 0);
      await status.getByText("Reading grid…", { exact: true }).waitFor();
      await release(second);
    }
    await loaded.waitFor();
    assert.equal(await loaded.innerText(), "Own input at each member");
    const cellText = await main
      .locator('[data-grid-row="0"][data-grid-column="0"]')
      .innerText();
    assert.equal(cellText.replaceAll(",", "").trim(), "21438.00000000");
    await main.getByText("SecondMargin", { exact: true }).first().waitFor();
    assert.equal(await focusText(), "Configure layout");
    assert.deepEqual(await page.evaluate(() => window.scopeProbe), {
      aborted: true,
      parsedStatus: firstStatus,
      leaks: [],
    });
    const scopes = requests
      .filter((request) => request.function === readFunction)
      .map((request) => request.scope);
    assert.deepEqual(scopes, [
      ["first", "planning"],
      ["second", "planning"],
    ]);
    const observation = {
      width,
      throughUnavailable,
      settleAt,
      firstStatus,
      scopes,
      secondSnapshot: second.revision,
      secondExactValue: cellText,
      focus: await focusText(),
      obsoleteResponseParsedAfterAbort: true,
      obsoleteContentObservations: 0,
    };
    if (settleAt === "second-loaded") {
      const withdrawTarget = width === 651;
      await configure.press("Enter");
      await main.getByText("Save current view", { exact: true }).press("Enter");
      await main
        .getByLabel("Display name", { exact: true })
        .fill("Draft operating plan");
      await page
        .getByRole("button", { name: "Search", exact: true })
        .press("Enter");
      const search = page.getByRole("dialog", { name: "Search Open EPM" });
      await search.getByRole("textbox").fill(first.summary.name);
      await search
        .getByRole("button", { name: /First application/ })
        .press("Enter");
      const confirmation = page.getByRole("alertdialog", {
        name: "Discard unsaved changes?",
      });
      await confirmation
        .getByText("Unsaved grid writeback or definition")
        .waitFor();
      applications = withdrawTarget
        ? [alternative, second]
        : [alternative, first, second];
      listingGate = Promise.withResolvers();
      const listed = page.waitForRequest(
        (request) => new URL(request.url()).pathname === "/api/applications",
      );
      await page.evaluate(() => window.dispatchEvent(new Event("online")));
      await listed;
      const revalidating = page.getByRole("heading", {
        name: "Revalidating your session",
      });
      await revalidating.waitFor();
      const pendingFocus = new URLSearchParams(
        new URL(page.url()).hash.split("?")[1],
      );
      assert.equal(pendingFocus.get("workspace"), second.summary.workspaceId);
      listingGate.resolve();
      await revalidating.waitFor({ state: "hidden" });
      const beforeChoice = requests.length;
      await confirmation
        .getByRole("button", { name: "Discard and continue" })
        .press("Enter");
      await main
        .getByRole("heading", {
          name: withdrawTarget ? "Application unavailable" : first.summary.name,
          exact: true,
        })
        .waitFor();
      const hash = new URL(page.url()).hash;
      const focus = new URLSearchParams(hash.split("?")[1]);
      assert.equal(focus.get("workspace"), first.summary.workspaceId);
      assert.equal(focus.get("application"), first.summary.applicationId);
      if (!withdrawTarget) assert.match(hash, /^#\/overview\/1\?/);
      const calls = requests.slice(beforeChoice);
      assert.deepEqual(
        calls
          .filter(({ path }) => path === "/api/catalog")
          .map(({ scope }) => scope),
        withdrawTarget
          ? []
          : [[first.summary.workspaceId, first.summary.applicationId]],
      );
      assert.ok(
        calls.every(
          ({ path, scope }) =>
            ["/api/catalog", "/api/tasks"].includes(path) &&
            scope.join("/") ===
              `${first.summary.workspaceId}/${first.summary.applicationId}`,
        ),
      );
      assert.equal(
        await main.evaluate((element) => document.activeElement === element),
        true,
      );
      report.applicationChoices.push({
        width,
        withdrawTarget,
        route: hash,
        focused: "main",
        scopedRequests: calls,
      });
    }
    return observation;
  } finally {
    listingGate?.resolve();
    for (const read of pending.values()) read.release();
    await context.close();
  }
}

let browser;
let server;
try {
  server = await createServer({
    root: web,
    cacheDir,
    server: { host: "127.0.0.1", port: 0 },
    clearScreen: false,
    logLevel: "error",
  });
  await server.listen();
  const base = `http://127.0.0.1:${server.httpServer.address().port}`;
  browser = await chromium.launch({ headless: true });
  report.browserVersion = browser.version();
  for (const width of [651, 1280])
    for (const settleAt of ["unavailable", "second-pending", "second-loaded"])
      report.scenarios.push(await checkScope(browser, base, width, settleAt));
  assert.deepEqual(report.pageErrors, []);
  assert.deepEqual(report.unexpectedRequests, []);
  report.passed = true;
} catch (error) {
  report.failure = error.stack;
  throw error;
} finally {
  await browser?.close();
  await server?.close();
  await rm(cacheDir, { recursive: true, force: true });
  report.cleanupVerified = true;
  await writeFile(output, `${JSON.stringify(report, null, 2)}\n`);
}
