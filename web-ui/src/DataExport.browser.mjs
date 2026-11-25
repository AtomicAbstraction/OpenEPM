// Real App/CapabilityArea/DataExport rendering with isolated intercepted APIs.
// Pure fixed-core builders create fabricated manifest/payload fixtures; no DB.
// Run: node web-ui/src/DataExport.browser.mjs [result.json]
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const projectRoot = resolve(webRoot, "..");
const require = createRequire(import.meta.url);
let playwrightModule = process.env.OPEN_EPM_PLAYWRIGHT_MODULE;
if (!playwrightModule) {
  try {
    playwrightModule = require.resolve("playwright");
  } catch {
    playwrightModule = resolve(
      execFileSync("npm", ["root", "--global"], { encoding: "utf8" }).trim(),
      "playwright",
    );
  }
}
const { chromium } = require(playwrightModule);
const { createServer } = await import(
  resolve(webRoot, "node_modules/vite/dist/node/index.js")
);
const cacheDir = await mkdtemp(resolve(tmpdir(), "openepm-export-recovery-"));
const server = await createServer({
  root: webRoot,
  cacheDir,
  server: { host: "127.0.0.1", port: 0 },
  clearScreen: false,
  logLevel: "error",
});
const application = {
  workspaceId: "fixture",
  applicationId: "export",
  name: "Export fixture",
  status: "Active",
  kind: "blank",
};
const requestId = "1".repeat(32),
  artifactId = "a".repeat(32);
const catalog = {
  applicationAccess: {
    role: "Administrator",
    workspaceAdministrator: false,
    issuer: "fixture",
    subjectId: "operator",
  },
  enabledCapabilities: [],
  functions: Object.fromEntries(
    ["request", "read", "cancel", "manifest.read", "payload.page"].map(
      (suffix) => [`facts.transfer.export.${suffix}`, {}],
    ),
  ),
  revisions: { metadata: 7, data: 9, policy: 1, security: 1, commit: 12 },
};
const fixtureCode = `
import copy,json,sys
from epm_core.export_artifact_manifest import ExportArtifactBuilder
from epm_core.export_payload_chunk import compile_export_payload,export_payload_matches
from epm_core.persistence_contract import ApplicationScope
from epm_core.postgres_fact_export import _EXPORT_SCHEMA,_content_digest
args=json.load(sys.stdin)
scope=ApplicationScope('fixture','export')
values=[{'type':'AmountLiteral','decimal':'0.00000000'}, {'type':'TextLiteral','text':''}, {'type':'LineDetailLiteral','items':[{'description':'Fabricated travel','decimal':'100.00000001'}]}]
rows=[{'members':{'Account':name,'Entity':'One','Year':'Y2026','Period':'M01','View':'Point','Value':'Native','Scenario':'Baseline','DataType':'Authored'},'value':value,'sourceRef':'export:'+format(index+1,'064x')} for index,(name,value) in enumerate(zip(['Zero','Empty','Detail'],values))]
page={'schema':copy.deepcopy(_EXPORT_SCHEMA),'rows':rows,'nextCursor':None,'hasMore':False,'snapshotRevision':12,'metadataRevision':7,'securityRevision':1,'source':'postgres_event_history'}
page['contentDigest']=_content_digest(scope,page)
manifest=ExportArtifactBuilder.begin(scope,snapshot_revision=12,metadata_revision=7,security_revision=1,expires_at=args['expiresAt']).append(page_index=0,request_cursor=None,page=page).finalize(expires_at=args['expiresAt']).manifest()
payload=compile_export_payload(args['artifactId'],scope,manifest,[page],max_chunk_rows=1)
assert export_payload_matches(payload,scope=scope,artifact_id=args['artifactId'],manifest=manifest)
print(json.dumps({'manifest':manifest,'payload':payload}))
`;
const sourcePaths = [
  "web-ui/src/DataExport.tsx",
  "web-ui/src/data-transfer-action.ts",
  "web-ui/src/data-workspaces.css",
  "web-ui/src/DataExport.browser.mjs",
  "web-ui/src/DataLoad.tsx",
  "web-ui/src/api.ts",
  "web-ui/src/App.tsx",
  "web-ui/src/CapabilityArea.tsx",
  "web-ui/src/unsaved-work.ts",
  "epm_core/export_artifact_manifest.py",
  "epm_core/export_payload_chunk.py",
  "epm_core/postgres_fact_export.py",
];
const sourceManifest = async () =>
  Promise.all(
    sourcePaths.map(async (path) => ({
      path,
      sha256: createHash("sha256")
        .update(await readFile(resolve(projectRoot, path)))
        .digest("hex"),
    })),
  );
const capturedSource = await sourceManifest();
const report = {
  startedAt: new Date().toISOString(),
  sourceFiles: capturedSource,
  method:
    "Real Chromium App/CapabilityArea/DataExport; all network API calls intercepted. Synthetic manifest and typed payload built and verified by existing pure fixed-core builders. No database, shared app, live identity, server authority or publication proof.",
  pageErrors: [],
  unknownApi: [],
  cases: [],
};
const json = (value, status = 200) => ({
  status,
  contentType: "application/json",
  body: JSON.stringify(value),
});
function pauseResponse() {
  const request = Promise.withResolvers();
  const response = Promise.withResolvers();
  return {
    requested: request.promise,
    hold: () => {
      request.resolve();
      return response.promise;
    },
    release: response.resolve,
  };
}
let browser;
try {
  await server.listen();
  const base = `http://127.0.0.1:${server.httpServer.address().port}`;
  browser = await chromium.launch({ headless: true });
  report.browserVersion = browser.version();
  for (const width of [650, 1280])
    for (const journey of ["complete", "cancel", "interrupt"]) {
      const context = await browser.newContext({
        viewport: { width, height: 1000 },
      });
      await context.addInitScript(() => {
        window.exportWriter = { writes: [], closeCount: 0, abortCount: 0 };
        window.showSaveFilePicker = async () => ({
          createWritable: async () => ({
            write: async (value) => {
              window.exportWriter.writes.push(value);
            },
            close: async () => {
              window.exportWriter.closeCount += 1;
            },
            abort: async () => {
              window.exportWriter.abortCount += 1;
            },
          }),
        });
      });
      const page = await context.newPage();
      page.setDefaultTimeout(15000);
      page.on("pageerror", (error) => report.pageErrors.push(error.message));
      page.on("dialog", (dialog) => dialog.accept());
      const requests = [],
        cancellations = [],
        statusReads = [];
      const pausedRequest = pauseResponse();
      const pausedCancellation = pauseResponse();
      const pausedStatus = pauseResponse();
      let admissionCount = 0,
        fixture,
        expiresAt,
        releasePayload;
      const outcome = (status, changes = {}) => ({
        requestId,
        status,
        snapshotRevision: 12,
        metadataRevision: 7,
        securityRevision: 1,
        expiresAt,
        pageCount: status === "Completed" ? fixture.manifest.pageCount : 0,
        cancelRequested: false,
        artifactId: status === "Completed" ? artifactId : null,
        errorCode: null,
        ...changes,
      });
      await page.route("**/*", async (route) => {
        const url = new URL(route.request().url());
        if (url.origin !== base) return route.abort();
        if (!url.pathname.startsWith("/api/")) return route.continue();
        const path = url.pathname,
          body = route.request().postDataJSON();
        if (path === "/api/applications")
          return route.fulfill(
            json({ applications: [application], nextAfter: null }),
          );
        if (path === "/api/session-identity")
          return route.fulfill(
            json({
              issuer: "fixture",
              subject: "operator",
              identityBinding: "a".repeat(64),
              displayIdentity: "Fixture operator",
            }),
          );
        if (path === "/api/runtime")
          return route.fulfill(
            json({
              readOnlyReview: false,
              build: { sourceCommit: "a".repeat(40), packagedSchema: 381 },
            }),
          );
        if (path === "/api/platform/browser/catalog")
          return route.fulfill(json({ languageVersion: 2, functions: {} }));
        if (path === "/api/catalog") return route.fulfill(json(catalog));
        if (path === "/api/tasks")
          return route.fulfill(
            json({ tasks: [], nextSequence: 0, hasMore: false }),
          );
        if (path === "/api/operation-admission") {
          admissionCount += 1;
          return route.fulfill(
            json({
              operationId: `oa1_zz_${admissionCount.toString(16).repeat(32)}_${"A".repeat(43)}`,
              expiresAt: Math.floor(Date.now() / 1000) + 900,
              intentDigest: "b".repeat(64),
            }),
          );
        }
        if (path === "/api/export") {
          const fn = body.program.function;
          if (fn === "facts.transfer.export.request") {
            requests.push(body);
            expiresAt = body.program.arguments.expiresAt;
            fixture ??= JSON.parse(
              execFileSync("python3", ["-c", fixtureCode], {
                cwd: projectRoot,
                encoding: "utf8",
                input: JSON.stringify({ expiresAt, artifactId }),
              }),
            );
            if (journey === "complete" && requests.length === 1) {
              await pausedRequest.hold();
              return route.abort("failed");
            }
            return route.fulfill(
              json({
                result: outcome(
                  journey === "interrupt" ? "Completed" : "Accepted",
                  { duplicate: requests.length > 1 },
                ),
              }),
            );
          }
          if (fn === "facts.transfer.export.read") {
            if (body.program.arguments.operationId) {
              assert.deepEqual(body.program.arguments, {
                operationId: requests[0].idempotencyKey,
              });
              return route.fulfill(json({ result: outcome("Accepted") }));
            }
            statusReads.push(body);
            assert.equal(body.program.arguments.requestId, requestId);
            await pausedStatus.hold();
            return route.fulfill(
              json({
                result: outcome(
                  journey === "cancel" ? "Cancelled" : "Completed",
                  { cancelRequested: journey === "cancel" },
                ),
              }),
            );
          }
          if (fn === "facts.transfer.export.cancel") {
            cancellations.push(body);
            if (cancellations.length === 1) {
              await pausedCancellation.hold();
              return route.abort("failed");
            }
            return route.fulfill(
              json({ error: "OPERATION_ADMISSION_EXPIRED" }, 400),
            );
          }
          if (fn === "facts.transfer.export.manifest.read") {
            assert.deepEqual(body.program.arguments, { artifactId });
            return route.fulfill(
              json({ result: { artifactId, artifact: fixture.manifest } }),
            );
          }
          if (fn === "facts.transfer.export.payload.page") {
            const args = body.program.arguments;
            const ordinal = args.cursor
              ? Number(args.cursor.slice("fixture-cursor-".length))
              : 0;
            if (journey === "interrupt")
              await new Promise((done) => {
                releasePayload = done;
              });
            const hasMore = ordinal + 1 < fixture.payload.chunkCount;
            return route
              .fulfill(
                json({
                  result: {
                    artifactId,
                    manifestDigest: fixture.manifest.manifestDigest,
                    payloadDigest: fixture.payload.payloadDigest,
                    schema: fixture.manifest.schema,
                    snapshotRevision: 12,
                    metadataRevision: 7,
                    securityRevision: 1,
                    storageFormat: "plaintext_json",
                    encryptionClaim: false,
                    ordinal,
                    chunk: fixture.payload.chunks[ordinal],
                    hasMore,
                    nextCursor: hasMore
                      ? `fixture-cursor-${ordinal + 1}`
                      : null,
                    expiresAt,
                  },
                }),
              )
              .catch((error) => {
                if (journey !== "interrupt") throw error;
              });
          }
        }
        report.unknownApi.push({ path, fn: body?.program?.function });
        return route.fulfill(json({ error: "FIXTURE_UNAVAILABLE" }, 400));
      });
      const exportHash =
        "#/data?section=export&workspace=fixture&application=export";
      const activityHash =
        "#/data?section=activity&workspace=fixture&application=export";
      const openExport = async () => {
        await page.evaluate((hash) => {
          location.hash = hash;
        }, exportHash);
        await page
          .getByRole("heading", { name: "Export a governed snapshot" })
          .waitFor();
      };
      await page.goto(base + "/" + exportHash);
      await page
        .getByRole("heading", { name: "Export a governed snapshot" })
        .waitFor();
      await page.getByLabel("Whole application", { exact: true }).check();
      assert.equal(
        await page
          .getByRole("button", { name: "Start snapshot export" })
          .isEnabled(),
        false,
      );
      await page
        .getByLabel("I reviewed this exact export scope and availability")
        .check();
      const observedStates = [];
      const progress = page.getByRole("list", { name: "Export progress" });
      const currentStep = () => progress.locator('[aria-current="step"]');
      assert.equal(
        await currentStep().getAttribute("aria-label"),
        "Review scope: current",
      );
      const start = page.getByRole("button", { name: "Start snapshot export" });
      const originalStart = await start.elementHandle();
      await start.press("Enter");
      if (journey === "complete") {
        await pausedRequest.requested;
        const transferring = page.getByText(
          /Submitting snapshot request…|Export outcome unknown/,
        );
        await transferring.waitFor();
        const observation = {
          state: "pending-request",
          focusRetained: await originalStart.evaluate(
            (element) => document.activeElement === element,
          ),
          status: await transferring.innerText(),
        };
        report.pendingObservation = observation;
        assert.deepEqual(observation, {
          state: "pending-request",
          focusRetained: true,
          status: "Submitting snapshot request…",
        });
        await page.keyboard.press("Enter");
        assert.equal(requests.length, 1);
        assert.equal(admissionCount, 1);
        pausedRequest.release();
        delete report.pendingObservation;
        observedStates.push(observation);
        await page.getByText(/Export outcome unknown/).waitFor();
        assert.equal(
          await page
            .getByLabel("Whole application", { exact: true })
            .isDisabled(),
          true,
        );
        await page.evaluate(() => {
          const now = Date.now();
          Date.now = () => now + 1200_000;
        });
        await page
          .getByRole("button", { name: "Retry connection", exact: true })
          .click();
        await page.evaluate((hash) => {
          location.hash = hash;
        }, activityHash);
        await page
          .getByRole("heading", { name: "Recent governed data activity" })
          .waitFor();
        await openExport();
        const reconcile = page.getByRole("button", {
          name: "Check original export status",
        });
        const original = await reconcile.elementHandle();
        await reconcile.press("Enter");
        await page.getByText("Accepted", { exact: true }).waitFor();
        assert.equal(
          await original.evaluate(
            (element) => document.activeElement === element,
          ),
          true,
        );
        assert.equal(admissionCount, 1);
        assert.equal(requests.length, 1);
      }
      if (journey === "cancel") {
        await page.getByText("Accepted", { exact: true }).waitFor();
        await page
          .getByLabel("Review cancellation of this exact current state")
          .check();
        const cancel = page.getByRole("button", {
          name: "Cancel export",
          exact: true,
        });
        const original = await cancel.elementHandle();
        await cancel.press("Enter");
        await pausedCancellation.requested;
        const waiting = page.getByText(
          /Requesting export cancellation…|Cancellation outcome unknown/,
        );
        await waiting.waitFor();
        assert.equal(
          await waiting.innerText(),
          "Requesting export cancellation…",
        );
        assert.equal(
          await original.evaluate(
            (element) => document.activeElement === element,
          ),
          true,
        );
        await page.keyboard.press("Enter");
        assert.equal(cancellations.length, 1);
        pausedCancellation.release();
        observedStates.push({
          state: "pending-cancellation",
          focusRetained: true,
        });
        await page.getByText(/Cancellation outcome unknown/).waitFor();
        await page.evaluate(() => {
          const now = Date.now();
          Date.now = () => now + 1200_000;
        });
        await page
          .getByRole("button", { name: "Retry connection", exact: true })
          .click();
        await page
          .getByRole("button", { name: "Reconcile original cancellation" })
          .click();
        await page
          .getByText("OPERATION_ADMISSION_EXPIRED", { exact: true })
          .waitFor();
        await page.getByText(/Cancellation outcome unknown/).waitFor();
        assert.equal(admissionCount, 2);
        assert.equal(cancellations.length, 2);
        assert.deepEqual(cancellations[1], cancellations[0]);
      }
      if (journey !== "interrupt") {
        const refresh = page.getByRole("button", {
          name: "Refresh status",
          exact: true,
        });
        await refresh.press("Enter");
        await pausedStatus.requested;
        await page
          .getByText("Checking export status…", { exact: true })
          .waitFor();
        assert.equal(
          await refresh.evaluate((el) => document.activeElement === el),
          true,
        );
        await page.keyboard.press("Enter");
        assert.equal(statusReads.length, 1);
        let expected = await refresh.elementHandle();
        if (journey === "cancel") {
          await page.keyboard.press("Shift+Tab");
          assert.equal(
            await refresh.evaluate((el) => document.activeElement === el),
            false,
          );
          expected = await page.locator(":focus").elementHandle();
          assert.equal(
            await expected.evaluate((el) => el === document.body),
            false,
          );
        }
        pausedStatus.release();
        const result =
          journey === "cancel"
            ? "Cancelled · cancellation requested"
            : "Completed";
        await page.getByText(result, { exact: true }).waitFor();
        assert.equal(
          await expected.evaluate((el) => document.activeElement === el),
          true,
        );
        observedStates.push({
          state: "status-read",
          focusRetained: true,
          deliberateExitRespected: journey === "cancel",
        });
      }
      if (journey === "cancel") {
        await page
          .getByText("Cancelled · cancellation requested", { exact: true })
          .waitFor();
        await page.getByText("No complete bundle", { exact: true }).waitFor();
        assert.equal(
          await page.getByText(/Cancellation outcome unknown/).count(),
          0,
        );
        assert.equal(admissionCount, 2);
        assert.equal(cancellations.length, 2);
        assert.equal(
          await page
            .getByRole("button", { name: "Download complete JSON bundle" })
            .isEnabled(),
          false,
        );
      } else {
        await page.getByText("Completed", { exact: true }).waitFor();
        assert.equal(
          await currentStep().getAttribute("aria-label"),
          "Download: current",
        );
        const download = page.getByRole("button", {
          name: "Download complete JSON bundle",
        });
        const original = await download.elementHandle();
        await download.press("Enter");
        if (journey === "interrupt") {
          await page.waitForFunction(
            () => window.exportWriter.writes.length === 1,
          );
          assert.equal(typeof releasePayload, "function");
          assert.equal(
            await original.evaluate(
              (element) => document.activeElement === element,
            ),
            true,
          );
          await page
            .getByRole("status")
            .filter({ hasText: "Downloading snapshot bundle…" })
            .waitFor();
          assert.equal(
            await currentStep().getAttribute("aria-label"),
            "Download: current",
          );
          observedStates.push({
            state: "partial-download",
            focusRetained: true,
          });
          await page.evaluate((hash) => {
            location.hash = hash;
          }, activityHash);
          await page
            .getByRole("heading", { name: "Recent governed data activity" })
            .waitFor();
          await page.waitForFunction(() => window.exportWriter.abortCount > 0);
          releasePayload();
          await openExport();
          assert.equal(
            await page
              .getByRole("button", { name: "Download complete JSON bundle" })
              .isEnabled(),
            true,
          );
          const writer = await page.evaluate(() => window.exportWriter);
          assert.equal(writer.writes.length, 1);
          assert.equal(writer.closeCount, 0);
          assert.ok(writer.abortCount >= 1);
        } else {
          await page
            .getByRole("button", {
              name: "Complete bundle downloaded · 3 chunks",
            })
            .waitFor();
          assert.equal(
            await original.evaluate(
              (element) => document.activeElement === element,
            ),
            true,
          );
          await page
            .getByRole("status")
            .filter({ hasText: "Complete bundle downloaded." })
            .waitFor();
          assert.equal(await currentStep().count(), 0);
          assert.equal(
            await progress.locator('[aria-label="Download: complete"]').count(),
            1,
          );
          observedStates.push({
            state: "completed-download",
            focusRetained: true,
          });
          const writer = await page.evaluate(() => window.exportWriter);
          assert.equal(writer.closeCount, 1);
          assert.equal(writer.abortCount, 0);
          const bundle = JSON.parse(writer.writes.join(""));
          assert.equal(bundle.chunkCount, 3);
          assert.deepEqual(bundle.manifest, fixture.manifest);
          assert.deepEqual(
            bundle.chunks.map((chunk) => chunk.chunk),
            fixture.payload.chunks,
          );
          assert.equal(
            bundle.chunks[0].chunk.rows[0].value.decimal,
            "0.00000000",
          );
          assert.equal(bundle.chunks[1].chunk.rows[0].value.text, "");
          assert.equal(
            bundle.chunks[2].chunk.rows[0].value.items[0].decimal,
            "100.00000001",
          );
        }
      }
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth + 1,
        ),
        true,
        "Viewport has horizontal overflow",
      );
      report.cases.push({
        width,
        journey,
        passed: true,
        admissionCount,
        exportDispatches: requests.length,
        cancellationDispatches: cancellations.length,
        observedStates,
      });
      await context.close();
    }
  assert.deepEqual(report.unknownApi, []);
  assert.deepEqual(report.pageErrors, []);
  assert.deepEqual(
    await sourceManifest(),
    capturedSource,
    "Source changed during rendered qualification",
  );
  report.passed = true;
} catch (error) {
  report.passed = false;
  report.error = error.message;
  report.body = await browser
    ?.contexts()
    .at(-1)
    ?.pages()
    .at(-1)
    ?.locator("body")
    .innerText();
  throw error;
} finally {
  await browser?.close();
  await server.close();
  await rm(cacheDir, { recursive: true, force: true });
  report.cleanup = {
    browserClosed: true,
    serverClosed: true,
    temporaryCacheRemoved: true,
    sharedBackendUsed: false,
  };
  if (process.argv[2])
    await writeFile(process.argv[2], JSON.stringify(report, null, 2) + "\n");
}
console.log(JSON.stringify(report, null, 2));
